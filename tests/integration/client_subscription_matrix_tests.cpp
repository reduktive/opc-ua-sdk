// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientSubscription cluster of the client integration-test matrix (the 15 `ClientSubscription.*`
/// rows
///        plus `ClientSubscription.SemanticsChangedBitTriggersPropertyRefresh`, 16 tests total).
///
/// These are END-TO-END integration tests of the managed SubscriptionsPipeline (client design section 8.4).
/// The completed rows enter through the highest public production API available for Subscription lifecycle:
/// `Connection::subscriptions()` / `Subscription`. No tier-2 Subscription domain facade exists; this public
/// lifecycle accessor is the repository's tier-1 surface. A real `Client` is bound to a
/// `MisbehavingServer`'s crypto + trusted certificate
/// store over ephemeral TCP; the tier-0 connect (open_channel / create_session / activate) yields an
/// activated Session that a `ConnectionImpl` wraps. The always-on Publish pump auto-runs on the pool, so
/// subscription behaviour is driven by the pump and observed through three client-visible surfaces:
///   - the DATA SINK - the per-monitored-item `DataValue` callback (notifications actually delivered);
///   - the REQUEST OBSERVER (`MisbehavingServer::set_request_observer`) - the DECODED outgoing PublishRequest
///     (the exact `{subscriptionId, sequenceNumber}` acks the client emits, and the presence/absence of a
///     Republish / ModifySubscription); and
///   - the pipeline INFO snapshot (`ConnectionImplTestAccess::pipeline_info`) - subscriptionCount /
///     unknownHandleDrops / pumpState (the strand-private state that has no public getter).
/// The server side is bent with `set_response_mutator` (rewrites each PublishResponse before signing:
/// controlled sequence numbers, present/empty availableSequenceNumbers, injected keep-alive /
/// StatusChangeNotification / unknown-clientHandle notifications) plus the wired subscription mutators
/// `inject_sequence_gap` / `bad_subscription_id_on_republish` / `drop_available_sequence_numbers`.
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable - the ack sub/seq the client sends, the sticky retransmission-false latch (no acks resume),
/// the keep-alive acceptance, the unknown-handle drop count, the terminal removal. Timing is ALWAYS bounded
/// polling on an observable (a delivered value / an ack count / a subscriptionCount), never a fixed sleep.
///
/// BLOCKED / REPORTED rows (behaviour not yet built - pin the built, spec-consistent observable and
/// record the unbuilt part in the header + report, per the ClientBrowse precedent):
///   - SemanticsChangedBitTriggersPropertyRefresh - `AddressSpaceObserver::on_semantic_change` firing off a
///     MonitoredItemNotification's SemanticsChanged status bit (section 8.14.X DataAccess) is UNBUILT. Pin:
///     the value carrying the bit is still delivered with the bit intact.

#include "compliance_helpers.h"

#include "misbehaving_server.h"
#include "test_utilities.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_semantic_change_cache.h"

#include "ua_connection_handle_factory.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_logger.h"
#include "ua_monitored_item_notification.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_create_subscription_request.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_ref_structure.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_status.h"
#include "ua_status_change_notification.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <algorithm>
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

// A standard NS0 Variable that exists on every server and carries a value, so a MonitoredItem can be created
// and the server delivers an initial-value notification. Value changes are injected via the response mutator
// (the MisbehavingServer has no user-writable node), so the tests never depend on the server updating it.
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

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

class TerminationObserver final : public SubscriptionObserver
{
public:
  void on_subscription_terminated(ua::IntegerId subscriptionId, ua::StatusCode reason,
    std::shared_ptr<const ua::ErrorDetail> chain) override
  {
    std::lock_guard lock(mMutex);
    mSubscriptionId = subscriptionId;
    mReason = reason;
    mChain = std::move(chain);
  }

  bool fired_for(std::uint32_t subscriptionId) const
  {
    std::lock_guard lock(mMutex);
    return mSubscriptionId == subscriptionId;
  }

  ua::StatusCode reason() const
  {
    std::lock_guard lock(mMutex);
    return mReason;
  }

  std::shared_ptr<const ua::ErrorDetail> chain() const
  {
    std::lock_guard lock(mMutex);
    return mChain;
  }

private:
  mutable std::mutex mMutex;
  std::uint32_t mSubscriptionId = 0;
  ua::StatusCode mReason{ua::Status::Good};
  std::shared_ptr<const ua::ErrorDetail> mChain;
};

// ---------------------------------------------------------------------------------------------
// A read-only capture of what the client put on the wire: the acks carried on each outgoing PublishRequest,
// plus counts of the request types a row asserts the ABSENCE of (Republish / ModifySubscription). Populated
// on a server strand by the MisbehavingServer request observer, read by the test thread.
// ---------------------------------------------------------------------------------------------
struct SentAck
{
  std::uint32_t subscriptionId = 0;
  std::uint32_t sequenceNumber = 0;
};

struct RequestCapture
{
  mutable std::mutex mutex;
  std::vector<std::vector<SentAck>> publishRequests;  // one entry per PublishRequest, its ack batch
  std::size_t republishCount = 0;
  std::size_t modifySubscriptionCount = 0;
  std::vector<std::uint32_t> modifiedMaxNotificationsPerPublish;
  std::size_t createSubscriptionCount = 0;
  std::vector<std::vector<std::uint32_t>> deleteSubscriptionIds;

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* publish = dynamic_cast<const ua::PublishRequest*>(&request))
    {
      std::vector<SentAck> acks;
      for (const auto& ack : publish->subscription_acknowledgements())
        acks.push_back(SentAck{ack.subscription_id(), ack.sequence_number()});
      publishRequests.push_back(std::move(acks));
    }
    else if (dynamic_cast<const ua::RepublishRequest*>(&request))
    {
      ++republishCount;
    }
    else if (const auto* modify = dynamic_cast<const ua::ModifySubscriptionRequest*>(&request))
    {
      ++modifySubscriptionCount;
      modifiedMaxNotificationsPerPublish.push_back(modify->max_notifications_per_publish());
    }
    else if (dynamic_cast<const ua::CreateSubscriptionRequest*>(&request))
    {
      ++createSubscriptionCount;
    }
    else if (const auto* deleteSubscriptions = dynamic_cast<const ua::DeleteSubscriptionsRequest*>(&request))
    {
      std::vector<std::uint32_t> ids;
      ids.reserve(deleteSubscriptions->subscription_ids().size());
      for (const auto id : deleteSubscriptions->subscription_ids())
      {
        ids.push_back(id);
      }
      deleteSubscriptionIds.push_back(std::move(ids));
    }
  }

  std::size_t publish_count() const
  {
    std::lock_guard lock(mutex);
    return publishRequests.size();
  }

  // Every ack the client has emitted so far, flattened across all PublishRequests.
  std::vector<SentAck> all_acks() const
  {
    std::lock_guard lock(mutex);
    std::vector<SentAck> flat;
    for (const auto& batch : publishRequests)
      for (const auto& ack : batch)
        flat.push_back(ack);
    return flat;
  }

  std::size_t ack_count_for(std::uint32_t subscriptionId) const
  {
    std::lock_guard lock(mutex);
    std::size_t count = 0;
    for (const auto& batch : publishRequests)
      for (const auto& ack : batch)
        if (ack.subscriptionId == subscriptionId)
          ++count;
    return count;
  }

  std::size_t republish_count() const
  {
    std::lock_guard lock(mutex);
    return republishCount;
  }

  std::size_t modify_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return modifySubscriptionCount;
  }

  std::vector<std::uint32_t> modified_notification_limits() const
  {
    std::lock_guard lock(mutex);
    return modifiedMaxNotificationsPerPublish;
  }

  std::size_t create_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return createSubscriptionCount;
  }

  std::vector<std::vector<std::uint32_t>> delete_subscription_ids() const
  {
    std::lock_guard lock(mutex);
    return deleteSubscriptionIds;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value. Every caller
// waits for something that must happen, so the budget only bounds a hang: an instrumented build gets the
// longer poll budget.
bool wait_until(const std::function<bool()>& predicate,
  std::chrono::milliseconds timeout = std::max<std::chrono::milliseconds>(
    6000ms, ua::test_utils::default_poll_budget()))
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

// ----- Response-mutator building blocks (each edits a PublishResponse in place, before signing) -----

// Forces the response's NotificationMessage sequence number, so classification is deterministic regardless of
// the server's own numbering (the client expects 1, 2, 3, ... from a fresh Subscription).
void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

// Sets availableSequenceNumbers to a single non-empty entry (retransmission-queue-supporting server) or
// clears it (no-retransmission-queue server) - the CL-SUB-007 latch input.
void set_available_sequence_numbers(ua::PublishResponse& publish, bool present)
{
  publish.available_sequence_numbers().clear();
  if (present)
    publish.available_sequence_numbers().push_back(
      ua::Counter{publish.notification_message().sequence_number()});
}

// Appends a DataChangeNotification carrying one MonitoredItemNotification for @p clientHandle.
void append_data_change(ua::PublishResponse& publish, std::uint32_t clientHandle, ua::Variant value,
  std::optional<ua::StatusCode> valueStatus = std::nullopt)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  ua::DataValue dataValue;
  dataValue.value() = std::move(value);
  if (valueStatus)
    dataValue.status() = *valueStatus;
  item.value() = std::move(dataValue);
  notification->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// Appends an EMPTY DataChangeNotification (a real notification message with zero items): makes the response
// notification-bearing (so it is acknowledged per spec) without delivering to any handle.
void append_empty_data_change(ua::PublishResponse& publish)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// Turns the response into a keep-alive: an empty NotificationMessage (no notification data).
void make_keep_alive(ua::PublishResponse& publish)
{
  publish.notification_message().notification_data().clear();
}

// Appends a StatusChangeNotification carrying @p status (e.g. Bad_Timeout, a unilateral server termination).
void append_status_change(ua::PublishResponse& publish, ua::StatusCode status)
{
  auto notification = std::make_unique<ua::StatusChangeNotification>();
  notification->status() = status;
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// ---------------------------------------------------------------------------------------------
// MisbehavingSubscriptionFixture: a real client bound to a MisbehavingServer, on its own thread pool, with an
// activated Session wrapped into a started tier-1 ConnectionImpl (the same interface as the
// ClientRead/Write/Browse Misbehaving fixtures). The bootstrap completes against the un-mutated server; the
// test arms the response mutators / request observer AFTER construction. The ConnectionImpl is exposed
// directly so a test can drive create_subscription_async / create_monitored_item_async and read the pipeline
// info snapshot.
// ---------------------------------------------------------------------------------------------
class MisbehavingSubscriptionFixture
{
public:
  explicit MisbehavingSubscriptionFixture(MisbehavingServer& server)
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
    auto session = channel.create_session_sync({.sessionName = "ClientSubscriptionMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingSubscriptionFixture()
  {
    if (mConnection)
      (void)close_and_wait(*mConnection);
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingSubscriptionFixture(const MisbehavingSubscriptionFixture&) = delete;
  MisbehavingSubscriptionFixture& operator=(const MisbehavingSubscriptionFixture&) = delete;

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  Connection connection()
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

  std::size_t subscription_count() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->subscriptionCount : 0;
  }

  std::size_t unknown_handle_drops() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->unknownHandleDrops : 0;
  }

  // True when the Publish pump is Idle - the drain-and-HOLD state after a Bad_NoSubscription (CL-SUB-009).
  bool pump_held() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info && info->pumpState == ua::client::detail::PumpState::Idle;
  }

  ua::client::detail::PumpState pump_state() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->pumpState : ua::client::detail::PumpState::Idle;
  }

  // The pump's sized outstanding-Publish target = max(2, ceil(totalMonitoredItems / 100)) (CL-SUB-015).
  std::size_t pump_target() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->pumpTarget : 0;
  }

  std::size_t monitored_item_count() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->monitoredItemCount : 0;
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

  Result<DeleteSubscriptionsResponse> delete_subscription(std::uint32_t subscriptionId)
  {
    std::promise<Result<DeleteSubscriptionsResponse>> promise;
    auto future = promise.get_future();
    mConnection->delete_subscription_async(subscriptionId,
      [&promise](Result<DeleteSubscriptionsResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// Arms both the request observer (capturing outgoing acks) and returns the shared capture.
std::shared_ptr<RequestCapture> arm_request_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

}  // namespace

class ClientSubscription : public ::testing::Test
{};

// =============================================================================================
// Row - GetMonitoredItemsUsesOwningSession  (MisbehavingServer)
// The Subscription handle owns the Connection that created it, so the Server.GetMonitoredItems Call is
// issued through that same active Session. A fresh Subscription has no monitored items and must return two
// empty, parallel handle arrays. [neg: call issued on an unrelated Session or outputs decoded incorrectly]
// =============================================================================================
// @verifies CL-BASE-006
// @relation(CL-BASE-006, scope=function)
TEST_F(ClientSubscription, GetMonitoredItemsUsesOwningSession)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto connection = fixture.connection();
  auto subscription =
    connection.subscriptions().try_create_sync(SubscriptionConfig{.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  auto handles = subscription.value().try_get_monitored_items_sync();
  ASSERT_TRUE(handles.is_good()) << to_string(handles.status_code());
  EXPECT_TRUE(handles.value().serverHandles.empty());
  EXPECT_TRUE(handles.value().clientHandles.empty());
}

// =============================================================================================
// Row - ResendDataUsesOwningSession  (MisbehavingServer)
// The public Subscription handle issues Server.ResendData through the Session that owns its subscription id.
// A fresh Subscription with no monitored items still accepts the method. [neg: call uses unrelated Session]
// =============================================================================================
// @verifies CL-BASE-007
// @relation(CL-BASE-007, scope=function)
TEST_F(ClientSubscription, ResendDataUsesOwningSession)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto connection = fixture.connection();
  auto subscription =
    connection.subscriptions().try_create_sync(SubscriptionConfig{.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  auto result = subscription.value().try_resend_data_sync();
  EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
}

// =============================================================================================
// Row - AcceptsEmptyNotificationMessageAsKeepAlive  (MisbehavingServer)
// A stream of keep-alive-only (empty) NotificationMessages must NOT be mistaken for a gap or a timeout: the
// Subscription stays alive (pump keeps running, no Republish, no termination) and still delivers a subsequent
// real notification. [neg: keep-alive is NOT termination]
//
// This models REAL server keep-alive semantics: every keep-alive carries the PEEKED (constant,
// non-incremented) sequence number = the number the next real NotificationMessage reuses
// (ua_subscription.cpp:533, OPC 10000-4 section 5.13.5). The corrected client leaves next_expected untouched
// on a keep-alive (the InOrder branch of on_publish_response_async gates on hasNotifications), so a stream of
// same-seq keep-alives is neither a gap nor a termination, and the following real notification at that same
// peeked seq is still delivered - not dropped as a Duplicate. This exercises the keep-alive data-loss fix
// end-to-end (the pipeline unit tests cover the classification in isolation).
// =============================================================================================
// @verifies CL-SUB-008
// @relation(CL-SUB-008, scope=function)
TEST_F(ClientSubscription, AcceptsEmptyNotificationMessageAsKeepAlive)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto deliverReal = std::make_shared<std::atomic<bool>>(false);
  const std::uint32_t clientHandle = 7;
  const std::int32_t realValue = 24680;

  // A REAL server keep-alive carries the PEEKED (constant, non-incremented) sequence number - the number the
  // next real NotificationMessage will reuse (ua_subscription.cpp:533). Model that: every response (each
  // keep-alive AND the eventual real DataChange) carries the same peeked seq. For a fresh subscription the
  // next-to-allocate number is 1, so all keep-alives and the real message carry seq 1; the corrected client
  // keeps next_expected at 1 across the keep-alives, and the real message at seq 1 is still InOrder ->
  // delivered.
  const std::uint32_t peekedSeq = 1;
  server.set_response_mutator(
    [deliverReal, clientHandle, realValue, peekedSeq](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, peekedSeq);
      if (deliverReal->load())
        append_data_change(*publish, clientHandle, ua::Variant{realValue});
      else
        make_keep_alive(*publish);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), clientHandle, sink).is_good());

  // Let several keep-alives be processed (the pump keeps refilling only because the server keeps answering).
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 4; }))
    << "the pump must keep publishing while keep-alives flow (a torn-down subscription would stop)";

  EXPECT_EQ(capture->republish_count(), 0u)
    << "empty keep-alive messages must NOT be mistaken for a sequence gap (no Republish)";
  EXPECT_EQ(fixture.subscription_count(), 1u)
    << "empty keep-alive messages must NOT be mistaken for a timeout (the Subscription is still registered)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "the Connection stays Active across keep-alives";

  // The Subscription is still healthy: a real notification after the keep-alive run is still delivered.
  deliverReal->store(true);
  EXPECT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
        if (value.value().is_int32() && value.value().as<std::int32_t>() == realValue)
          return true;
      return false;
    }))
    << "a real notification after a keep-alive run must still be delivered (the subscription is alive)";
}

// =============================================================================================
// Row - AcknowledgesWhenAvailableSeqNumsNonEmpty  (MisbehavingServer)
// A notification-bearing response whose availableSequenceNumbers is non-empty must be acknowledged on the
// next Publish, carrying that exact {subscriptionId, sequenceNumber}. [neg: piggybacked ack]
// =============================================================================================
// @verifies AC-CL-SUB-006-ACKNOWLEDGE
// @relation(AC-CL-SUB-006-ACKNOWLEDGE, scope=function)
TEST_F(ClientSubscription, AcknowledgesWhenAvailableSeqNumsNonEmpty)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  // Each response is an in-order notification with a non-empty availableSequenceNumbers (the server keeps a
  // retransmission queue), so the client must acknowledge each one.
  server.set_response_mutator(
    [sequenceNumber](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      append_empty_data_change(*publish);
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  ASSERT_TRUE(wait_until([&] { return capture->ack_count_for(subscriptionId) >= 1; }))
    << "a non-empty availableSequenceNumbers must drive an acknowledgement";

  auto acks = capture->all_acks();
  bool foundSeqOne = false;
  for (const auto& ack : acks)
  {
    EXPECT_EQ(ack.subscriptionId, subscriptionId) << "acks must carry the Subscription id";
    if (ack.subscriptionId == subscriptionId && ack.sequenceNumber == 1u)
      foundSeqOne = true;
  }
  EXPECT_TRUE(foundSeqOne)
    << "the first notification (sequence 1) must be acknowledged (an absent ack would grow the server's "
       "retransmission queue unbounded)";
}

// =============================================================================================
// Row - BatchesMultiplePendingAcknowledgements  (MisbehavingServer)
// Every delivered sequence number must be acknowledged exactly once - none dropped in favour of only the
// latest. [neg: batched acks across multiple cycles]
//
// REPORTED (observability): the literal "three acks in ONE PublishRequest" batching is a property of
// `AckQueue::drain()` covered by the unit suite (ack_queue_tests.cpp); the always-on pump (target 2) issues a
// refill Publish per response, so at the integration boundary each ack rides its own Publish. The
// client-observable guarantee asserted here is the falsifier's real content: the UNION of acks equals the set
// of delivered sequence numbers (each acked once), which fails iff the queue only carried the latest.
// =============================================================================================
// @verifies AC-CL-SUB-006-ACKNOWLEDGE
// @relation(AC-CL-SUB-006-ACKNOWLEDGE, scope=function)
TEST_F(ClientSubscription, BatchesMultiplePendingAcknowledgements)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  server.set_response_mutator(
    [sequenceNumber](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      append_empty_data_change(*publish);
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  ASSERT_TRUE(wait_until([&] { return capture->ack_count_for(subscriptionId) >= 3; }))
    << "three delivered notifications must produce three acknowledgements";

  // Collect the distinct sequence numbers acked for our Subscription; the first three (1, 2, 3) must all be
  // present, none skipped.
  auto acks = capture->all_acks();
  std::vector<bool> seen(4, false);
  for (const auto& ack : acks)
    if (ack.subscriptionId == subscriptionId && ack.sequenceNumber >= 1 && ack.sequenceNumber <= 3)
      seen[ack.sequenceNumber] = true;
  EXPECT_TRUE(seen[1] && seen[2] && seen[3])
    << "sequences 1, 2 and 3 must each be acknowledged (only carrying the latest would drop earlier ones)";
}

// =============================================================================================
// Row - CreateSurfacesBadTooManySubscriptions  (MisbehavingServer)
// A CreateSubscription that the server rejects with Bad_TooManySubscriptions must surface that status to the
// caller, and the client must not blindly retry. [neg: create rejected at server capacity]
// =============================================================================================
TEST_F(ClientSubscription, CreateSurfacesBadTooManySubscriptions)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* create = dynamic_cast<ua::CreateSubscriptionResponse*>(response.second.get()))
        create->response_header().service_result() = ua::StatusCode{ua::Status::BadTooManySubscriptions};
    });

  auto subscription = fixture.create_subscription(500.0);
  EXPECT_TRUE(subscription.is_bad()) << "a server at capacity must surface an error, not a phantom id";
  EXPECT_EQ(subscription.status_code(), ua::StatusCode{ua::Status::BadTooManySubscriptions})
    << "the exact server status must reach the caller";
  EXPECT_EQ(fixture.subscription_count(), 0u) << "a rejected create must register no Subscription";

  // The client must not spin against a server at capacity.
  EXPECT_EQ(capture->create_subscription_count(), 1u)
    << "exactly one CreateSubscription must be sent (no blind retry against a full server)";
}

// =============================================================================================
// Row - PublishBackpressurePausesUntilOutstandingResponse  (MisbehavingServer)
// The first Publish response is changed to Bad_TooManyPublishRequests. The managed pump must enter Paused
// with no replacement request; only the next already-outstanding response may resume/refill it.
// [neg: forbidden immediate replacement after server backpressure]
// =============================================================================================
// @verifies CL-SUB-004
// @relation(CL-SUB-004, scope=function)
TEST_F(ClientSubscription, PublishBackpressurePausesUntilOutstandingResponse)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto injectBackpressure = std::make_shared<std::atomic_bool>(true);
  server.set_response_mutator(
    [injectBackpressure](Response& response)
    {
      if (auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
          publish != nullptr && injectBackpressure->exchange(false))
      {
        publish->response_header().service_result() = ua::StatusCode{ua::Status::BadTooManyPublishRequests};
      }
    });

  auto subscription = fixture.create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= 2; }))
    << "the initial two-request window must be on the wire (non-vacuous)";

  ASSERT_TRUE(wait_until([&] { return fixture.pump_state() == ua::client::detail::PumpState::Paused; }))
    << "Bad_TooManyPublishRequests must pause the managed Publish pump";
  const std::size_t publishesWhilePaused = capture->publish_count();
  EXPECT_EQ(publishesWhilePaused, 2u)
    << "the backpressured response must not be replaced before another outstanding response returns";

  EXPECT_TRUE(wait_until(
    [&]
    {
      return fixture.pump_state() == ua::client::detail::PumpState::Running &&
             capture->publish_count() > publishesWhilePaused;
    }))
    << "the next outstanding response must resume and refill the Publish pump";
}

// =============================================================================================
// Row - DoesNotAckWhenAvailableSeqNumsEmpty  (MisbehavingServer)  [integration+unit]
// A server that always reports an empty availableSequenceNumbers has no retransmission queue: the client must
// never send a subscriptionAcknowledgement for that Subscription, even though it processes notifications.
// [neg: no-retransmission-queue server]
//
// The retransmission-support latch (CL-SUB-007, sticky on the FIRST response's availableSequenceNumbers) is
// unit-pinned in ack_queue_tests.cpp; this asserts the wire-observable proxy - zero acks ever leave the
// client for the Subscription.
// =============================================================================================
// @verifies CL-SUB-007
// @relation(CL-SUB-007, scope=function)
TEST_F(ClientSubscription, DoesNotAckWhenAvailableSeqNumsEmpty)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  // In-order notifications, but availableSequenceNumbers is ALWAYS empty: the server cannot consume acks.
  server.set_response_mutator(
    [sequenceNumber](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      append_empty_data_change(*publish);
      set_available_sequence_numbers(*publish, /*present=*/false);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  // Wait until several notifications have been processed (the pump keeps refilling), which is exactly when a
  // buggy client WOULD have queued acks.
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 4; }))
    << "notifications must flow so the no-ack assertion is not vacuous";

  EXPECT_EQ(capture->ack_count_for(subscriptionId), 0u)
    << "a server that reports empty availableSequenceNumbers must never receive an acknowledgement";
}

// =============================================================================================
// Row - DropsPendingRepublishOnBadTimeout  (MisbehavingServer)
// A terminated Subscription must not be resurrected by a late Republish response. [neg: race: termination vs
// in-flight republish]
//
// This remains a useful wire-level analog: a Republish returning Bad_SubscriptionIdInvalid removes the
// Subscription and later traffic cannot resurrect it. The exact StatusChange-vs-in-flight-Republish race is
// deterministic owning-component coverage in
// SubscriptionsPipeline.BadTimeoutStatusChangeAtomicallyTerminatesOnlyTargetSubscription; it is not claimed
// here because this server fixture cannot hold a Republish completion while independently delivering a
// Publish response on the same channel strand.
// =============================================================================================
// @covers CL-SUB-008
TEST_F(ClientSubscription, DropsPendingRepublishOnBadTimeout)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  ASSERT_EQ(fixture.subscription_count(), 1u);

  // Make every Republish fail Bad_SubscriptionIdInvalid and put a sequence gap before the item's initial
  // value (client issues Republish), so the pipeline treats the Subscription as gone and removes it. The gap
  // is armed before the item exists and shifts only messages that carry notifications, so it lands on the
  // initial value, which the server retains because the client never acknowledges a gap: the Republish finds
  // it and answers with a RepublishResponse, the response bad_subscription_id_on_republish rewrites. A gap on
  // a keep-alive would ask for a number the server never sent, and the server answers that with a
  // ServiceFault carrying Bad_MessageNotAvailable, which ends the drain cleanly and leaves the Subscription.
  server.bad_subscription_id_on_republish();
  server.set_response_mutator(
    [subscriptionId](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (publish && publish->subscription_id() == subscriptionId &&
          !publish->notification_message().notification_data().empty())
        publish->notification_message().sequence_number() += 5;
    });
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sink).is_good());

  ASSERT_TRUE(wait_until([&] { return capture->republish_count() >= 1; }))
    << "a sequence gap must drive a Republish";
  ASSERT_TRUE(wait_until([&] { return fixture.subscription_count() == 0; }))
    << "a Republish returning Bad_SubscriptionIdInvalid must remove the terminated Subscription";

  // The terminated Subscription is not resurrected: no later ack references its id.
  const std::size_t acksAtTermination = capture->ack_count_for(subscriptionId);
  const std::size_t publishesAtTermination = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= publishesAtTermination + 3; }))
    << "the pump keeps running after the removal";
  EXPECT_EQ(capture->ack_count_for(subscriptionId), acksAtTermination)
    << "a removed Subscription must not be re-registered by a late Republish/Publish (no new acks for it)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "the Connection is unaffected by the removal";
}

// =============================================================================================
// Row - IgnoresUnknownClientHandle  (MisbehavingServer)
// A MonitoredItemNotification whose clientHandle was never assigned must be dropped (counted as an advisory)
// with no user callback fired, while a legitimate handle in the same message is still delivered.
// [neg: unknown clientHandle]
// =============================================================================================
// @verifies CL-SUB-016
// @verifies CL-MI-003
// @relation(CL-MI-003, CL-SUB-016, scope=function)
TEST_F(ClientSubscription, IgnoresUnknownClientHandle)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  const std::uint32_t knownHandle = 1;
  const std::uint32_t unknownHandle = 0x7FFF0001;  // never allocated by the SDK
  const std::int32_t knownValue = 13579;

  server.set_response_mutator(
    [sequenceNumber, knownHandle, unknownHandle, knownValue](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      // One notification for the KNOWN handle (must be delivered) + one for an UNKNOWN handle (must be
      // dropped) in the same DataChangeNotification.
      auto notification = std::make_unique<ua::DataChangeNotification>();
      ua::MonitoredItemNotification knownItem;
      knownItem.client_handle() = knownHandle;
      ua::DataValue knownData;
      knownData.value() = ua::Variant{knownValue};
      knownItem.value() = std::move(knownData);
      notification->monitored_items().push_back(std::move(knownItem));
      ua::MonitoredItemNotification unknownItem;
      unknownItem.client_handle() = unknownHandle;
      ua::DataValue unknownData;
      unknownData.value() = ua::Variant{std::int32_t{999}};
      unknownItem.value() = std::move(unknownData);
      notification->monitored_items().push_back(std::move(unknownItem));
      ua::RefStructure<ua::Structure> ref;
      ref.inner_unique_ptr() = std::move(notification);
      publish->notification_message().notification_data().push_back(std::move(ref));
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), knownHandle, sink).is_good());

  // The known handle is delivered.
  ASSERT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
        if (value.value().is_int32() && value.value().as<std::int32_t>() == knownValue)
          return true;
      return false;
    }))
    << "the legitimate clientHandle's notification must be delivered";

  // The unknown handle is dropped and counted (advisory), never delivered.
  EXPECT_TRUE(wait_until([&] { return fixture.unknown_handle_drops() >= 1; }))
    << "a notification for an unregistered clientHandle must be dropped and counted (CL-MI-003)";
  for (const auto& value : sink->snapshot())
    EXPECT_FALSE(value.value().is_int32() && value.value().as<std::int32_t>() == 999)
      << "the unknown-handle value must never reach the user callback";
  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "an unknown handle must not fault the Connection";
}

// =============================================================================================
// Row - IssuesPublishImmediatelyAfterCreate  (MisbehavingServer)
// CreateSubscription must prime the full two-request Publish window immediately: both Publishes are on the
// wire well before the first publishing-interval tick. This proves the production client is prepared for
// back-to-back responses rather than allowing only one response per interval. [neg: eager pipelined prime]
// =============================================================================================
// @verifies CL-SUB-001
// @verifies CL-SUB-003
// @verifies CL-SUB-018
// @relation(CL-SUB-001, CL-SUB-003, CL-SUB-018, scope=function)
// @relation(AC-CL-SUB-001-01, scope=function)
TEST_F(ClientSubscription, IssuesPublishImmediatelyAfterCreate)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  ASSERT_EQ(capture->publish_count(), 0u) << "no Publish before a Subscription exists";

  // A deliberately huge publishing interval: any Publish observed within a second cannot be an interval tick.
  const double hugePublishingIntervalMs = 60000.0;
  auto subscription = fixture.create_subscription(hugePublishingIntervalMs);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  EXPECT_TRUE(wait_until([&] { return capture->publish_count() >= 2; }, 2000ms))
    << "the pump must prime its full two-Publish window on create (well under the 60 s publishing interval), "
       "not rate-limit requests to interval ticks";
}

// =============================================================================================
// Row - RefillsPublishImmediatelyAfterResponse  (MisbehavingServer)
// After the initial two-request window, the first ordinary Publish response consumes one slot. The pump must
// refill it immediately, producing a third outgoing Publish without an SDK publishing-interval timer.
// [neg: response consumes a slot but the client does not refill]
// =============================================================================================
// @verifies CL-SUB-018
// @relation(CL-SUB-018, scope=function)
TEST_F(ClientSubscription, RefillsPublishImmediatelyAfterResponse)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto subscription = fixture.create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= 2; }))
    << "creation must first prime the two-request Publish window";
  EXPECT_TRUE(wait_until([&] { return capture->publish_count() >= 3; }))
    << "the first ordinary Publish response must immediately refill its consumed slot";
}

// =============================================================================================
// Row - OversizedPublishAloneAdjusts  (MisbehavingServer)
// Ratified OR semantics: one whole-service Publish Bad_ResponseTooLarge is sufficient to drive a
// ModifySubscription with maxNotificationsPerPublish halved. [neg: Publish-only oversize -> exact adjustment]
//
// Public-tier rationale: Subscription lifecycle has no tier-2 domain facade. The operation enters through
// the highest public production surface (`Connection::subscriptions().try_create_sync`) with a public
// SubscriptionConfig; MisbehavingServer only injects the wire failure and observes the outgoing request.
// =============================================================================================
// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST_F(ClientSubscription, OversizedPublishAloneAdjusts)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto failFirstPublish = std::make_shared<std::atomic_bool>(true);
  server.set_response_mutator(
    [failFirstPublish](ua::Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (publish != nullptr && failFirstPublish->exchange(false))
      {
        publish->response_header().service_result() = ua::StatusCode{ua::Status::BadResponseTooLarge};
      }
    });

  auto connection = fixture.connection();
  SubscriptionConfig config;
  config.publishingIntervalMs = 50.0;
  config.maxNotificationsPerPublish = 64;
  auto subscription = connection.subscriptions().try_create_sync(config);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  ASSERT_TRUE(wait_until([&] { return capture->modify_subscription_count() >= 1; }))
    << "a Publish Bad_ResponseTooLarge must emit an automatic ModifySubscription";
  ASSERT_EQ(capture->modified_notification_limits(), (std::vector<std::uint32_t>{32}));
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "oversized recovery adjusts the Subscription without faulting the Connection";
}

// =============================================================================================
// Row - PublishPumpHandlesBadNoSubscriptionOnLastDelete  (MisbehavingServer)
// Deleting the only Subscription leaves outstanding Publishes to return Bad_NoSubscription; the pump must
// drain them WITHOUT treating them as a transport fault AND drain-and-HOLD (stop issuing further Publishes)
// rather than spinning doomed ones (CL-SUB-009 now built). [neg: contractual Bad_NoSubscription not a fault;
// held pump issues no further Publishes]
// =============================================================================================
// @verifies CL-SUB-009
// @relation(CL-SUB-009, scope=function)
TEST_F(ClientSubscription, PublishPumpHandlesBadNoSubscriptionOnLastDelete)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sink).is_good());

  // Delete the only Subscription; the server now answers outstanding Publishes with Bad_NoSubscription.
  auto deleteResult = fixture.delete_subscription(subscriptionId);
  ASSERT_TRUE(deleteResult.is_good()) << to_string(deleteResult.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.subscription_count() == 0; }))
    << "the deleted Subscription is deregistered";

  // The outstanding Publishes come back Bad_NoSubscription and drive the pump into drain-and-HOLD (Idle). The
  // falsifier: mis-classifying it as a transport error would flip the Connection out of Active.
  ASSERT_TRUE(wait_until([&] { return fixture.pump_held(); }, 2000ms))
    << "a Bad_NoSubscription on the last delete must drain-and-HOLD the pump (Idle), not spin doomed "
       "Publishes";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a contractual Bad_NoSubscription must not be treated as a connection fault";

  // A held pump issues no further Publishes (the doomed-retry spin is exactly what the hold prevents).
  const std::size_t held = capture->publish_count();
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(capture->publish_count(), held) << "a held pump issues no further Publishes";
}

// =============================================================================================
// Row - PublishPumpResumesAfterNewSubscriptionFollowingDrain  (MisbehavingServer)
// After the last Subscription is deleted, creating a NEW Subscription must restart the pump and deliver its
// notifications. [neg: restart after drain]
// =============================================================================================
// @verifies CL-SUB-009
// @relation(CL-SUB-009, scope=function)
TEST_F(ClientSubscription, PublishPumpResumesAfterNewSubscriptionFollowingDrain)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // First Subscription, then delete it (the drain).
  auto first = fixture.create_subscription(50.0);
  ASSERT_TRUE(first.is_good()) << to_string(first.status_code());
  auto firstSink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(first.value(), /*clientHandle=*/1, firstSink).is_good());
  ASSERT_TRUE(fixture.delete_subscription(first.value()).is_good());
  ASSERT_TRUE(wait_until([&] { return fixture.subscription_count() == 0; }));

  // A new Subscription on the same Connection: its notifications must be delivered (pump restarted). Deliver
  // to the second Subscription's handle via the mutator (the MisbehavingServer has no user-writable node).
  const std::uint32_t secondHandle = 2;
  const std::int32_t secondValue = 55555;
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [sequenceNumber, secondHandle, secondValue](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      append_data_change(*publish, secondHandle, ua::Variant{secondValue});
    });

  auto second = fixture.create_subscription(50.0);
  ASSERT_TRUE(second.is_good()) << to_string(second.status_code());
  auto secondSink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(second.value(), secondHandle, secondSink).is_good());

  EXPECT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : secondSink->snapshot())
        if (value.value().is_int32() && value.value().as<std::int32_t>() == secondValue)
          return true;
      return false;
    }))
    << "the pump must restart and deliver the new Subscription's notifications after a drain";
}

// =============================================================================================
// Row - PublishResponseWithUnknownSubscriptionIdRejected  (MisbehavingServer)
// A Publish whose subscriptionId is nonzero but unknown to the client must be rejected as stale: even a
// registered clientHandle under that spoofed id must not inject data or an acknowledgement.
// [neg: unknown nonzero subscriptionId carrying a known clientHandle]
// =============================================================================================
// @verifies CL-SUB-016
// @relation(CL-SUB-016, scope=function)
TEST_F(ClientSubscription, PublishResponseWithUnknownSubscriptionIdRejected)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  const std::uint32_t spoofedSubscriptionId = 0x7F00ABCD;  // nonzero, never assigned to this client
  const std::uint32_t knownHandle = 1;
  const std::int32_t spoofedValue = 0x13572468;

  // Rewrite every PublishResponse's subscriptionId to a spoofed value, attach a REGISTERED handle, and mark
  // it ack-eligible. A client that routes only by clientHandle leaks spoofedValue to the user.
  server.set_response_mutator(
    [sequenceNumber, spoofedSubscriptionId, knownHandle, spoofedValue](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      auto notification = std::make_unique<ua::DataChangeNotification>();
      ua::MonitoredItemNotification item;
      item.client_handle() = knownHandle;
      ua::DataValue value;
      value.value() = ua::Variant{spoofedValue};
      item.value() = std::move(value);
      notification->monitored_items().push_back(std::move(item));
      ua::RefStructure<ua::Structure> ref;
      ref.inner_unique_ptr() = std::move(notification);
      publish->notification_message().notification_data().push_back(std::move(ref));
      set_available_sequence_numbers(*publish, /*present=*/true);
      publish->subscription_id() = spoofedSubscriptionId;
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t realSubscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(realSubscriptionId, knownHandle, sink).is_good());

  // Let several spoofed-id responses be processed, which is exactly when a buggy client would ack the stale
  // id.
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 4; }))
    << "responses must flow so the no-ack assertion is not vacuous";

  EXPECT_EQ(capture->ack_count_for(spoofedSubscriptionId), 0u)
    << "the client must never acknowledge a subscriptionId it does not track (a spoofed/stale id)";
  EXPECT_EQ(capture->ack_count_for(realSubscriptionId), 0u)
    << "and the real Subscription received no genuine responses (all were relabelled), so it too has no acks";
  for (const auto& value : sink->snapshot())
    EXPECT_FALSE(value.value().is_int32() && value.value().as<std::int32_t>() == spoofedValue)
      << "a registered clientHandle under an unknown subscriptionId must not reach the user callback";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "an unknown subscriptionId must not fault the Connection";
}

// =============================================================================================
// Row - RetransmissionFlagStickyFalseAfterFirstEmpty  (MisbehavingServer)
// Once the FIRST Publish response reports an empty availableSequenceNumbers, the retransmission-support latch
// is FALSE and stays false: a later non-empty array must NOT resume acknowledgements.
// [neg: flag must not flip back to TRUE]
// =============================================================================================
// @verifies CL-SUB-007
// @relation(CL-SUB-007, scope=function)
TEST_F(ClientSubscription, RetransmissionFlagStickyFalseAfterFirstEmpty)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  // Response #1 has an EMPTY availableSequenceNumbers (latch FALSE); every later response has a NON-empty
  // one. A correct client, having latched false on the first, never acks - even after the array turns
  // non-empty.
  server.set_response_mutator(
    [sequenceNumber](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      const std::uint32_t seq = ++(*sequenceNumber);
      set_publish_sequence(*publish, seq);
      append_empty_data_change(*publish);
      set_available_sequence_numbers(*publish, /*present=*/seq != 1);  // first empty, rest non-empty
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  // Wait until several later (non-empty-array) responses have been processed - the falsifying window where a
  // flag that flipped back to TRUE would resume acks.
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 5; }))
    << "later non-empty-array responses must be processed to test the sticky latch";

  EXPECT_EQ(capture->ack_count_for(subscriptionId), 0u)
    << "the retransmission-support latch is sticky-FALSE: acks must not resume when the array turns "
       "non-empty";
}

// =============================================================================================
// Row - OversizedRepublishAloneAdjusts  (MisbehavingServer)
// Ratified OR semantics: a Republish Bad_ResponseTooLarge for a known gap is independently sufficient to
// halve that Subscription's maxNotificationsPerPublish. [neg: Republish-only oversize -> exact adjustment]
//
// Public-tier rationale: Subscription lifecycle has no tier-2 domain facade. Creation and ownership use the
// highest public production `Subscriptions`/`Subscription` API; server hooks only create the sequence gap,
// inject the Republish service failure, and observe the outgoing ModifySubscription.
// =============================================================================================
// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST_F(ClientSubscription, OversizedRepublishAloneAdjusts)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto failFirstRepublish = std::make_shared<std::atomic_bool>(true);
  auto mutatedRepublish = std::make_shared<std::atomic_bool>(false);
  server.set_response_mutator(
    [failFirstRepublish, mutatedRepublish](ua::Response& response)
    {
      auto* republish = dynamic_cast<ua::RepublishResponse*>(response.second.get());
      if (republish != nullptr && failFirstRepublish->exchange(false))
      {
        mutatedRepublish->store(true);
        republish->response_header().service_result() = ua::StatusCode{ua::Status::BadResponseTooLarge};
      }
    });

  auto connection = fixture.connection();
  SubscriptionConfig config;
  config.publishingIntervalMs = 50.0;
  config.maxNotificationsPerPublish = 64;
  auto subscription = connection.subscriptions().try_create_sync(config);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();
  auto delivered = std::make_shared<std::atomic_size_t>(0);
  MonitorRequest monitorRequest;
  monitorRequest.nodeId = NodeId{VariableId::Server_ServerStatus_CurrentTime};
  monitorRequest.samplingIntervalMs = 25.0;
  auto item = subscription.value().try_monitor_sync(
    monitorRequest, [delivered](DataChangeEvent) { delivered->fetch_add(1); });
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  ASSERT_TRUE(wait_until([&] { return delivered->load() >= 1; }))
    << "the public MonitoredItem must produce a retained notification to Republish";
  // Drive a gap on a subsequent real notification so the server's retransmission queue has a typed retained
  // message to answer with; only that Republish response is mutated to Bad_ResponseTooLarge.
  server.inject_sequence_gap(subscriptionId, /*skip=*/3);
  ASSERT_TRUE(wait_until([&] { return capture->republish_count() >= 1; }))
    << "the injected sequence gap must drive a Republish";
  ASSERT_TRUE(wait_until([&] { return mutatedRepublish->load(); }))
    << "the server hook must mutate the Republish response";
  ASSERT_TRUE(wait_until([&] { return capture->modify_subscription_count() >= 1; }))
    << "a Republish Bad_ResponseTooLarge must emit an automatic ModifySubscription";
  ASSERT_EQ(capture->modified_notification_limits(), (std::vector<std::uint32_t>{32}));
}

// =============================================================================================
// Row - TerminatesOnStatusChangeBadTimeout  (MisbehavingServer)  [integration+unit]
// A StatusChangeNotification carrying Bad_Timeout must terminate the Subscription: remove it from the
// registry, flush each MonitoredItem callback with Bad_SubscriptionIdInvalid, fire
// on_subscription_terminated, and stop referencing the id. [neg: unilateral server termination]
//
// Public-tier rationale: Subscription lifecycle has no tier-2 domain facade. This row enters through the
// highest public production surface (`Connection::subscriptions()` and `Subscription::monitor_sync`);
// MisbehavingServer only injects/observes the adversarial wire response.
// =============================================================================================
// @verifies CL-SUB-008
// @relation(CL-SUB-008, scope=function)
TEST_F(ClientSubscription, TerminatesOnStatusChangeBadTimeout)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  auto connection = fixture.connection();
  auto observer = std::make_shared<TerminationObserver>();
  connection.set_subscription_observer(observer);
  auto subscription =
    connection.subscriptions().try_create_sync(SubscriptionConfig{.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();
  auto sink = std::make_shared<DataValueSink>();
  auto item = subscription.value().try_monitor_sync(MonitorRequest{.nodeId = monitoredNode},
    [sink](DataChangeEvent event) { sink->push(std::move(event.value)); });
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  // The item's initial value is the only notification the server sends before the mutator below takes over
  // (the monitored Variable does not change). The client acknowledges it in a later PublishRequest, so wait
  // for that acknowledgement before counting, and number the mutated messages after it: a mutated message
  // reusing its number would be dropped as a duplicate.
  ASSERT_TRUE(wait_until([&] { return capture->ack_count_for(subscriptionId) >= 1; }))
    << "the client must acknowledge the item's initial value";
  const std::size_t acknowledgementsBeforeTermination = capture->ack_count_for(subscriptionId);
  for (const auto& ack : capture->all_acks())
    if (ack.subscriptionId == subscriptionId && ack.sequenceNumber > sequenceNumber->load())
      sequenceNumber->store(ack.sequenceNumber);

  // Only after the public handles exist, make every response a pure Bad_Timeout StatusChange notification.
  server.set_response_mutator(
    [sequenceNumber](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      make_keep_alive(*publish);
      append_status_change(*publish, ua::StatusCode{ua::Status::BadTimeout});
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  ASSERT_TRUE(wait_until([&] { return observer->fired_for(subscriptionId); }))
    << "the public SubscriptionObserver must receive the unilateral termination";
  ASSERT_TRUE(wait_until([&] { return connection.subscriptions().list_sync().empty(); }))
    << "the public live-Subscription enumeration must drop the terminated handle";
  ASSERT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
        if (value.status().has_value() && value.status()->as_status() == ua::Status::BadSubscriptionIdInvalid)
          return true;
      return false;
    }))
    << "the monitored-item callback must be flushed with Bad_SubscriptionIdInvalid";

  const auto values = sink->snapshot();
  EXPECT_EQ(std::count_if(values.begin(),
              values.end(),
              [](const DataValue& value)
              {
                return value.status().has_value() &&
                       value.status()->as_status() == ua::Status::BadSubscriptionIdInvalid;
              }),
    1)
    << "each monitored item is flushed exactly once";
  EXPECT_EQ(observer->reason().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(observer->chain(), observer->reason().shared_detail());
  EXPECT_EQ(fixture.subscription_count(), 0u);
  EXPECT_EQ(fixture.monitored_item_count(), 0u);
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "Subscription lifetime expiry is not a Connection fault";

  // The terminal NotificationMessage itself is acknowledged exactly once (Part 4 section 5.13.1.1), then the
  // owning unit test proves the last-Subscription pump holds with no later reference to the closed id.
  ASSERT_TRUE(wait_until(
    [&] { return capture->ack_count_for(subscriptionId) == acknowledgementsBeforeTermination + 1; }));
  EXPECT_EQ(capture->ack_count_for(subscriptionId), acknowledgementsBeforeTermination + 1);
}

// =============================================================================================
// Row - CloseDeletesOwnedSubscriptionsBeforeSessionTeardown  (MisbehavingServer)
// A graceful public Connection close emits DeleteSubscriptions for its live, locally-owned Subscription
// while the Session is still usable. Reconnect-time transferred ownership is pinned by the owning unit test;
// this row confirms the highest public lifecycle path reaches the real wire. [neg: Session closes first]
// =============================================================================================
// @verifies CL-SUB-010
// @relation(CL-SUB-010, scope=function)
// @relation(AC-CL-SUB-010-A-SUBSCRIPTION-ACQUIRED-BY-TRANSFERSUBSCRIPTIONS, scope=function)
TEST_F(ClientSubscription, CloseDeletesOwnedSubscriptionsBeforeSessionTeardown)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_request_capture(server);

  auto connection = fixture.connection();
  auto createPromise = std::make_shared<std::promise<Result<Subscription>>>();
  auto createFuture = createPromise->get_future();
  connection.subscriptions().create_async(SubscriptionConfig{.publishingIntervalMs = 50.0},
    [createPromise](Result<Subscription> result) { createPromise->set_value(std::move(result)); });
  ASSERT_EQ(createFuture.wait_for(10s), std::future_status::ready) << "public Subscription creation stalled";
  auto subscription = createFuture.get();
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().server_subscription_id();

  auto closePromise = std::make_shared<std::promise<VoidResult>>();
  auto closeFuture = closePromise->get_future();
  connection.close_async([closePromise](VoidResult result) { closePromise->set_value(std::move(result)); });
  ASSERT_EQ(closeFuture.wait_for(10s), std::future_status::ready)
    << "public Connection close stalled before completing owned-Subscription teardown";
  const auto closeResult = closeFuture.get();
  ASSERT_TRUE(closeResult.is_good()) << to_string(closeResult.status_code());
  const auto deleteBatches = capture->delete_subscription_ids();
  ASSERT_EQ(deleteBatches.size(), 1u);
  ASSERT_EQ(deleteBatches.front().size(), 1u);
  EXPECT_EQ(deleteBatches.front()[0], subscriptionId);
}

// =============================================================================================
// Row - SemanticsChangedBitTriggersPropertyRefresh  (MisbehavingServer)  [integration+unit]
// A delivered DataChange whose DataValue StatusCode carries the in-band SemanticsChanged bit must trigger a
// property REFRESH for the monitored node - AND the value is still delivered to the user callback (the bit is
// advisory metadata, never suppresses delivery). [neg: a plain Good status must NOT invalidate]
//
// DESIGN (OPEN-ADDRSP-008): the SDK implements the trigger as LAZY invalidation, not an eager
// on_semantic_change callback: the pipeline detects the bit and routes the monitored node into the
// per-Connection SemanticChangeCache (ua_client_subscriptions_pipeline.cpp -> ConnectionImpl wires
// mOnSemanticsChanged -> semantic_change_cache()->invalidate_async), which flips every registered DA
// TypedPropertiesState's invalidated so the typed accessor re-resolves fresh Properties on its NEXT read
// (do_typed_read invalidated path). This test proves that FULL production wiring end-to-end: it registers a
// TypedPropertiesState for the monitored node, delivers a SemanticsChanged DataChange, and asserts both the
// value delivery AND the state invalidation. Falsifiable: were the connection wiring absent (or the bit
// ignored), invalidated would stay false. The negative sub-case (plain Good does not invalidate) is covered
// by the CL-DA-010 pipeline unit test
// (SubscriptionsPipeline.DataChangeWithoutSemanticsChangedDoesNotInvalidate).
// =============================================================================================
// @verifies CL-ADDRSP-008
// @relation(CL-ADDRSP-008, scope=function)
TEST_F(ClientSubscription, SemanticsChangedBitTriggersPropertyRefresh)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  const std::uint32_t clientHandle = 1;
  const std::int32_t semanticValue = 8642;

  // Register a DA TypedPropertiesState for the monitored node with the Connection's SemanticChangeCache -
  // this stands in for an AnalogItemHandle watching monitoredNode. The in-band bit must flip its
  // invalidated.
  auto propertyState = std::make_shared<ua::client::detail::TypedPropertiesState>();
  auto cache = ConnectionImplTestAccess::semantic_change_cache(fixture.conn());
  ASSERT_NE(cache, nullptr);
  auto registration = cache->register_state(monitoredNode, propertyState);
  ASSERT_FALSE(propertyState->invalidated.load()) << "a freshly-registered state starts valid";

  // Deliver a DataChange whose value status carries the SemanticsChanged info bit.
  server.set_response_mutator(
    [sequenceNumber, clientHandle, semanticValue](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish)
        return;
      set_publish_sequence(*publish, ++(*sequenceNumber));
      ua::StatusCode status{ua::Status::Good};
      status.semantics_changed(true);
      append_data_change(*publish, clientHandle, ua::Variant{semanticValue}, status);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), clientHandle, sink).is_good());

  // BUILT observable 1: the value is delivered and the SemanticsChanged status bit survives to the callback.
  EXPECT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
        if (value.value().is_int32() && value.value().as<std::int32_t>() == semanticValue &&
            value.status().has_value() && value.status()->semantics_changed())
          return true;
      return false;
    }))
    << "the value carrying the SemanticsChanged bit must be delivered with the bit intact";

  // BUILT observable 2 (the CL-ADDRSP-008 refresh trigger): the pipeline detected the bit and the Connection
  // wiring routed the node into the cache, flipping the registered DA state's invalidated -> its next read
  // re-resolves fresh Properties.
  EXPECT_TRUE(wait_until([&] { return propertyState->invalidated.load(); }))
    << "the in-band SemanticsChanged bit must invalidate the registered DA property state (the property "
       "refresh trigger, via the production pipeline->cache wiring)";
}

// =============================================================================================
// Row - PumpTargetScalesWithTotalMonitoredItems  (single shared pump, TOTAL sizing; CL-SUB-015)
// The one Publish pump per Connection sizes on the TOTAL monitored-item count across ALL subscriptions:
// target = max(2, ceil(total / 100)). Creating 250 items spread over two subscriptions through the real
// create path must drive the shared pump's target to ceil(250/100) = 3 (a per-Subscription pump would size
// each at the floor 2 and never reach 3). Deleting the subscription that owns 150 of them drops the total to
// 100, returning the target to the floor of 2. This is a falsifiable end-to-end oracle for the wiring:
// without it the target stays at the default 2 regardless of item count.
// =============================================================================================
// @verifies CL-SUB-015
// @relation(CL-SUB-015, scope=function)
TEST_F(ClientSubscription, PumpTargetScalesWithTotalMonitoredItems)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const auto firstSubscription = fixture.create_subscription(500.0);
  ASSERT_TRUE(firstSubscription.is_good()) << to_string(firstSubscription.status_code());
  const auto secondSubscription = fixture.create_subscription(500.0);
  ASSERT_TRUE(secondSubscription.is_good()) << to_string(secondSubscription.status_code());

  auto sink = std::make_shared<DataValueSink>();
  std::uint32_t clientHandle = 1;
  for (; clientHandle <= 100; ++clientHandle)  // 100 items on the first subscription
  {
    ASSERT_TRUE(fixture.create_monitored_item(firstSubscription.value(), clientHandle, sink).is_good())
      << "item " << clientHandle;
  }
  for (; clientHandle <= 250; ++clientHandle)  // 150 items on the second subscription -> 250 total
  {
    ASSERT_TRUE(fixture.create_monitored_item(secondSubscription.value(), clientHandle, sink).is_good())
      << "item " << clientHandle;
  }

  ASSERT_EQ(fixture.monitored_item_count(), 250u) << "all 250 items registered on the one pipeline";
  EXPECT_EQ(fixture.pump_target(), 3u)
    << "one shared pump sizes on the TOTAL 250 items: max(2, ceil(250/100)) = 3";

  ASSERT_TRUE(fixture.delete_subscription(secondSubscription.value()).is_good());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 100u; }))
    << "deleting the second subscription must cascade-purge its 150 items";
  EXPECT_EQ(fixture.pump_target(), 2u) << "100 items -> max(2, ceil(100/100)) = 2 (the floor)";
}

// =============================================================================================
// OPC 10000-4 section 5.13.3.3: Bad_SubscriptionIdInvalid from ModifySubscription means the Subscription no
// longer exists server-side (deleted, transferred, or lifetime-expired). A plausible implementation treats a
// bad modify like any other transient service failure and re-issues it, or keeps the local record alive so a
// later reconnect "restores" a Subscription the server has already forgotten. Retrying is the specific
// hazard: the status is definitive, so no number of attempts can converge, and each looks like a transient
// failure. The correct reaction is surface-and-forget, NOT the CreateSubscription fallback the Republish path
// uses for the same code.
// @verifies AC-CL-SUB-013-MODIFY-NO-RETRY
// =============================================================================================
TEST_F(ClientSubscription, ModifyRejectedWithBadSubscriptionIdIsSurfacedAndForgotten)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto connection = fixture.connection();
  auto subscription =
    connection.subscriptions().try_create_sync(SubscriptionConfig{.publishingIntervalMs = 100.0});
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  ASSERT_EQ(fixture.subscription_count(), 1u)
    << "the Subscription must be locally registered before the modify (the removal below is falsifiable only "
       "if there is a record to remove)";
  ASSERT_EQ(capture->modify_subscription_count(), 0u)
    << "no ModifySubscription before the caller asks for one";

  // Only the ModifySubscription answer is bent; every other response (including Publish) is untouched, so the
  // Subscription is otherwise perfectly healthy when the client is told its id is invalid.
  auto modifyRejected = std::make_shared<std::atomic_bool>(false);
  server.set_response_mutator(
    [modifyRejected](Response& response)
    {
      if (auto* modify = dynamic_cast<ua::ModifySubscriptionResponse*>(response.second.get()))
      {
        modify->response_header().service_result() = ua::StatusCode{ua::Status::BadSubscriptionIdInvalid};
        modifyRejected->store(true);
      }
    });

  SubscriptionModifyConfig modifyConfig;
  modifyConfig.publishingIntervalMs = 250.0;
  const auto modifyResult = subscription.value().try_modify_sync(modifyConfig);

  ASSERT_TRUE(modifyRejected->load())
    << "the server hook must have rewritten a ModifySubscription response (otherwise nothing was stimulated)";

  // Conjunct 1 - the error reaches the caller, with the exact status, not a swallowed or remapped one.
  EXPECT_TRUE(modifyResult.is_bad()) << "a rejected modify must not be reported as success";
  EXPECT_EQ(modifyResult.status_code().as_status(), ua::Status::BadSubscriptionIdInvalid)
    << "the exact server status must reach the caller";

  // Conjunct 2 - the local Subscription record is removed (the id is authoritatively gone server-side).
  ASSERT_TRUE(wait_until([&] { return fixture.subscription_count() == 0u; }))
    << "Bad_SubscriptionIdInvalid means the Subscription is gone: the stale local record must be dropped so "
       "its sequence tracking and acknowledgements stop";
  EXPECT_TRUE(connection.subscriptions().list_sync().empty())
    << "the public live-Subscription enumeration must drop the record too";

  // Conjunct 3 - no modify is reissued. Assert over a window in which a retry loop would have fired.
  const std::size_t modifiesAtRejection = capture->modify_subscription_count();
  EXPECT_EQ(modifiesAtRejection, 1u) << "exactly one ModifySubscription was put on the wire";
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(capture->modify_subscription_count(), modifiesAtRejection)
    << "Bad_SubscriptionIdInvalid must never be retried: the Subscription is gone, so a retry loop cannot "
       "converge";
  EXPECT_EQ(capture->create_subscription_count(), 1u)
    << "and the modify path must not fall back to CreateSubscription (that is the Republish path's reaction, "
       "not this one)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a per-Subscription terminal status is not a Connection fault";
}

// =============================================================================================
// OPC 10000-4 sections 5.13.4.2 and 5.13.4.4: SetPublishingMode reports its outcome PER Subscription in
// results[], positionally paired with subscriptionIds; the service result only says the request itself was
// processed. A Good service result carrying a failing slot is the shape that gets mishandled, because the
// service result is the value a caller naturally checks and it says the request succeeded - which it did. A
// client reading only the service result would report publishing enabled on a Subscription that never enabled
// it, and the symptom is an absence of notifications with nothing anywhere reporting an error.
//
// The SDK sends one subscriptionId per SetPublishingMode request (ConnectionImpl::set_publishing_mode_async),
// so the three-Subscription stimulus is driven as the three requests the client actually emits; the injected
// answer for the SECOND of them carries the Good service result with Bad_SubscriptionIdInvalid in its slot,
// and the first and third carry the Good service result with a Good slot.
// @verifies AC-CL-SUB-014-SETPUBLISHING-PERITEM
// =============================================================================================
TEST_F(ClientSubscription, SetPublishingModeHonoursPerSubscriptionResultUnderGoodServiceResult)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Created dormant, so "takes the new mode" is an observable flip rather than a value that was already true.
  SubscriptionConfig dormant;
  dormant.publishingIntervalMs = 200.0;
  dormant.publishingEnabled = false;

  auto connection = fixture.connection();
  auto first = connection.subscriptions().try_create_sync(dormant);
  ASSERT_TRUE(first.is_good()) << to_string(first.status_code());
  auto second = connection.subscriptions().try_create_sync(dormant);
  ASSERT_TRUE(second.is_good()) << to_string(second.status_code());
  auto third = connection.subscriptions().try_create_sync(dormant);
  ASSERT_TRUE(third.is_good()) << to_string(third.status_code());
  ASSERT_FALSE(first.value().is_publishing_enabled()) << "all three start dormant";
  ASSERT_FALSE(second.value().is_publishing_enabled()) << "all three start dormant";
  ASSERT_FALSE(third.value().is_publishing_enabled()) << "all three start dormant";

  // Every SetPublishingMode answer states Good at the SERVICE level; only the second Subscription's per-item
  // slot is bad. A client that trusts the service result reports all three enabled.
  auto modeResponses = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [modeResponses](Response& response)
    {
      auto* mode = dynamic_cast<ua::SetPublishingModeResponse*>(response.second.get());
      if (!mode)
        return;
      const std::uint32_t ordinal = ++(*modeResponses);
      mode->response_header().service_result() = ua::StatusCode{ua::Status::Good};
      mode->results().clear();
      mode->results().push_back(ordinal == 2 ? ua::StatusCode{ua::Status::BadSubscriptionIdInvalid}
                                             : ua::StatusCode{ua::Status::Good});
    });

  const auto firstResult = first.value().try_set_publishing_mode_sync(true);
  const auto secondResult = second.value().try_set_publishing_mode_sync(true);
  const auto thirdResult = third.value().try_set_publishing_mode_sync(true);
  ASSERT_EQ(modeResponses->load(), 3u)
    << "all three SetPublishingMode answers must have been bent (else the slot under test never existed)";

  // Conjunct 1 - the second Subscription's per-item failure reaches the caller, with its exact status.
  EXPECT_TRUE(secondResult.is_bad())
    << "a Bad_SubscriptionIdInvalid in the per-Subscription slot must fail the operation even though the "
       "service result is Good";
  EXPECT_EQ(secondResult.status_code().as_status(), ua::Status::BadSubscriptionIdInvalid)
    << "the per-Subscription status is the operation's outcome and must reach the caller verbatim";
  EXPECT_FALSE(second.value().is_publishing_enabled())
    << "a Subscription whose slot failed must not be recorded as having taken the new mode";

  // Conjunct 2 - the first and third take the new mode.
  EXPECT_TRUE(firstResult.is_good()) << to_string(firstResult.status_code());
  EXPECT_TRUE(thirdResult.is_good()) << to_string(thirdResult.status_code());
  EXPECT_TRUE(first.value().is_publishing_enabled())
    << "the first Subscription's slot was Good, so it takes the new mode";
  EXPECT_TRUE(third.value().is_publishing_enabled())
    << "the third Subscription's slot was Good, so it takes the new mode";

  // Conjunct 3 - the Good service result is not reported as success for all three.
  const int successes = static_cast<int>(firstResult.is_good()) + static_cast<int>(secondResult.is_good()) +
                        static_cast<int>(thirdResult.is_good());
  EXPECT_EQ(successes, 2)
    << "exactly two of the three operations succeeded; a client reading only the Good service result would "
       "report three";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a per-Subscription failure is not a Connection fault";
}
