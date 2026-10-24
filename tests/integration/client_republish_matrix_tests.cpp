// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientRepublish cluster of the client integration-test matrix (the 14 `ClientRepublish.*` rows).
///
/// These are END-TO-END integration tests of the TIER-1 SubscriptionsPipeline sequence tracker
/// (ua_sequence_tracker.{h,cpp}) and its reactive Republish driver
/// (ua_client_subscriptions_pipeline.cpp: on_publish_response_async classify/advance/ack section 8.4.5 +
/// on_republish_response_async drain loop section 8.4.8), reached through the internal
/// `ua::client::detail::ConnectionImpl` orchestrator. The harness is the same MisbehavingSubscriptionFixture
/// the committed ClientSubscription slice uses (verbatim): a real `Client` bound to a `MisbehavingServer`'s
/// crypto + trusted certificate store over ephemeral TCP, whose tier-0 connect yields an activated Session
/// wrapped into a started tier-1 ConnectionImpl. The always-on Publish pump auto-runs on the pool; behaviour
/// is observed through three client-visible surfaces:
///   - the DATA SINK - the per-monitored-item `DataValue` callback (notifications actually delivered);
///   - the REQUEST OBSERVER (`MisbehavingServer::set_request_observer`) - the DECODED outgoing PublishRequest
///     acks AND the exact outgoing RepublishRequest `{subscriptionId, retransmitSequenceNumber}` the driver
///     emits, in wire order; and
///   - the pipeline INFO snapshot (`ConnectionImplTestAccess::pipeline_info`) - subscriptionCount /
///   pumpState.
///
/// DETERMINISTIC GAP DRIVER. `MisbehavingServer::set_response_mutator` runs on the server channel strand
/// BEFORE signing, and receives the whole `ua::Response` (a `{requestId, shared_ptr<Structure>}` pair) - so a
/// scenario can not only edit a `PublishResponse` in place (forcing sequence numbers, injecting a gap,
/// clearing the payload) but also REPLACE the body of a `RepublishResponse`/`ServiceFault` with a synthesized
/// one. Response correlation on the client is by the secure-channel requestId (the pair's untouched
/// `.first`), NOT by the decoded response header (ua_client_secure_channel_impl.cpp:739 /
/// ua_client_session_impl.cpp:1519 correlate on requestId/requestHandle counters), so a synthesized
/// RepublishResponse is delivered to the pending Republish exactly like a real one. @ref GapDriver exploits
/// this: it PRIMES the client's next-expected sequence number to a known value, fires ONE gap-revealing
/// Publish (skipping `gapSize` numbers), then answers the driver's ascending Republish requests with
/// `recoverCount` synthesized Good recoveries followed by a synthesized terminator (Bad_MessageNotAvailable /
/// Bad_SubscriptionIdInvalid / Bad_InternalError). This makes the gap -> drain -> recovery -> terminate path
/// fully observable and falsifiable without any server-retransmission-queue guesswork.
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable - the Republish `{subId, seq}` the driver puts on the wire (ascending, one-outstanding, stops
/// at the terminator), the recovered values delivered in order, the ack stream, the removal on a gone
/// Subscription. Timing is ALWAYS bounded polling on an observable (a delivered value / a republish count /
/// an ack count), never a fixed sleep.
///
/// REPORTED DIVERGENCE (built-code vs matrix "no dispatch" clause). SeqNumZeroRejected /
/// ReplayedSeqNumRejected assert the built TRACKER observable (an Invalid / Duplicate sequence number is not
/// acked, not advanced, and drives no Republish, and does not corrupt next-expected) - but they do NOT assert
/// the matrix's stronger "no user callback dispatch" clause, because the built ConnectionImpl demux
/// (feed_publish_response, ua_connection_impl.cpp:269) routes each DataChangeNotification's items to their
/// clientHandle INDEPENDENTLY of the sequence classification, so an Invalid/Duplicate message's payload is
/// still delivered. This is the same delivery-decoupling divergence the committed ClientSubscription slice
/// reported for PublishResponseWithUnknownSubscriptionIdRejected (delivery routed purely by clientHandle).
/// Fixing it is an architectural change spanning feed_publish_response + on_publish_response_async (deliver
/// only when the classification is InOrder or Gap; drop Invalid/Duplicate) with cross-slice scope of change -
/// batched as a follow-up rather than folded silently into this cluster.
///
/// BLOCKED / REPORTED rows (RecoveringSubscriptions is a RECONNECT-FSM gate the single-shot Connection cannot
/// drive - pin the built, reactive, spec-consistent observable and record the reconnect-only part in the
/// header + report, per the ClientSubscription / ClientBrowse precedent):
///   - FallsBackToCreateOnBadSubscriptionIdInvalid - the reactive drain REMOVES a Subscription whose
///   Republish
///     returns Bad_SubscriptionIdInvalid (on_republish_response_async goneSubscription branch); the
///     recreate-a-fresh-Subscription fallback lives in the ReconnectionFSM session-CHANGED path
///     (section 8.3), which needs a transport reconnect. Pin: reactive Bad_SubscriptionIdInvalid ->
///     Subscription removed + NO new CreateSubscription. Report the recreate as reconnect-harness-blocked.
///   - PublishHeldDuringRepublishLoop / PublishResumesAfterTerminator - the "hold the Publish pump while a
///     Republish loop drains, then resume promptly" gate (CL-RECONN-007) is a RecoveringSubscriptions
///     property (the pump is stopped only during the reconnect recovery step). On the REACTIVE drain path the
///     pump is by design NOT held (a reactive gap drain runs concurrently with the pump, section 8.4.5). Pin
///     the reactive reality (the pump keeps publishing across a reactive drain; notifications still flow
///     after a terminator) and report the reconnect-recovery hold/resume gate as reconnect-harness-blocked.
///
/// UNIT-DELEGATED row. SeqNumRolloverAtFourBillionSurvives cannot advance next-expected to the 2^32 boundary
/// at the integration boundary (that needs ~4 billion in-order messages); the modular wrap arithmetic is
/// unit-pinned in tests/unit/client/subscription/sequence_tracker_tests.cpp. This integration test pins the
/// falsifiable near-wrap observable it CAN reach: a near-maximum sequence number on a fresh tracker is
/// classified stale (signed-distance Duplicate), NOT a ~4-billion forward gap - so a naive unsigned compare
/// (which would flood Republishes) is refuted end-to-end.

#include "compliance_helpers.h"

#include "misbehaving_server.h"
#include "subscription.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_create_subscription_request.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_logger.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_monitored_item_notification.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_ref_structure.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_service_fault.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_to_string.h"
#include "ua_transfer_result.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
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
// All delivered values in these tests are injected via the response mutator (the MisbehavingServer has no
// user-writable node), so the tests never depend on the server updating it.
const NodeId monitoredNode{VariableId::Server_ServerStatus_State};

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

  // True iff an Int32 value equal to @p wanted was delivered.
  bool contains_int32(std::int32_t wanted) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
      if (value.value().is_int32() && value.value().as<std::int32_t>() == wanted)
        return true;
    return false;
  }

  // The ordered list of the Int32 values delivered (for asserting recovery order).
  std::vector<std::int32_t> int32_sequence() const
  {
    std::lock_guard lock(mMutex);
    std::vector<std::int32_t> seq;
    for (const auto& value : mValues)
      if (value.value().is_int32())
        seq.push_back(value.value().as<std::int32_t>());
    return seq;
  }

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

// ---------------------------------------------------------------------------------------------
// A read-only capture of what the client put on the wire: the acks carried on each outgoing PublishRequest,
// and the exact {subscriptionId, retransmitSequenceNumber} of every outgoing RepublishRequest in wire order.
// Populated on the server strand by the MisbehavingServer request observer, read by the test thread.
// ---------------------------------------------------------------------------------------------
struct SentAck
{
  std::uint32_t subscriptionId = 0;
  std::uint32_t sequenceNumber = 0;
};

struct SentRepublish
{
  std::uint32_t subscriptionId = 0;
  std::uint32_t sequenceNumber = 0;
};

struct RequestCapture
{
  mutable std::mutex mutex;
  std::vector<std::vector<SentAck>> publishRequests;  // one entry per PublishRequest, its ack batch
  std::vector<SentRepublish> republishes;  // one entry per RepublishRequest, in wire order
  std::size_t modifySubscriptionCount = 0;
  std::size_t createSubscriptionCount = 0;

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
    else if (const auto* republish = dynamic_cast<const ua::RepublishRequest*>(&request))
    {
      republishes.push_back(
        SentRepublish{republish->subscription_id(), republish->retransmit_sequence_number()});
    }
    else if (dynamic_cast<const ua::ModifySubscriptionRequest*>(&request))
    {
      ++modifySubscriptionCount;
    }
    else if (dynamic_cast<const ua::CreateSubscriptionRequest*>(&request))
    {
      ++createSubscriptionCount;
    }
  }

  std::size_t publish_count() const
  {
    std::lock_guard lock(mutex);
    return publishRequests.size();
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

  std::size_t ack_count_for_seq(std::uint32_t subscriptionId, std::uint32_t sequenceNumber) const
  {
    std::lock_guard lock(mutex);
    std::size_t count = 0;
    for (const auto& batch : publishRequests)
      for (const auto& ack : batch)
        if (ack.subscriptionId == subscriptionId && ack.sequenceNumber == sequenceNumber)
          ++count;
    return count;
  }

  std::vector<SentRepublish> republishes_for(std::uint32_t subscriptionId) const
  {
    std::lock_guard lock(mutex);
    std::vector<SentRepublish> out;
    for (const auto& republish : republishes)
      if (republish.subscriptionId == subscriptionId)
        out.push_back(republish);
    return out;
  }

  std::size_t republish_count() const
  {
    std::lock_guard lock(mutex);
    return republishes.size();
  }

  std::size_t republish_count_for(std::uint32_t subscriptionId) const
  {
    std::lock_guard lock(mutex);
    std::size_t count = 0;
    for (const auto& republish : republishes)
      if (republish.subscriptionId == subscriptionId)
        ++count;
    return count;
  }

  std::size_t modify_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return modifySubscriptionCount;
  }

  std::size_t create_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return createSubscriptionCount;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 6000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(5ms);
  }
  return predicate();
}

// ----- Response-mutator building blocks (each edits a PublishResponse in place, before signing) -----

void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

void set_available_sequence_numbers(ua::PublishResponse& publish, bool present)
{
  publish.available_sequence_numbers().clear();
  if (present)
    publish.available_sequence_numbers().push_back(
      ua::Counter{publish.notification_message().sequence_number()});
}

// Appends a DataChangeNotification carrying one MonitoredItemNotification for @p clientHandle.
void append_data_change(ua::PublishResponse& publish, std::uint32_t clientHandle, ua::Variant value)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  ua::DataValue dataValue;
  dataValue.value() = std::move(value);
  item.value() = std::move(dataValue);
  notification->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// Appends an EMPTY DataChangeNotification (a real notification entry with zero items): makes the response
// notification-bearing (hasNotifications == true, so the tracker advances/acks) without delivering to any
// handle.
void append_empty_data_change(ua::PublishResponse& publish)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// Builds a synthesized Good RepublishResponse that recovers sequence @p seq, carrying one DataChange for
// @p clientHandle valued @p value (mirrors what the reference server returns from its retransmission queue).
std::shared_ptr<ua::Structure> make_republish_recovery(
  std::uint32_t seq, std::uint32_t clientHandle, std::int32_t value)
{
  auto response = std::make_shared<ua::RepublishResponse>();
  response->response_header().service_result() = ua::StatusCode{ua::Status::Good};
  response->notification_message().sequence_number() = seq;
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  ua::DataValue dataValue;
  dataValue.value() = ua::Variant{value};
  item.value() = std::move(dataValue);
  notification->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  response->notification_message().notification_data().push_back(std::move(ref));
  return response;
}

// Builds a synthesized ServiceFault terminating the drain with @p status (the client maps a ServiceFault to a
// Bad Result, ua_client_secure_channel_impl.cpp:809).
std::shared_ptr<ua::Structure> make_republish_terminator(ua::Status status)
{
  auto fault = std::make_shared<ua::ServiceFault>();
  fault->response_header().service_result() = ua::StatusCode{status};
  return fault;
}

// ---------------------------------------------------------------------------------------------
// GapDriver - a deterministic sequence-gap scenario installed as a response mutator.
//
// Lifecycle (driven by the test thread flipping `phase`):
//   PRIME : every Publish for the Subscription carries sequenceNumber 1 with an empty (deliver-nothing)
//           DataChangeNotification and a non-empty availableSequenceNumbers. The first is InOrder -> the
//           tracker advances to 2 and acks 1 (observable), later PRIME publishes are Duplicate no-ops. Once
//           the seq-1 ack is seen, next-expected is known to be 2.
//   GAP   : the FIRST Publish after the flip carries sequenceNumber (2 + gapSize) with a data notification
//           valued `gapValue` - a gap skipping {2 .. 1 + gapSize} - which the tracker classifies Gap and the
//           driver reacts to with Republish(2). Every later Publish reverts to a keep-alive at sequenceNumber
//           2 (Duplicate no-op), so the gap fires exactly ONCE and drives exactly one drain.
//   post  : the driver answers the drain's ascending Republish requests (2, 3, ...): the k-th recovers
//           sequence (2 + k) valued recoveredValue(2 + k) for the first `recoverCount`, then a terminator
//           carrying `terminatorStatus`.
//
// Recovery values are 3000 + seq, distinct from `gapValue`, so a test can assert exactly which recovered
// messages were dispatched and in what order.
// ---------------------------------------------------------------------------------------------
struct GapDriver
{
  std::atomic<std::uint32_t> subscriptionId{0};  // set after CreateSubscription; 0 = inert
  std::uint32_t clientHandle = 1;
  std::uint32_t gapSize = 1;  // how many sequence numbers the gap skips
  std::uint32_t recoverCount = 1;  // how many the driver recovers before terminating
  ua::Status terminatorStatus = ua::Status::BadMessageNotAvailable;
  std::int32_t gapValue = 9999;  // delivered live by the gap-revealing Publish

  std::atomic<int> phase{0};  // 0 = PRIME, 1 = GAP
  std::atomic<bool> gapFired{false};  // one-shot latch: the gap Publish is emitted once
  std::atomic<std::uint32_t> republishSeen{0};  // count of Republish responses answered (drives the script)

  static std::int32_t recovered_value(std::uint32_t seq)
  {
    return 3000 + static_cast<std::int32_t>(seq);
  }

  void mutate(ua::Response& response)
  {
    const std::uint32_t subId = subscriptionId.load();
    if (subId == 0)
      return;

    if (auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get()))
    {
      if (publish->subscription_id() != subId)
        return;
      publish->notification_message().notification_data().clear();
      if (phase.load() == 0)
      {
        set_publish_sequence(*publish, 1);
        append_empty_data_change(*publish);
        set_available_sequence_numbers(*publish, /*present=*/true);
      }
      else if (!gapFired.exchange(true))
      {
        set_publish_sequence(*publish, 2 + gapSize);
        append_data_change(*publish, clientHandle, ua::Variant{gapValue});
        set_available_sequence_numbers(*publish, /*present=*/true);
      }
      else
      {
        // Post-gap keep-alive at the pre-gap next-expected: Duplicate/keep-alive no-op, so no further gap.
        set_publish_sequence(*publish, 2);
        set_available_sequence_numbers(*publish, /*present=*/true);
      }
      return;
    }

    // A Republish response (in these controlled scenarios the only ServiceFaults or RepublishResponses are
    // the driver's own): script the ascending drain. The client requests sequence (2 + k) on its k-th
    // Republish.
    const bool isRepublish = dynamic_cast<ua::RepublishResponse*>(response.second.get()) != nullptr ||
                             dynamic_cast<ua::ServiceFault*>(response.second.get()) != nullptr;
    if (!isRepublish)
      return;
    const std::uint32_t k = republishSeen.fetch_add(1);
    const std::uint32_t requestedSeq = 2 + k;
    if (k < recoverCount)
      response.second = make_republish_recovery(requestedSeq, clientHandle, recovered_value(requestedSeq));
    else
      response.second = make_republish_terminator(terminatorStatus);
  }
};

// ---------------------------------------------------------------------------------------------
// MisbehavingSubscriptionFixture: a real client bound to a MisbehavingServer, on its own thread pool, with an
// activated Session wrapped into a started tier-1 ConnectionImpl (identical to the ClientSubscription slice's
// fixture). The test arms the response mutators / request observer AFTER construction.
// ---------------------------------------------------------------------------------------------
class MisbehavingSubscriptionFixture
{
public:
  explicit MisbehavingSubscriptionFixture(
    MisbehavingServer& server, ua::client::detail::ObserverSlots observers = {})
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
    auto session = channel.create_session_sync({.sessionName = "ClientRepublishMatrix"});
    session.activate_sync();

    ua::client::detail::ConnectionConfig connectionConfig;
    connectionConfig.observers = std::move(observers);
    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), std::move(connectionConfig), Logger{});
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

  // Issues a ModifySubscription stating the whole parameter set the keep-alive obligation needs (interval,
  // lifetime count, keep-alive count), and hands back the server's revised values. Same promise/future shape
  // as create_subscription.
  Result<ua::ModifySubscriptionResponse> modify_subscription(std::uint32_t subscriptionId,
    double publishingInterval, std::uint32_t lifetimeCount, std::uint32_t maxKeepAliveCount)
  {
    std::promise<Result<ua::ModifySubscriptionResponse>> promise;
    auto future = promise.get_future();
    mConnection->modify_subscription_async(subscriptionId,
      publishingInterval,
      lifetimeCount,
      maxKeepAliveCount,
      std::nullopt,
      std::nullopt,
      [&promise](Result<ua::ModifySubscriptionResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// Arms the request observer (capturing outgoing acks + Republishes) and returns the shared capture.
std::shared_ptr<RequestCapture> arm_request_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

// Installs @p driver as the server's response mutator.
void install_gap_driver(MisbehavingServer& server, const std::shared_ptr<GapDriver>& driver)
{
  server.set_response_mutator([driver](Response& response) { driver->mutate(response); });
}

// Creates the Subscription + one MonitoredItem, wires the driver to them, drives the PRIME phase to settle
// next-expected at 2 (observing the seq-1 ack), then flips the driver to GAP. Returns the subscriptionId.
std::uint32_t prime_and_arm_gap(MisbehavingSubscriptionFixture& fixture,
  const std::shared_ptr<RequestCapture>& capture, const std::shared_ptr<GapDriver>& driver,
  const std::shared_ptr<DataValueSink>& sink)
{
  auto subscription = fixture.create_subscription(50.0);
  EXPECT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  driver->subscriptionId.store(subscriptionId);
  EXPECT_TRUE(fixture.create_monitored_item(subscriptionId, driver->clientHandle, sink).is_good());

  // PRIME settles: the seq-1 ack proves the first PRIME Publish was InOrder -> next-expected == 2.
  EXPECT_TRUE(wait_until([&] { return capture->ack_count_for_seq(subscriptionId, 1) >= 1; }))
    << "the PRIME phase must advance the tracker to next-expected 2 (seq-1 acknowledged)";
  driver->phase.store(1);
  return subscriptionId;
}

}  // namespace

class ClientRepublish : public ::testing::Test
{};

// =============================================================================================
// Row - SeqNumZeroRejected  (MisbehavingServer)
// A NotificationMessage with sequenceNumber == 0 is rejected (0 is never a valid Publish sequence number,
// CL-SUB-002): the tracker classifies it Invalid, so it is never acknowledged, never drives a Republish, and
// does NOT corrupt next-expected - a subsequent valid seq-1 message is still accepted and acked. [neg:
// illegal zero sequence number]
//
// The delivery site now honours the classification (feed_publish_response gates dispatch on the pipeline's
// reported SequenceClass): a zero-sequence message is Invalid, so its payload is NOT delivered to the user
// callback. This test therefore pins BOTH the tracker guarantee (no ack, no Republish, no corruption) AND the
// no-dispatch clause (the sink stays empty while the zeros flow).
// =============================================================================================
// @verifies AC-CL-SUB-002-SEQNUM-UNIQUE
// @relation(AC-CL-SUB-002-SEQNUM-UNIQUE, scope=function)
TEST_F(ClientRepublish, SeqNumZeroRejected)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  const std::uint32_t clientHandle = 1;
  const std::int32_t zeroValue = 111;
  auto validPhase = std::make_shared<std::atomic<bool>>(false);
  auto subId = std::make_shared<std::atomic<std::uint32_t>>(0);

  // Phase A: every response carries sequenceNumber 0 (Invalid). Phase B (validPhase): sequenceNumber 1
  // (InOrder) - must be acked, proving the zeros did not corrupt the tracker's next-expected.
  server.set_response_mutator(
    [validPhase, subId, clientHandle, zeroValue](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish || publish->subscription_id() != subId->load())
        return;
      publish->notification_message().notification_data().clear();
      set_publish_sequence(*publish, validPhase->load() ? 1u : 0u);
      append_data_change(*publish, clientHandle, ua::Variant{zeroValue});
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  subId->store(subscriptionId);
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, clientHandle, sink).is_good());

  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 4; }))
    << "responses must flow so the reject assertion is not vacuous";

  EXPECT_EQ(capture->republish_count_for(subscriptionId), 0u)
    << "a zero sequence number is Invalid, not a gap: it must not drive a Republish";
  EXPECT_EQ(capture->ack_count_for(subscriptionId), 0u)
    << "a zero (Invalid) sequence number must never be acknowledged";
  EXPECT_EQ(sink->size(), 0u)
    << "a seq-0 (Invalid) message must NOT be delivered to the user callback: the delivery site gates on the "
       "classification, so no zero-sequence payload reaches the monitored item";

  // No corruption: after the zeros, a genuine in-order seq-1 message is still accepted and acknowledged.
  validPhase->store(true);
  EXPECT_TRUE(wait_until([&] { return capture->ack_count_for_seq(subscriptionId, 1) >= 1; }))
    << "a valid seq-1 message after the zeros must still be accepted and acked (the zero did not corrupt "
       "next-expected)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "an illegal sequence number must not fault the Connection";
}

// =============================================================================================
// Row - ReplayedSeqNumRejectedAsStale  (MisbehavingServer)
// A previously-used (behind next-expected) sequence number is classified Duplicate: it is not acknowledged
// again and the tracker does NOT rewind - a later genuine in-order number is still accepted without a
// spurious Republish. [neg: replayed/duplicate seq num]
//
// The delivery site now gates dispatch on the classification, so the replayed (Duplicate) payload is NOT
// re-delivered: only the first (InOrder) seq-1 reaches the user callback, then the seq-2 message. This test
// pins BOTH the tracker guarantee (no re-ack, no rewind) AND the no-double-dispatch clause (the sink holds
// the InOrder delivery exactly once while the replays flow).
// =============================================================================================
// @verifies AC-CL-SUB-002-SEQNUM-UNIQUE
// @relation(AC-CL-SUB-002-SEQNUM-UNIQUE, scope=function)
TEST_F(ClientRepublish, ReplayedSeqNumRejectedAsStale)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  const std::uint32_t clientHandle = 1;
  auto subId = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto advance = std::make_shared<std::atomic<bool>>(false);  // false: replay seq 1; true: deliver seq 2

  // Every response carries sequenceNumber 1 until `advance` flips to 2. The first seq-1 is InOrder (acked,
  // next-expected -> 2); every later seq-1 is a REPLAY (Duplicate, behind next-expected) -> no re-ack, no
  // rewind. The seq-2 message then confirms the tracker still expects 2 (no rewind to 1).
  server.set_response_mutator(
    [advance, subId, clientHandle](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish || publish->subscription_id() != subId->load())
        return;
      publish->notification_message().notification_data().clear();
      set_publish_sequence(*publish, advance->load() ? 2u : 1u);
      append_data_change(*publish, clientHandle, ua::Variant{std::int32_t{7}});
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  subId->store(subscriptionId);
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, clientHandle, sink).is_good());

  // Wait for the first (InOrder) seq-1 to be acked AND delivered, then let several REPLAYS flow.
  ASSERT_TRUE(wait_until([&] { return capture->ack_count_for_seq(subscriptionId, 1) >= 1; }))
    << "the first seq-1 must be acknowledged in order";
  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "the first (InOrder) seq-1 must be delivered to the user callback";
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 5; }))
    << "replays must flow so the no-re-ack assertion is not vacuous";

  EXPECT_EQ(capture->ack_count_for_seq(subscriptionId, 1), 1u)
    << "a replayed (Duplicate) sequence number must be acknowledged exactly once - never again";
  EXPECT_EQ(capture->republish_count_for(subscriptionId), 0u)
    << "a replay is behind, not ahead: it must not be mistaken for a gap (no Republish, no tracker rewind)";
  EXPECT_EQ(sink->size(), 1u)
    << "a replayed (Duplicate) message must NOT be re-delivered: the delivery site gates on the "
       "classification, so only the first (InOrder) seq-1 reaches the user callback";

  // No rewind: a genuine seq-2 is still InOrder (would be a Gap if the replays had rewound next-expected to
  // 1).
  advance->store(true);
  EXPECT_TRUE(wait_until([&] { return capture->ack_count_for_seq(subscriptionId, 2) >= 1; }))
    << "seq 2 must be acked as in-order (the replays did not rewind next-expected)";
  EXPECT_EQ(capture->republish_count_for(subscriptionId), 0u)
    << "seq 2 must not trigger a Republish (proving next-expected was still 2, never rewound to 1)";
  EXPECT_TRUE(wait_until([&] { return sink->size() >= 2; }))
    << "the in-order seq-2 message must be delivered (the second and final user dispatch)";
  EXPECT_EQ(sink->size(), 2u)
    << "exactly the two in-order messages (seq 1, then seq 2) are delivered; every replay of each is dropped";
}

// =============================================================================================
// Row - ClearedNotificationDataAdvancesCounter  (MisbehavingServer)
// A notification-bearing message whose DataChangeNotification carries NO monitored items (cleared payload)
// but a valid ADVANCING sequence number is a normal in-order message: the tracker advances next-expected and
// acks it, and issues NO Republish (it is not mistaken for a gap). [neg: empty notification payload with
// valid seq]
// =============================================================================================
// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=function)
TEST_F(ClientRepublish, ClearedNotificationDataAdvancesCounter)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto subId = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);

  // Each response advances the sequence number by one and carries an EMPTY DataChangeNotification (present,
  // so hasNotifications is true, but zero items). A correct tracker advances + acks each; a buggy one that
  // read the empty payload as a gap would Republish endlessly.
  server.set_response_mutator(
    [sequenceNumber, subId](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish || publish->subscription_id() != subId->load())
        return;
      publish->notification_message().notification_data().clear();
      set_publish_sequence(*publish, ++(*sequenceNumber));
      append_empty_data_change(*publish);
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  subId->store(subscriptionId);
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, 1, sink).is_good());

  // Three advancing empties must produce three ascending acknowledgements (the counter advanced each time).
  ASSERT_TRUE(wait_until([&] { return capture->ack_count_for(subscriptionId) >= 3; }))
    << "three advancing cleared-payload messages must each advance + ack the counter";

  EXPECT_GE(capture->ack_count_for_seq(subscriptionId, 1), 1u) << "sequence 1 must be acknowledged";
  EXPECT_GE(capture->ack_count_for_seq(subscriptionId, 2), 1u) << "sequence 2 must be acknowledged";
  EXPECT_GE(capture->ack_count_for_seq(subscriptionId, 3), 1u) << "sequence 3 must be acknowledged";
  EXPECT_EQ(capture->republish_count_for(subscriptionId), 0u)
    << "a cleared (but present, advancing) payload must NOT be mistaken for a gap (no Republish)";
  EXPECT_EQ(sink->size(), 0u) << "a cleared DataChangeNotification carries no item to deliver";
}

// =============================================================================================
// Row - SeqNumRolloverAtFourBillionSurvives  (MisbehavingServer)  [integration proxy; wrap unit-covered]
// A near-maximum sequence number on a fresh tracker (next-expected 1) is classified stale (signed-distance
// Duplicate), NOT a ~4-billion forward gap - so it drives no Republish flood, and a subsequent in-order seq-1
// message is still accepted. This refutes the naive-unsigned bug the matrix warns about ("would flood
// Republishes"). The exact 2^32 -> 1 wrap of next-expected is unit-pinned (sequence_tracker_tests.cpp), being
// unreachable at the integration boundary. [neg: 32-bit rollover; modular next-expected arithmetic]
// =============================================================================================
// @verifies AC-CL-SUB-002-SEQNUM-UNIQUE
// @relation(AC-CL-SUB-002-SEQNUM-UNIQUE, scope=function)
TEST_F(ClientRepublish, SeqNumRolloverAtFourBillionSurvives)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto subId = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto validPhase = std::make_shared<std::atomic<bool>>(false);
  const std::uint32_t nearMax = 0xFFFFFFFEu;  // signed distance from 1 is negative -> Duplicate, not a gap

  server.set_response_mutator(
    [validPhase, subId, nearMax](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish || publish->subscription_id() != subId->load())
        return;
      publish->notification_message().notification_data().clear();
      set_publish_sequence(*publish, validPhase->load() ? 1u : nearMax);
      append_data_change(*publish, 1, ua::Variant{std::int32_t{42}});
      set_available_sequence_numbers(*publish, /*present=*/true);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  subId->store(subscriptionId);
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, 1, sink).is_good());

  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 5; }))
    << "near-max responses must flow so the no-flood assertion is not vacuous";

  EXPECT_EQ(capture->republish_count_for(subscriptionId), 0u)
    << "a near-maximum sequence number on a fresh tracker is Duplicate (behind), not a ~4-billion forward "
       "gap: the signed-distance math must NOT flood Republishes";
  EXPECT_EQ(capture->ack_count_for(subscriptionId), 0u)
    << "a stale (Duplicate) near-max sequence number must never be acknowledged";

  // The tracker still expects 1: a genuine seq-1 message is accepted and acked.
  validPhase->store(true);
  EXPECT_TRUE(wait_until([&] { return capture->ack_count_for_seq(subscriptionId, 1) >= 1; }))
    << "next-expected is still 1: a real seq-1 message must be accepted after the near-max stales";
}

// =============================================================================================
// Row - SeqNumGapPlusOneTriggersRepublish  (MisbehavingServer)
// A single-message gap (received == next-expected + 1) drives a Republish carrying the subscriptionId and the
// SKIPPED sequence number, and the recovered message is dispatched to the user callback. [neg: single-message
// gap; which seq num is requested]
// =============================================================================================
// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=function)
TEST_F(ClientRepublish, SeqNumGapPlusOneTriggersRepublish)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 1;
  driver->recoverCount = 1;  // recover the one skipped message (seq 2), then terminate
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // The drain issues Republish(2) [recover] then Republish(3) [terminator]: two requests, the first carrying
  // the skipped sequence number 2.
  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 1; }))
    << "a +1 gap must drive a Republish (broken gap detection would silently accept the skipped seq)";
  ASSERT_TRUE(wait_until([&] { return sink->contains_int32(GapDriver::recovered_value(2)); }))
    << "the recovered (seq-2) message must be dispatched to the user callback";

  auto republishes = capture->republishes_for(subscriptionId);
  ASSERT_FALSE(republishes.empty());
  EXPECT_EQ(republishes.front().sequenceNumber, 2u)
    << "the first Republish must carry the SKIPPED sequence number (next-expected == 2)";
  EXPECT_EQ(republishes.front().subscriptionId, subscriptionId)
    << "the Republish must carry the Subscription "
       "id";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - SeqNumGapPlusTwoRepublishesBothInOrder  (MisbehavingServer)
// A two-message gap (received == next-expected + 2) drives Republish requests for BOTH skipped sequence
// numbers in ascending order, and both recovered messages are dispatched in order. [neg: two-message gap,
// ordered recovery]
// =============================================================================================
// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=function)
TEST_F(ClientRepublish, SeqNumGapPlusTwoRepublishesBothInOrder)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 2;
  driver->recoverCount = 2;  // recover both skipped messages (seq 2, seq 3), then terminate
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // Both recovered values must be delivered.
  ASSERT_TRUE(wait_until(
    [&]
    {
      return sink->contains_int32(GapDriver::recovered_value(2)) &&
             sink->contains_int32(GapDriver::recovered_value(3));
    }))
    << "both skipped messages (seq 2 and seq 3) must be recovered and dispatched";

  // The two recoveries must have driven Republish(2) then Republish(3) in ascending order (plus the seq-4
  // terminator probe) - a broken tracker that recovered only one would show a single Republish.
  ASSERT_TRUE(wait_until([&] { return capture->republishes_for(subscriptionId).size() >= 2; }));
  auto republishes = capture->republishes_for(subscriptionId);
  ASSERT_GE(republishes.size(), 2u)
    << "a +2 gap must drive at least two Republish requests (one per skipped seq)";
  EXPECT_EQ(republishes[0].sequenceNumber, 2u) << "first Republish requests the lower skipped seq";
  EXPECT_EQ(republishes[1].sequenceNumber, 3u)
    << "second Republish requests the higher skipped seq (ascending)";

  // The recovered values arrive in ascending sequence order.
  auto delivered = sink->int32_sequence();
  std::optional<std::size_t> indexOfTwo;
  std::optional<std::size_t> indexOfThree;
  for (std::size_t i = 0; i < delivered.size(); ++i)
  {
    if (delivered[i] == GapDriver::recovered_value(2) && !indexOfTwo)
      indexOfTwo = i;
    if (delivered[i] == GapDriver::recovered_value(3) && !indexOfThree)
      indexOfThree = i;
  }
  ASSERT_TRUE(indexOfTwo && indexOfThree);
  EXPECT_LT(*indexOfTwo, *indexOfThree)
    << "recovered messages must be dispatched in ascending sequence order";
}

// =============================================================================================
// Row - GapIsolatedToOneSubscription  (MisbehavingServer)
// Two Subscriptions on one Connection; a persistent +1 sequence gap injected on Sub A's stream only drives a
// Republish for Sub A only - Sub B's independent per-Subscription tracker advances normally and issues no
// Republish. [neg: gap on one of two subscriptions; a Session-scoped tracker would false-Republish Sub B]
// =============================================================================================
// @verifies CL-SUB-002
// @verifies AC-CL-SUB-017-SEQNUM-PER-SUBSCRIPTION
// @relation(CL-SUB-002, CL-SUB-017, scope=function)
TEST_F(ClientRepublish, GapIsolatedToOneSubscription)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);

  auto subA = fixture.create_subscription(50.0);
  ASSERT_TRUE(subA.is_good()) << to_string(subA.status_code());
  auto subB = fixture.create_subscription(50.0);
  ASSERT_TRUE(subB.is_good()) << to_string(subB.status_code());
  const std::uint32_t subIdA = subA.value();
  const std::uint32_t subIdB = subB.value();
  ASSERT_NE(subIdA, subIdB);

  // A persistent +1 gap on Sub A ONLY: every one of Sub A's PublishResponses arrives one ahead of expected,
  // so Sub A's tracker keeps detecting a gap and Republishing; Sub B is untouched.
  server.inject_sequence_gap(subIdA, /*skip=*/1);

  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subIdA) >= 1; }))
    << "a +1 gap on Sub A must drive a Republish for Sub A";

  // Let Sub B process several responses - the falsifying window where a Session-scoped tracker would emit a
  // spurious Republish for Sub B.
  const std::size_t baseline = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= baseline + 6; }));

  EXPECT_EQ(capture->republish_count_for(subIdB), 0u)
    << "Sub B's per-Subscription tracker is isolated: a gap on Sub A must NOT drive a Republish for Sub B";
  for (const auto& republish : capture->republishes_for(subIdA))
    EXPECT_EQ(republish.subscriptionId, subIdA) << "Sub A's Republishes must all carry Sub A's id";
}

// =============================================================================================
// Row - TwoConcurrentGapsRecoverIndependently  (MisbehavingServer)
// Two Subscriptions each suffering a gap in the same window drive two INDEPENDENT Republish operations, one
// per subscriptionId - neither Sub's recovery clobbers the other's expected counter. [neg: simultaneous
// independent gaps; shared tracker state would cross-contaminate]
// =============================================================================================
// @verifies AC-CL-SUB-017-SEQNUM-PER-SUBSCRIPTION
// @relation(AC-CL-SUB-017-SEQNUM-PER-SUBSCRIPTION, scope=function)
TEST_F(ClientRepublish, TwoConcurrentGapsRecoverIndependently)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);

  auto subA = fixture.create_subscription(50.0);
  ASSERT_TRUE(subA.is_good()) << to_string(subA.status_code());
  auto subB = fixture.create_subscription(50.0);
  ASSERT_TRUE(subB.is_good()) << to_string(subB.status_code());
  const std::uint32_t subIdA = subA.value();
  const std::uint32_t subIdB = subB.value();
  ASSERT_NE(subIdA, subIdB);

  // Inject a gap on BOTH Subscriptions in the same window.
  server.inject_sequence_gap(subIdA, /*skip=*/1);
  server.inject_sequence_gap(subIdB, /*skip=*/1);

  ASSERT_TRUE(wait_until(
    [&] { return capture->republish_count_for(subIdA) >= 1 && capture->republish_count_for(subIdB) >= 1; }))
    << "each Subscription's own gap must drive its own Republish (independent per-Subscription trackers)";

  // Each Sub's Republishes carry only its own id - no cross-contamination of tracker state.
  for (const auto& republish : capture->republishes_for(subIdA))
    EXPECT_EQ(republish.subscriptionId, subIdA);
  for (const auto& republish : capture->republishes_for(subIdB))
    EXPECT_EQ(republish.subscriptionId, subIdB);
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - SerialNotPipelined  (MisbehavingServer)
// The Republish driver is strictly serial: at most ONE Republish is outstanding at any time (Republish N+1 is
// issued only from within Republish N's response handler). A multi-message drain therefore never shows more
// than one request ahead of the responses delivered. [neg: no overlap of consecutive Republishes]
//
// This exercises the SubscriptionsPipeline Republish driver section 8.4.8 - the same driver the
// ReconnectionFSM RecoveringSubscriptions step reuses. The one-outstanding invariant is a driver property
// independent of what triggers the drain, so it is validated here on the reactive path.
// =============================================================================================
// @verifies CL-RECONN-004
// @relation(CL-RECONN-004, scope=function)
TEST_F(ClientRepublish, SerialNotPipelined)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 4;
  driver->recoverCount = 4;  // a four-step recovery, then a terminator: [2,3,4,5 recovered] + [6 terminator]
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // While the drain runs, sample the one-outstanding invariant: the number of Republish REQUESTS observed
  // never exceeds the number of responses answered by more than one. A pipelined driver would burst several
  // requests ahead of the responses.
  std::size_t maxOutstanding = 0;
  const auto sampleOutstanding = [&]
  {
    const std::size_t requests = capture->republish_count_for(subscriptionId);
    const std::size_t responses = driver->republishSeen.load();
    const std::size_t outstanding = requests >= responses ? requests - responses : 0;
    maxOutstanding = std::max(maxOutstanding, outstanding);
    return false;  // keep sampling until the drain completes
  };
  // Poll until the drain has issued all five requests (four recoveries + terminator), sampling as we go.
  wait_until(
    [&]
    {
      sampleOutstanding();
      return capture->republish_count_for(subscriptionId) >= 5;
    });
  sampleOutstanding();

  EXPECT_LE(maxOutstanding, 1u)
    << "the Republish driver is strictly serial: at most one Republish may be outstanding at a time";
  EXPECT_EQ(capture->republish_count_for(subscriptionId), 5u)
    << "a four-message gap drives exactly five Republishes (four recoveries + one terminator), not a burst";
}

// =============================================================================================
// Row - LoopAfterReconnectUntilBadMessageNotAvailable  (MisbehavingServer)
// The Republish driver loops in strict ascending sequence order from next-expected until the server returns
// the Bad_MessageNotAvailable terminator, then STOPS - it neither ends early (data loss) nor spins past the
// terminator. [neg: terminator handling; loop-exit]
//
// The reconnect RecoveringSubscriptions step reuses this exact driver (section 8.4.8); the loop/terminator
// logic is validated here on the reactive path (a real transport reconnect trigger needs the reconnect
// harness).
// =============================================================================================
// @verifies CL-RECONN-004
// @relation(CL-RECONN-004, scope=function)
TEST_F(ClientRepublish, LoopAfterReconnectUntilBadMessageNotAvailable)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 5;
  driver->recoverCount =
    5;  // recover seq 2..6, then Republish(7) hits the Bad_MessageNotAvailable terminator
  driver->terminatorStatus = ua::Status::BadMessageNotAvailable;
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // The loop recovers seq 2..6 and requests seq 7 (terminator): six Republishes total, ascending, then stop.
  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 6; }))
    << "the driver must loop until the Bad_MessageNotAvailable terminator (six Republishes for a 5-gap)";

  auto republishes = capture->republishes_for(subscriptionId);
  ASSERT_GE(republishes.size(), 6u);
  for (std::uint32_t index = 0; index < 6; ++index)
    EXPECT_EQ(republishes[index].sequenceNumber, 2u + index)
      << "Republish " << index << " must request the next ascending sequence number";

  // All five retained messages were recovered and dispatched in order.
  for (std::uint32_t seq = 2; seq <= 6; ++seq)
    EXPECT_TRUE(sink->contains_int32(GapDriver::recovered_value(seq)))
      << "recovered message seq " << seq << " must be dispatched";

  // STOP: no seventh (post-terminator) Republish, even after the pump keeps running.
  const std::size_t publishesAtTerminator = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= publishesAtTerminator + 4; }));
  EXPECT_EQ(capture->republish_count_for(subscriptionId), 6u)
    << "the driver must STOP at the terminator - no Republish after Bad_MessageNotAvailable";
}

// =============================================================================================
// Row - OtherServiceResultErrorSurfacedNoInfiniteLoop  (MisbehavingServer)
// A non-terminator Bad service result (e.g. Bad_InternalError) on a Republish ends the reactive drain
// immediately - it neither loops nor retries - leaving the Subscription registered and the Connection Active.
// [neg: non-terminator service error during recovery]
//
// REPORTED (reconnect-only surface): the matrix's "exactly one error surfaced to ClientObserver with
// source-tagged ErrorDetail + bounded retry count" is a RecoveringSubscriptions barrier property
// (finish_drain_terminal folds the worst status into the reconnect recover-step result; a reactive drain is
// not inRecovery, so it logs the ErrorDetail - error_handling.md - and ends without surfacing to a
// ClientObserver). This test pins the built reactive bound (the drain ends after exactly one failed
// Republish; no spin) and reports the ClientObserver surface as reconnect-harness-blocked.
// =============================================================================================
// @verifies CL-RECONN-004
// @relation(CL-RECONN-004, scope=function)
TEST_F(ClientRepublish, OtherServiceResultErrorSurfacedNoInfiniteLoop)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 1;
  driver->recoverCount = 0;  // recover nothing: the first Republish gets the non-terminator error
  driver->terminatorStatus = ua::Status::BadInternalError;
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // Exactly one Republish is issued and fails Bad_InternalError; the drain ends (republishing cleared) and
  // the one-shot gap does not re-arm, so no further Republish for the Subscription.
  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 1; }))
    << "the gap must drive a Republish";

  const std::size_t publishesAfterError = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= publishesAfterError + 5; }))
    << "let the pump run so a spinning/retrying driver would reveal extra Republishes";

  EXPECT_EQ(capture->republish_count_for(subscriptionId), 1u)
    << "a non-terminator Bad ends the reactive drain immediately: exactly one Republish, no retry/spin";
  EXPECT_EQ(fixture.subscription_count(), 1u)
    << "a non-terminator error (unlike Bad_SubscriptionIdInvalid) does not remove the Subscription";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a non-terminator Republish error must not fault the Connection";
}

// =============================================================================================
// Row - FallsBackToCreateOnBadSubscriptionIdInvalid  (MisbehavingServer)
// A Republish returning Bad_SubscriptionIdInvalid means the Subscription is gone server-side: the reactive
// driver REMOVES it (so a dead Subscription is not left inflating the pump), and does NOT keep Republishing a
// dead id. [neg: subscription gone server-side during recovery]
//
// REPORTED (reconnect-only recreate): the section 8.3 fallback that CREATES a fresh Subscription (+ re-adds
// monitored items) lives in the ReconnectionFSM session-CHANGED path, which needs a transport reconnect. This
// test pins the built reactive terminal (removal + no further Republish, and no CreateSubscription is issued)
// and reports the recreate-a-fresh-Subscription step as reconnect-harness-blocked.
// =============================================================================================
// @verifies CL-RECONN-004
// @verifies CL-RECONN-003
// @relation(CL-RECONN-003, CL-RECONN-004, scope=function)
TEST_F(ClientRepublish, FallsBackToCreateOnBadSubscriptionIdInvalid)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 1;
  driver->recoverCount = 0;  // the first Republish gets Bad_SubscriptionIdInvalid
  driver->terminatorStatus = ua::Status::BadSubscriptionIdInvalid;
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);
  const std::size_t createsBefore = capture->create_subscription_count();

  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 1; }))
    << "the gap must drive a Republish";
  ASSERT_TRUE(wait_until([&] { return fixture.subscription_count() == 0; }))
    << "a Republish returning Bad_SubscriptionIdInvalid must remove the gone Subscription";

  // No further Republish references the removed id, and (reactive path) no recreate CreateSubscription fires.
  const std::size_t republishesAtRemoval = capture->republish_count_for(subscriptionId);
  const std::size_t publishesAtRemoval = capture->publish_count();
  ASSERT_TRUE(wait_until([&] { return capture->publish_count() >= publishesAtRemoval + 4; }));
  EXPECT_EQ(capture->republish_count_for(subscriptionId), republishesAtRemoval)
    << "a removed Subscription must not keep being Republished";
  EXPECT_EQ(capture->create_subscription_count(), createsBefore)
    << "the reactive path does not recreate (the section 8.3 CreateSubscription fallback needs the reconnect "
       "FSM)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "the removal must not fault the Connection";
}

// =============================================================================================
// Row - PublishHeldDuringRepublishLoop  (MisbehavingServer)  [reconnect-harness-blocked; reactive pinned]
// CL-RECONN-007 requires the Publish pump to be HELD while a Republish loop drains during reconnect recovery,
// so an interleaved Publish cannot dequeue/overwrite the messages being recovered. That pump-hold is a
// RecoveringSubscriptions gate (section 8.3): the pump is stopped only during the reconnect recovery step.
//
// On the single-shot Connection's REACTIVE drain path there is no reconnect, so the pump is by design NOT
// held (section 8.4.5: a reactive gap drain runs concurrently with the pump). This test pins that built
// reactive reality - the pump keeps publishing across a multi-step reactive drain - and reports the
// reconnect-recovery pump-hold as blocked on a transport-reconnect harness.
// =============================================================================================
// @verifies CL-RECONN-007
// @relation(CL-RECONN-007, scope=function)
TEST_F(ClientRepublish, PublishHeldDuringRepublishLoop)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 3;
  driver->recoverCount = 3;
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  const std::size_t publishesAtGap = capture->publish_count();

  // The reactive drain runs (multiple Republishes) AND the pump keeps publishing concurrently - the reactive
  // path does not hold the pump (the reconnect-recovery hold is a separate section 8.3 gate, reported
  // blocked).
  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 2; }))
    << "the multi-step reactive drain must run";
  EXPECT_TRUE(wait_until([&] { return capture->publish_count() >= publishesAtGap + 2; }))
    << "REPORTED: the reactive pump is NOT held during a reactive drain (the CL-RECONN-007 pump-hold is a "
       "reconnect RecoveringSubscriptions gate - reconnect-harness-blocked)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - PublishResumesAfterTerminator  (MisbehavingServer)  [reconnect-harness-blocked; reactive pinned]
// CL-RECONN-007 requires the first normal Publish to resume PROMPTLY after the Republish loop's terminator,
// when the pump was HELD during reconnect recovery. That resume boundary presupposes the pump was held, which
// is a RecoveringSubscriptions gate (section 8.3) needing a transport reconnect.
//
// On the reactive path the pump is never held, so a "resume" cannot be observed; instead this pins the built
// reactive analog - after the drain terminates cleanly, the pump is healthy and a subsequent in-order
// notification is still delivered - and reports the reconnect-recovery resume gate as blocked.
// =============================================================================================
// @verifies CL-RECONN-007
// @relation(CL-RECONN-007, scope=function)
TEST_F(ClientRepublish, PublishResumesAfterTerminator)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  driver->gapSize = 1;
  driver->recoverCount = 1;  // recover seq 2, then terminate cleanly (Bad_MessageNotAvailable)
  install_gap_driver(server, driver);

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, capture, driver, sink);

  // Drain terminates cleanly (recovered value dispatched, Republish(3) terminator).
  ASSERT_TRUE(wait_until([&] { return sink->contains_int32(GapDriver::recovered_value(2)); }))
    << "the recovered message must be dispatched before the terminator";
  ASSERT_TRUE(wait_until([&] { return capture->republish_count_for(subscriptionId) >= 2; }))
    << "the drain must reach its terminator probe";

  // Reactive analog of "publish resumes": the pump keeps running and a fresh in-order value is delivered
  // after the terminator (the gapValue at seq 4 becomes in-order once the drain has advanced next-expected to
  // 4).
  EXPECT_TRUE(wait_until([&] { return sink->contains_int32(driver->gapValue); }))
    << "REPORTED: after the reactive drain terminator the pump stays healthy and delivers again (the "
       "CL-RECONN-007 held-pump resume boundary is a reconnect RecoveringSubscriptions gate - "
       "reconnect-harness-blocked)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// ---------------------------------------------------------------------------------------------
// SubscriptionObserver::on_publish_gap - the gap the pipeline already detects is now reported.
//
// The pipeline has always classified SequenceClass::Gap and started a Republish drain from it; the
// observer callback documenting that was never called by any production code. Only the pipeline can
// see a sequence discontinuity, so an application had no other way to learn one occurred.
//
// The driver makes the numbers exact rather than approximate: PRIME settles next-expected at 2, and
// the gap-revealing Publish carries 2 + gapSize. The callback must report precisely that pair.
// ---------------------------------------------------------------------------------------------

namespace
{

struct PublishGapCapture
{
  std::atomic<int> calls{0};
  std::atomic<std::uint32_t> subscriptionId{0};
  std::atomic<std::uint32_t> lostFrom{0};
  std::atomic<std::uint32_t> to{0};
};

class CapturingGapObserver : public ua::client::SubscriptionObserver
{
public:
  explicit CapturingGapObserver(std::shared_ptr<PublishGapCapture> capture) : mCapture(std::move(capture))
  {}

  void on_publish_gap(ua::IntegerId subscriptionId, std::uint32_t lostFrom, std::uint32_t to) override
  {
    mCapture->subscriptionId.store(subscriptionId);
    mCapture->lostFrom.store(lostFrom);
    mCapture->to.store(to);
    ++mCapture->calls;
  }

private:
  std::shared_ptr<PublishGapCapture> mCapture;
};

}  // namespace

TEST(ClientRepublishObserver, PublishGapIsReportedWithTheExactMissedRange)
{
  auto capture = std::make_shared<PublishGapCapture>();
  ua::client::detail::ObserverSlots slots;
  slots.subscription = std::make_shared<CapturingGapObserver>(capture);

  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server, slots};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto captureRequests = arm_request_capture(server);
  auto driver = std::make_shared<GapDriver>();
  install_gap_driver(server, driver);
  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t subscriptionId = prime_and_arm_gap(fixture, captureRequests, driver, sink);

  ASSERT_TRUE(wait_until([&] { return capture->calls.load() > 0; }))
    << "a sequence gap the pipeline acted on must be reported to the SubscriptionObserver";

  EXPECT_EQ(capture->subscriptionId.load(), subscriptionId)
    << "the gap must be attributed to the Subscription it happened on";
  EXPECT_EQ(capture->lostFrom.load(), 2u)
    << "lostFrom must be the first MISSED sequence number (next-expected at the time of the gap)";
  EXPECT_EQ(capture->to.load(), 2u + driver->gapSize)
    << "to must be the sequence number of the live Publish that revealed the gap";

  // One report per drain, not one per late Publish: the driver keeps publishing after the gap.
  EXPECT_EQ(capture->calls.load(), 1)
    << "a single discontinuity must be reported once, however many Publishes follow it";
}

// ---------------------------------------------------------------------------------------------
// Keep-alive cadence - the server side of the Subscription's publishing timer, observed through the same
// MisbehavingServer harness. A Subscription with NO MonitoredItems has nothing to notify, so every
// NotificationMessage it ever emits is a keep-alive (empty notificationData): the interval between the
// server's PublishResponses IS the keep-alive interval, and it is measurable without touching the response.
// ---------------------------------------------------------------------------------------------

namespace
{

// A read-only, timestamped record of the keep-alive PublishResponses the server produced for one
// Subscription. Written on the server channel strand, read by the test thread.
class KeepAliveWatch
{
public:
  void record()
  {
    std::lock_guard lock(mMutex);
    mKeepAlives.push_back(std::chrono::steady_clock::now());
  }

  std::size_t count() const
  {
    std::lock_guard lock(mMutex);
    return mKeepAlives.size();
  }

  // The time the keep-alive at @p index was emitted, or nullopt if that many have not been emitted.
  std::optional<std::chrono::steady_clock::time_point> at(std::size_t index) const
  {
    std::lock_guard lock(mMutex);
    if (index >= mKeepAlives.size())
      return std::nullopt;
    return mKeepAlives[index];
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::chrono::steady_clock::time_point> mKeepAlives;
};

// Installs a response mutator that only OBSERVES: it timestamps each keep-alive PublishResponse the server
// emits for the Subscription and edits nothing, so the cadence asserted on is the server's own.
std::shared_ptr<KeepAliveWatch> arm_keep_alive_watch(
  MisbehavingServer& server, const std::shared_ptr<std::atomic<std::uint32_t>>& subscriptionId)
{
  auto watch = std::make_shared<KeepAliveWatch>();
  server.set_response_mutator(
    [watch, subscriptionId](Response& response)
    {
      auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get());
      if (!publish || publish->subscription_id() != subscriptionId->load())
        return;
      if (publish->notification_message().notification_data().empty())
        watch->record();
    });
  return watch;
}

}  // namespace

// =============================================================================================
// Part 4 section 5.13.3 (UpdateSubscriptionParams) - when a ModifySubscription negotiates a keep-alive count
// smaller than the keep-alive counter currently standing, the server resets the keep-alive and lifetime
// counters, so the shortened interval governs from the NEXT publishing cycle.
//
// The plausible implementation stores the negotiated parameters and leaves the running counter alone. That
// server still reports the shortened interval back in revisedMaxKeepAliveCount and still keeps its keep-alive
// promise on every later cycle - it just serves out the whole OLD window once more first, which is exactly
// the silence a client shortens the keep-alive to close. Only the timing of the FIRST keep-alive after the
// modification separates the two.
// =============================================================================================
// @verifies AC-SVR-SUB-GEN-113-KEEPALIVE-SHORTENS
TEST(ClientRepublishKeepAlive, ShortenedKeepAliveIntervalAppliesFromTheNextCycle)
{
  MisbehavingServer server;
  MisbehavingSubscriptionFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto subId = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto watch = arm_keep_alive_watch(server, subId);

  // No MonitoredItem is created: with nothing to notify, every message this Subscription emits is a
  // keep-alive, so the keep-alive cadence is the only thing on the wire.
  auto subscription = fixture.create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  subId->store(subscriptionId);

  // The FIRST Message a Subscription emits is due at the end of its FIRST publishing cycle whatever the
  // keep-alive count says (Part 4 section 5.13.1.1 - AC-SVR-SUB-GEN-080 / -081: only the SECOND keep-alive
  // waits out the full count). That message is ~100 ms away and has nothing to do with the keep-alive WINDOW
  // this test is about, so it is consumed here, before the long window is established - otherwise it lands
  // inside the silence measured below and is misread as the window failing. Waiting for it is also the
  // positive control for the rest of the test: it proves this Subscription's keep-alives reach the watch at
  // all, so the silence asserted next is the server's and not a blind observer's.
  ASSERT_TRUE(wait_until([&] { return watch->count() > 0; }, 2000ms))
    << "the first-cycle keep-alive must arrive before a keep-alive WINDOW is observable at all";

  // ---- Establish a LONG keep-alive interval, and let the counter run well into it. ----
  auto widen = fixture.modify_subscription(subscriptionId,
    100.0,
    /*lifetimeCount=*/300,
    /*maxKeepAliveCount=*/100);
  ASSERT_TRUE(widen.is_good()) << to_string(widen.status_code());
  const double longIntervalMs = widen.value().revised_publishing_interval();
  const std::uint32_t longKeepAliveCount = widen.value().revised_max_keep_alive_count();
  const double longWindowMs = longIntervalMs * static_cast<double>(longKeepAliveCount);
  ASSERT_GE(longWindowMs, 5000.0)
    << "the obligation's antecedent is a long CURRENT keep-alive interval; the server revised it to "
    << longWindowMs << " ms, which is too short to tell a deferred shortening from a prompt one";

  // The long interval is genuinely running: with the first-cycle message already spent, the Subscription
  // stays silent through the first 1.5 s of the widened window, which also advances the keep-alive counter
  // (15 cycles at 100 ms) far past the count of 5 the shortening modify is about to ask for - the exact
  // antecedent SPEC-SVR-SUB-GEN-113 states.
  const std::size_t settled = watch->count();
  ASSERT_FALSE(wait_until([&] { return watch->count() > settled; }, 1500ms))
    << "a Subscription with a " << longWindowMs
    << " ms keep-alive interval must emit nothing during the first 1.5 s of it - otherwise the shortening "
       "below is not being applied to a long window at all";

  // ---- Shorten the keep-alive far below the counter now standing. ----
  const std::size_t baseline = watch->count();
  const auto shortenedAt = std::chrono::steady_clock::now();
  auto shorten = fixture.modify_subscription(subscriptionId,
    100.0,
    /*lifetimeCount=*/30,
    /*maxKeepAliveCount=*/5);
  ASSERT_TRUE(shorten.is_good()) << to_string(shorten.status_code());
  const double shortIntervalMs = shorten.value().revised_publishing_interval();
  const std::uint32_t shortKeepAliveCount = shorten.value().revised_max_keep_alive_count();
  const double shortWindowMs = shortIntervalMs * static_cast<double>(shortKeepAliveCount);
  ASSERT_LT(shortWindowMs, longWindowMs)
    << "the server must actually have accepted a SHORTER keep-alive interval (" << shortWindowMs << " ms vs "
    << longWindowMs << " ms), or there is no shortening to observe";
  ASSERT_EQ(capture->modify_subscription_count(), 2u)
    << "both modifications must have reached the server: the shortening is not a client-side no-op";

  // OBSERVATION, first half - the shortened interval applies from the next cycle.
  ASSERT_TRUE(wait_until([&] { return watch->count() > baseline; }, 2500ms))
    << "after shortening the keep-alive to " << shortWindowMs
    << " ms the server must emit a keep-alive within its new window, not after the old one";
  const auto firstAfterShorten = watch->at(baseline);
  ASSERT_TRUE(firstAfterShorten.has_value());
  const auto delayMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(*firstAfterShorten - shortenedAt).count();

  // OBSERVATION, second half - rather than waiting for the current (long) one to elapse.
  EXPECT_LT(static_cast<double>(delayMs), longWindowMs)
    << "the first keep-alive after the shortening arrived " << delayMs
    << " ms later: a server that leaves the standing keep-alive counter alone serves out the whole "
    << longWindowMs << " ms window before the shortened one takes effect";
  EXPECT_LT(delayMs, 2500)
    << "the shortened keep-alive window is " << shortWindowMs
    << " ms: the first keep-alive after the modification must land inside it, not a window later";

  // The shortened interval governs the following cycles too, not just one catch-up flush.
  EXPECT_TRUE(wait_until([&] { return watch->count() >= baseline + 3; }, 4000ms))
    << "the keep-alive cadence must CONTINUE at the shortened " << shortWindowMs
    << " ms interval, not revert to the long one after a single prompt message";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "shortening the keep-alive interval must not disturb the Connection";
}

// ---------------------------------------------------------------------------------------------
// Subscription transfer - the other end of the Republish contract. Republish reads the SUBSCRIPTION's
// retransmission queue, so the question "whose queue is it" is answerable only by moving the
// Subscription to a different Session and asking both Sessions for the same message.
//
// The harness below is deliberately NOT the MisbehavingSubscriptionFixture: TransferSubscriptions
// needs two activated Sessions and no response mutation at all, and it needs them on the
// Basic256Sha256 / SignAndEncrypt endpoint. Part 4 section 5.13.7.1 admits an ANONYMOUS transfer only when
// the two Sessions share an ApplicationUri AND the requesting channel is Sign or SignAndEncrypt, so
// both Sessions are opened from ONE `Client` (one ApplicationUri) on the secured endpoint. Anything
// weaker is refused with Bad_UserAccessDenied before the queue-migration code under test ever runs,
// which would make the whole test a study of the authorization guard instead.
// ---------------------------------------------------------------------------------------------

namespace
{

// Two activated Sessions of one client application, on two channels of the MisbehavingServer's
// SignAndEncrypt endpoint. Channels are declared before the Sessions they carry, so each Session is
// destroyed before the channel it lives on.
class TransferSessionPair
{
public:
  explicit TransferSessionPair(MisbehavingServer& server)
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
    openConfig.endpointUrl = server.endpoint_url_sign_encrypt();
    openConfig.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
    openConfig.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    openConfig.serverCertificate = server.server_certificate();
    openConfig.timeout = 5000ms;

    mOldChannel.emplace(mClient->core().open_channel_sync(openConfig));
    mOldSession.emplace(mOldChannel->create_session_sync({.sessionName = "ClientRepublishTransferOld"}));
    mOldSession->activate_sync();

    mNewChannel.emplace(mClient->core().open_channel_sync(openConfig));
    mNewSession.emplace(mNewChannel->create_session_sync({.sessionName = "ClientRepublishTransferNew"}));
    mNewSession->activate_sync();
  }

  ~TransferSessionPair()
  {
    if (mNewSession)
      (void)mNewSession->try_close_sync();
    mNewSession.reset();
    if (mNewChannel)
      (void)mNewChannel->try_close_sync();
    mNewChannel.reset();
    if (mOldSession)
      (void)mOldSession->try_close_sync();
    mOldSession.reset();
    if (mOldChannel)
      (void)mOldChannel->try_close_sync();
    mOldChannel.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  TransferSessionPair(const TransferSessionPair&) = delete;
  TransferSessionPair& operator=(const TransferSessionPair&) = delete;

  // The Session the Subscription is created on and transferred AWAY from.
  ua::client::Session& old_session()
  {
    return *mOldSession;
  }

  // The Session the Subscription is transferred TO.
  ua::client::Session& new_session()
  {
    return *mNewSession;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<ua::client::SecureChannel> mOldChannel;
  std::optional<ua::client::Session> mOldSession;
  std::optional<ua::client::SecureChannel> mNewChannel;
  std::optional<ua::client::Session> mNewSession;
};

}  // namespace

// =============================================================================================
// Part 4 section 5.13.1.1 - if a Subscription is transferred to another Session, the queued (unacknowledged)
// NotificationMessages for that Subscription move from the old Session to the new one.
//
// The same specification describes the retransmission queue as the SESSION's, which is exactly why
// the plausible implementation keeps the queue where it is and hands over only the Subscription. That
// server transfers cleanly, reports Good, and publishes normally afterwards - the loss surfaces only
// later, when the new Session's client detects a sequence gap and Republishes messages that still
// exist, on a Session that no longer owns the Subscription. The old Session retaining them is the
// same defect seen from the other side, so both halves are asserted: every accumulated message must
// be Republishable from the NEW Session and refused by the OLD one.
// =============================================================================================
// @verifies AC-SVR-SUB-GEN-053-QUEUE-FOLLOWS
TEST(ClientRepublishTransfer, QueuedNotificationMessagesMoveToTheNewSessionAndLeaveTheOldOne)
{
  MisbehavingServer server;
  TransferSessionPair sessions{server};

  // A node whose value genuinely changes, so several NotificationMessages accumulate instead of one
  // initial value followed by keep-alives (a keep-alive is not queued for retransmission and so could
  // never be Republished from either Session).
  const NodeId changingNode{VariableId::Server_ServerStatus_CurrentTime};
  const auto created =
    ua::test_helpers::create_subscription_with_monitored_item(sessions.old_session(), changingNode);
  const std::uint32_t subscriptionId = created.subscriptionId;
  ASSERT_NE(subscriptionId, 0u) << "the Subscription must exist before it can be transferred";

  const auto notificationBearing = [subscriptionId](const ua::PublishResponse& response)
  {
    if (response.subscription_id() != subscriptionId)
      return false;
    const auto* dataChange = ua::test_helpers::as_data_change(response);
    return dataChange != nullptr && !dataChange->monitored_items().empty();
  };

  // Accumulate. NOTHING is ever acknowledged, so every message received stays in the retransmission
  // queue and is still observable at the point the assertions run.
  std::vector<std::uint32_t> queued;
  for (int attempt = 0; attempt < 3; ++attempt)
  {
    auto response = ua::test_helpers::wait_for_publish(
      sessions.old_session(), notificationBearing, attempt == 0 ? 5000ms : 2000ms);
    if (!response)
      break;
    const std::uint32_t sequenceNumber = response->notification_message().sequence_number();
    if (std::find(queued.begin(), queued.end(), sequenceNumber) == queued.end())
      queued.push_back(sequenceNumber);
  }
  ASSERT_FALSE(queued.empty())
    << "no NotificationMessage accumulated on the old Session, so there is no queue to move and the "
       "obligation could only pass vacuously";

  // ---- Transfer the Subscription to the second Session. ----
  ua::TransferSubscriptionsRequest transferRequest;
  transferRequest.subscription_ids().push_back(subscriptionId);
  transferRequest.send_initial_values() = false;
  auto transfer =
    sessions.new_session().subscriptions().try_transfer_subscriptions_sync(std::move(transferRequest));
  ASSERT_TRUE(transfer.is_good()) << to_string(transfer.status_code());
  ASSERT_TRUE(transfer.value().response_header().service_result().is_good())
    << to_string(transfer.value().response_header().service_result());
  ASSERT_EQ(transfer.value().results().size(), 1u);
  ASSERT_TRUE(transfer.value().results()[0].status_code().is_good())
    << "the transfer itself must succeed before the queue can be said to follow it: "
    << to_string(transfer.value().results()[0].status_code());

  // The TransferResult states what moved: availableSequenceNumbers is the new owner's view of the
  // retransmission queue, so a server that left the messages behind reports an empty list here.
  const auto& movedSequenceNumbers = transfer.value().results()[0].available_sequence_numbers();
  ASSERT_FALSE(movedSequenceNumbers.empty())
    << "the TransferResult reports an empty availableSequenceNumbers: the queued NotificationMessages "
       "did not move with the Subscription";
  for (const std::uint32_t sequenceNumber : queued)
  {
    const bool moved = std::find(movedSequenceNumbers.begin(), movedSequenceNumbers.end(), sequenceNumber) !=
                       movedSequenceNumbers.end();
    EXPECT_TRUE(moved)
      << "sequence " << sequenceNumber
      << " was queued on the old Session but is absent from the transferred availableSequenceNumbers";
  }

  // ---- Half one: every queued message is retrievable from the NEW Session. ----
  for (const std::uint32_t sequenceNumber : queued)
  {
    ua::RepublishRequest republishRequest;
    republishRequest.subscription_id() = subscriptionId;
    republishRequest.retransmit_sequence_number() = sequenceNumber;
    auto republished = sessions.new_session().subscriptions().try_republish_sync(std::move(republishRequest));
    ASSERT_TRUE(republished.is_good())
      << "Republish of sequence " << sequenceNumber
      << " on the new Session failed: " << to_string(republished.status_code());
    EXPECT_TRUE(republished.value().response_header().service_result().is_good())
      << "Republish of sequence " << sequenceNumber << " on the new Session returned "
      << to_string(republished.value().response_header().service_result());
    EXPECT_EQ(republished.value().notification_message().sequence_number(), sequenceNumber)
      << "the new Session returned a different message than the one asked for";

    // The MESSAGE moved, not an empty shell bearing its sequence number.
    const ua::DataChangeNotification* recovered = nullptr;
    for (const auto& notification : republished.value().notification_message().notification_data())
    {
      if (const auto* candidate = dynamic_cast<const ua::DataChangeNotification*>(notification.get()))
      {
        recovered = candidate;
        break;
      }
    }
    ASSERT_NE(recovered, nullptr) << "the republished message for sequence " << sequenceNumber
                                  << " carries no DataChangeNotification: the queue entry did not "
                                     "survive the move intact";
    EXPECT_FALSE(recovered->monitored_items().empty())
      << "the republished message for sequence " << sequenceNumber
      << " carries an empty DataChangeNotification: the values it queued were lost in the move";
  }

  // ---- Half two: the OLD Session retains none of them. ----
  for (const std::uint32_t sequenceNumber : queued)
  {
    ua::RepublishRequest staleRequest;
    staleRequest.subscription_id() = subscriptionId;
    staleRequest.retransmit_sequence_number() = sequenceNumber;
    auto stale = sessions.old_session().subscriptions().try_republish_sync(std::move(staleRequest));
    if (stale.is_good())
    {
      EXPECT_EQ(stale.value().response_header().service_result(),
        ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
        << "the old Session must no longer serve Republish for a transferred Subscription, got "
        << to_string(stale.value().response_header().service_result());
      EXPECT_NE(stale.value().notification_message().sequence_number(), sequenceNumber)
        << "the old Session handed back sequence " << sequenceNumber
        << ", a message it gave up when the Subscription moved: the queue was copied, not moved";
    }
    else
    {
      EXPECT_EQ(stale.status_code(), ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
        << "the old Session must no longer serve Republish for a transferred Subscription, got "
        << to_string(stale.status_code());
    }
  }
}
