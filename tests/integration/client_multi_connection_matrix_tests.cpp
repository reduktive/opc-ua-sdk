// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMultiConnection and public reconnect-hint cluster of the client integration-test matrix (the
///        six `ClientMultiConnection.*` rows, traced to CL-MULTI-001/002/003). CONNECTION ISOLATION: two
///        `Connection`s made from ONE `Client` must share NO state - distinct Sessions +
///        authenticationTokens, per-Connection NamespaceTables, per-Connection Subscription sequence
///        trackers, and independent strands (one Connection backing off / closing must not touch the other).
///        The bug-hunt is therefore SHARED / STATIC state and cross-Connection coupling: a static token /
///        session, a global namespace table, a shared next-expected sequence counter, a shared strand or
///        blocking resource.
///
/// Harness: the sibling `client_diagnostics_matrix_tests.cpp` / `client_republish_matrix_tests.cpp` pattern
/// - a real `Client` bound to a `MisbehavingServer`'s crypto + trusted store over ephemeral TCP, an
/// activated Session wrapped into a started `ConnectionImpl`, then into the public tier-2
/// `ua::client::Connection` (via `ConnectionHandleFactory`). Here the fixture stands up TWO
/// MisbehavingServers on distinct ephemeral loopback ports (two genuine endpoints) and drives BOTH from ONE
/// Client on ONE shared thread pool - so any state a real product bug shared across Connections would show
/// up. `MultiConnectionClient` owns the pool + Client + both `ConnectionImpl`s and, on teardown, closes
/// every impl BEFORE draining the pool (so no strand-bound teardown post is orphaned).
///
/// KEY INVESTIGATION FINDINGS (the forensic isolation results this file pins):
///   1. DISTINCT SESSIONS + TOKENS. Each `create_session_sync` allocates an independent tier-0 Session; the
///      server assigns `authenticationToken = NodeId(1, Guid::create_and_generate())` per Session
///      (ua_server_session.cpp:249) - a random GUID, so two independent servers never collide. Rows 1/3
///      pin non-null + DISTINCT session ids and DISTINCT wire authenticationTokens, and that each server
///      only ever accepts its OWN Connection's token (a cross-pollinated token would be rejected, so both
///      reads succeeding is the second isolation layer). No shared/static token or session was found.
///   2. PER-CONNECTION NAMESPACETABLE. `NamespaceTable` is immutable/value-typed with NO static or
///      cross-Connection state (ua_namespace_table.h section one-per-Connection); `ConnectionImpl` bootstraps
///      its OWN snapshot from ITS server's NamespaceArray. Row 4 makes the two servers publish DIFFERENT
///      arrays (urn:multi:a@2 vs urn:multi:b@2) and pins that each Connection's `namespace_table()` maps
///      index 2 to its OWN uri and does NOT resolve the other's - a shared/global table is refuted.
///   3. PER-CONNECTION SEQUENCE TRACKER. Each `ConnectionImpl` owns its own SubscriptionsPipeline ->
///      SequenceTracker. Row 5 primes BOTH Connections' trackers to next-expected 2, then injects a
///      one-shot gap on A ONLY: A emits exactly one `Republish(2)` while B emits ZERO Republishes and keeps
///      acking its own stream - A's gap never leaks into B's next-expected (no shared counter).
///   4. INDEPENDENT STRANDS. Each `ConnectionImpl` has its OWN private strand off the SHARED executor. Row 2
///      closes A and shows B stays Active + serves a Read with no disconnect/close/error hook fanned to B's
///      observer; row 6 pins A stuck in `Reconnecting` (backoff cycles observable via a climbing reopen
///      count) while B completes N `read_value_async` round-trips within a bounded window. A shared strand /
///      shared blocking resource across Connections would stall B - which is exactly what falsifies
///      CL-MULTI-002.
///
/// CALIBRATIONS / FIXTURE LIMITATIONS:
///   - Row 4 makes the two servers differ by REWRITING each server's bootstrap `NamespaceArray` Read
///     response (the same response-replacement technique the diagnostics/republish siblings use), because
///     two vanilla MisbehavingServers publish identical NS0-only arrays and the fixture does not expose the
///     server executor needed to register a real custom namespace. The client-side path under test - read
///     NamespaceArray -> `NamespaceTable::create` -> per-Connection immutable snapshot -> `lookup_uri` /
///     `lookup_index` - is fully real; only the servers' wire output is shaped. The isolation property (no
///     shared client table) is entirely client-side and fully exercised.
///   - Row 6 drives A's reconnect with a SYNTHETIC failing reopen interface (posts `Bad_NotConnected`)
///   instead
///     of a real transport drop, so A provably backs off (retries forever, `maxAttempts` unset) without any
///     real second server teardown race. Keep-alive is disabled on A so ONLY the manual trigger drives the
///     FSM. The shared pool is sized to 4 threads so pool-sizing can never be mistaken for the strand
///     isolation the row actually tests (a SINGLE shared strand would still stall B regardless of thread
///     count).
///
/// Falsifiability: every row encodes its matrix `[neg: ...]` falsifier and asserts the exact observable.
/// Timing is ALWAYS bounded polling on an observable (a delivered ack / a republish count / a completion
/// counter / a climbing reopen count), never a fixed sleep.

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_observer_sink.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_client_configuration.h"
#include "ua_client_observers.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_counter.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_monitored_item_notification.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_reconnect_policy.h"
#include "ua_ref_structure.h"
#include "ua_request_header.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_result.h"
#include "ua_service_fault.h"
#include "ua_server_state.h"
#include "ua_session_authentication_token.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>
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
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::ObserverSlots;
using ua::client::detail::ReconnectWiring;

namespace
{

// A standard NS0 Variable present on every server and readable - the neutral probe every row reads.
const NodeId readNode{VariableId::Server_ServerStatus_State};

// Busy-wait until @p predicate holds or @p timeout elapses; returns the final predicate value. Polls on an
// observable (never a fixed sleep-then-assert).
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

// ---------------------------------------------------------------------------------------------
// A started tier-1/2 Connection: keeps the ConnectionImpl (for subscription-level ops + TestAccess) AND
// the public tier-2 Connection handle wrapping the SAME impl. Move-only via its members' defaults. Its
// impl is registered with the owning MultiConnectionClient, which closes + drains on teardown, so this has
// no destructor of its own (avoiding double-close / ordering pitfalls).
// ---------------------------------------------------------------------------------------------
struct ManagedConnection
{
  std::shared_ptr<ConnectionImpl> impl;
  std::optional<Connection> connection;
  VoidResult startStatus{};

  Connection& operator*()
  {
    return *connection;
  }

  Connection* operator->()
  {
    return &*connection;
  }
};

// ---------------------------------------------------------------------------------------------
// MultiConnectionClient: ONE Client on ONE shared thread pool, driving MANY Connections to (potentially
// different) MisbehavingServers. Bound to a crypto/trusted-store source (any server works - the None
// endpoints exchange no certificates). Owns every ConnectionImpl it builds and, on teardown, closes each
// gracefully BEFORE draining the pool.
// ---------------------------------------------------------------------------------------------
class MultiConnectionClient
{
public:
  explicit MultiConnectionClient(MisbehavingServer& cryptoSource)
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = cryptoSource.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig createConfig{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appConfig),
      .client = ClientConfig{}};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(createConfig),
      ua::client::ClientComponents{.crypto = cryptoSource.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));
  }

  ~MultiConnectionClient()
  {
    for (auto& impl : mImpls)
    {
      if (!impl)
        continue;
      std::promise<VoidResult> promise;
      auto future = promise.get_future();
      impl->close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
      (void)future.get();
    }
    mImpls.clear();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MultiConnectionClient(const MultiConnectionClient&) = delete;
  MultiConnectionClient& operator=(const MultiConnectionClient&) = delete;

  // Opens a channel + activated Session to @p server, builds a ConnectionImpl (optionally reconnect-wired
  // and/or observer-wired), runs the bootstrap, and wraps it into a public Connection handle.
  ManagedConnection connect(MisbehavingServer& server, std::string name,
    std::optional<ReconnectWiring> reconnect = std::nullopt, ObserverSlots observers = {})
  {
    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();

    ua::client::detail::ConnectionConfig connectionConfig;
    connectionConfig.observers = std::move(observers);
    auto impl = ConnectionImpl::create(mThreadPool.executor(),
      std::move(session),
      std::move(connectionConfig),
      Logger{},
      std::move(reconnect));
    mImpls.push_back(impl);

    ManagedConnection managed;
    managed.impl = impl;
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    managed.startStatus = future.get();
    managed.connection.emplace(ConnectionHandleFactory::make_connection(impl));
    return managed;
  }

  boost::asio::any_io_executor executor()
  {
    return mThreadPool.executor();
  }

  ReconnectWiring reconnect_to(
    MisbehavingServer& server, std::shared_ptr<std::atomic<int>> reopenCount, KeepAlivePolicy keepAlive)
  {
    ReconnectWiring wiring;
    wiring.reopenChannel = [client = &*mClient,
                             url = server.endpoint_url_none(),
                             reopenCount = std::move(reopenCount)](auto callback)
    {
      reopenCount->fetch_add(1, std::memory_order_acq_rel);
      client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
    };
    wiring.activateConfig = Session::ActivateConfig{};
    wiring.policy = ReconnectPolicy{};
    wiring.policy.backoff.base = 50ms;
    wiring.policy.backoff.max = 50ms;
    wiring.policy.backoff.jitterPct = 0.0;
    wiring.keepAlive = keepAlive;
    return wiring;
  }

private:
  boost::asio::thread_pool mThreadPool{4};
  std::optional<Client> mClient;
  std::vector<std::shared_ptr<ConnectionImpl>> mImpls;
};

// ---------------------------------------------------------------------------------------------
// Blocking helpers for the tier-1 ConnectionImpl subscription ops (row 5).
// ---------------------------------------------------------------------------------------------
Result<std::uint32_t> create_subscription(ConnectionImpl& connection, double publishingInterval)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_subscription_async(
    publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

Result<std::uint32_t> create_monitored_item(
  ConnectionImpl& connection, std::uint32_t subscriptionId, std::uint32_t clientHandle)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_monitored_item_async(
    subscriptionId,
    readNode,
    clientHandle,
    [](DataValue) {},
    [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

// ---------------------------------------------------------------------------------------------
// TokenCapture (row 3): records the authenticationToken of the first ReadRequest a server observes. A
// Session carries ONE token for its lifetime, so the first is representative. Populated on the server
// strand; read by the test thread.
// ---------------------------------------------------------------------------------------------
struct TokenCapture
{
  mutable std::mutex mutex;
  std::optional<ua::NodeId> token;

  void observe(const ua::Structure& request)
  {
    if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      if (!token)
        token = read->request_header().authentication_token();
    }
  }

  std::optional<ua::NodeId> get() const
  {
    std::lock_guard lock(mutex);
    return token;
  }
};

// ---------------------------------------------------------------------------------------------
// LifecycleObserver (row 2): counts the negative / lifecycle-change hooks that a cross-Connection teardown
// leak would fan onto an untouched Connection, plus on_connected (bootstrap) so a "0 fires" assertion is
// non-vacuous.
// ---------------------------------------------------------------------------------------------
class LifecycleObserver : public ua::client::ConnectionObserver
{
public:
  void on_connected(const Connection&) override
  {
    mConnected.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_disconnected(const Connection&, ua::StatusCode, std::shared_ptr<const ua::ErrorDetail>) override
  {
    mDisconnected.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_reconnecting(const Connection&, std::size_t, ReconnectCause) override
  {
    mReconnecting.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_closed(const Connection&) override
  {
    mClosed.fetch_add(1, std::memory_order_acq_rel);
  }

  void on_error_chain(
    const Connection&, ua::StatusCode, std::shared_ptr<const ua::ErrorDetail>, std::string_view) override
  {
    mErrorChain.fetch_add(1, std::memory_order_acq_rel);
  }

  int connected() const
  {
    return mConnected.load(std::memory_order_acquire);
  }

  int disturbances() const
  {
    return mDisconnected.load(std::memory_order_acquire) + mReconnecting.load(std::memory_order_acquire) +
           mClosed.load(std::memory_order_acquire) + mErrorChain.load(std::memory_order_acquire);
  }

private:
  std::atomic<int> mConnected{0};
  std::atomic<int> mDisconnected{0};
  std::atomic<int> mReconnecting{0};
  std::atomic<int> mClosed{0};
  std::atomic<int> mErrorChain{0};
};

class MaintenanceReconnectObserver : public ua::client::ConnectionObserver
{
public:
  void on_reconnecting(const Connection&, std::size_t, ReconnectCause cause) override
  {
    mSawServerShutdown.store(
      std::holds_alternative<ua::client::ServerShutdown>(cause), std::memory_order_release);
  }

  [[nodiscard]] bool saw_server_shutdown() const noexcept
  {
    return mSawServerShutdown.load(std::memory_order_acquire);
  }

private:
  std::atomic<bool> mSawServerShutdown{false};
};

// ---------------------------------------------------------------------------------------------
// Namespace-array rewrite (row 4): while armed, replace result 0 of the bootstrap ReadResponse with a
// NamespaceArray carrying @p uris. Preserve the remaining results because the production bootstrap reads
// NamespaceArray, ServerArray, and UrisVersion together.
// ---------------------------------------------------------------------------------------------
void install_namespace_array(
  MisbehavingServer& server, std::shared_ptr<std::atomic<bool>> armed, std::vector<std::string> uris)
{
  server.set_response_mutator(
    [armed = std::move(armed), uris = std::move(uris)](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire))
        return;
      auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
      if (read == nullptr || read->results().empty())
        return;
      ua::Array<ua::String> array;
      for (const auto& uri : uris)
        array.push_back(ua::String{uri});
      read->results()[0] = ua::DataValue{ua::Variant{std::move(array)}};
    });
}

// ---------------------------------------------------------------------------------------------
// Row-5 wire building blocks (mirroring client_republish_matrix_tests.cpp): shape a PublishResponse in
// place and synthesize a Republish terminator.
// ---------------------------------------------------------------------------------------------
void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

void set_available_sequence_numbers(ua::PublishResponse& publish)
{
  publish.available_sequence_numbers().clear();
  publish.available_sequence_numbers().push_back(
    ua::Counter{publish.notification_message().sequence_number()});
}

// Appends an EMPTY DataChangeNotification: makes the response notification-bearing (the tracker
// advances/acks) without delivering to any handle.
void append_empty_data_change(ua::PublishResponse& publish)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// Appends a DataChangeNotification carrying one MonitoredItemNotification for @p clientHandle.
void append_data_change(ua::PublishResponse& publish, std::uint32_t clientHandle, std::int32_t value)
{
  auto notification = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  ua::DataValue dataValue;
  dataValue.value() = ua::Variant{value};
  item.value() = std::move(dataValue);
  notification->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

std::shared_ptr<ua::Structure> make_republish_terminator(ua::Status status)
{
  auto fault = std::make_shared<ua::ServiceFault>();
  fault->response_header().service_result() = ua::StatusCode{status};
  return fault;
}

// ---------------------------------------------------------------------------------------------
// SeqDriver (row 5): a per-server response mutator that PRIMES a Subscription's tracker to next-expected 2
// (seq-1 InOrder -> ack 1), and, once flipped to GAP, fires ONE gap-revealing Publish (seq 3, skipping 2)
// so the client emits exactly one Republish(2), then reverts to a keep-alive. Any Republish that results is
// answered with a terminator to end the drain. A server left in PRIME (never flipped) acks its own stream
// and never gaps -> never republishes.
// ---------------------------------------------------------------------------------------------
struct SeqDriver
{
  std::atomic<std::uint32_t> subscriptionId{0};  // 0 = inert
  std::uint32_t clientHandle = 1;
  std::atomic<int> phase{0};  // 0 = PRIME, 1 = GAP
  std::atomic<bool> gapFired{false};

  void mutate(ua::Response& response)
  {
    const std::uint32_t subId = subscriptionId.load(std::memory_order_acquire);
    if (subId == 0)
      return;

    if (auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get()))
    {
      if (publish->subscription_id() != subId)
        return;
      publish->notification_message().notification_data().clear();
      if (phase.load(std::memory_order_acquire) == 0)
      {
        set_publish_sequence(*publish, 1);
        append_empty_data_change(*publish);
        set_available_sequence_numbers(*publish);
      }
      else if (!gapFired.exchange(true))
      {
        set_publish_sequence(*publish, 3);  // gap: skips the expected 2
        append_data_change(*publish, clientHandle, 9999);
        set_available_sequence_numbers(*publish);
      }
      else
      {
        set_publish_sequence(*publish, 2);  // post-gap keep-alive at pre-gap next-expected (no re-gap)
        set_available_sequence_numbers(*publish);
      }
      return;
    }

    // Only after the gap: end the reactive drain by terminating any Republish/ServiceFault. A PRIME-only
    // server never sends a Republish, so this never triggers there.
    if (!gapFired.load(std::memory_order_acquire))
      return;
    const bool isRepublish = dynamic_cast<ua::RepublishResponse*>(response.second.get()) != nullptr ||
                             dynamic_cast<ua::ServiceFault*>(response.second.get()) != nullptr;
    if (isRepublish)
      response.second = make_republish_terminator(ua::Status::BadMessageNotAvailable);
  }
};

// ---------------------------------------------------------------------------------------------
// WireCapture (rows 5): per-server observation of outgoing acks + Republish {subId, seq} in wire order,
// plus a raw PublishRequest count (to prove a Connection's pump is genuinely running).
// ---------------------------------------------------------------------------------------------
struct WireCapture
{
  mutable std::mutex mutex;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> acks;  // (subId, seq)
  std::vector<std::pair<std::uint32_t, std::uint32_t>> republishes;  // (subId, seq)
  std::size_t publishCount = 0;

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* publish = dynamic_cast<const ua::PublishRequest*>(&request))
    {
      ++publishCount;
      for (const auto& ack : publish->subscription_acknowledgements())
        acks.emplace_back(ack.subscription_id(), ack.sequence_number());
    }
    else if (const auto* republish = dynamic_cast<const ua::RepublishRequest*>(&request))
    {
      republishes.emplace_back(republish->subscription_id(), republish->retransmit_sequence_number());
    }
  }

  std::size_t publish_count() const
  {
    std::lock_guard lock(mutex);
    return publishCount;
  }

  std::size_t ack_count_for_seq(std::uint32_t subscriptionId, std::uint32_t sequenceNumber) const
  {
    std::lock_guard lock(mutex);
    std::size_t count = 0;
    for (const auto& ack : acks)
      if (ack.first == subscriptionId && ack.second == sequenceNumber)
        ++count;
    return count;
  }

  std::size_t republish_count_for(std::uint32_t subscriptionId) const
  {
    std::lock_guard lock(mutex);
    std::size_t count = 0;
    for (const auto& republish : republishes)
      if (republish.first == subscriptionId)
        ++count;
    return count;
  }
};

// Builds reconnect wiring whose reopen interface ALWAYS fails (synthetic `Bad_NotConnected`, posted to the
// executor to avoid re-entrancy). With `maxAttempts` unset the FSM retries forever, so the Connection sits
// in Reconnecting and @p reopenCount climbs (each increment == one backoff cycle). Keep-alive is disabled
// so ONLY the manual trigger drives the FSM.
ReconnectWiring make_failing_reconnect(
  boost::asio::any_io_executor executor, std::shared_ptr<std::atomic<int>> reopenCount)
{
  ReconnectWiring wiring;
  wiring.reopenChannel = [executor, reopenCount = std::move(reopenCount)](
                           std::function<void(Result<SecureChannel>)> callback)
  {
    reopenCount->fetch_add(1, std::memory_order_acq_rel);
    boost::asio::post(executor,
      [callback = std::move(callback)]() mutable
      { callback(Result<SecureChannel>{StatusCode{Status::BadNotConnected}}); });
  };
  wiring.activateConfig = Session::ActivateConfig{};
  ReconnectPolicy policy;
  policy.backoff.base = 50ms;
  policy.backoff.max = 50ms;
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;  // maxAttempts unset -> retry forever, stays Reconnecting
  wiring.keepAlive.interval = std::chrono::milliseconds{0};  // disable keep-alive
  return wiring;
}

std::size_t subscription_count(ConnectionImpl& connection)
{
  auto info = ConnectionImplTestAccess::pipeline_info(connection);
  return info ? info->subscriptionCount : 0;
}

}  // namespace

// =============================================================================================
// ClientMultiConnection.TwoConnectionsTwoEndpointsBothActiveDistinctSessions  (CL-MULTI-001)
// From ONE Client, connect to two distinct in-tree servers on different loopback ports. Both Connections
// report a non-null session_id() and the two ids DIFFER. Falsified if the second connect reuses/overwrites
// the first's session (shared-state regression) yielding null or equal ids.
// =============================================================================================
// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(ClientMultiConnection, TwoConnectionsTwoEndpointsBothActiveDistinctSessions)
{
  MisbehavingServer serverA;
  MisbehavingServer serverB;
  MultiConnectionClient client{serverA};

  auto connectionA = client.connect(serverA, "MULTI_A");
  auto connectionB = client.connect(serverB, "MULTI_B");
  ASSERT_TRUE(connectionA.startStatus.is_good())
    << "A bootstrap failed: 0x" << std::hex << connectionA.startStatus.status_code().as_uint32();
  ASSERT_TRUE(connectionB.startStatus.is_good())
    << "B bootstrap failed: 0x" << std::hex << connectionB.startStatus.status_code().as_uint32();

  EXPECT_EQ(connectionA->state(), ConnectionState::Active) << "A must be Active";
  EXPECT_EQ(connectionB->state(), ConnectionState::Active) << "B must be Active";

  auto sessionA = connectionA->session_id();
  auto sessionB = connectionB->session_id();
  ASSERT_TRUE(sessionA.is_good()) << "A must have a session id: 0x" << std::hex
                                  << sessionA.status_code().as_uint32();
  ASSERT_TRUE(sessionB.is_good()) << "B must have a session id: 0x" << std::hex
                                  << sessionB.status_code().as_uint32();
  EXPECT_FALSE(sessionA.value().is_null()) << "A's session id must be non-null";
  EXPECT_FALSE(sessionB.value().is_null()) << "B's session id must be non-null";
  EXPECT_NE(sessionA.value(), sessionB.value())
    << "two Connections must own DISTINCT Sessions - the second connect must not reuse/overwrite the first";
}

// =============================================================================================
// ClientMultiConnection.CloseOneConnectionLeavesOtherActive  (CL-MULTI-001)
// Two active Connections A and B from one Client; close A; then issue a Read on B. B's Read completes Good
// and B stays Active; closing A fires callbacks only for A. Falsified if closing A tears down B or fans a
// disconnect callback to B.
// [neg: cross-Connection teardown leak]
// =============================================================================================
// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(ClientMultiConnection, CloseOneConnectionLeavesOtherActive)
{
  MisbehavingServer serverA;
  MisbehavingServer serverB;
  MultiConnectionClient client{serverA};

  auto observerB = std::make_shared<LifecycleObserver>();
  auto connectionA = client.connect(serverA, "MULTI_CLOSE_A");
  auto connectionB =
    client.connect(serverB, "MULTI_CLOSE_B", std::nullopt, ObserverSlots{.connection = observerB});
  ASSERT_TRUE(connectionA.startStatus.is_good());
  ASSERT_TRUE(connectionB.startStatus.is_good());
  ASSERT_EQ(connectionB->state(), ConnectionState::Active);

  // Wiring proof (non-vacuity): B's observer received the bootstrap on_connected, so it genuinely delivers.
  ASSERT_TRUE(wait_until([&] { return observerB->connected() >= 1; }))
    << "B's observer must be wired (on_connected delivered during bootstrap)";

  // Close A gracefully.
  ASSERT_TRUE(connectionA->try_close_sync().is_good()) << "A must close cleanly";
  ASSERT_EQ(connectionA->state(), ConnectionState::Closed);

  // B must still be Active and serve a Read.
  auto readResult = connectionB->try_read_value_sync(readNode);
  ASSERT_TRUE(readResult.is_good()) << "B's Read must succeed after A is closed, got 0x" << std::hex
                                    << readResult.status_code().as_uint32();
  EXPECT_EQ(connectionB->state(), ConnectionState::Active) << "closing A must NOT change B's state";

  // No cross-Connection teardown leak: closing A must not fan ANY disconnect/reconnect/close/error hook to
  // B's observer.
  EXPECT_EQ(observerB->disturbances(), 0)
    << "closing A must NOT fan a disconnect/reconnect/close/error callback to Connection B";
}

// =============================================================================================
// ClientMultiConnection.EachConnectionCarriesDistinctAuthenticationToken  (CL-MULTI-003)
// Two Connections to two servers; each server records the authenticationToken on inbound service requests.
// Each server only ever sees its OWN Connection's token; neither server receives the other's token.
// Falsified if token cross-pollination occurs (server B receives A's token) - which the server would also
// reject.
// [neg: token cross-pollination]
// =============================================================================================
// @verifies CL-MULTI-003
// @relation(CL-MULTI-003, scope=function)
TEST(ClientMultiConnection, EachConnectionCarriesDistinctAuthenticationToken)
{
  MisbehavingServer serverA;
  MisbehavingServer serverB;
  MultiConnectionClient client{serverA};

  auto tokenA = std::make_shared<TokenCapture>();
  auto tokenB = std::make_shared<TokenCapture>();
  serverA.set_request_observer([tokenA](const ua::Structure& request) { tokenA->observe(request); });
  serverB.set_request_observer([tokenB](const ua::Structure& request) { tokenB->observe(request); });

  auto connectionA = client.connect(serverA, "MULTI_TOK_A");
  auto connectionB = client.connect(serverB, "MULTI_TOK_B");
  ASSERT_TRUE(connectionA.startStatus.is_good());
  ASSERT_TRUE(connectionB.startStatus.is_good());

  // Each Read carries THIS Connection's Session token; each server accepts its own token (a cross-pollinated
  // token would be rejected, so both Goods are the second isolation layer).
  ASSERT_TRUE(connectionA->try_read_value_sync(readNode).is_good())
    << "A's Read must be accepted by server A (its own token)";
  ASSERT_TRUE(connectionB->try_read_value_sync(readNode).is_good())
    << "B's Read must be accepted by server B (its own token)";

  ASSERT_TRUE(wait_until([&] { return tokenA->get().has_value() && tokenB->get().has_value(); }))
    << "each server must observe a ReadRequest carrying an authenticationToken";
  auto observedA = tokenA->get().value();
  auto observedB = tokenB->get().value();
  EXPECT_FALSE(observedA.is_null()) << "A's token must be non-null";
  EXPECT_FALSE(observedB.is_null()) << "B's token must be non-null";
  EXPECT_NE(observedA, observedB)
    << "each Connection must carry its OWN Session authenticationToken - no shared/static token, no "
       "cross-pollination between the two servers";
}

// =============================================================================================
// ClientMultiConnection.NamespaceTableIsPerConnection  (CL-MULTI-003)
// Server A publishes NamespaceArray with 'urn:multi:a' at index 2; server B publishes 'urn:multi:b' at
// index 2; connect to both. Connection A.namespace_table() maps index 2 -> 'urn:multi:a' and B maps 2 ->
// 'urn:multi:b'. Falsified if a shared client-wide table lets one server's mapping overwrite the other's
// (both read the same uri at index 2).
// [neg: shared namespace table]
//
// CALIBRATION: the two servers are made to publish DIFFERENT NamespaceArrays by rewriting each server's
// bootstrap NamespaceArray Read response (see the file header). The client-side per-Connection NamespaceTable
// bootstrap + snapshot path is fully real; the isolation property (no shared/global table) is client-side.
// =============================================================================================
// @verifies CL-MULTI-003
// @relation(CL-MULTI-003, scope=function)
TEST(ClientMultiConnection, NamespaceTableIsPerConnection)
{
  const std::string ns0{"http://opcfoundation.org/UA/"};
  const std::string uriA{"urn:multi:a"};
  const std::string uriB{"urn:multi:b"};

  MisbehavingServer serverA;
  MisbehavingServer serverB;

  // Arm the array rewrite BEFORE the bootstrap Read (the only Read before start completes).
  auto armedA = std::make_shared<std::atomic<bool>>(true);
  auto armedB = std::make_shared<std::atomic<bool>>(true);
  install_namespace_array(serverA, armedA, {ns0, "urn:multi:filler", uriA});
  install_namespace_array(serverB, armedB, {ns0, "urn:multi:filler", uriB});

  MultiConnectionClient client{serverA};
  auto connectionA = client.connect(serverA, "MULTI_NS_A");
  auto connectionB = client.connect(serverB, "MULTI_NS_B");
  armedA->store(false, std::memory_order_release);  // stop rewriting once bootstrap is done
  armedB->store(false, std::memory_order_release);
  ASSERT_TRUE(connectionA.startStatus.is_good())
    << "A bootstrap failed: 0x" << std::hex << connectionA.startStatus.status_code().as_uint32();
  ASSERT_TRUE(connectionB.startStatus.is_good())
    << "B bootstrap failed: 0x" << std::hex << connectionB.startStatus.status_code().as_uint32();

  auto tableA = connectionA->namespace_table();
  auto tableB = connectionB->namespace_table();
  ASSERT_NE(tableA, nullptr) << "A must have a bootstrapped NamespaceTable";
  ASSERT_NE(tableB, nullptr) << "B must have a bootstrapped NamespaceTable";
  EXPECT_NE(tableA.get(), tableB.get()) << "the two Connections must hold DISTINCT NamespaceTable snapshots";

  // Each Connection maps index 2 to ITS OWN server's uri.
  ASSERT_TRUE(tableA->lookup_uri(2).has_value()) << "A must have an index 2";
  ASSERT_TRUE(tableB->lookup_uri(2).has_value()) << "B must have an index 2";
  EXPECT_EQ(std::string{tableA->lookup_uri(2).value()}, uriA) << "A index 2 must be urn:multi:a";
  EXPECT_EQ(std::string{tableB->lookup_uri(2).value()}, uriB) << "B index 2 must be urn:multi:b";

  // No shared/global table: neither Connection resolves the OTHER server's uri.
  EXPECT_FALSE(tableA->lookup_index(uriB).has_value())
    << "A must NOT know server B's uri - a shared client-wide table is refuted";
  EXPECT_FALSE(tableB->lookup_index(uriA).has_value())
    << "B must NOT know server A's uri - a shared client-wide table is refuted";
  EXPECT_EQ(tableA->lookup_index(uriA).value_or(0xFFFF), 2u) << "A resolves its own uri to index 2";
  EXPECT_EQ(tableB->lookup_index(uriB).value_or(0xFFFF), 2u) << "B resolves its own uri to index 2";
}

// =============================================================================================
// ClientMultiConnection.SubscriptionSequenceStateIsPerConnection  (CL-MULTI-003)
// Create a subscription on each of two Connections; drive Publish notifications with independent sequence
// numbers on A and B. A's nextExpectedSequenceNumber advances only from A's Publish responses; B's from B's.
// Falsified if a shared sequence counter causes B's Publish to be rejected as an out-of-order gap (spurious
// Republish on B).
// [neg: shared nextExpectedSequenceNumber]
//
// Mechanism: BOTH Connections' trackers are primed to next-expected 2 (seq-1 InOrder -> ack 1). A one-shot
// gap is then injected on A ONLY (seq 3, skipping 2) -> A emits exactly one Republish(2). B stays in PRIME
// (keeps acking its own stream) and must emit ZERO Republishes: A's gap must not leak into B's tracker.
// =============================================================================================
// @verifies CL-MULTI-003
// @relation(CL-MULTI-003, scope=function)
TEST(ClientMultiConnection, SubscriptionSequenceStateIsPerConnection)
{
  MisbehavingServer serverA;
  MisbehavingServer serverB;
  MultiConnectionClient client{serverA};

  auto captureA = std::make_shared<WireCapture>();
  auto captureB = std::make_shared<WireCapture>();
  serverA.set_request_observer([captureA](const ua::Structure& request) { captureA->observe(request); });
  serverB.set_request_observer([captureB](const ua::Structure& request) { captureB->observe(request); });

  auto driverA = std::make_shared<SeqDriver>();
  auto driverB = std::make_shared<SeqDriver>();
  serverA.set_response_mutator([driverA](ua::Response& response) { driverA->mutate(response); });
  serverB.set_response_mutator([driverB](ua::Response& response) { driverB->mutate(response); });

  auto connectionA = client.connect(serverA, "MULTI_SEQ_A");
  auto connectionB = client.connect(serverB, "MULTI_SEQ_B");
  ASSERT_TRUE(connectionA.startStatus.is_good());
  ASSERT_TRUE(connectionB.startStatus.is_good());

  // A subscription + monitored item on each Connection (each has its OWN pipeline / SequenceTracker).
  auto subA = create_subscription(*connectionA.impl, 50.0);
  auto subB = create_subscription(*connectionB.impl, 50.0);
  ASSERT_TRUE(subA.is_good()) << "A CreateSubscription failed: 0x" << std::hex
                              << subA.status_code().as_uint32();
  ASSERT_TRUE(subB.is_good()) << "B CreateSubscription failed: 0x" << std::hex
                              << subB.status_code().as_uint32();
  driverA->subscriptionId.store(subA.value(), std::memory_order_release);
  driverB->subscriptionId.store(subB.value(), std::memory_order_release);
  ASSERT_TRUE(create_monitored_item(*connectionA.impl, subA.value(), driverA->clientHandle).is_good());
  ASSERT_TRUE(create_monitored_item(*connectionB.impl, subB.value(), driverB->clientHandle).is_good());

  // Per-Connection isolation of the pipeline itself: one Subscription each.
  EXPECT_EQ(subscription_count(*connectionA.impl), 1u) << "A must own exactly its own Subscription";
  EXPECT_EQ(subscription_count(*connectionB.impl), 1u) << "B must own exactly its own Subscription";

  // PRIME settles on BOTH: the seq-1 ack proves each tracker advanced to next-expected 2 independently.
  ASSERT_TRUE(wait_until([&] { return captureA->ack_count_for_seq(subA.value(), 1) >= 1; }))
    << "A's tracker must advance to next-expected 2 (seq-1 acked)";
  ASSERT_TRUE(wait_until([&] { return captureB->ack_count_for_seq(subB.value(), 1) >= 1; }))
    << "B's tracker must advance to next-expected 2 (seq-1 acked)";

  // Inject the gap on A ONLY.
  driverA->phase.store(1, std::memory_order_release);

  // A detects the gap and emits exactly one Republish(2).
  ASSERT_TRUE(wait_until([&] { return captureA->republish_count_for(subA.value()) >= 1; }))
    << "A's gap must drive a Republish on A";

  // Give B ample time to keep publishing past the point A republished, so the "no republish on B" assertion
  // is not vacuous: a SHARED counter would have made B's own in-order stream look like a gap by now.
  const std::size_t bPublishBaseline = captureB->publish_count();
  ASSERT_TRUE(wait_until([&] { return captureB->publish_count() >= bPublishBaseline + 4; }))
    << "B's Publish pump must keep running so the isolation assertion is meaningful";

  EXPECT_EQ(captureB->republish_count_for(subB.value()), 0u)
    << "B must NOT Republish - A's sequence gap must not leak into B's tracker (no shared next-expected)";
  EXPECT_GE(captureB->ack_count_for_seq(subB.value(), 1), 1u)
    << "B's tracker stays live and independent (it acked its own seq-1) throughout A's gap/drain";
}

// =============================================================================================
// ClientMultiConnection.OneConnectionBackingOffOtherServesCallsPromptly  (CL-MULTI-002)
// Connection A's server is made unreachable so A enters BackingOff with backoff; concurrently issue repeated
// read_async on Connection B (healthy server). State-based per the matrix: assert A is provably in
// Reconnecting/backing off (a climbing reopen count == backoff cycles) AND B completes N read_async
// round-trips during that window. A shared-strand regression makes B's reads not complete at all while A
// backs off.
// [neg: one Connection reconnecting must not block another]
// =============================================================================================
// @verifies CL-MULTI-002
// @relation(CL-MULTI-002, scope=function)
TEST(ClientMultiConnection, OneConnectionBackingOffOtherServesCallsPromptly)
{
  MisbehavingServer serverA;
  MisbehavingServer serverB;
  MultiConnectionClient client{serverA};

  // B: a healthy, single-shot Connection.
  auto connectionB = client.connect(serverB, "MULTI_BACKOFF_B");
  ASSERT_TRUE(connectionB.startStatus.is_good());
  ASSERT_EQ(connectionB->state(), ConnectionState::Active);
  ASSERT_TRUE(connectionB->try_read_value_sync(readNode).is_good()) << "baseline B Read must succeed";

  // A: reconnect-wired with a reopen interface that ALWAYS fails -> A gets stuck backing off.
  auto reopenCount = std::make_shared<std::atomic<int>>(0);
  auto connectionA =
    client.connect(serverA, "MULTI_BACKOFF_A", make_failing_reconnect(client.executor(), reopenCount));
  ASSERT_TRUE(connectionA.startStatus.is_good());
  ASSERT_EQ(connectionA->state(), ConnectionState::Active);

  // Drive A into a never-completing reconnect; it must remain in Reconnecting and genuinely BACK OFF
  // (reopen invoked >= 2 == it retried after at least one backoff cycle).
  connectionA.impl->trigger_reconnect_async();
  ASSERT_TRUE(wait_until(
    [&]
    {
      auto info = connectionA.impl->info();
      return info && info->state == ConnectionState::Reconnecting &&
             reopenCount->load(std::memory_order_acquire) >= 2;
    }))
    << "A must be provably backing off (Reconnecting + repeated failed reopen attempts)";

  // WHILE A backs off, B must complete N read_value_async round-trips PROMPTLY. Async (not the blocking
  // sync form) so a shared-strand regression fails cleanly with a bounded wait rather than hanging the test
  // thread forever.
  constexpr int reads = 5;
  auto completed = std::make_shared<std::atomic<int>>(0);
  auto allGood = std::make_shared<std::atomic<bool>>(true);
  for (int i = 0; i < reads; ++i)
  {
    connectionB->read_value_async(readNode,
      [completed, allGood](Result<DataValue> result)
      {
        if (result.is_bad())
          allGood->store(false, std::memory_order_release);
        completed->fetch_add(1, std::memory_order_acq_rel);
      });
  }

  ASSERT_TRUE(wait_until([&] { return completed->load(std::memory_order_acquire) >= reads; }, 4000ms))
    << "Connection B must keep serving Reads while Connection A backs off - a shared strand across "
       "Connections would stall B (only "
    << completed->load() << " of " << reads << " completed)";
  EXPECT_TRUE(allGood->load(std::memory_order_acquire)) << "every B Read during A's backoff must be Good";

  // A is STILL backing off (independent, not recovered) - the isolation held throughout B's calls.
  auto infoA = connectionA.impl->info();
  ASSERT_NE(infoA, nullptr);
  EXPECT_EQ(infoA->state, ConnectionState::Reconnecting)
    << "A must remain in its backoff loop (unreachable server) - proving B's progress was independent";
  EXPECT_GE(reopenCount->load(std::memory_order_acquire), 2)
    << "A must have kept retrying (backing off) across B's read window";
}

// =============================================================================================
// EstimatedReturnTime.ReconnectHonoursFutureValue  (CL-BASE-005)
//
// Highest production tier: the real server response is the stimulus and the public ConnectionObserver +
// public Connection state are the observations. ConnectionImpl is used only by the fixture to construct the
// public handle; no TestAccess hook drives or observes the behavior.
//
// The server's final responsive keep-alive answer reports SHUTDOWN, ServiceLevel=0, and a far-future
// EstimatedReturnTime. The public observer must see a ServerShutdown reconnect while the channel-reopen
// effect remains at zero: the FSM is parked before OPN. Ignoring the hint increments reopenCount before the
// observer/state assertion settles.
// [neg: future EstimatedReturnTime must hold the first reconnect OPN]
// @verifies CL-BASE-005
// @verifies CL-RECONN-009
// @verifies CL-SESS-025
// @relation(CL-BASE-005, CL-RECONN-009, CL-SESS-025, scope=function)
TEST(EstimatedReturnTime, ReconnectHonoursFutureValue)
{
  MisbehavingServer server;
  MultiConnectionClient client{server};

  auto armed = std::make_shared<std::atomic<bool>>(false);
  const ua::DateTime returnTime{
    ua::DateTime::now().value() + std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(1h)};
  server.set_response_mutator(
    [armed, returnTime](ua::Response& response)
    {
      if (!armed->load(std::memory_order_acquire) ||
          dynamic_cast<ua::ReadResponse*>(response.second.get()) == nullptr)
      {
        return;
      }
      auto maintenance = std::make_shared<ua::ReadResponse>();
      maintenance->results().push_back(
        ua::DataValue{ua::Variant{static_cast<std::int32_t>(ua::ServerState::Shutdown)}});
      maintenance->results().push_back(ua::DataValue{ua::Variant{std::uint8_t{0}}});
      maintenance->results().push_back(ua::DataValue{ua::Variant{returnTime}});
      response.second = std::move(maintenance);
    });

  auto observer = std::make_shared<MaintenanceReconnectObserver>();
  auto reopenCount = std::make_shared<std::atomic<int>>(0);
  auto wiring =
    client.reconnect_to(server, reopenCount, KeepAlivePolicy{.interval = 20ms, .missedBeforeReconnect = 1});
  auto connection =
    client.connect(server, "ESTIMATED_RETURN_TIME", std::move(wiring), ObserverSlots{.connection = observer});
  ASSERT_TRUE(connection.startStatus.is_good());
  ASSERT_EQ(connection->state(), ConnectionState::Active);

  armed->store(true, std::memory_order_release);
  ASSERT_TRUE(wait_until([&] { return observer->saw_server_shutdown(); }))
    << "the public observer must see the maintenance answer drive a ServerShutdown reconnect";

  EXPECT_EQ(connection->state(), ConnectionState::Reconnecting);
  EXPECT_EQ(reopenCount->load(std::memory_order_acquire), 0)
    << "the future EstimatedReturnTime must defer the first channel-open attempt";
}
