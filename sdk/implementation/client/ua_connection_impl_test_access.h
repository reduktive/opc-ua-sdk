// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_IMPL_TEST_ACCESS_H
#define UA_CONNECTION_IMPL_TEST_ACCESS_H

/// @file
/// @brief Test-only access to @ref ua::client::detail::ConnectionImpl strand-private state and the
///        reconnect primitives, for the ConnectionImpl unit suite (see the design specification).
///
/// A friend of @ref ua::client::detail::ConnectionImpl. Adds NO public members to ConnectionImpl for
/// testing: it reaches the private injecting factory, the strand-only state, and the reconnect FSM
/// primitives directly. Every strand-only read is delivered via a strand hop the caller waits for (never a
/// raw cross-strand read), so a snapshot reflects a consistent point on the orchestrator's strand.

#include "ua_address_space_cache_test_access.h"
#include "ua_array.h"
#include "ua_client_subscriptions_pipeline.h"
#include "ua_client_subscriptions_pipeline_test_access.h"  // has_subscription_event_loss_callback (CL-AC-003 wiring pin)
#include "ua_connection_impl.h"
#include "ua_reconnection_fsm.h"
#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_reconnect_types.h"  // ua::client::ReconnectCause / ReconnectOutcome / TransportDropped (notify interfaces)
#include "ua_result.h"
#include "ua_string.h"
#include "ua_sync_wait.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client::detail
{

namespace connection_test_access
{
/// The `done` callback of @ref ConnectionImplTestAccess::wait_for: it receives the value, or nothing.
template<class T>
struct DoneOf
{
  using type = std::function<void(T)>;
};

template<>
struct DoneOf<void>
{
  using type = std::function<void()>;
};
}  // namespace connection_test_access

/// Friend accessor for @ref ConnectionImpl unit tests.
class ConnectionImplTestAccess
{
public:
  /// A consistent strand-snapshot of the orchestrator's reconnect-relevant private state.
  struct Snapshot
  {
    ConnectionState state = ConnectionState::Connecting;
    std::shared_ptr<ChannelOps> pendingChannel;
    std::shared_ptr<SessionOps> pendingSession;
    std::uint64_t reconnectAttemptEpoch = 0;
    std::size_t browseContinuationPoints = 0;
    std::size_t browseContinuationQueue = 0;
    std::size_t queryContinuationPoints = 0;
    std::size_t queryContinuationQueue = 0;
    std::size_t historyContinuationPoints = 0;
    std::size_t historyContinuationQueue = 0;
  };

  /// Builds a ConnectionImpl with the tier-0 interface + reopen injected directly (fakes). The trailing
  /// @p serverCertValidator injects the W5 server-cert re-validation interface (empty by default) so a test can
  /// script a Good / Bad verdict and drive @ref ConnectionImpl::revalidate_server_cert_async.
  [[nodiscard]] static std::shared_ptr<ConnectionImpl> create_with_ops(boost::asio::any_io_executor executor,
    std::shared_ptr<SessionOps> sessionOps, ConnectionConfig config, ua::Logger logger,
    ReopenChannelOps reopen, ua::client::Session::ActivateConfig activateConfig,
    ua::client::ReconnectPolicy policy, KeepAlivePolicy keepAlivePolicy = {},
    ObserverSlots clientObserverDefaults = {}, bool enableRedundancy = false,
    ua::client::RedundancyPolicy redundancyPolicy = {}, RedundancyDiscoveryProvider redundancyDiscovery = {},
    ServerCertValidator serverCertValidator = {})
  {
    return ConnectionImpl::create_with_ops(std::move(executor),
      std::move(sessionOps),
      std::move(config),
      std::move(logger),
      std::move(reopen),
      std::move(activateConfig),
      std::move(policy),
      std::move(keepAlivePolicy),
      std::move(clientObserverDefaults),
      enableRedundancy,
      std::move(redundancyPolicy),
      std::move(redundancyDiscovery),
      std::move(serverCertValidator));
  }

  /// Forwards @ref ConnectionImpl::revalidate_server_cert_async (public, but exposed here so the W5
  /// revalidate suite can drive it uniformly through the test-access facade alongside create_with_ops).
  static void revalidate_server_cert_async(ConnectionImpl& connection,
    std::function<void(ua::VoidResult)> callback, bool ownCertificateChanged = false,
    bool revalidateServerCertificate = true)
  {
    connection.revalidate_server_cert_async(
      ownCertificateChanged, revalidateServerCertificate, std::move(callback));
  }

  /// The eagerly-constructed own-strand redundancy engine (reconnect-wired only; null on a single-shot
  /// Connection). Write-once, so a plain synchronous read.
  [[nodiscard]] static std::shared_ptr<detail::RedundancyManagerImpl> redundancy_manager(
    ConnectionImpl& connection)
  {
    return connection.mRedundancyManager;
  }

  /// The concrete tier-1 redundancy host shim @p connection owns (null on a single-shot Connection).
  [[nodiscard]] static std::shared_ptr<RedundancyManagerConnectionHost> redundancy_host(
    ConnectionImpl& connection)
  {
    return connection.mRedundancyHost;
  }

  /// Strand-hopped snapshot of the orchestrator's private reconnect state (blocks on a runner thread).
  // NOT [[nodiscard]]: this helper is used both as a value-getter AND as a bare strand-drain barrier (call
  // for its round-trip side effect where a test only needs "all previously-posted strand work has settled"),
  // so flagging a discarded return would false-positive on the legitimate barrier sites.
  static Snapshot snapshot(ConnectionImpl& connection)
  {
    return on_strand(connection,
      [&connection]
      {
        return Snapshot{connection.mState,
          connection.mPendingChannel,
          connection.mPendingSession,
          connection.mReconnectAttemptEpoch,
          connection.mBrowseContinuationPoints.open_count(),
          connection.mBrowseContinuationPoints.queued_count(),
          connection.mQueryContinuationPoints.open_count(),
          connection.mQueryContinuationPoints.queued_count(),
          connection.mHistoryContinuationPoints.open_count(),
          connection.mHistoryContinuationPoints.queued_count()};
      });
  }

  static void configure_browse_continuation_tracker(
    ConnectionImpl& connection, std::size_t queueLimit, std::uint16_t limit)
  {
    on_strand(connection,
      [&connection, queueLimit, limit]
      {
        connection.mBrowseContinuationPoints = OpenContinuationPointTracker{queueLimit};
        connection.mBrowseContinuationPoints.set_limit(limit);
      });
  }

  /// True when two ConnectionImpl instances own different serialization domains.
  /// This compares the private strands directly without exposing them through a
  /// production API.
  [[nodiscard]] static bool have_distinct_strands(
    const ConnectionImpl& first, const ConnectionImpl& second) noexcept
  {
    return first.mStrand != second.mStrand;
  }

  /// Drives the reconnect NamespaceArray re-read (@ref ConnectionImpl::apply_namespace_read) directly on the
  /// connection strand  -  the exact method the reconnect re-read invokes  -  with a scripted
  /// `Server.NamespaceArray` ReadResponse, and barriers on it. Swaps the published NamespaceTable snapshot
  /// for one built from @p uris with a bumped generation, letting a test deterministically simulate a
  /// per-Session index renumbering (CL-ADDRSP-004 / CL-SESS-028) without orchestrating a full reconnect FSM.
  /// Returns the method's VoidResult.
  static ua::VoidResult apply_namespace_read(ConnectionImpl& connection, std::vector<std::string> uris,
    std::vector<std::string> serverUris = {"urn:test:connection"}, bool replaceServerTable = true)
  {
    ua::Array<ua::String> array;
    for (auto& uri : uris)
    {
      array.push_back(ua::String{uri});
    }
    ua::ReadResponse response;
    response.results().push_back(ua::DataValue{ua::Variant{std::move(array)}});
    ua::Array<ua::String> serverArray;
    for (auto& uri : serverUris)
    {
      serverArray.push_back(ua::String{uri});
    }
    response.results().push_back(ua::DataValue{ua::Variant{std::move(serverArray)}});
    return on_strand(connection,
      [&connection, response = std::move(response), replaceServerTable]() mutable
      {
        return connection.apply_namespace_read(
          ua::Result<ua::ReadResponse>{std::move(response)}, replaceServerTable);
      });
  }

  /// Invokes the FREE-THREADED @ref ConnectionImpl::semantic_change_cache accessor directly on the CALLING
  /// thread (no strand hop). Lets a test post this onto the bare Connection executor  -  i.e. OFF the
  /// connection strand  -  to prove the accessor is free-threaded (does not assert running-on-strand) and
  /// hands back a non-null cache (C1: the sole real caller reaches it off-strand via
  /// `Connection::data_access()`).
  [[nodiscard]] static std::shared_ptr<SemanticChangeCache> semantic_change_cache(ConnectionImpl& connection)
  {
    return connection.semantic_change_cache();
  }

  /// Invokes the FREE-THREADED @ref ConnectionImpl::address_space_cache accessor directly on the CALLING
  /// thread (no strand hop). Lets a test post this onto the bare Connection executor  -  i.e. OFF the
  /// connection strand  -  to prove the accessor is free-threaded (does not assert running-on-strand) and
  /// hands back a non-null, idempotent cache (W8a: the W8b model-change router reaches it off-strand from the
  /// executor).
  [[nodiscard]] static std::shared_ptr<AddressSpaceCache> address_space_cache(ConnectionImpl& connection)
  {
    return connection.address_space_cache();
  }

  /// The number of alias entries the per-Connection @ref AddressSpaceCache currently holds, read ON the
  /// connection strand (the cache is caller-on-strand; the connection strand is where the register / read /
  /// session-change wiring mutates it, so a raw cross-thread read would race). Constructs the cache if the
  /// wiring never has (an empty count). Lets the Slice V1 wiring suite assert install-on-register / LRU-evict
  /// / clear-on-session-change without reaching into strand-private state cross-thread.
  [[nodiscard]] static std::size_t address_space_cache_alias_count(ConnectionImpl& connection)
  {
    return on_strand(connection,
      [&connection] { return AddressSpaceCacheTestAccess::alias_count(*connection.address_space_cache()); });
  }

  /// The alias cache's current session generation (bumped by `on_session_changed_async`), read on the
  /// connection strand. Lets the CL-VIEW-011 wiring test prove a session-CHANGED reconnect bumped it.
  [[nodiscard]] static std::uint64_t address_space_cache_session_generation(ConnectionImpl& connection)
  {
    return on_strand(connection,
      [&connection]
      { return AddressSpaceCacheTestAccess::session_generation(*connection.address_space_cache()); });
  }

  /// Reads the free-threaded Session identity generation used to bind Browse continuation points. The token
  /// is atomic because BrowseCursor observes it from its own strand while ConnectionImpl publishes fresh
  /// Session installation from the connection strand.
  [[nodiscard]] static std::uint64_t browse_session_generation(const ConnectionImpl& connection) noexcept
  {
    return connection.mSessionGeneration->load(std::memory_order_relaxed);
  }

  /// Test precondition setter for the free-threaded Browse Session generation token.
  static void set_browse_session_generation(ConnectionImpl& connection, std::uint64_t generation) noexcept
  {
    connection.mSessionGeneration->store(generation, std::memory_order_relaxed);
  }

  /// The cached alias entry for @p node in the per-Connection @ref AddressSpaceCache (or `nullopt` on a
  /// miss), read on the connection strand. Lets the CL-VIEW-010 install test assert the exact registered
  /// handle stored for a user NodeId.
  [[nodiscard]] static std::optional<AliasEntry> address_space_cache_alias(
    ConnectionImpl& connection, ua::NodeId node)
  {
    return on_strand(connection,
      [&connection, node = std::move(node)]
      { return AddressSpaceCacheTestAccess::alias(*connection.address_space_cache(), node); });
  }

  /// Drives the Session-scoped alias-cache clear (CL-VIEW-011) directly on the connection strand  -  the
  /// exact method the reconnect session-CHANGED branch (`reconnect_recover_subscriptions`) invokes  -  and
  /// barriers on it. Lets an INTEGRATION test simulate a session change on a single-shot Connection (which
  /// owns no reconnect FSM) and assert, end-to-end over the real wire, that a subsequent request falls back
  /// to the RAW NodeId. Mirrors the production flags (serverIdentityPreserved=true /
  /// namespaceArrayChanged=false); the alias-clear + generation-bump is unconditional in
  /// `on_session_changed_async` regardless of those flags.
  static void drive_address_space_cache_session_changed(ConnectionImpl& connection)
  {
    // The accessor is free-threaded and `on_session_changed_async` self-marshals onto the connection strand,
    // so this is driven off-strand exactly as the W8b model-change router reaches the cache.
    wait_for<void>(connection,
      [&connection](std::function<void()> done)
      {
        connection.address_space_cache()->on_session_changed_async(
          /*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/false, std::move(done));
      });
  }

  /// The bare (non-strand) executor the orchestrator was created over. Posting a task onto it runs OFF the
  /// connection strand, so a test can reproduce the off-strand reach of the DataAccess handle-build
  /// completion.
  [[nodiscard]] static boost::asio::any_io_executor executor(ConnectionImpl& connection)
  {
    return connection.mExecutor;
  }

  /// The per-Connection EventSubscriber to observer/cache routing router (Slice W8b). Lets the W8b routing
  /// suite drive @ref EventRouter::handle_model_event / handle_semantic_event / handle_audit_event with a
  /// scripted
  /// @ref ua::client::EventNotification on the REAL decode + route code path (the router re-marshals onto the
  /// connection strand internally), and call @ref EventRouter::start to exercise the eager subscribe.
  [[nodiscard]] static std::shared_ptr<EventRouter> event_router(ConnectionImpl& connection)
  {
    return connection.mEventRouter;
  }

  /// Drives @ref ConnectionImpl::on_first_session_active on the strand (fires the first-active fan-out AND
  /// start()s the event router), then barriers on the strand so the subscribe has been posted.
  static void start_event_routing(ConnectionImpl& connection)
  {
    drive_first_session_active(connection);
    snapshot(connection);  // strand-drain barrier
  }

  /// Publishes @p endpoint into the orchestrator's cross-strand endpoint snapshot (F1/J45), so a W4 test can
  /// set the identity the tier-2 redundancy host reads (`current_endpoint` / `current_application_uri`)
  /// without a real connect path. Atomic store  -  safe from any thread.
  static void set_endpoint_snapshot(ConnectionImpl& connection, ua::EndpointDescription endpoint)
  {
    connection.mEndpointSnapshot.store(std::make_shared<const ua::EndpointDescription>(std::move(endpoint)));
  }

  /// The currently-installed (non-pending) tier-0 session interface (strand-hopped snapshot).
  [[nodiscard]] static std::shared_ptr<SessionOps> session_ops(ConnectionImpl& connection)
  {
    return on_strand(connection, [&connection] { return connection.mSessionOps; });
  }

  /// The orchestrator's SubscriptionsPipeline info snapshot (or null if it has no pipeline).
  [[nodiscard]] static std::shared_ptr<const PipelineInfo> pipeline_info(ConnectionImpl& connection)
  {
    return connection.mPipeline ? connection.mPipeline->info() : nullptr;
  }

  /// Whether the pipeline `wire_pipeline_and_ops` built actually received the Finding-2 / CL-AC-003
  /// event-loss interface (the lossy-gap  to  A&C resync signal). A production regression that used the 5-arg
  /// `create` would leave it empty, silently disabling the resync in a real client while injected-lambda unit
  /// tests still pass  -  so this pin exercises the REAL construction path (`create_with_ops`  to
  /// `wire_pipeline_and_ops`), not an injected callback. False when the orchestrator has no pipeline.
  [[nodiscard]] static bool pipeline_has_event_loss_callback(ConnectionImpl& connection)
  {
    return connection.mPipeline &&
           SubscriptionsPipelineTestAccess::has_subscription_event_loss_callback(*connection.mPipeline);
  }

  /// The pipeline's CALLBACK-FREE recovery descriptors (id + retained replay-record publishing interval +
  /// monitored items), strand-hopped via @ref SubscriptionsPipeline::recovery_descriptors_async. Empty when
  /// the orchestrator has no pipeline. Lets a modify/replay test assert the RETAINED interval a
  /// session-CHANGED recreate would replay (the pipeline single-owner record) rather than only the ids.
  [[nodiscard]] static std::vector<RecoveryDescriptor> pipeline_recovery_descriptors(
    ConnectionImpl& connection)
  {
    if (!connection.mPipeline)
    {
      return {};
    }
    return wait_for<std::vector<RecoveryDescriptor>>(connection,
      [&connection](std::function<void(std::vector<RecoveryDescriptor>)> done)
      { connection.mPipeline->recovery_descriptors_async(std::move(done)); });
  }

  // --- Direct forwarders to the reconnect FSM primitives (each posts onto the orchestrator strand). ---

  static void reconnect_get_endpoints(ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_get_endpoints(std::move(done));
  }

  static void reconnect_open_secure_channel(
    ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_open_secure_channel(std::move(done));
  }

  static void reconnect_activate_session(ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_activate_session(std::move(done));
  }

  static void reconnect_create_session(ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_create_session(std::move(done));
  }

  static void reconnect_recover_subscriptions(ConnectionImpl& connection,
    ua::client::SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_recover_subscriptions(recovery, std::move(done));
  }

  /// Drives the reconnect NamespaceArray re-read step (CL-SESS-028) directly on the strand: reads via the
  /// active session and rebuilds @ref ConnectionImpl::mNamespaceTable with a bumped generation (and, once
  /// wired, re-seeds the TypeResolver). Lets a seeding test exercise the reconnect re-seed without driving
  /// the full FSM sequence. @p done fires with the re-read outcome.
  static void reconnect_re_read_namespace_array(
    ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_re_read_namespace_array(std::move(done));
  }

  static void reconnect_commit(ConnectionImpl& connection, std::function<void(ua::VoidResult)> done)
  {
    connection.reconnect_commit(std::move(done));
  }

  /// The pipeline's currently-registered Subscription ids (strand-hopped via the callback-free descriptor
  /// snapshot). Empty when the orchestrator has no pipeline. Lets a session-CHANGED recovery test assert the
  /// exact post-recovery ids (a transfer keeps the old id; a recreate re-keys to the new server id).
  [[nodiscard]] static std::vector<std::uint32_t> pipeline_subscription_ids(ConnectionImpl& connection)
  {
    std::vector<std::uint32_t> ids;
    for (const auto& descriptor : pipeline_recovery_descriptors(connection))
    {
      ids.push_back(descriptor.subscriptionId);
    }
    return ids;
  }

  // --- Direct forwarders to the reconnect FSM notify hooks (drive mState without the FSM sequence). ---

  static void reconnect_notify_reconnecting(ConnectionImpl& connection, std::size_t attempt = 1,
    ua::client::ReconnectCause cause = ua::client::TransportDropped{})
  {
    connection.reconnect_notify_reconnecting(attempt, std::move(cause));
  }

  static void reconnect_notify_active(ConnectionImpl& connection, ua::client::ReconnectOutcome outcome = {})
  {
    connection.reconnect_notify_active(std::move(outcome));
  }

  static void reconnect_notify_failed(ConnectionImpl& connection, ua::StatusCode terminal,
    std::shared_ptr<const ua::ErrorDetail> chain = nullptr)
  {
    connection.reconnect_notify_failed(terminal, std::move(chain));
  }

  /// Drives the first-reach-Active hook directly (fires on_connected/on_session_activated + the W4
  /// RedundancyManager on_session_active drive), for tests that exercise the attach without a full bootstrap.
  static void drive_first_session_active(ConnectionImpl& connection)
  {
    boost::asio::post(connection.mStrand,
      ua::async::guarded(ua::Logger{}, [&connection] { connection.on_first_session_active(); }));
  }

  /// Installs the strand-only W4 close-step probe (F5 ordering oracle) via a strand hop, so the plain
  /// (non-atomic) member is written on the connection strand  -  the same strand begin_close reads it on.
  static void set_close_step_probe(ConnectionImpl& connection, std::function<void(std::string_view)> probe)
  {
    on_strand(connection, [&connection, &probe] { connection.mCloseStepProbe = std::move(probe); });
  }

  /// Drives the automatic drop-detection entry point directly (as a channel/session-fatal Publish result
  /// would), so a unit test can exercise the trigger/terminal-guard/epoch-guard logic without timing the
  /// pump. @p issuedEpoch is the reconnect epoch the (simulated) Publish was issued under; pass the current
  /// epoch to model a live drop, or a stale value to model a superseded-channel completion.
  static void notify_transport_drop(
    ConnectionImpl& connection, ua::StatusCode cause, std::uint64_t issuedEpoch = 0)
  {
    connection.notify_transport_drop_async(cause, issuedEpoch);
  }

  /// Drives ONE keep-alive poll step directly on the connection strand and blocks until it returns (the
  /// read is issued; its completion is posted to run on a later strand turn). A deterministic interface that
  /// replaces waiting for the real periodic Timer to fire (section 8.2A.6). The keep-alive read's Result
  /// comes from whatever the fake `read` op is currently scripted to return, so a test can script a miss /
  /// good / shutdown read per poll. Follow with a @ref snapshot to barrier on the read completion having
  /// settled.
  static void run_keep_alive_poll(ConnectionImpl& connection)
  {
    on_strand(connection, [&connection] { connection.keep_alive_poll_on_strand(); });
  }

  /// Whether the keep-alive timer is currently armed (strand-hopped read of the member's engaged state).
  /// Lets a test assert the interval<=0 opt-out never arms it, and that close / reconnecting disarm it.
  [[nodiscard]] static bool keep_alive_timer_armed(ConnectionImpl& connection)
  {
    return on_strand(connection, [&connection] { return static_cast<bool>(connection.mKeepAliveTimer); });
  }

  /// The effective keep-alive poll interval last computed at arm time (strand-hopped read). Lets a test
  /// assert the CL-SESS-020 bound: min(configured, revisedSessionTimeout / (missedBeforeReconnect + 1)),
  /// clamped to the floor.
  [[nodiscard]] static std::chrono::milliseconds effective_keep_alive_interval(ConnectionImpl& connection)
  {
    return on_strand(connection, [&connection] { return connection.mEffectiveKeepAliveInterval; });
  }

  /// Whether a keep-alive poll read is currently outstanding (strand-hopped). Lets a test pin that a STALE
  /// (superseded-attempt) poll completion does NOT clear the live poll's in-flight guard - the ordering the
  /// finish_keep_alive_poll epoch-guard-before-clear fix protects.
  [[nodiscard]] static bool keep_alive_poll_in_flight(ConnectionImpl& connection)
  {
    return on_strand(connection, [&connection] { return connection.mKeepAlivePollInFlight; });
  }

  /// Cross-strand reconnect-FSM snapshot used only to observe whether a keep-alive maintenance hint entered
  /// the real `ShutdownDeferred` state. This does not mutate or bypass the production transition.
  [[nodiscard]] static std::shared_ptr<const ReconnectionFSMInfo> reconnect_fsm_info(
    const ConnectionImpl& connection)
  {
    return connection.mReconnectFsm ? connection.mReconnectFsm->info() : nullptr;
  }

  /// Attempt-local recovery facts that are copied into the public ReconnectOutcome at reach-Active.
  [[nodiscard]] static std::pair<bool, std::size_t> reconnect_recovery_outcome(ConnectionImpl& connection)
  {
    return on_strand(connection,
      [&connection]
      {
        return std::pair<bool, std::size_t>{
          connection.mSubscriptionsTransferredThisAttempt, connection.mMonitoredItemsRecreatedThisAttempt};
      });
  }

private:
  template<class T>
  using Done = typename connection_test_access::DoneOf<T>::type;

  /// Calls @p start with a `done` callback and returns what `done` receives, blocking the calling test
  /// thread. The wait is `blocking_call`'s, so on a thread of the connection's executor - where `done`
  /// would have to run - it throws `Bad_WouldBlock` instead of deadlocking.
  template<class T, class Start>
  static T wait_for(ConnectionImpl& connection, Start start)
  {
    using Held = std::conditional_t<std::is_void_v<T>, ua::VoidResult, ua::Result<T>>;
    auto held = ua::async::detail::blocking_call<Held>(connection.mExecutor,
      [&start](std::function<void(Held)> complete)
      {
        if constexpr (std::is_void_v<T>)
        {
          start(Done<T>{[complete]
            {
              complete(Held{});
            }});
        }
        else
        {
          start(Done<T>{[complete](T value)
            {
              complete(Held{std::move(value)});
            }});
        }
      });
    if constexpr (std::is_void_v<T>)
    {
      held.value();
    }
    else
    {
      return std::move(held).value();
    }
  }

  /// Runs @p body on the connection strand and returns what it returns (see @ref wait_for).
  template<class Body>
  static auto on_strand(ConnectionImpl& connection, Body body) -> std::invoke_result_t<Body&>
  {
    using T = std::invoke_result_t<Body&>;
    return wait_for<T>(connection,
      [&connection, &body](Done<T> done)
      {
        boost::asio::post(connection.mStrand,
          ua::async::guarded(ua::Logger{},
            [&body, done = std::move(done)]
            {
              if constexpr (std::is_void_v<T>)
              {
                body();
                done();
              }
              else
              {
                done(body());
              }
            }));
      });
  }
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_IMPL_TEST_ACCESS_H
