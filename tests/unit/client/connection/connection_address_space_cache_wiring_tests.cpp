// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ConnectionImpl's Slice V1 AddressSpaceCache wiring (client design section 8.7,
// CL-VIEW-009/010/011).
//
// The per-Connection AddressSpaceCache (ua::client::detail::AddressSpaceCache) is a strand-serialised
// accelerator whose OWN logic (alias install / LRU-evict / substitute / session-scope clear) is already
// comprehensively unit-tested in client_address_space_cache_tests.cpp. THESE tests pin the WIRING that
// Slice V1 added inside ConnectionImpl: an ENABLED AddressSpaceCachePolicy threaded through the connect
// config reaches the constructed cache, and the orchestrator drives it at the four production points -
//   - register_nodes_async  -> install_aliases            (CL-VIEW-010 populate + LRU-evict)
//   - read/write/call/hist   -> lookup_for_request         (CL-VIEW-009 alias substitution at request build)
//   - reconnect session-CHANGED branch -> on_session_changed_async  (CL-VIEW-011 Session-scoped clear)
//   - begin_close            -> drain_async                (CL-VIEW-010 shutdown drain)
// - and, critically, that the DEFAULT (disabled) policy is a STRICT no-op: register / request-build /
// session-change behave byte-for-byte as before (the regression guard).
//
// Driven in isolation over the fake tier-0 interface (FakeSessionOps / FakeChannelOps / FakeReopen) via
// ConnectionImplTestAccess::create_with_ops, mirroring connection_type_resolver_seeding_tests.cpp. The
// alias-cache state is read ON the connection strand through the ConnectionImplTestAccess forwarders (the
// cache is caller-on-strand; a raw cross-thread read would race the strand-side wiring).
//
// Falsifiability: each substitution / install / invalidate test asserts a CONCRETE observable (the exact
// NodeId that reached the fake session, the alias-cache count / generation), so a stubbed-out wiring body
// fails a specific assertion rather than merely "not crashing". The RED->GREEN evidence is recorded in the
// slice report (each wiring body was temporarily stubbed and the corresponding test confirmed RED).
//
// @verifies CL-VIEW-009 - registered NodeIds (alias substitution) are used for subsequent Read/Write/Call
// @relation(CL-VIEW-009, scope=file)
//           requests: after RegisterNodes the outgoing request carries the server alias, not the original.
// @verifies CL-VIEW-010 - RegisterNodes aliases are installed (populate) and LRU-evicted past the ceiling;
// @relation(CL-VIEW-010, scope=file)
//           close drains them.
// @verifies CL-VIEW-011 - registered NodeIds are Session-scoped: a session-CHANGED reconnect clears the
// @relation(CL-VIEW-011, scope=file)
//           alias cache and bumps its generation, so no stale alias survives a fresh Session.

#include "fake_session_ops.h"

#include "ua_address_space_cache.h"
#include "ua_address_space_cache_test_access.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reconnect_policy.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_write_request.h"
#include "ua_write_value.h"

#include "async_test_runtime.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::NodeId;
using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::SubscriptionRecovery;
using ua::client::detail::AddressSpaceCacheTestAccess;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::KeepAlivePolicy;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

NodeId node(std::uint16_t ns, std::uint32_t id)
{
  return NodeId{ns, id};
}

/// A near-zero backoff so any incidental FSM timer fires promptly (the suite drives the reconnect
/// primitives directly).
ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// Keep-alive DISABLED (interval 0) so no keep-alive poll Read pollutes the fake session's recorded reads.
KeepAlivePolicy keep_alive_disabled()
{
  return KeepAlivePolicy{/*interval=*/0ms, /*missedBeforeReconnect=*/3};
}

ua::RegisterNodesRequest register_request(std::vector<NodeId> originals)
{
  ua::RegisterNodesRequest request;
  for (auto& original : originals)
  {
    request.nodes_to_register().push_back(std::move(original));
  }
  return request;
}

ua::RegisterNodesResponse register_response(std::vector<NodeId> aliases)
{
  ua::RegisterNodesResponse response;
  for (auto& alias : aliases)
  {
    response.registered_node_ids().push_back(std::move(alias));
  }
  return response;
}

ua::ReadRequest read_request(NodeId target)
{
  ua::ReadRequest request;
  ua::ReadValueId valueId;
  valueId.node_id() = std::move(target);
  request.nodes_to_read().push_back(std::move(valueId));
  return request;
}

ua::WriteRequest write_request(NodeId target)
{
  ua::WriteRequest request;
  ua::WriteValue value;
  value.node_id() = std::move(target);
  request.nodes_to_write().push_back(std::move(value));
  return request;
}

ua::CallRequest call_request(NodeId objectId, NodeId methodId)
{
  ua::CallRequest request;
  ua::CallMethodRequest method;
  method.object_id() = std::move(objectId);
  method.method_id() = std::move(methodId);
  request.methods_to_call().push_back(std::move(method));
  return request;
}

class ConnectionAddressSpaceCacheWiring : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  /// Builds a Connection whose AddressSpaceCachePolicy is @p enabled (useRegisterNodes on), with the alias
  /// ceiling @p maxRegisteredNodes - so the FULL policy (not just the enable bit) is proven to thread
  /// through.
  std::shared_ptr<ConnectionImpl> make_connection(bool enabled, std::size_t maxRegisteredNodes = 1024)
  {
    ConnectionConfig config;
    config.addressSpaceCache.enabled = enabled;
    config.addressSpaceCache.useRegisterNodes = true;
    config.addressSpaceCache.maxRegisteredNodes = maxRegisteredNodes;
    return TA::create_with_ops(mRuntime.executor(),
      mSession,
      std::move(config),
      Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      keep_alive_disabled());
  }

  static void start(ConnectionImpl& connection)
  {
    std::promise<VoidResult> started;
    auto future = started.get_future();
    connection.start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  Result<ua::RegisterNodesResponse> register_and_wait(
    ConnectionImpl& connection, ua::RegisterNodesRequest request)
  {
    std::promise<Result<ua::RegisterNodesResponse>> promise;
    auto future = promise.get_future();
    connection.register_nodes_async(std::move(request),
      [&promise](Result<ua::RegisterNodesResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<ua::ReadResponse> read_and_wait(ConnectionImpl& connection, ua::ReadRequest request)
  {
    std::promise<Result<ua::ReadResponse>> promise;
    auto future = promise.get_future();
    connection.read_async(std::move(request),
      [&promise](Result<ua::ReadResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<ua::WriteResponse> write_and_wait(ConnectionImpl& connection, ua::WriteRequest request)
  {
    std::promise<Result<ua::WriteResponse>> promise;
    auto future = promise.get_future();
    connection.write_async(std::move(request),
      [&promise](Result<ua::WriteResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<ua::CallResponse> call_and_wait(ConnectionImpl& connection, ua::CallRequest request)
  {
    std::promise<Result<ua::CallResponse>> promise;
    auto future = promise.get_future();
    connection.call_async(std::move(request),
      [&promise](Result<ua::CallResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // --- reconnect FSM primitive drivers (block until the step's `done` fires) ---

  static VoidResult run_open(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_open_secure_channel(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_activate(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_activate_session(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_create_session(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_create_session(
      connection, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult run_recover(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    TA::reconnect_recover_subscriptions(connection,
      SubscriptionRecovery::TransferThenRecreate,
      [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Drives a CL-RECONN-003 rebind that creates a FRESH Session (activate-existing fails ->
  /// create_session), then runs the recover step through the session-CHANGED branch - the production point
  /// where ConnectionImpl invalidates the Session-scoped alias cache (CL-VIEW-011).
  void drive_session_changed_recover(ConnectionImpl& connection)
  {
    ASSERT_TRUE(run_open(connection).is_good());
    mSession->activateOnChannel.set_result(VoidResult{Status::BadSessionIdInvalid});
    ASSERT_TRUE(run_activate(connection).is_bad());  // activate EXISTING fails -> route to create_session
    ASSERT_TRUE(run_create_session(connection).is_good());  // sets mSessionChangedThisAttempt
    ASSERT_TRUE(run_activate(connection).is_good());  // activate the fresh session on its bound channel
    ASSERT_TRUE(run_recover(connection).is_good());  // session-CHANGED branch: clears + bumps generation
  }

  template<typename Predicate>
  static bool wait_until(Predicate predicate, std::chrono::milliseconds timeout = 2s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (predicate())
      {
        return true;
      }
      std::this_thread::sleep_for(2ms);
    }
    return predicate();
  }
};

// ============================================================================================
// Phase 1 - enablement plumbing: the policy threads config -> constructed cache.
// ============================================================================================

// @verifies CL-VIEW-009/010/011 (enablement) - an ENABLED AddressSpaceCachePolicy in the connect config
// reaches the constructed per-Connection cache. RED before the config threading: the accessor built the
// cache from a default (disabled) policy, so enabled() would be false.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, EnabledPolicyReachesConstructedCache)
{
  auto connection = make_connection(/*enabled=*/true);
  EXPECT_TRUE(TA::address_space_cache(*connection)->enabled())
    << "an enabled AddressSpaceCachePolicy must thread through config -> the constructed cache";
}

// @verifies CL-VIEW-009/010/011 (enablement default) - the DEFAULT policy leaves the cache disabled, so a
// Connection that does not opt in keeps the pass-through no-op behaviour.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, DefaultPolicyLeavesCacheDisabled)
{
  auto connection = make_connection(/*enabled=*/false);
  EXPECT_FALSE(TA::address_space_cache(*connection)->enabled())
    << "the default (opt-in) policy must leave the cache disabled";
}

// ============================================================================================
// Phase 2 - CL-VIEW-010 install (populate).
// ============================================================================================

// @verifies CL-VIEW-010 - a successful RegisterNodes installs the (requested -> registered) alias pairs into
// the cache. RED if install_aliases_on_register is stubbed to pass the completion straight through: no alias
// is stored, so address_space_cache_alias returns nullopt and the count stays 0.
// @relation(CL-VIEW-010, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, RegisterNodesInstallsAliasPairsWhenEnabled)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);

  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());

  const auto alias = TA::address_space_cache_alias(*connection, node(2, 5));
  ASSERT_TRUE(alias.has_value()) << "RegisterNodes must install the alias into the cache (CL-VIEW-010)";
  EXPECT_EQ(alias->registered, node(0, 9001)) << "the stored alias is the server-assigned registered handle";
  EXPECT_EQ(TA::address_space_cache_alias_count(*connection), 1u);
}

// @verifies CL-VIEW-010 - the LRU ceiling (maxRegisteredNodes) evicts the oldest alias once exceeded (the
// full policy, not just the enable bit, threads through). RED if the ceiling were ignored (count would be 2).
// @relation(CL-VIEW-010, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, LruEvictsOldestAliasPastCeiling)
{
  auto connection = make_connection(/*enabled=*/true, /*maxRegisteredNodes=*/1);
  start(*connection);

  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());

  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9002)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 6)})).is_good());

  EXPECT_EQ(TA::address_space_cache_alias_count(*connection), 1u) << "the ceiling of 1 bounds the cache";
  EXPECT_FALSE(TA::address_space_cache_alias(*connection, node(2, 5)).has_value())
    << "the least-recently-used alias is evicted past the ceiling";
  const auto kept = TA::address_space_cache_alias(*connection, node(2, 6));
  ASSERT_TRUE(kept.has_value());
  EXPECT_EQ(kept->registered, node(0, 9002)) << "the most recent alias is retained";
}

// ============================================================================================
// Phase 2 - CL-VIEW-009 substitution at request build (Read + Write + Call).
// ============================================================================================

// @verifies CL-VIEW-009 - after an alias is installed, a Read carries the REGISTERED alias on the wire, not
// the original NodeId. RED if apply_alias_substitution(ReadRequest&) is stubbed: the original {2,5} reaches
// the fake session unchanged.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, ReadSubstitutesRegisteredAliasWhenEnabled)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());

  ASSERT_TRUE(read_and_wait(*connection, read_request(node(2, 5))).is_good());

  const auto reads = mSession->read.requests();
  ASSERT_FALSE(reads.empty());
  ASSERT_EQ(reads.back().nodes_to_read().size(), 1u);
  EXPECT_EQ(reads.back().nodes_to_read()[0].node_id(), node(0, 9001))
    << "the Read must carry the registered alias, not the original NodeId (CL-VIEW-009)";
}

// @verifies CL-VIEW-009 - substitution applies to Write too.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, WriteSubstitutesRegisteredAliasWhenEnabled)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());

  ASSERT_TRUE(write_and_wait(*connection, write_request(node(2, 5))).is_good());

  const auto writes = mSession->write.requests();
  ASSERT_FALSE(writes.empty());
  ASSERT_EQ(writes.back().nodes_to_write().size(), 1u);
  EXPECT_EQ(writes.back().nodes_to_write()[0].node_id(), node(0, 9001))
    << "the Write must carry the registered alias, not the original NodeId (CL-VIEW-009)";
}

// @verifies CL-VIEW-009 - substitution applies to both the object and method NodeId of a Call.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, CallSubstitutesRegisteredAliasesWhenEnabled)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);
  // Register BOTH the object and the method node so both are aliased at request build.
  mSession->registerNodes.set_result(
    Result<ua::RegisterNodesResponse>{register_response({node(0, 9001), node(0, 9002)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5), node(2, 6)})).is_good());

  ASSERT_TRUE(call_and_wait(*connection, call_request(node(2, 5), node(2, 6))).is_good());

  const auto calls = mSession->call.requests();
  ASSERT_FALSE(calls.empty());
  ASSERT_EQ(calls.back().methods_to_call().size(), 1u);
  EXPECT_EQ(calls.back().methods_to_call()[0].object_id(), node(0, 9001))
    << "the Call objectId must be aliased (CL-VIEW-009)";
  EXPECT_EQ(calls.back().methods_to_call()[0].method_id(), node(0, 9002))
    << "the Call methodId must be aliased (CL-VIEW-009)";
}

// ============================================================================================
// Phase 2 - CL-VIEW-011 Session-scoped clear + CL-VIEW-010 drain on close.
// ============================================================================================

// @verifies CL-VIEW-011 - aliases are Session-scoped: a session-CHANGED reconnect clears the alias cache and
// bumps its generation, so no stale alias (which the fresh Session never registered) survives. RED if the
// on_session_changed_async call in the reconnect session-CHANGED branch is removed: the alias survives (count
// stays 1) and the generation stays 0.
// @relation(CL-VIEW-011, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, SessionChangedReconnectClearsAliasCache)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());
  ASSERT_EQ(TA::address_space_cache_alias_count(*connection), 1u);
  ASSERT_EQ(TA::address_space_cache_session_generation(*connection), 0u);

  drive_session_changed_recover(*connection);

  EXPECT_TRUE(wait_until([&] { return TA::address_space_cache_alias_count(*connection) == 0u; }))
    << "a session-CHANGED reconnect must clear the Session-scoped alias cache (CL-VIEW-011)";
  EXPECT_EQ(TA::address_space_cache_session_generation(*connection), 1u)
    << "the session generation must bump so any surviving alias is treated as stale on lookup";
}

// @verifies CL-VIEW-010 - graceful close drains the alias cache (best-effort UnregisterNodes + local clear)
// without error or hang. RED if the drain_async call in begin_close is removed: the alias survives close
// (count stays 1). The close itself must remain Good (the drain is fire-and-forget).
// @relation(CL-VIEW-010, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, CloseDrainsAliasCache)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());
  ASSERT_EQ(TA::address_space_cache_alias_count(*connection), 1u);

  EXPECT_TRUE(close_and_wait(*connection).is_good()) << "close must complete Good (the drain is best-effort)";
  EXPECT_TRUE(wait_until([&] { return TA::address_space_cache_alias_count(*connection) == 0u; }))
    << "close must drain the alias cache (CL-VIEW-010)";
}

// ============================================================================================
// section 3.1 fix - CL-VIEW-009/011: alias substitution runs at DISPATCH time, not request-BUILD time.
// ============================================================================================

// @verifies CL-VIEW-009 - substitution is applied at DISPATCH time (on the connection strand, after the
//           session is (re)bound), NOT at request build. A Read QUEUED during a reconnect re-consults the
//           alias cache when it dispatches, so a session-CHANGED reconnect that CLEARS the (session-scoped)
//           cache between the Read being issued and it dispatching makes the dispatched Read carry the RAW
//           NodeId.
// @verifies CL-VIEW-011 - the same guarantee from the Session-scope angle: the stale OLD-session alias must
//           not survive onto a request the FRESH session dispatches (a section 3.1 finding: a request queued
//           across a session-CHANGED reconnect kept a stale old-session alias and dispatched it on the new
//           session
//           -> Bad_NodeIdUnknown).
//
// Drives the REAL queue/flush/session-change path: install alias A for X; enter Reconnecting so the dispatch
// gate QUEUES the Read (CL-SESS-019/021 reconnect transparency); drive the session-CHANGED reconnect (the
// production point that clears the cache + bumps the generation) WHILE the Read is parked; then flush the
// gate to Active so the queued Read dispatches and re-consults the now-cleared cache.
//
// RED under the OLD build-time substitution: A is baked into the request before the clear, so the queued Read
// dispatches A. GREEN with dispatch-time substitution: the cleared cache yields no alias for X, so the Read
// dispatches the RAW X. (Stash-revert RED evidence recorded in the slice report.)
// @relation(CL-VIEW-009, CL-VIEW-011, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, QueuedReadAcrossSessionChangeDispatchesRawNodeId)
{
  auto connection = make_connection(/*enabled=*/true);
  start(*connection);

  // Install alias A = {0, 9001} for X = {2, 5}.
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());
  ASSERT_EQ(TA::address_space_cache_alias_count(*connection), 1u);
  // The bootstrap NamespaceArray Read already recorded one read on the fake session; anchor to that count so
  // the queued Read's dispatch is isolated as "exactly one MORE read, carrying X".
  const std::size_t readsBeforeQueue = mSession->read.requests().size();

  // Enter Reconnecting: the dispatch gate now QUEUES wire ops instead of dispatching them.
  TA::reconnect_notify_reconnecting(*connection);
  ASSERT_EQ(TA::snapshot(*connection).state, ConnectionState::Reconnecting)
    << "the Connection must be Reconnecting so the next wire op queues in the dispatch gate";

  // Issue the Read for X WHILE queued. Do NOT block on it here - a queued Read does not complete until the
  // gate flushes on reach-Active, so a blocking wait would deadlock the test thread.
  std::promise<Result<ua::ReadResponse>> readDone;
  auto readFuture = readDone.get_future();
  connection->read_async(read_request(node(2, 5)),
    [&readDone](Result<ua::ReadResponse> result) { readDone.set_value(std::move(result)); });

  // Session-CHANGED reconnect: the production point that clears the Session-scoped alias cache + bumps the
  // generation, driven BETWEEN the Read being queued and it dispatching. Its many strand round-trips also
  // guarantee the Read has routed into (and parked in) the gate by the time it returns.
  drive_session_changed_recover(*connection);
  ASSERT_TRUE(wait_until([&] { return TA::address_space_cache_alias_count(*connection) == 0u; }))
    << "the session-CHANGED reconnect must clear the alias cache before the queued Read dispatches";

  // The Read stayed PARKED through the whole outage - it never reached the session while Reconnecting.
  ASSERT_EQ(mSession->read.requests().size(), readsBeforeQueue)
    << "a Read issued during Reconnecting must QUEUE in the dispatch gate, not reach the session";

  // Flush the gate (reach Active): the queued Read now DISPATCHES and re-consults the cleared cache.
  TA::reconnect_notify_active(*connection);
  ASSERT_TRUE(readFuture.get().is_good());

  const auto reads = mSession->read.requests();
  ASSERT_EQ(reads.size(), readsBeforeQueue + 1u) << "the queued Read dispatched exactly once on flush";
  ASSERT_EQ(reads.back().nodes_to_read().size(), 1u);
  EXPECT_EQ(reads.back().nodes_to_read()[0].node_id(), node(2, 5))
    << "a Read queued across a session-CHANGED reconnect must dispatch the RAW NodeId: substitution at "
       "DISPATCH time re-consults the cleared cache and sends X, not the stale old-session alias A (section "
       "3.1)";
  EXPECT_NE(reads.back().nodes_to_read()[0].node_id(), node(0, 9001))
    << "the stale old-session alias A must NOT survive onto the queued Read (the section 3.1 build-time bug)";
}

// ============================================================================================
// The critical regression guard: the DISABLED default is a STRICT no-op.
// ============================================================================================

// @verifies CL-VIEW-009/010 (disabled no-op) - with the default (disabled) policy, RegisterNodes installs
// NOTHING and a subsequent Read carries the ORIGINAL NodeId (no substitution) - exactly as before Slice V1.
// This is the guard that keeps the whole existing suite (which uses the default config) green.
// @relation(CL-VIEW-009, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, DisabledCacheInstallsNothingAndDoesNotSubstitute)
{
  auto connection = make_connection(/*enabled=*/false);
  start(*connection);
  mSession->registerNodes.set_result(Result<ua::RegisterNodesResponse>{register_response({node(0, 9001)})});
  ASSERT_TRUE(register_and_wait(*connection, register_request({node(2, 5)})).is_good());

  EXPECT_EQ(TA::address_space_cache_alias_count(*connection), 0u)
    << "a disabled cache installs nothing on RegisterNodes";
  EXPECT_FALSE(TA::address_space_cache_alias(*connection, node(2, 5)).has_value());

  ASSERT_TRUE(read_and_wait(*connection, read_request(node(2, 5))).is_good());
  const auto reads = mSession->read.requests();
  ASSERT_FALSE(reads.empty());
  ASSERT_EQ(reads.back().nodes_to_read().size(), 1u);
  EXPECT_EQ(reads.back().nodes_to_read()[0].node_id(), node(2, 5))
    << "a disabled cache never substitutes - the ORIGINAL NodeId reaches the wire (strict no-op)";
}

// @verifies CL-VIEW-011 (disabled no-op) - with the default (disabled) policy, a session-CHANGED reconnect
// does NOT touch the cache: the generation stays 0. RED if the `mAddressSpaceCachePolicy.enabled` gate on the
// on_session_changed_async call were removed - on_session_changed_async unconditionally bumps the generation,
// so a disabled Connection would wrongly bump to 1.
// @relation(CL-VIEW-011, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, DisabledCacheSessionChangeLeavesGenerationUntouched)
{
  auto connection = make_connection(/*enabled=*/false);
  start(*connection);

  drive_session_changed_recover(*connection);

  EXPECT_EQ(TA::address_space_cache_session_generation(*connection), 0u)
    << "a disabled cache must not be driven on session change (strict no-op)";
}

/// AC-COMP-CL-CONNIMPL-06-B. The pre-flight surface of this cache - `validate_index_range_write_async` and
/// the two `observe_*` recorders - had no unit stimulus anywhere in the tree; only the alias-substitution
/// surface was driven. The obligation here is the header's own words: a disabled cache or an attribute miss
/// returns Good, because the server remains authoritative and refusing on absent knowledge would reject a
/// legal write. The two arms differ in exactly one variable and are asserted to agree, so removing the
/// pass-through and rejecting on a miss reddens the pair.
// @relation(AC-COMP-CL-CONNIMPL-06-B, scope=function)
TEST_F(ConnectionAddressSpaceCacheWiring, RangedWriteValidationDefersToServerWhenCacheHasNoAnswer)
{
  auto disabled = make_connection(/*enabled=*/false);
  start(*disabled);

  std::promise<VoidResult> disabledVerdict;
  auto disabledFuture = disabledVerdict.get_future();
  disabled->validate_index_range_write_async(ua::NodeId{2, 4242},
    ua::String{"0:1"},
    [&disabledVerdict](VoidResult result) { disabledVerdict.set_value(std::move(result)); });
  EXPECT_TRUE(disabledFuture.get().is_good())
    << "a disabled cache must be a clean pass-through: the server stays authoritative";

  // Same stimulus against an ENABLED cache that holds nothing for the node - the attribute-miss class.
  mSession = std::make_shared<FakeSessionOps>();
  mReopen = std::make_shared<FakeReopen>();
  auto enabled = make_connection(/*enabled=*/true);
  start(*enabled);

  std::promise<VoidResult> missVerdict;
  auto missFuture = missVerdict.get_future();
  enabled->validate_index_range_write_async(ua::NodeId{2, 4242},
    ua::String{"0:1"},
    [&missVerdict](VoidResult result) { missVerdict.set_value(std::move(result)); });
  EXPECT_TRUE(missFuture.get().is_good())
    << "an attribute miss must defer to the server rather than refuse the write locally";
}

}  // namespace
