// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include "ua_application_configuration.h"
#include "ua_server_configuration.h"
#include "ua_server_impl.h"
#include "ua_tcp_transport_connection.h"
#include <boost/asio/thread_pool.hpp>

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"
#include "ua_connection_protocol.h"
#include "ua_server_observer.h"
#include "ua_log_sink.h"

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::server;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

// These rows exercise the throttle map directly, keyed by the unsecured-connection identifier.
boost::asio::ip::address ip(std::string_view address)
{
  return boost::asio::ip::make_address(std::string{address});
}

shared_ptr<ServerImpl> create_test_server_impl(
  boost::asio::any_io_executor ex, ServerConfig serverConfig = {}, std::shared_ptr<LogSink> logSink = {})
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  // Add a minimal listener so validate() passes.
  {
    ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    serverConfig.listeners().push_back(std::move(listener));
  }

  serverConfig.validate();
  frozen.server = std::move(serverConfig);

  return ua::server::ServerImpl::create(ex,
    std::move(frozen),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
      .logSink = std::move(logSink),
      .logLevel = LogLevel::Warning});
}

class ThrottlingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    if (entry.level != LogLevel::Warning || !entry.message.starts_with("Per-IP connection "))
    {
      return;
    }
    warningCalls.fetch_add(1);
    auto owner = server.lock();
    if (!owner)
    {
      return;
    }
    // Probe from another thread: recursively trying a non-recursive shared_mutex is not supported.
    auto available =
      std::async(std::launch::async, [owner] { return TestAccess{*owner}.server_mutex_available(); });
    if (!available.get())
    {
      return;
    }
    outsideMutex.fetch_add(1);
    const auto endpoints = owner->endpoints(ListenerHandle{1});
    endpointQueries.fetch_add(1);
    if (endpoints.size() == 1 && endpoints.front().name == "None")
    {
      matchingEndpointQueries.fetch_add(1);
    }
  }

  std::weak_ptr<ServerImpl> server;
  std::atomic<unsigned> warningCalls{0};
  std::atomic<unsigned> outsideMutex{0};
  std::atomic<unsigned> endpointQueries{0};
  std::atomic<unsigned> matchingEndpointQueries{0};
};

}  // namespace

// ---------------------------------------------------------------------------
// S11: Identity token attack protection
// ---------------------------------------------------------------------------

class ServerThrottlingIdentity : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  boost::asio::thread_pool mPool{1};
  boost::asio::any_io_executor mExecutor{mPool.get_executor()};
};

TEST_F(ServerThrottlingIdentity, NoLockoutWhenNoFailuresRecorded)
{
  auto server = create_test_server_impl(mExecutor);
  auto result = TestAccess{*server}.check_identity_lockout(ip("192.168.1.1"), "admin");
  EXPECT_FALSE(result.has_value());
}

// Covers SVR-IDENT-007, SVR-SESS-029 (coverage-audit retag).
TEST_F(ServerThrottlingIdentity, LockoutAfterMaxFailures)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 3;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // Record 3 failures (the threshold).
  for (int i = 0; i < 3; ++i)
  {
    TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "bob");
  }

  auto result = TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "bob");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, StatusCode{Status::BadIdentityTokenInvalid});
}

// @relation(AC-SVR-IDENT-007-LOCKOUT-AFTER-FIVE, scope=function)
TEST_F(ServerThrottlingIdentity, ClientScopeIsIndependentOfClaimedUserIdentity)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 2;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // Lock out client application IP1 while it claims user1.
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");

  // IP1 is locked.
  EXPECT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "alice").has_value());

  // IP2 is NOT locked -- it is a different client application.
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.2"), "alice").has_value());

  // Changing the claimed user does not bypass the lockout for the same client application.
  EXPECT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "bob").has_value());
}

// RATIFIED EXPECTATION CHANGE (SESS-2): this arm was `SuccessClearsLockout`, which drove a state that
// production cannot reach (a success recorded while the client application is locked out: begin refuses
// the attempt before any credential is checked). The obligation it stood next to is kept as what CAN be
// observed: a lockout period runs its course, and when it has run its course the client application
// starts again with a fresh budget (Part 4 7.41.2.1).
// @verifies AC-SVR-IDENT-007-A-SUCCESS-CLEARS-ONLY-ITS-OWN-USER
TEST_F(ServerThrottlingIdentity, LockoutExpiryRestoresTheBudget)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 2;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{1};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  ASSERT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "alice").has_value())
    << "two failures lock the client application out";
  std::this_thread::sleep_for(std::chrono::milliseconds{1200});
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "alice").has_value())
    << "after the lockout period the budget is fresh: the count that started the lockout is gone";
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "bob").has_value());
}

// @verifies AC-SVR-IDENT-007-A-SUCCESS-CLEARS-ONLY-ITS-OWN-USER
TEST_F(ServerThrottlingIdentity, SuccessForOneUserDoesNotResetAnotherUsersFailures)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 5;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  for (int i = 0; i < 4; ++i)
    TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  TestAccess{*server}.record_auth_success(ip("10.0.0.1"), "mallory");  // a valid, unrelated user
  ASSERT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value());
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");  // the fifth admin guess
  EXPECT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value())
    << "mallory's success did not reset admin's four failures";
}

// @verifies AC-SVR-IDENT-007-A-SUCCESS-CLEARS-ONLY-ITS-OWN-USER
// The control: a success DOES clear the same user's own failures.
TEST_F(ServerThrottlingIdentity, SuccessClearsOnlyItsOwnUsersFailures)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 3;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_success(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "alice");
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "alice").has_value())
    << "two failures after the success are below the threshold of three";
}

// @verifies AC-SVR-IDENT-007-CONCURRENT-ATTEMPTS-ARE-RESERVED
// The budget counts attempts in flight: with a threshold of 3, a fourth parallel guess is refused before
// it reaches the authenticator, and refusing it starts no lockout period.
TEST_F(ServerThrottlingIdentity, ConcurrentAttemptsBeyondTheRemainingBudgetAreRefusedBeforeAuthentication)
{
  using Outcome = ua::server::IdentityAttemptOutcome;
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 3;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  for (int i = 0; i < 3; ++i)
    EXPECT_FALSE(TestAccess{*server}.begin_identity_attempt(ip("10.0.0.1"), "admin").has_value())
      << "attempt " << i << " is within the budget";
  EXPECT_EQ(TestAccess{*server}.identity_attempts_in_flight(ip("10.0.0.1")), 3u);
  const auto refusal = TestAccess{*server}.begin_identity_attempt(ip("10.0.0.1"), "admin");
  ASSERT_TRUE(refusal.has_value()) << "the fourth parallel attempt exceeds the budget";
  EXPECT_EQ(*refusal, Status::BadIdentityTokenInvalid) << "refused with the lockout's own code";
  // Releasing the three as abandoned restores the budget: no lockout period was started.
  for (int i = 0; i < 3; ++i)
    TestAccess{*server}.finish_identity_attempt(ip("10.0.0.1"), "admin", Outcome::Abandoned);
  EXPECT_EQ(TestAccess{*server}.identity_attempts_in_flight(ip("10.0.0.1")), 0u);
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value());
}

// @verifies AC-SVR-IDENT-007-CONCURRENT-ATTEMPTS-ARE-RESERVED
// Failures below the threshold age out after one lockout duration of quiet: a stale count neither caps
// the client application's concurrency nor turns a later single failure into a lockout.
TEST_F(ServerThrottlingIdentity, StaleSubThresholdFailuresAgeOut)
{
  using Outcome = ua::server::IdentityAttemptOutcome;
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 5;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{1};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  for (int i = 0; i < 4; ++i)
    TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "bob");
  std::this_thread::sleep_for(std::chrono::milliseconds{1200});
  ASSERT_FALSE(TestAccess{*server}.begin_identity_attempt(ip("10.0.0.1"), "alice").has_value());
  EXPECT_FALSE(TestAccess{*server}.begin_identity_attempt(ip("10.0.0.1"), "alice").has_value())
    << "bob's stale failures no longer cap alice's concurrency";
  TestAccess{*server}.finish_identity_attempt(ip("10.0.0.1"), "alice", Outcome::Abandoned);
  TestAccess{*server}.finish_identity_attempt(ip("10.0.0.1"), "alice", Outcome::Abandoned);
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "carol");
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "carol").has_value())
    << "one failure after the quiet period is one failure, not the fifth";
}

// @verifies AC-SVR-IDENT-007-CONCURRENT-ATTEMPTS-ARE-RESERVED
TEST_F(ServerThrottlingIdentity, AbandonedAttemptReleasesItsReservationWithoutCounting)
{
  using Outcome = ua::server::IdentityAttemptOutcome;
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 2;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  ASSERT_FALSE(TestAccess{*server}.begin_identity_attempt(ip("10.0.0.1"), "admin").has_value());
  TestAccess{*server}.finish_identity_attempt(ip("10.0.0.1"), "admin", Outcome::Abandoned);
  EXPECT_EQ(TestAccess{*server}.identity_attempts_in_flight(ip("10.0.0.1")), 0u);
  // Two REAL failures still lock; the abandoned attempt did not count as a third.
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value())
    << "one failure and one abandoned attempt are one guess";
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  EXPECT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value());
}

TEST_F(ServerThrottlingIdentity, LockoutReturnsBadIdentityTokenInvalid)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 1;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  auto result = TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin");
  ASSERT_TRUE(result.has_value());
  // OPC 10000-4 v1.05 section 7.41.2.1: the user-identity-token error path returns
  // BadIdentityTokenInvalid. The lockout reuses that code so a locked-out response is
  // code-indistinguishable from an ordinary validation failure (no lockout-state leakage).
  EXPECT_EQ(*result, StatusCode{Status::BadIdentityTokenInvalid});
}

// Covers SVR-SESS-030 (coverage-audit retag).
TEST_F(ServerThrottlingIdentity, SubThresholdFailuresDoNotTriggerLockout)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 5;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // Record 4 failures (one less than threshold).
  for (int i = 0; i < 4; ++i)
  {
    TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  }

  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value());
}

TEST_F(ServerThrottlingIdentity, DisabledThrottlingBypassesAllChecks)
{
  ServerConfig cfg;
  cfg.identityThrottling.enabled = false;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 1;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // Record well above threshold.
  for (int i = 0; i < 10; ++i)
  {
    TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "admin");
  }

  // Should not be locked because throttling is disabled.
  EXPECT_FALSE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "admin").has_value());
}

// P1.D #7: the attacker-keyed identity-throttle map is bounded by a hard cap. Without it, distinct
// (IP, userId) keys would grow the map without limit.
TEST_F(ServerThrottlingIdentity, CapBoundsMapSize)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 100;  // no lockouts; just accumulate keys
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.set_max_identity_throttle_entries(3);

  for (int i = 0; i < 6; ++i)
  {
    TestAccess{*server}.record_auth_failure(ip("10.0.0." + std::to_string(i)), "user");
  }

  EXPECT_EQ(TestAccess{*server}.identity_throttle_size(), 3u);
}

// The cap is sourced from ServerConfig (not just the test-access override): a low configured
// maxTrackedIdentities must bound the live map.
TEST_F(ServerThrottlingIdentity, CapSourcedFromConfiguration)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 100;  // no lockouts; just accumulate keys
  cfg.identityThrottling.maxTrackedIdentities = 3;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  for (int i = 0; i < 6; ++i)
  {
    TestAccess{*server}.record_auth_failure(ip("10.0.0." + std::to_string(i)), "user");
  }

  EXPECT_EQ(TestAccess{*server}.identity_throttle_size(), 3u);
}

// At capacity a new key evicts the least-recently-active entry - demonstrated by evicting an early
// lockout once newer keys saturate the map.
TEST_F(ServerThrottlingIdentity, CapEvictsLeastRecentlyUsedEntry)
{
  ServerConfig cfg;
  cfg.identityThrottling.maxFailedAttemptsBeforeLockout = 2;
  cfg.identityThrottling.lockoutDuration = std::chrono::seconds{60};
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.set_max_identity_throttle_entries(3);

  // Lock out the first key - its last-failure time is the oldest, so it is the LRU entry.
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "victim");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.1"), "victim");
  ASSERT_TRUE(TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "victim").has_value());

  // Saturate the map with newer keys, then push one more to force eviction of the LRU entry.
  TestAccess{*server}.record_auth_failure(ip("10.0.0.2"), "u");
  TestAccess{*server}.record_auth_failure(ip("10.0.0.3"), "u");
  ASSERT_EQ(TestAccess{*server}.identity_throttle_size(), 3u);
  TestAccess{*server}.record_auth_failure(ip("10.0.0.4"), "u");

  EXPECT_EQ(TestAccess{*server}.identity_throttle_size(), 3u);  // stayed bounded
  EXPECT_FALSE(
    TestAccess{*server}.check_identity_lockout(ip("10.0.0.1"), "victim").has_value());  // LRU evicted
}

// ---------------------------------------------------------------------------
// S10: Per-IP connection throttling behavior
// ---------------------------------------------------------------------------

namespace
{

/// Creates a connected TCP socket pair on loopback. Returns (server-side socket, client-side socket).
std::pair<boost::asio::ip::tcp::socket, boost::asio::ip::tcp::socket> make_loopback_pair(
  boost::asio::io_context& ioc)
{
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();

  boost::asio::ip::tcp::socket client(ioc);
  client.connect({boost::asio::ip::address_v4::loopback(), port});

  auto serverSock = acceptor.accept();
  return {std::move(serverSock), std::move(client)};
}

/// Creates a TcpTransportConnection from a loopback socket pair. Keeps the client socket alive in the
/// returned pair so the connection stays open.
std::pair<shared_ptr<TcpTransportConnection>, boost::asio::ip::tcp::socket> make_loopback_transport(
  boost::asio::io_context& ioc)
{
  auto [serverSock, clientSock] = make_loopback_pair(ioc);
  auto transport = TcpTransportConnection::create(std::move(serverSock));
  return {std::move(transport), std::move(clientSock)};
}

}  // namespace

class ServerThrottlingConnection : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
    // A closing transport queues its continuation on mIoc, and that continuation holds a strand of
    // mPool. Run it now, while mPool's strand service exists, rather than let ~io_context destroy it
    // after mPool is gone.
    mIoc.restart();
    while (mIoc.poll() > 0)
    {
    }
  }

  // mIoc is declared first so it is destroyed last. mPool's queued ops can
  // transitively own TcpTransportConnections whose sockets are bound to
  // mIoc's executor; if mIoc were destroyed before mPool, the pool's
  // io_context destructor would unwind those sockets through a freed
  // reactor.
  boost::asio::io_context mIoc;
  boost::asio::thread_pool mPool{1};
  boost::asio::any_io_executor mExecutor{mPool.get_executor()};
};

TEST_F(ServerThrottlingConnection, AcceptedWhenBelowPerIpLimit)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 2;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  auto rejectedBefore =
    TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed);

  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);

  auto rejectedAfter =
    TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed);
  EXPECT_EQ(rejectedAfter, rejectedBefore);
}

TEST_F(ServerThrottlingConnection, RejectedWhenPerIpLimitReached)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // First connection - accepted.
  auto [transport1, client1] = make_loopback_transport(mIoc);
  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport1);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);

  // Second connection from same IP - should be rejected (per-IP limit is 1).
  auto [transport2, client2] = make_loopback_transport(mIoc);
  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport2);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 1u);
}

TEST_F(ServerThrottlingConnection, RateLimitExceeded)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 100;  // high active limit
  // Rate limit check fires when attempts.size() >= limit (attempt is recorded before the check),
  // so maxConnectionAttemptsPerMinute = 3 allows 2 connections before the 3rd triggers throttle.
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 3;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // First two connections - accepted (within rate limit).
  auto [transport1, client1] = make_loopback_transport(mIoc);
  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport1);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);

  auto [transport2, client2] = make_loopback_transport(mIoc);
  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport2);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);

  // Third - rate limit exceeded (3 attempts >= maxConnectionAttemptsPerMinute of 3).
  auto [transport3, client3] = make_loopback_transport(mIoc);
  TestAccess{*server}.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport3);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 1u);
}

// @relation(AC-SVR-TCP-040-ATTEMPT-HISTORY-BOUNDED, scope=function)
TEST_F(ServerThrottlingConnection, AttemptHistoryHoldsNoMoreThanTheRateLimitAndStillRefuses)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 100;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 3;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  std::vector<std::pair<shared_ptr<TcpTransportConnection>, boost::asio::ip::tcp::socket>> connections;
  for (int i = 0; i < 50; ++i)
  {
    connections.push_back(make_loopback_transport(mIoc));
    access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", connections.back().first);
  }

  // The first two are inside the rate limit; every later attempt within the minute is refused.
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 48u);
  EXPECT_EQ(access.per_ip_recent_attempt_count("127.0.0.1"), 3u);
}

TEST_F(ServerThrottlingConnection, DisabledThrottlingAcceptsAll)
{
  ServerConfig cfg;
  cfg.connectionThrottling.enabled = false;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 1;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));

  // Open more connections than the limit - all should be accepted since throttling is disabled.
  std::vector<std::pair<shared_ptr<TcpTransportConnection>, boost::asio::ip::tcp::socket>> connections;
  for (int i = 0; i < 3; ++i)
  {
    connections.push_back(make_loopback_transport(mIoc));
    TestAccess{*server}.new_tcp_connection(
      ListenerHandle{1}, "TestListener", Status::Good, "", connections.back().first);
  }

  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);
}

// ---------------------------------------------------------------------------
// A handshake that fails must release everything the accept path reserved for it: the entry in the
// initialising-connection list (counted against MaxConnections) and the per-IP concurrent slot.
// ---------------------------------------------------------------------------

namespace
{

/// Pumps the loopback io_context that owns the server-side socket until `predicate` holds or
/// `timeout` elapses. The ConnectionProtocol runs on the pool; the test thread only drives the socket.
template<typename Predicate>
bool pump_until(boost::asio::io_context& ioc, Predicate predicate, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    ioc.poll();
    ioc.restart();
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  return predicate();
}

/// An 8-byte frame whose message type is not HEL. The server handshake refuses it.
std::vector<unsigned char> not_a_hello_frame()
{
  return {'X', 'X', 'X', 'F', 8, 0, 0, 0};
}

/// A stalled fake-transport ConnectionProtocol, for completing a handshake through the test access.
struct FakeConnectionBundle
{
  shared_ptr<test_helpers::FakeConnectionProtocolDeps> deps;
  shared_ptr<test_helpers::FakeTransportConnection> transport;
  shared_ptr<ConnectionProtocol> protocol;
};

FakeConnectionBundle make_fake_connection(boost::asio::any_io_executor ex)
{
  FakeConnectionBundle bundle;
  bundle.deps = std::make_shared<test_helpers::FakeConnectionProtocolDeps>(ex);
  bundle.transport = std::make_shared<test_helpers::FakeTransportConnection>();
  bundle.transport->stall_reads();
  bundle.protocol = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    bundle.deps,
    bundle.transport,
    false,
    std::chrono::seconds{0},
    [](StatusCode,
      shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [](StatusCode, string_view, ua::FatalCloseDisposition) {});
  return bundle;
}

}  // namespace

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, RejectedFirstFrameReleasesThePerIpSlotAndTheInitialisingEntry)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);
  ASSERT_EQ(access.initialising_connection_count(), 1u);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  const auto frame = not_a_hello_frame();
  boost::asio::write(clientSock, boost::asio::buffer(frame));

  ASSERT_TRUE(pump_until(
    mIoc, [&] { return access.initialising_connection_count() == 0; }, std::chrono::seconds{3}))
    << "a refused first frame must remove the connection from the initialising list";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 0u)
    << "the per-IP concurrent slot reserved at accept must be released when the handshake fails";

  // The slot is free in fact, not only in the counter: a second connection from the same address is
  // admitted where the limit of 1 would otherwise refuse it.
  const auto rejectedBefore = access.connection_counters()->rejectedCount.load(std::memory_order_relaxed);
  auto [second, secondClient] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", second);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), rejectedBefore);
}

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, PeerClosingBeforeHelloReleasesThePerIpSlotAndTheInitialisingEntry)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);
  ASSERT_EQ(access.initialising_connection_count(), 1u);

  clientSock.close();

  ASSERT_TRUE(pump_until(
    mIoc, [&] { return access.initialising_connection_count() == 0; }, std::chrono::seconds{3}))
    << "a peer that disconnects before HEL must be removed from the initialising list";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 0u);
}

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, FailedHandshakeDoesNotOccupyAMaxConnectionsSlot)
{
  ServerConfig cfg;
  cfg.maxConnections = 1;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 10;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);
  const auto frame = not_a_hello_frame();
  boost::asio::write(clientSock, boost::asio::buffer(frame));
  ASSERT_TRUE(
    pump_until(mIoc, [&] { return access.initialising_connection_count() == 0; }, std::chrono::seconds{3}));

  // With MaxConnections = 1 the failed handshake, were it still counted, would make this completion
  // the second connection and it would be answered with ERR Bad_MaxConnectionsReached.
  const auto rejectedBefore = access.connection_counters()->rejectedCount.load(std::memory_order_relaxed);
  auto completed = make_fake_connection(mExecutor);
  access.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, completed.protocol, {}, "127.0.0.1:1");
  EXPECT_FALSE(completed.transport->wait_for_write_count(1, std::chrono::milliseconds{300}))
    << "the completed handshake must be admitted, not answered with an ERR frame";
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), rejectedBefore);
}

// The ConnectionProtocol starts reading inside ConnectionProtocol::create, so a peer whose refused
// frame is already buffered when the connection is accepted can fail its handshake before the accept
// path publishes the initialising entry. That early failure must still release the reservation.
// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, HandshakeThatFailsBeforeTheEntryIsPublishedIsStillReleased)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const auto frame = not_a_hello_frame();
  boost::asio::write(clientSock, boost::asio::buffer(frame));  // buffered before accept

  // In the window between protocol creation and publication, drive the socket side until the server
  // has refused the frame and closed the connection (the client then reads end-of-stream).
  clientSock.non_blocking(true);
  access.set_before_initialising_publication(
    [&]
    {
      std::array<char, 16> sink{};
      boost::system::error_code readError;
      ASSERT_TRUE(pump_until(
        mIoc,
        [&]
        {
          clientSock.read_some(boost::asio::buffer(sink), readError);
          return readError && readError != boost::asio::error::would_block;
        },
        std::chrono::seconds{3}))
        << "the refused frame must make the server close the connection";
    });

  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);

  EXPECT_EQ(access.initialising_connection_count(), 0u)
    << "a handshake that failed before publication must not be published";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 0u)
    << "the per-IP reservation must be released although no entry ever carried it";
}

// ---------------------------------------------------------------------------
// A handshake that COMPLETES in the window before publication is released exactly once, with exactly
// one close event when the completion is refused, and never recast as a failure by the close that
// follows the refusal.
// ---------------------------------------------------------------------------

namespace
{

void append_uint32(std::vector<unsigned char>& out, uint32_t value)
{
  for (int shift = 0; shift < 32; shift += 8)
  {
    out.push_back(static_cast<unsigned char>((value >> shift) & 0xFF));
  }
}

/// A conforming HEL frame for the test listener, hand-rolled so the SDK's own encoder is not both
/// the sender and the oracle.
std::vector<unsigned char> hello_frame_for_test_listener()
{
  const std::string endpointUrl = "opc.tcp://127.0.0.1:4840";
  std::vector<unsigned char> body;
  append_uint32(body, 0u);  // ProtocolVersion
  append_uint32(body, 65536u);  // ReceiveBufferSize
  append_uint32(body, 65536u);  // SendBufferSize
  append_uint32(body, 1u << 20);  // MaxMessageSize
  append_uint32(body, 64u);  // MaxChunkCount
  append_uint32(body, static_cast<uint32_t>(endpointUrl.size()));
  body.insert(body.end(), endpointUrl.begin(), endpointUrl.end());
  std::vector<unsigned char> frame{'H', 'E', 'L', 'F'};
  append_uint32(frame, static_cast<uint32_t>(8 + body.size()));
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

struct CloseEvent
{
  ConnectionCloseReason reason;
  StatusCode status;
  std::string remoteAddress;
};

/// Records every connection-closed event the server emits.
class RecordingObserver final : public ServerObserver
{
public:
  void on_connection_closed(
    const std::string& remoteAddress, ConnectionCloseReason reason, StatusCode status) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCloses.push_back(CloseEvent{reason, status, remoteAddress});
  }

  std::vector<CloseEvent> closes() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mCloses;
  }

private:
  mutable std::mutex mMutex;
  std::vector<CloseEvent> mCloses;
};

/// Reads from `clientSock` (non-blocking) until `bytesWanted` bytes arrived or the peer closed.
/// Returns true when the peer closed the connection.
bool pump_until_ack_or_close(boost::asio::io_context& ioc, boost::asio::ip::tcp::socket& clientSock,
  size_t bytesWanted, std::chrono::milliseconds timeout)
{
  size_t received = 0;
  bool closed = false;
  std::array<char, 64> sink{};
  pump_until(
    ioc,
    [&]
    {
      boost::system::error_code readError;
      const auto n = clientSock.read_some(boost::asio::buffer(sink), readError);
      if (!readError)
      {
        received += n;
      }
      else if (readError != boost::asio::error::would_block)
      {
        closed = true;
      }
      return closed || received >= bytesWanted;
    },
    timeout);
  return closed;
}

}  // namespace

// The close event of a handshake that failed before the accept path published it names the peer: the
// address was moved into the completion callback before the event was emitted, so the event carried an
// empty string.
// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, AHandshakeThatFailsBeforePublicationReportsTheClosedPeer)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};
  auto observer = std::make_shared<RecordingObserver>();
  access.add_internal_observer(observer);

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const auto frame = not_a_hello_frame();
  boost::asio::write(clientSock, boost::asio::buffer(frame));  // buffered before accept
  clientSock.non_blocking(true);
  access.set_before_initialising_publication(
    [&]
    {
      std::array<char, 16> sink{};
      boost::system::error_code readError;
      ASSERT_TRUE(pump_until(
        mIoc,
        [&]
        {
          clientSock.read_some(boost::asio::buffer(sink), readError);
          return readError && readError != boost::asio::error::would_block;
        },
        std::chrono::seconds{3}));
    });

  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);

  bool reported = false;
  for (const auto& close : observer->closes())
  {
    if (close.reason == ConnectionCloseReason::ProtocolError)
    {
      reported = true;
      EXPECT_EQ(close.remoteAddress.rfind("127.0.0.1:", 0), 0u)
        << "the close event must name the peer, got '" << close.remoteAddress << "'";
    }
  }
  EXPECT_TRUE(reported) << "the failed handshake must be reported as a protocol-error close";
}

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
// @verifies AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED
TEST_F(ServerThrottlingConnection, HandshakeThatCompletesBeforeTheEntryIsPublishedReleasesTheReservationOnce)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 2;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  // The HEL names the configured listener; the endpoint-URL validator needs the listener published.
  TestAccess{*server}.initialise_listeners_from_config();
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);
  auto observer = std::make_shared<RecordingObserver>();
  access.add_internal_observer(observer);

  // A second connection from the same address holds one reservation across the window, so a double
  // release of the connection under test would show as a count of 0 instead of 1.
  auto [holderTransport, holderSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", holderTransport);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(clientSock, boost::asio::buffer(hello));  // buffered before accept
  clientSock.non_blocking(true);

  // In the window before publication: the server answers with ACK (28 bytes) and admits the channel.
  access.set_before_initialising_publication(
    [&]
    {
      ASSERT_FALSE(pump_until_ack_or_close(mIoc, clientSock, 28, std::chrono::seconds{3}))
        << "the handshake must complete with an ACK, not a close";
      ASSERT_TRUE(pump_until(
        mIoc,
        [&] { return access.connection_counters()->currentCount.load() == 1; },
        std::chrono::seconds{3}))
        << "the completed handshake must have been admitted before publication runs";
    });

  auto admission = std::make_shared<std::promise<shared_ptr<SecureChannel>>>();
  auto admitted = admission->get_future();
  access.set_on_secure_channel_available(
    [admission](shared_ptr<SecureChannel> channel) { admission->set_value(std::move(channel)); });

  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);

  // The diagnostic counter advances before channel construction. Wait for registration before
  // reading the callback result or removing the channel; the existing deadline remains unchanged.
  ASSERT_TRUE(pump_until(mIoc, [&] { return access.secure_channel_count() == 1; }, std::chrono::seconds{3}));
  EXPECT_EQ(access.initialising_connection_count(), 1u)
    << "a handshake that completed before publication must not leave a stale initialising entry (only "
       "the holder remains)";
  // RATIFIED EXPECTATION CHANGE (group I, I-D4): the slot is held by the admitted channel, so the count
  // is the holder's plus the channel's; it was 1 while the slot was released at ACK.
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 2u)
    << "the reservation is carried by the admitted channel although no initialising entry ever held it "
       "(the holder's reservation remains beside it)";
  EXPECT_TRUE(observer->closes().empty()) << "an admitted connection has no close event";

  ASSERT_EQ(admitted.wait_for(std::chrono::seconds{0}), std::future_status::ready);
  auto channel = admitted.get();
  ASSERT_NE(channel, nullptr);
  access.remove_secure_channel(channel);
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 1u)
    << "released exactly once, when the channel is removed: the holder's remains";
  channel->close();
  channel.reset();
}

// @relation(AC-SVR-TCP-012-FAILED-HANDSHAKE-RELEASES-ADMISSION, scope=function)
TEST_F(ServerThrottlingConnection, HandshakeRefusedAtCompletionBeforePublicationEmitsExactlyOneCloseEvent)
{
  // RATIFIED TEST ADAPTATION (group I, I-D2): MaxConnections is now applied at accept too, so the
  // refusal at completion is reached only when the count rises DURING the handshake: the ceiling is 3,
  // one occupant is in place before the accept and a second completes inside the window.
  ServerConfig cfg;
  cfg.maxConnections = 3;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 10;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  // The HEL names the configured listener; the endpoint-URL validator needs the listener published.
  TestAccess{*server}.initialise_listeners_from_config();
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);
  auto observer = std::make_shared<RecordingObserver>();
  access.add_internal_observer(observer);

  // One occupant before the accept; the second (below) completes inside the window, so the accept
  // gate sees 2 of 3 and the completion gate sees 3 of 3.
  auto occupant = make_fake_connection(mExecutor);
  access.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, occupant.protocol, {}, "127.0.0.1:1");
  auto secondOccupant = make_fake_connection(mExecutor);

  // A second connection from the same address holds one reservation across the window, so a double
  // release of the connection under test would show as a count of 0 instead of 1.
  auto [holderTransport, holderSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", holderTransport);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(clientSock, boost::asio::buffer(hello));
  clientSock.non_blocking(true);

  // In the window before publication: ACK, then the refusal (ERR Bad_MaxConnectionsReached) and the
  // close that follows it, all observed by the peer as end-of-stream.
  access.set_before_initialising_publication(
    [&]
    {
      access.new_connection_complete(
        ListenerHandle{1}, "TestListener", Status::Good, secondOccupant.protocol, {}, "127.0.0.1:2");
      ASSERT_TRUE(pump_until_ack_or_close(mIoc, clientSock, SIZE_MAX, std::chrono::seconds{3}))
        << "the refused completion must close the connection before publication runs";
    });

  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);

  EXPECT_EQ(access.initialising_connection_count(), 1u) << "only the holder remains";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 1u) << "released exactly once: the holder's remains";
  const auto closes = observer->closes();
  ASSERT_EQ(closes.size(), 1u)
    << "exactly one close event: the refusal, not a second one for the close it caused";
  EXPECT_EQ(closes.front().reason, ConnectionCloseReason::MaxConnections);
  EXPECT_EQ(closes.front().status, Status::BadMaxConnectionsReached);
}

// ---------------------------------------------------------------------------
// Group I: MaxConnections at accept, the per-IP slot held with the channel, the throttle key.
// ---------------------------------------------------------------------------

// MaxConnections is applied at accept as well as after the ACK: a socket arriving at the ceiling is
// closed before a ConnectionProtocol (strand, timers, read buffer) exists for it, counted as
// rejected, reported as a MaxConnections close, and consumes no per-IP slot.
// @verifies AC-SVR-TCP-012-MAXCONNECTIONS-IS-APPLIED-AT-ACCEPT
TEST_F(ServerThrottlingConnection, AConnectionArrivingAtMaxConnectionsIsClosedAtAcceptBeforeAnyHandshake)
{
  ServerConfig cfg;
  cfg.maxConnections = 1;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 10;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);
  auto observer = std::make_shared<RecordingObserver>();
  access.add_internal_observer(observer);

  auto [first, firstSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", first);
  ASSERT_EQ(access.initialising_connection_count(), 1u);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  auto [second, secondSock] = make_loopback_transport(mIoc);
  secondSock.non_blocking(true);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", second);

  EXPECT_EQ(access.initialising_connection_count(), 1u) << "no handshake was started for the refused socket";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 1u) << "the refused socket holds no per-IP slot";
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 1u);
  EXPECT_TRUE(pump_until_ack_or_close(mIoc, secondSock, SIZE_MAX, std::chrono::seconds{3}))
    << "the refused socket is closed";
  const auto closes = observer->closes();
  ASSERT_EQ(closes.size(), 1u);
  EXPECT_EQ(closes.front().reason, ConnectionCloseReason::MaxConnections);
  EXPECT_EQ(closes.front().status, Status::BadMaxConnectionsReached);
}

// Control: one below the ceiling, the second socket starts its handshake.
// @verifies AC-SVR-TCP-012-MAXCONNECTIONS-IS-APPLIED-AT-ACCEPT
TEST_F(ServerThrottlingConnection, AConnectionArrivingBelowMaxConnectionsStartsItsHandshake)
{
  ServerConfig cfg;
  cfg.maxConnections = 2;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 10;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);

  auto [first, firstSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", first);
  auto [second, secondSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", second);

  EXPECT_EQ(access.initialising_connection_count(), 2u);
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 2u);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);
}

// The per-IP slot reserved at accept is held for as long as the connection is with the server: through
// the handshake AND while the channel it became is open. MaxConnectionsPerEndpoint therefore bounds
// concurrent connections from one remote, as its documentation says, not concurrent handshakes: a
// second connection from the address is refused while the channel lives and admitted once it is gone.
// @verifies AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED
TEST_F(ServerThrottlingConnection, ThePerIpSlotIsHeldWhileTheChannelIsOpenAndReleasedWhenItIsRemoved)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.initialise_listeners_from_config();
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);

  std::mutex channelMutex;
  shared_ptr<SecureChannel> admitted;
  access.set_on_secure_channel_available(
    [&](shared_ptr<SecureChannel> channel)
    {
      const std::lock_guard<std::mutex> lock(channelMutex);
      admitted = std::move(channel);
    });

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  // Complete the handshake over the real socket: ACK, then the channel is created.
  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(clientSock, boost::asio::buffer(hello));
  clientSock.non_blocking(true);
  ASSERT_FALSE(pump_until_ack_or_close(mIoc, clientSock, 28, std::chrono::seconds{3}))
    << "the handshake must complete with an ACK";
  ASSERT_TRUE(pump_until(mIoc, [&] { return access.secure_channel_count() == 1; }, std::chrono::seconds{3}));
  ASSERT_EQ(access.initialising_connection_count(), 0u);

  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 1u)
    << "the slot is held by the open channel, not released at ACK";
  const auto rejectedBefore = access.connection_counters()->rejectedCount.load(std::memory_order_relaxed);
  auto [second, secondSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", second);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), rejectedBefore + 1)
    << "a second connection from the address is refused while the channel holds the only slot";

  shared_ptr<SecureChannel> channel;
  {
    const std::lock_guard<std::mutex> lock(channelMutex);
    channel = admitted;
  }
  ASSERT_NE(channel, nullptr);

  // The peer disconnects: the production teardown (transport error -> channel close -> removal from
  // the server) is what releases the slot, not a call into the server.
  clientSock.close();
  EXPECT_TRUE(pump_until(
    mIoc, [&] { return access.per_ip_active_count("127.0.0.1") == 0; }, std::chrono::seconds{3}))
    << "the peer's disconnect must release the slot through the channel's removal";
  EXPECT_EQ(access.secure_channel_count(), 0u);

  auto [third, thirdSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", third);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(std::memory_order_relaxed), rejectedBefore + 1)
    << "the slot is free again";

  channel.reset();
}

// The throttle key: an IPv4 address is itself and a v4-mapped IPv6 address is the IPv4 it carries,
// whatever the prefix length; a native IPv6 address is itself at the default prefix (128).
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST(ServerThrottlingKey, IPv4AndV4MappedAddressesAreKeyedByTheIPv4AddressAndIPv6ByItselfAtTheDefault)
{
  EXPECT_EQ(ServerImpl::connection_throttle_key(ip("10.0.0.1"), 128), "10.0.0.1");
  EXPECT_EQ(ServerImpl::connection_throttle_key(ip("::ffff:10.0.0.1"), 128), "10.0.0.1")
    << "a v4-mapped address shares the budget of the IPv4 it carries";
  EXPECT_EQ(ServerImpl::connection_throttle_key(ip("::ffff:10.0.0.1"), 64), "10.0.0.1")
    << "the prefix length is an IPv6 setting";
  EXPECT_NE(ServerImpl::connection_throttle_key(ip("2001:db8:1:2:3:4:5:6"), 128),
    ServerImpl::connection_throttle_key(ip("2001:db8:1:2:3:4:5:7"), 128))
    << "at the default every IPv6 host is its own remote";
}

// With a 64-bit prefix configured, every address of one /64 is one remote and another /64 is another.
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST(ServerThrottlingKey, AConfiguredPrefixGroupsTheIPv6AddressesItCovers)
{
  const auto a = ServerImpl::connection_throttle_key(ip("2001:db8:1:2:3:4:5:6"), 64);
  const auto b = ServerImpl::connection_throttle_key(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"), 64);
  const auto c = ServerImpl::connection_throttle_key(ip("2001:db8:1:3::1"), 64);
  EXPECT_EQ(a, "2001:db8:1:2::/64");
  EXPECT_EQ(a, b) << "two interface ids in one /64 are one remote";
  EXPECT_NE(a, c) << "a different /64 is a different remote";
  EXPECT_EQ(ServerImpl::connection_throttle_key(ip("2001:db8:1:2:3:4:5:6"), 60), "2001:db8:1::/60")
    << "a prefix that ends inside a byte masks the remaining bits";
}

// The accept path derives the key with the configured prefix: an IPv6 peer accepted with a 64-bit
// prefix is counted under its /64 key, not under its address (a revert to keying by the address
// string would count it under "::1"). The peer endpoint is given to the accept path over an IPv4
// loopback socket, so the arm runs on a host without IPv6 loopback.
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST_F(ServerThrottlingConnection, AnIPv6PeerIsCountedUnderTheConfiguredPrefixKeyAtAccept)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 10;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  cfg.connectionThrottling.ipv6PrefixLength = 64;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const boost::asio::ip::tcp::endpoint ipv6Peer{boost::asio::ip::address_v6::loopback(), 40000};
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", transport, ipv6Peer);

  EXPECT_EQ(access.per_ip_active_count("::/64"), 1u) << "::1 masked to 64 bits";
  EXPECT_EQ(access.per_ip_active_count("::1"), 0u) << "not keyed by the address string";
}

// A channel that fails to come into being after the admission gates (here: the channel-available
// hook throws) leaves the connection with neither an initialising entry nor a channel, and the slot
// it reserved is released on that path too.
// @verifies AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED
TEST_F(ServerThrottlingConnection, AChannelThatFailsToComeIntoBeingReleasesTheSlot)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.initialise_listeners_from_config();
  TestAccess access{*server};
  access.set_on_secure_channel_available(
    [](shared_ptr<SecureChannel>) { throw std::runtime_error{"the channel could not be set up"}; });

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport);
  ASSERT_EQ(access.per_ip_active_count("127.0.0.1"), 1u);

  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(clientSock, boost::asio::buffer(hello));
  clientSock.non_blocking(true);
  EXPECT_TRUE(pump_until(
    mIoc, [&] { return access.per_ip_active_count("127.0.0.1") == 0; }, std::chrono::seconds{3}))
    << "the failed channel setup must release the slot";
  EXPECT_EQ(access.secure_channel_count(), 0u);
  EXPECT_EQ(access.initialising_connection_count(), 0u);
}

// A throw between the reservation and the publication of the protocol (here: the pre-publication test
// hook) leaves the transport without a protocol; the slot it reserved is released on that path too,
// instead of staying keyed by a transport that is about to be freed.
// @verifies AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED
TEST_F(ServerThrottlingConnection, AThrowBeforeTheProtocolIsPublishedReleasesTheSlot)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 1;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess access{*server};
  access.set_before_initialising_publication([] { throw std::runtime_error{"publication failed"}; });

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  EXPECT_ANY_THROW(access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport));

  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 0u) << "the slot must not stay with a lost transport";
  EXPECT_EQ(access.initialising_connection_count(), 0u);
}

// A link-local peer is keyed whole (scope id included) whatever the prefix: with a prefix below 128
// every link-local peer of every interface would otherwise share one key.
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST(ServerThrottlingKey, ALinkLocalAddressIsNeverMaskedByThePrefix)
{
  // The key is the address as it renders itself (Asio spells the scope id by interface name where one
  // exists, e.g. "%lo" for index 1), unmasked.
  EXPECT_EQ(ServerImpl::connection_throttle_key(ip("fe80::1%1"), 64), ip("fe80::1%1").to_v6().to_string());
  EXPECT_NE(ServerImpl::connection_throttle_key(ip("fe80::1%1"), 64), "fe80::/64") << "not masked";
  EXPECT_NE(ServerImpl::connection_throttle_key(ip("fe80::1%1"), 64),
    ServerImpl::connection_throttle_key(ip("fe80::1%2"), 64))
    << "the same link-local address on two interfaces is two remotes";
}

// The guard that releases the slot on a throw before publication does not touch a slot that a
// handshake completed inside the accept call has already handed to its channel.
// @verifies AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED
TEST_F(ServerThrottlingConnection, AThrowAfterAHandshakeCompletedInsideTheAcceptCallLeavesTheChannelsSlot)
{
  ServerConfig cfg;
  cfg.connectionThrottling.maxConnectionsPerEndpoint = 2;
  cfg.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(cfg));
  TestAccess{*server}.initialise_listeners_from_config();
  TestAccess access{*server};
  access.diagnostics_enabled()->store(true);

  auto [transport, clientSock] = make_loopback_transport(mIoc);
  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(clientSock, boost::asio::buffer(hello));  // buffered before accept
  clientSock.non_blocking(true);

  access.set_before_initialising_publication(
    [&]
    {
      ASSERT_FALSE(pump_until_ack_or_close(mIoc, clientSock, 28, std::chrono::seconds{3}));
      ASSERT_TRUE(
        pump_until(mIoc, [&] { return access.secure_channel_count() == 1; }, std::chrono::seconds{3}));
      throw std::runtime_error{"publication failed after the handshake completed"};
    });

  EXPECT_ANY_THROW(access.new_tcp_connection(ListenerHandle{1}, "TestListener", Status::Good, "", transport));

  EXPECT_EQ(access.secure_channel_count(), 1u) << "the admitted channel is unaffected";
  EXPECT_EQ(access.per_ip_active_count("127.0.0.1"), 1u) << "the channel still holds its slot";
}

// @relation(AC-SVR-TCP-040-THE-PER-IP-SLOT-IS-HELD-UNTIL-THE-CHANNEL-IS-REMOVED, scope=function)
TEST_F(ServerThrottlingConnection, LivePerIpReservationsSurviveMapCapacityAndReleaseExactlyOnce)
{
  ServerConfig config;
  config.connectionThrottling.maxTrackedEndpoints = 1;
  config.connectionThrottling.maxConnectionsPerEndpoint = 1;
  config.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
  auto server = create_test_server_impl(mExecutor, std::move(config));
  TestAccess access{*server};
  access.initialise_listeners_from_config();
  access.diagnostics_enabled()->store(true);
  const boost::asio::ip::tcp::endpoint firstRemote{ip("10.0.0.1"), 1001};
  const boost::asio::ip::tcp::endpoint otherRemote{ip("10.0.0.2"), 1002};

  auto channelPromise = std::make_shared<std::promise<shared_ptr<SecureChannel>>>();
  auto channelReady = channelPromise->get_future();
  access.set_on_secure_channel_available(
    [channelPromise](shared_ptr<SecureChannel> channel) { channelPromise->set_value(std::move(channel)); });
  auto [firstTransport, firstPeer] = make_loopback_transport(mIoc);
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", firstTransport, firstRemote);
  const auto hello = hello_frame_for_test_listener();
  boost::asio::write(firstPeer, boost::asio::buffer(hello));
  firstPeer.non_blocking(true);
  ASSERT_FALSE(pump_until_ack_or_close(mIoc, firstPeer, 28, std::chrono::seconds{3}));
  ASSERT_TRUE(pump_until(mIoc, [&] { return access.secure_channel_count() == 1; }, std::chrono::seconds{3}));
  ASSERT_EQ(channelReady.wait_for(std::chrono::seconds{0}), std::future_status::ready);
  auto firstChannel = channelReady.get();
  ASSERT_NE(firstChannel, nullptr);
  access.set_on_secure_channel_available({});
  ASSERT_EQ(access.per_ip_active_count("10.0.0.1"), 1u);
  ASSERT_EQ(access.per_ip_throttle_size(), 1u);

  auto [blockedOther, blockedOtherPeer] = make_loopback_transport(mIoc);
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", blockedOther, otherRemote);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 1u);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 1u)
    << "an untracked address must not replace a live reservation at map capacity";
  EXPECT_EQ(access.per_ip_active_count("10.0.0.2"), 0u);
  EXPECT_EQ(access.initialising_connection_count(), 0u);
  EXPECT_EQ(access.per_ip_throttle_size(), 1u);

  auto [blockedFirst, blockedFirstPeer] = make_loopback_transport(mIoc);
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", blockedFirst, firstRemote);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 2u);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 1u);
  EXPECT_EQ(access.initialising_connection_count(), 0u);

  access.remove_secure_channel(firstChannel);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 0u);
  auto [otherTransport, otherPeer] = make_loopback_transport(mIoc);
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", otherTransport, otherRemote);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 2u);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.2"), 1u)
    << "the inactive entry can be evicted after its owner releases the reservation";
  EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 0u);
  EXPECT_EQ(access.per_ip_throttle_size(), 1u);
  EXPECT_EQ(access.initialising_connection_count(), 1u);

  access.remove_secure_channel(firstChannel);
  firstChannel->close();
  EXPECT_EQ(access.per_ip_active_count("10.0.0.2"), 1u)
    << "releasing an old owner again must not decrement a replacement entry";
  EXPECT_EQ(access.per_ip_throttle_size(), 1u);
  otherPeer.close();
  ASSERT_TRUE(
    pump_until(mIoc, [&] { return access.per_ip_active_count("10.0.0.2") == 0; }, std::chrono::seconds{3}));
  auto [nextFirst, nextFirstPeer] = make_loopback_transport(mIoc);
  access.accept_tcp_connection(ListenerHandle{1}, "TestListener", nextFirst, firstRemote);
  EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 2u);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 1u);
  EXPECT_EQ(access.per_ip_active_count("10.0.0.2"), 0u);
  EXPECT_EQ(access.per_ip_throttle_size(), 1u);
  nextFirstPeer.close();
  EXPECT_TRUE(
    pump_until(mIoc, [&] { return access.per_ip_active_count("10.0.0.1") == 0; }, std::chrono::seconds{3}));
}

// Disabled: making the channel admission decision and its insertion one step (PAB-3) is deferred for
// the release (security_review_summary_and_status_2026_10_18.md, decisions of 2026-10-19); MaxConnections
// still bounds live sockets. This test asserts the deferred repair and is kept for it.
// @relation(AC-SVR-SC-002-EVICT-SESSIONLESS-CHANNEL, scope=function)
TEST_F(ServerThrottlingConnection, DISABLED_OverlappingChannelAdmissionsNeverExceedTheConfiguredMaximum)
{
  for (const bool initiallyFull : {false, true})
  {
    SCOPED_TRACE(initiallyFull);
    ServerConfig config;
    config.maxSecureChannels = 1;
    config.maxConnections = 10;
    auto server = create_test_server_impl(mExecutor, std::move(config));
    TestAccess access{*server};
    auto occupant = make_fake_connection(mExecutor);
    if (initiallyFull)
    {
      access.new_connection_complete(
        ListenerHandle{1}, "TestListener", Status::Good, occupant.protocol, {}, "10.0.0.1:1");
      ASSERT_EQ(access.secure_channel_count(), 1u);
    }

    auto callbackCalls = std::make_shared<std::atomic<unsigned>>(0);
    auto firstEntered = std::make_shared<std::promise<void>>();
    auto firstReady = firstEntered->get_future();
    auto releaseFirst = std::make_shared<std::promise<void>>();
    auto released = releaseFirst->get_future().share();
    auto channels = std::make_shared<std::vector<shared_ptr<SecureChannel>>>();
    auto channelsMutex = std::make_shared<std::mutex>();
    access.set_on_secure_channel_available(
      [callbackCalls, firstEntered, released, channels, channelsMutex](shared_ptr<SecureChannel> channel)
      {
        {
          const std::lock_guard lock(*channelsMutex);
          channels->push_back(std::move(channel));
        }
        if (callbackCalls->fetch_add(1) == 0)
        {
          firstEntered->set_value();
          released.wait();
        }
      });

    auto first = make_fake_connection(mExecutor);
    auto second = make_fake_connection(mExecutor);
    auto firstAdmission = std::async(std::launch::async,
      [server, protocol = first.protocol]
      {
        TestAccess{*server}.new_connection_complete(
          ListenerHandle{1}, "TestListener", Status::Good, protocol, {}, "10.0.0.2:2");
      });
    const auto firstStatus = firstReady.wait_for(std::chrono::seconds{5});
    EXPECT_EQ(firstStatus, std::future_status::ready);
    auto secondAdmission = std::async(std::launch::async,
      [server, protocol = second.protocol]
      {
        TestAccess{*server}.new_connection_complete(
          ListenerHandle{1}, "TestListener", Status::Good, protocol, {}, "10.0.0.3:3");
      });
    const auto secondStatus = secondAdmission.wait_for(std::chrono::seconds{5});
    // Always release the first callback before any fatal assertion or future destruction.
    releaseFirst->set_value();
    EXPECT_EQ(secondStatus, std::future_status::ready)
      << "an outstanding application callback must not hold admission's mutex";
    EXPECT_NO_THROW(firstAdmission.get());
    EXPECT_NO_THROW(secondAdmission.get());
    EXPECT_LE(access.secure_channel_count(), 1u)
      << "overlapping decision, construction and publication must share the configured capacity";
    EXPECT_EQ(access.secure_channel_count(), 1u) << "one valid completed handshake remains admitted";

    for (const auto& channel : *channels)
    {
      access.remove_secure_channel(channel);
      access.remove_secure_channel(channel);
      channel->close();
    }
    EXPECT_EQ(access.secure_channel_count(), 0u);
    access.set_on_secure_channel_available({});
    auto afterRelease = make_fake_connection(mExecutor);
    access.new_connection_complete(
      ListenerHandle{1}, "TestListener", Status::Good, afterRelease.protocol, {}, "10.0.0.4:4");
    EXPECT_EQ(access.secure_channel_count(), 1u) << "the removed channel's capacity is reusable";
  }
}

// @relation(AC-SVR-SC-002-EVICT-SESSIONLESS-CHANNEL, scope=function)
TEST_F(ServerThrottlingConnection, AFailedChannelConstructionRestoresAdmissionCapacity)
{
  ServerConfig config;
  config.maxSecureChannels = 1;
  config.maxConnections = 10;
  auto server = create_test_server_impl(mExecutor, std::move(config));
  TestAccess access{*server};
  access.set_on_secure_channel_available(
    [](shared_ptr<SecureChannel>) { throw std::runtime_error{"channel construction failed"}; });
  auto failed = make_fake_connection(mExecutor);
  EXPECT_THROW(access.new_connection_complete(
                 ListenerHandle{1}, "TestListener", Status::Good, failed.protocol, {}, "10.0.0.1:1"),
    std::runtime_error);
  EXPECT_EQ(access.secure_channel_count(), 0u);

  access.set_on_secure_channel_available({});
  auto control = make_fake_connection(mExecutor);
  EXPECT_NO_THROW(access.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, control.protocol, {}, "10.0.0.2:2"));
  EXPECT_EQ(access.secure_channel_count(), 1u)
    << "failed construction must release the admission reservation";
}

// @relation(AC-SVR-TCP-040-THROTTLE-LOG-CALLBACK-OUTSIDE-SERVER-LOCK, scope=function)
TEST_F(ServerThrottlingConnection, ThrottleWarningsPermitReentrantEndpointQueries)
{
  for (const bool rateLimit : {false, true})
  {
    SCOPED_TRACE(rateLimit);
    ServerConfig config;
    config.connectionThrottling.maxConnectionsPerEndpoint = 1;
    config.connectionThrottling.maxConnectionAttemptsPerMinute = 100;
    if (rateLimit)
    {
      config.connectionThrottling.maxConnectionsPerEndpoint = 100;
      config.connectionThrottling.maxConnectionAttemptsPerMinute = 2;
    }
    auto sink = std::make_shared<ThrottlingLogSink>();
    auto server = create_test_server_impl(mExecutor, std::move(config), sink);
    sink->server = server;
    TestAccess access{*server};
    access.initialise_listeners_from_config();
    access.diagnostics_enabled()->store(true);
    const boost::asio::ip::tcp::endpoint firstRemote{ip("10.0.0.1"), 1001};
    const boost::asio::ip::tcp::endpoint otherRemote{ip("10.0.0.2"), 1002};

    auto [holder, holderPeer] = make_loopback_transport(mIoc);
    access.accept_tcp_connection(ListenerHandle{1}, "TestListener", holder, firstRemote);
    EXPECT_EQ(sink->warningCalls.load(), 0u);
    EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 1u);
    auto [refused, refusedPeer] = make_loopback_transport(mIoc);
    access.accept_tcp_connection(ListenerHandle{1}, "TestListener", refused, firstRemote);
    EXPECT_EQ(sink->warningCalls.load(), 1u);
    EXPECT_EQ(sink->outsideMutex.load(), 1u) << "the configured LogSink must run after mMutex is released";
    EXPECT_EQ(sink->endpointQueries.load(), 1u);
    EXPECT_EQ(sink->matchingEndpointQueries.load(), 1u);
    EXPECT_EQ(access.per_ip_active_count("10.0.0.1"), 1u);
    EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 1u);

    holderPeer.close();
    ASSERT_TRUE(
      pump_until(mIoc, [&] { return access.per_ip_active_count("10.0.0.1") == 0; }, std::chrono::seconds{3}));
    auto [control, controlPeer] = make_loopback_transport(mIoc);
    access.accept_tcp_connection(ListenerHandle{1}, "TestListener", control, otherRemote);
    EXPECT_EQ(access.per_ip_active_count("10.0.0.2"), 1u);
    EXPECT_EQ(access.connection_counters()->rejectedCount.load(), 1u);
    EXPECT_EQ(sink->warningCalls.load(), 1u);
    controlPeer.close();
    EXPECT_TRUE(
      pump_until(mIoc, [&] { return access.per_ip_active_count("10.0.0.2") == 0; }, std::chrono::seconds{3}));
  }
}
