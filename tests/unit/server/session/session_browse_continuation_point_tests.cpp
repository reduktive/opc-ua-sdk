// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_server_impl.h"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/strand.hpp>

#include "ua_create_session_request.h"
#include "ua_security_policy.h"

#include "ua_browse_response.h"

// Test-only access to SecureChannel interfaces/state without exposing them publicly.
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"

// Test-only access to Session interfaces/state without exposing them publicly.
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

shared_ptr<ServerImpl> create_test_server_impl_with_caps(boost::asio::any_io_executor ex,
  ServerConfig::ServerCapabilities caps,
  std::optional<std::chrono::milliseconds> browseCpTimeout = std::nullopt)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.server_capabilities() = std::move(caps);
  if (browseCpTimeout)
    sc.browseContinuationPointTimeout = *browseCpTimeout;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
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

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  auto server = ua::server::ServerImpl::create(
    ex, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

struct ScHarness
{
  boost::asio::thread_pool threadPool;
  boost::asio::any_io_executor executor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> strand;

  shared_ptr<ServerImpl> server;
  weak_ptr<SecureChannelDependencies> deps;
  shared_ptr<SecureChannel> sc;
};

std::unique_ptr<ScHarness> create_secure_channel_harness_with_caps(ServerConfig::ServerCapabilities caps,
  std::optional<std::chrono::milliseconds> browseCpTimeout = std::nullopt)
{
  auto h = std::make_unique<ScHarness>();
  h->executor = h->threadPool.get_executor();
  h->strand = boost::asio::make_strand(h->executor);

  h->server = create_test_server_impl_with_caps(h->executor, std::move(caps), browseCpTimeout);
  h->deps = TestAccess{*h->server}.secure_channel_dependencies();

  h->sc = ua::server::SecureChannel::create(
    h->deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");

  // Ensure the server tracks this secure channel for service routing.
  TestAccess{*h->server}.add_secure_channel(h->sc);

  // Minimal context required by the secure channel shell.
  SecureChannelTestAccess::on_strand(
    *h->sc, [&](auto& g) { g.set_minimal_context_none(h->executor, "TestListener/None"); });

  return h;
}

shared_ptr<Session> create_session(ScHarness& h)
{
  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  req.session_name() = "test";
  req.client_description().application_name().text() = "client";

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(h.sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*h.sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  return Session::create(TestAccess{*h.server}.session_dependencies(), info, 1, std::move(req));
}

BrowseContinuationPoint make_dummy_continuation_point()
{
  ViewDescription view;
  BrowseDescription desc;
  return BrowseContinuationPoint{std::move(view), Counter{0}, desc};
}

std::pair<Response, std::shared_ptr<BrowseResponse>> make_browse_response_with_cp(
  uint32_t requestId, const Guid& cpId)
{
  auto resp = std::make_shared<BrowseResponse>();
  resp->results().resize(1);

  auto enc = cpId.as_ua_binary();
  ByteString cpBytes{span<const byte>{enc}};

  resp->results()[0].continuation_point() = std::move(cpBytes);

  return {Response{requestId, resp}, resp};
}

}  // namespace

// @relation(SVR-VIEW-CPT-002, SVR-VIEW-URG-002, scope=function)
TEST(SessionBrowseContinuationPointTests, MaxBrowseContinuationPointsZeroRejectsStorage)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxBrowseContinuationPoints = 0;
  auto h = create_secure_channel_harness_with_caps(std::move(caps), 10s);
  auto session = create_session(*h);

  auto cp = make_dummy_continuation_point();
  auto [response, respPtr] = make_browse_response_with_cp(10u, cp.identifier());

  std::vector<BrowseContinuationPoint> cps;
  cps.push_back(std::move(cp));

  ASSERT_NO_THROW(SessionTestAccess::on_strand(*session,
    [&](auto& g)
    { g.browse_response_received(std::move(std::move(response)), std::move(std::move(cps))); }););

  ASSERT_EQ(respPtr->results().size(), 1u);
  EXPECT_TRUE(respPtr->results()[0].continuation_point().empty());
  EXPECT_EQ(respPtr->results()[0].status_code(), Status::BadNoContinuationPoints);

  EXPECT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    0u);

  session->terminate_for_shutdown();
  session.reset();
  h->sc.reset();
  h->server.reset();
  h->strand.reset();
  h->executor = {};
  ::ua::test_utils::drain_with_timeout(h->threadPool);
}

// @relation(SVR-ATTR-CP-002, SVR-ATTR-CP-003, SVR-ATTR-CP-006, SVR-ATTR-HUPD-013, SVR-VIEW-CPT-003, SVR-VIEW-URG-002, scope=function)
TEST(SessionBrowseContinuationPointTests, MaxBrowseContinuationPointsOneAutoFreesOldForNew)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxBrowseContinuationPoints = 1;
  auto h = create_secure_channel_harness_with_caps(std::move(caps), 10s);
  auto session = create_session(*h);

  Guid firstId;
  {
    auto cp = make_dummy_continuation_point();
    firstId = cp.identifier();
    auto [response, respPtr] = make_browse_response_with_cp(10u, cp.identifier());
    std::vector<BrowseContinuationPoint> cps;
    cps.push_back(std::move(cp));
    ASSERT_NO_THROW(SessionTestAccess::on_strand(*session,
      [&](auto& g)
      { g.browse_response_received(std::move(std::move(response)), std::move(std::move(cps))); }););
    ASSERT_EQ(respPtr->results().size(), 1u);
    EXPECT_FALSE(respPtr->results()[0].status_code().is_bad());
  }

  EXPECT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    1u);
  EXPECT_TRUE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(firstId); }));

  Guid secondId;
  {
    auto cp = make_dummy_continuation_point();
    secondId = cp.identifier();
    auto [response, respPtr] = make_browse_response_with_cp(11u, cp.identifier());
    std::vector<BrowseContinuationPoint> cps;
    cps.push_back(std::move(cp));
    ASSERT_NO_THROW(SessionTestAccess::on_strand(*session,
      [&](auto& g)
      { g.browse_response_received(std::move(std::move(response)), std::move(std::move(cps))); }););
    ASSERT_EQ(respPtr->results().size(), 1u);
    // Auto-free evicts the first CP and accepts the second.
    EXPECT_FALSE(respPtr->results()[0].continuation_point().empty());
    EXPECT_FALSE(respPtr->results()[0].status_code().is_bad());
  }

  // First CP evicted, second accepted - count stays at 1.
  EXPECT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    1u);
  EXPECT_FALSE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(firstId); }));
  EXPECT_TRUE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(secondId); }));

  session->terminate_for_shutdown();
  session.reset();
  h->sc.reset();
  h->server.reset();
  h->strand.reset();
  h->executor = {};
  ::ua::test_utils::drain_with_timeout(h->threadPool);
}

// @relation(SVR-ATTR-CP-003, scope=function)
TEST(SessionBrowseContinuationPointTests, BrowseContinuationPointTimeoutPurgesExpiredPoints)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxBrowseContinuationPoints = 1;
  auto h = create_secure_channel_harness_with_caps(std::move(caps), 10s);
  auto session = create_session(*h);

  Guid storedId;
  {
    auto cp = make_dummy_continuation_point();
    storedId = cp.identifier();
    auto [response, respPtr] = make_browse_response_with_cp(10u, storedId);
    std::vector<BrowseContinuationPoint> cps;
    cps.push_back(std::move(cp));
    ASSERT_NO_THROW(SessionTestAccess::on_strand(*session,
      [&](auto& g)
      { g.browse_response_received(std::move(std::move(response)), std::move(std::move(cps))); }););
    ASSERT_EQ(respPtr->results().size(), 1u);
    EXPECT_FALSE(respPtr->results()[0].status_code().is_bad());
  }

  ASSERT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    1u);
  ASSERT_TRUE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(storedId); }));

  SessionTestAccess::on_strand(*session,
    [](auto& g)
    {
      const auto now = std::chrono::steady_clock::now();
      for (auto& [id, expiry] : g.browse_continuation_point_expiry())
      {
        expiry = now - std::chrono::milliseconds{1};
      }
    });

  // Any browse response triggers purge of expired continuation points.
  BrowseResponse emptyResp;
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.browse_response_received(Response{20u, std::make_shared<BrowseResponse>(std::move(emptyResp))},
        std::vector<BrowseContinuationPoint>{});
    });

  EXPECT_EQ(
    SessionTestAccess::on_strand(*session, [](auto& g) { return g.browse_continuation_points().size(); }),
    0u);
  EXPECT_FALSE(SessionTestAccess::on_strand(
    *session, [&](auto& g) { return g.browse_continuation_points().contains(storedId); }));

  session->terminate_for_shutdown();
  session.reset();
  h->sc.reset();
  h->server.reset();
  h->strand.reset();
  h->executor = {};
  ::ua::test_utils::drain_with_timeout(h->threadPool);
}

// Buffered-response cap (P1.D #6): a detached session must not accumulate undeliverable responses
// without limit. enqueue_response drops the oldest buffered response once the cap is reached.
TEST(SessionBufferedResponseCapTest, EnqueueResponseDropsOldestAtCap)
{
  auto h = create_secure_channel_harness_with_caps(ServerConfig::ServerCapabilities{});
  auto session = create_session(*h);

  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.max_buffered_responses() = 2;  // tighten the cap for the test
      g.enqueue_response(Response{1u, nullptr});
      g.enqueue_response(Response{2u, nullptr});
      g.enqueue_response(Response{3u, nullptr});  // exceeds cap -> drop oldest (id 1)
    });

  SessionTestAccess::on_strand(*session,
    [](auto& g)
    {
      auto& q = g.response_messages();
      ASSERT_EQ(q.size(), 2u);
      EXPECT_EQ(q.front().first, 2u);  // oldest survivor
      EXPECT_EQ(q.back().first, 3u);  // newest
    });

  session->terminate_for_shutdown();
  session.reset();
  h->sc.reset();
  h->server.reset();
  h->strand.reset();
  h->executor = {};
  ::ua::test_utils::drain_with_timeout(h->threadPool);
}
