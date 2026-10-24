// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_test_server.h"

#include <gtest/gtest.h>

#include "mutable_claim_authenticator.h"
#include "test_log_sink.h"
#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_built_in_authenticators.h"
#include "ua_log_level.h"
#include "ua_role_configuration.h"
#include "ua_server_components.h"

#include "test_components.h"

namespace ua::test_helpers
{

TestServer::~TestServer()
{
  // Graceful: ask the server to drain queued responses, close channels, and stop
  // accepting connections. Then destroy the server and join the thread pool -
  // dropping pending handlers via abort leaves dangling state that crashes at
  // static destruction (notably on Windows).
  if (mServer)
    (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  mServer.reset();
  mThreadPool.join();
}

void TestServer::create()
{
  create({});  // default server configuration, no extra tuning
}

void TestServer::create(std::function<void(ua::server::ServerConfig&)> configureServer,
  std::shared_ptr<ua::LogSink> logSink, ua::LogLevel logLevel)
{
  create(nullptr, std::move(configureServer), std::move(logSink), logLevel);
}

void TestServer::create(std::function<void(ua::ApplicationConfig&)> configureApplication,
  std::function<void(ua::server::ServerConfig&)> configureServer, std::shared_ptr<ua::LogSink> logSink,
  ua::LogLevel logLevel, std::function<void(ua::ApplicationIdentity&)> configureIdentity)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  if (configureApplication)
    configureApplication(appCfg);

  ua::server::ServerConfig serverCfg{};
  if (configureServer)
    configureServer(serverCfg);

  auto identity = ua::ApplicationIdentity::load_default();
  if (configureIdentity)
    configureIdentity(identity);
  ua::server::CreateConfig cfg{
    .identity = std::move(identity), .application = std::move(appCfg), .server = std::move(serverCfg)};

  // Use the production authentication interval. A shorter fixture-only interval makes an inline
  // authenticator's posted completion race its fixed timer under instrumentation and session churn.
  if (!mAuthenticator)
    mAuthenticator = std::make_shared<MutableClaimAuthenticator>();
  ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto(),
    .authenticator = mAuthenticator,
    .logSink = logSink ? std::move(logSink) : test_log_sink(),
    .logLevel = logLevel};
  // Observer is the Role whose Table 2 sentence names subscribing to Events, and these fixtures
  // subscribe. It is held deliberately rather than relying on SecurityAdmin above: that Role carries
  // ReceiveEvents only as a policy grant (see `well_known_role_permissions`), so a test client that
  // needs Events should not depend on an administrative Role continuing to supply them. Redundant as
  // of that grant - no test currently distinguishes the two - and kept for that independence.
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants({
    {ua::server::WellKnownRole::SecurityAdmin, ua::IdentityCriteriaType::Anonymous},
    {ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous},
  });

  mServer.emplace(
    ua::server::Server::create(mThreadPool.get_executor(), std::move(cfg), std::move(components)));
}

ua::server::ListenerHandle TestServer::listen_ephemeral()
{
  ua::transport::BindAddress listenerBind;
  listenerBind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  listenerBind.address = "127.0.0.1:0";
  return server().listen_sync(std::move(listenerBind), {});
}

void TestServer::add_endpoint(ua::server::ListenerHandle listener, ua::server::ServerEndpointConfig endpoint)
{
  server().add_endpoint(listener, std::move(endpoint));
}

void TestServer::start()
{
  server().start_sync();
}

void TestServer::set_authentication_claims(std::unordered_map<std::string, std::string> claims)
{
  if (!mAuthenticator)
    mAuthenticator = std::make_shared<MutableClaimAuthenticator>();
  mAuthenticator->set_claims(std::move(claims));
}

boost::asio::thread_pool& TestServer::thread_pool()
{
  return mThreadPool;
}

ua::server::Server& TestServer::server()
{
  check(mServer, ua::Status::BadInvalidState);
  return *mServer;
}

}  // namespace ua::test_helpers
