// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_SERVER_H
#define UA_TEST_SERVER_H

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>

#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test_helpers
{

/**
 * @brief Minimal reusable test helper to spin up an in-process server with an ephemeral TCP listener.
 *
 * This is intended to be extended into a full client/server harness (CreateSession/ActivateSession etc.).
 */
class TestServer
{
public:
  TestServer() = default;
  ~TestServer();
  TestServer(const TestServer&) = delete;
  TestServer& operator=(const TestServer&) = delete;

  // Starts thread pool + creates server.
  void create();

  // Starts thread pool + creates server with custom configuration. The log sink is installed at
  // construction (there is no runtime sink setter); null uses the buffering test_log_sink().
  void create(std::function<void(ua::server::ServerConfig&)> configureServer,
    std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Debug);

  // Starts thread pool + creates server with application- and server-level config hooks.
  // The application hook runs first and may adjust immutable application config (e.g. stack
  // limits such as the minimum session timeout); the server hook adjusts the
  // ServerConfig. Either may be null.
  /// @param configureIdentity Optional hook on the `ApplicationIdentity` (BuildInfo, product URI,
  ///                           application name). Runs before the server is created; the identity is
  ///                           immutable afterwards, and it is the only route to those fields.
  void create(std::function<void(ua::ApplicationConfig&)> configureApplication,
    std::function<void(ua::server::ServerConfig&)> configureServer,
    std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Debug,
    std::function<void(ua::ApplicationIdentity&)> configureIdentity = nullptr);

  // Starts an ephemeral listener and returns its handle.
  ua::server::ListenerHandle listen_ephemeral();

  // Adds a basic endpoint configuration (endpoint names are mandatory).
  void add_endpoint(ua::server::ListenerHandle listener, ua::server::ServerEndpointConfig endpoint);

  void start();

  /// Claims issued to Sessions activated after this call. Existing Sessions
  /// retain the identity snapshot from their own activation.
  void set_authentication_claims(std::unordered_map<std::string, std::string> claims);

  boost::asio::thread_pool& thread_pool();
  ua::server::Server& server();

private:
  boost::asio::thread_pool mThreadPool;
  optional<ua::server::Server> mServer;
  std::shared_ptr<class MutableClaimAuthenticator> mAuthenticator;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_SERVER_H
