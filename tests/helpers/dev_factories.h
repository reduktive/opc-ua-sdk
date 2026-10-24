// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#pragma once

/// @file
/// Zero-configuration Server and Client factories, for TESTS ONLY.
///
/// These were public API - `Server::create(executor)` and `CoreClient::create(executor)`. They were
/// removed from the public surface because nothing a customer would build could use them:
///
///   - `Server::create(executor)` generated a per-process applicationUri, explicitly "not stable
///     across restarts", which no certificate SAN can be bound to. It therefore could never carry
///     security at all.
///   - It installed EMPTY security hooks, so the resulting server bound its listener and then
///     rejected every session at activation with BadUserAccessDenied. The book had to warn readers
///     off it in the very passage introducing server construction: "A server that admits no one is
///     not a useful hello world".
///   - No shipped example or quickstart used either of them. Every one passes explicit crypto and
///     certificate store.
///
/// What they ARE good for is a test that wants a server or client object without caring about its
/// identity or security - which is exactly what the call sites below want. That is a fixture
/// concern, so the code lives with the fixtures.
///
/// Removed while the public API was still unreleased. After a stable tag this would have been a
/// breaking change; before one it costs nothing.

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_core_client.h"
#include "ua_guid.h"
#include "ua_server.h"

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <string>
#include <utility>

#include "test_components.h"

namespace ua::test_helpers
{

/// A server with default identity, configuration, cryptography and certificate store.
/// Binds and answers unauthenticated discovery; admits no sessions (empty security hooks).
inline ua::server::Server make_dev_server(boost::asio::any_io_executor executor,
  std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Info)
{
  // Unique per process, not stable across restarts: nothing is bound to it by a certificate SAN.
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    "urn:reduktive:opcua-sdk:" + ua::Guid::create_and_generate().as_string();

  return ua::server::Server::create(std::move(executor),
    ua::server::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    ua::server::ServerComponents{
      .crypto = ua::test_helpers::test_crypto(), .logSink = std::move(logSink), .logLevel = logLevel});
}

/// A core client with default identity and configuration, and SDK-supplied crypto and store.
inline ua::client::CoreClient make_dev_core_client(boost::asio::any_io_executor executor,
  std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Info)
{
  return ua::client::CoreClient::create(std::move(executor),
    ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::ApplicationConfig::load_default(),
      .client = {}},
    ua::client::ClientComponents{
      .crypto = ua::test_helpers::test_crypto(), .logSink = std::move(logSink), .logLevel = logLevel});
}

/// The tier-1 @ref ua::client::Client equivalent of @ref make_dev_core_client.
inline ua::client::Client make_dev_client(boost::asio::any_io_executor executor,
  std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Info)
{
  return ua::client::Client::create(std::move(executor),
    ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::ApplicationConfig::load_default(),
      .client = {}},
    ua::client::ClientComponents{
      .crypto = ua::test_helpers::test_crypto(), .logSink = std::move(logSink), .logLevel = logLevel});
}

}  // namespace ua::test_helpers
