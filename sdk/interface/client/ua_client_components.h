// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The live objects a Client is built from: crypto, certificate store and logging.
/// @ingroup client

#ifndef UA_CLIENT_COMPONENTS_H
#define UA_CLIENT_COMPONENTS_H

#include "ua_log_level.h"

#include <memory>

namespace ua
{
class Crypto;
class CertificateStore;
class LogSink;
}  // namespace ua

namespace ua::client
{

/// The objects the application supplies to @ref CoreClient::create and @ref Client::create (and
/// their `try_create` forms).
///
/// Settings live in @ref CreateConfig; this struct holds the live objects the client uses. Only
/// @ref crypto is required. The client takes shared ownership of everything installed here.
/// @ingroup client
struct ClientComponents
{
  /// The cryptographic provider. Required: create refuses a null provider.
  ///
  /// The provider also encrypts the private keys the client writes (pull certificate management), so
  /// its private-key credential must be one the application can supply again after a restart.
  std::shared_ptr<const ::ua::Crypto> crypto{};

  /// The certificate store for the DefaultApplicationGroup. When null the client builds one from
  /// `ApplicationConfig::FileTrustListConfig::defaultApplicationGroupTrustListPath`
  /// when that path is set, and has no store otherwise.
  std::shared_ptr<::ua::CertificateStore> applicationGroupCertificateStore{};

  /// Structured-log sink installed at construction, or null to disable logging. Fixed for the
  /// client's lifetime; the level stays adjustable through `set_log_level`.
  std::shared_ptr<::ua::LogSink> logSink{};

  /// Minimum level to emit (only meaningful when @ref logSink is set).
  ::ua::LogLevel logLevel = ::ua::LogLevel::Info;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_COMPONENTS_H
