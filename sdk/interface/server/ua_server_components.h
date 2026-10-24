// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The live objects a Server is built from: crypto, certificate stores, authentication, Roles and
/// logging.
/// @ingroup server

#ifndef UA_SERVER_COMPONENTS_H
#define UA_SERVER_COMPONENTS_H

#include "ua_log_level.h"

#include <memory>

namespace ua
{
class Crypto;
class CertificateStore;
class LogSink;
}  // namespace ua

namespace ua::server
{

class UserAuthenticator;
class RoleConfiguration;

/// The objects the application supplies to @ref Server::create and @ref Server::try_create.
///
/// Settings live in @ref CreateConfig; this struct holds the live objects the server uses. Only
/// @ref crypto is required. Every other member is optional and says what the server does without it.
/// The server takes shared ownership of everything installed here.
/// @ingroup server
struct ServerComponents
{
  /// The cryptographic provider. Required: @ref Server::create refuses a null provider.
  ///
  /// The provider also encrypts the private keys the server writes (push certificate management), so
  /// its private-key credential must be one the application can supply again after a restart.
  std::shared_ptr<const ::ua::Crypto> crypto{};

  /// The certificate store for the DefaultApplicationGroup. When null the server builds one from
  /// `ApplicationConfig::FileTrustListConfig::defaultApplicationGroupTrustListPath`.
  ///
  /// With push management on (`ServerConfig::pushCertificateManagementEnabled`, the default) the
  /// server's TrustList is the only writer of this store's trust lists through the server. Anything else that
  /// writes the store (a `PullCertificateManager` given it as its `runtimeCertStore`, or the application
  /// through `Server::default_application_group_certificate_store()`) bypasses that serialisation: an
  /// application provisioning the server by pull management turns push management off itself.
  std::shared_ptr<::ua::CertificateStore> applicationGroupCertificateStore{};

  /// Certificate store holding the trusted issuers for X.509 user identity tokens.
  ///
  /// Set this when the application already owns a user-token store, or needs one the SDK cannot
  /// build (a database-backed or remotely-managed store rather than a directory). The SDK then offers
  /// it to the @ref UserAuthenticator on every activation as
  /// @ref AuthnRequest::userTokenCertificateStore, and publishes it as the Part 12
  /// `DefaultUserTokenGroup` so a remote administrator can manage its trust list.
  ///
  /// When null the server builds one from
  /// `ApplicationConfig::FileTrustListConfig::defaultUserTokenGroupTrustListPath`,
  /// and when that path is also unset no user-token store exists at all: an
  /// `X509UserAuthenticator` constructed without its own store then rejects every token, because
  /// there is nothing to establish trust against.
  std::shared_ptr<::ua::CertificateStore> userTokenCertificateStore{};

  /// Authenticator that validates user identity tokens during session activation.
  ///
  /// When null, session activation is always rejected with `BadUserAccessDenied`
  /// (secure-by-default). Set `AnonymousAuthenticator` for anonymous access, or
  /// `CompositeAuthenticator` to combine multiple authenticators.
  std::shared_ptr<UserAuthenticator> authenticator{};

  /// Optional Part-18 RoleSet configuration wired into NS0 at server bring-up.
  ///
  /// When set, the SDK runs the RoleSet startup setup:
  ///   - Seeds well-known roles in this @ref RoleConfiguration (skipping any
  ///     role already pre-populated by the application).
  ///   - Installs the materialised well-known Role defaults on NS0 and NS1.
  ///   - Populates the NS0 `RoleSet` Object with admin-only attrs + per-role
  ///     Variable values mirroring `RoleConfiguration` state.
  ///   - When `ServerConfig::roleManagementEnabled == true`, attaches
  ///     `AddRole` / `RemoveRole` and per-role Method handlers.
  ///
  /// The same configuration maps the activated user to the Role NodeIds carried
  /// by the immutable AccessIdentity used for every namespace decision.
  std::shared_ptr<RoleConfiguration> roleConfiguration{};

  /// Structured-log sink installed at construction, or null to disable logging. Installed before any
  /// subsystem captures a logger, so the address space, namespaces, sampling engine, conditions and
  /// the rest all log to it from birth. The sink is fixed for the server's lifetime; the level remains
  /// adjustable through `Server::set_log_level`.
  std::shared_ptr<::ua::LogSink> logSink{};

  /// Minimum level to emit (only meaningful when @ref logSink is set).
  ::ua::LogLevel logLevel = ::ua::LogLevel::Info;
};

}  // namespace ua::server

#endif  // !UA_SERVER_COMPONENTS_H
