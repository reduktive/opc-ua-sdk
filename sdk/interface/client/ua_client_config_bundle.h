// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Value-based and shared configuration bundles passed to CoreClient::create().
/// @ingroup client

#ifndef UA_CLIENT_CONFIG_BUNDLE_H
#define UA_CLIENT_CONFIG_BUNDLE_H

#include "ua_application_configuration.h"
#include "ua_client_configuration.h"

#include <memory>

namespace ua::client
{

/// Value-based configuration bundle used when creating a Client.
///
/// Aggregates the three inputs CoreClient::create() needs: the application's identity, the
/// shared application/stack configuration, and the client-specific defaults. It is passed
/// by value so callers may edit it freely before construction; the client freezes its
/// contents internally once created, and later mutation of the original struct has no effect.
///
/// @see CoreClient::create
/// @ingroup client
struct CreateConfig
{
  ::ua::ApplicationIdentity identity;  ///< Identity advertised by the client (product URI, name,
                                       ///< application type, build info).
  ::ua::ApplicationConfig application;  ///< Shared application and stack configuration
                                        ///< (security, timeouts, trust list, limits).
  ::ua::client::ClientConfig client;  ///< Client-specific defaults (service/session/channel
                                      ///< timeouts, reverse-connect listeners).
};

/// Complete configuration required to construct a client instance.
///
/// Bundles the three configuration inputs a client needs: the application
/// identity advertised to servers, the shared application-wide configuration,
/// and the client-only defaults.
/// @ingroup client
struct CombinedConfig
{
  /// Application identity (product URI, application name, type) advertised to servers.
  ::ua::ApplicationIdentity identity;

  /// Shared application-wide configuration (stack limits, trust list, etc.).
  ///
  /// Shared ownership; the pointed-to configuration is immutable and may be
  /// shared across multiple client instances. Must not be null when used to
  /// construct a client.
  std::shared_ptr<const ::ua::ApplicationConfig> application;

  /// Client-only defaults (service/session timeouts, reverse-connect listeners, etc.).
  ::ua::client::ClientConfig client;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_CONFIG_BUNDLE_H
