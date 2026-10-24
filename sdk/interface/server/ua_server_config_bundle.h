// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server configuration bundles: the value-based @ref ua::server::CreateConfig passed to
///        Server::create() and the resolved @ref ua::server::CombinedConfig it freezes into.
/// @ingroup server

#ifndef UA_SERVER_CONFIG_BUNDLE_H
#define UA_SERVER_CONFIG_BUNDLE_H

#include "ua_application_configuration.h"
#include "ua_server_configuration.h"

#include <memory>

namespace ua::server
{

/// Value-based configuration bundle supplied when creating a @ref Server.
///
/// Aggregates the three configuration objects a server needs at construction:
/// the application identity, the deployment configuration, and the server-only
/// settings. Every field is held by value so the caller can populate and edit
/// the bundle freely before handing it to @ref Server::create. The factory
/// freezes the contents internally into an immutable shared configuration, so
/// later mutation of this struct has no effect on a server already created.
/// @ingroup server
/// @see Server::create
struct CreateConfig
{
  ::ua::ApplicationIdentity identity;  ///< Application identity advertised to peers (product URI,
                                       ///< name, type, build info).
  ::ua::ApplicationConfig application;  ///< Deployment configuration (protocol timeouts,
                                        ///< lifetimes, limits, trust-list locations,
                                        ///< security policy).
  ::ua::server::ServerConfig server;  ///< Server-only settings (limits, throttling,
                                      ///< capabilities, listeners, roles).
};

/// The complete configuration needed to construct a server instance.
///
/// Bundles the three configuration layers a server is built from: the static
/// application identity, the shared deployment-wide @ref ua::ApplicationConfig,
/// and the server-only @ref ua::server::ServerConfig. The application
/// configuration is held by shared, const-qualified pointer because it is
/// immutable once loaded and may be shared with other components (for example a
/// co-hosted client); the identity and server settings are owned by value.
/// @ingroup server
struct CombinedConfig
{
  ::ua::ApplicationIdentity identity;  ///< Static identity the server advertises about itself.
  std::shared_ptr<const ::ua::ApplicationConfig>
    application;  ///< Shared, immutable deployment configuration. Must be non-null when used to
                  ///< construct a server.
  ::ua::server::ServerConfig server;  ///< Server-only settings (connection/channel limits,
                                      ///< endpoints, roles).
};

}  // namespace ua::server

#endif  // !UA_SERVER_CONFIG_BUNDLE_H
