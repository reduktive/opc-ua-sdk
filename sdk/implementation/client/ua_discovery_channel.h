// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Mockable interface for the Discovery facade's ephemeral discovery channel (client design
/// section 7.6).
/// @ingroup client
///
/// The Discovery facade (`ua::client::Discovery`) opens an ephemeral None-policy channel per query,
/// issues the session-less request, and closes it. `SecureChannel` is a concrete move-only handle and
/// `CoreClientImpl::open_channel_async` needs a real server, so the open/issue/close surface is abstracted
/// here: the real implementation wraps the tier-0 stack, and unit tests inject a fake.

#ifndef UA_DISCOVERY_CHANNEL_H
#define UA_DISCOVERY_CHANNEL_H

#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_on_network_response.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_call_method_result.h"
#include "ua_connection_config.h"
#include "ua_logger.h"
#include "ua_namespace_table.h"
#include "ua_relative_path.h"
#include "ua_result.h"
#include "ua_translated_node_id.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ua::client
{
class CoreClientImpl;
}  // namespace ua::client

namespace ua::client::detail
{

/// An opened ephemeral discovery channel (client design section 7.6). Carries only the session-less discovery
/// surface plus close. Produced by @ref DiscoveryChannelFactory::open_async.
class DiscoveryChannel
{
public:
  virtual ~DiscoveryChannel() = default;

  virtual void find_servers_async(
    ua::FindServersRequest request, std::function<void(ua::Result<ua::FindServersResponse>)> callback) = 0;

  virtual void get_endpoints_async(
    ua::GetEndpointsRequest request, std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) = 0;

  virtual void find_servers_on_network_async(ua::FindServersOnNetworkRequest request,
    std::function<void(ua::Result<ua::FindServersOnNetworkResponse>)> callback) = 0;

  /// Gracefully closes the ephemeral channel. Idempotent. The callback fires on completion.
  virtual void close_async(std::function<void(ua::VoidResult)> callback) = 0;

protected:
  DiscoveryChannel() = default;
  DiscoveryChannel(const DiscoveryChannel&) = default;
  DiscoveryChannel& operator=(const DiscoveryChannel&) = default;
  DiscoveryChannel(DiscoveryChannel&&) = default;
  DiscoveryChannel& operator=(DiscoveryChannel&&) = default;
};

/// One temporary managed GDS Connection. The facade owns it for exactly one action sequence.
class GdsConnection
{
public:
  virtual ~GdsConnection() = default;

  [[nodiscard]] virtual std::shared_ptr<const NamespaceTable> namespace_table() const = 0;

  virtual void resolve_path_async(
    ua::NodeId start, ua::RelativePath path, std::function<void(ua::NodeIdResult)> callback) = 0;

  virtual void call_method_async(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments,
    std::function<void(ua::Result<ua::CallResult>)> callback) = 0;

  virtual void close_async(std::function<void(ua::VoidResult)> callback) = 0;

protected:
  GdsConnection() = default;
  GdsConnection(const GdsConnection&) = default;
  GdsConnection& operator=(const GdsConnection&) = default;
  GdsConnection(GdsConnection&&) = default;
  GdsConnection& operator=(GdsConnection&&) = default;
};

/// Opens an ephemeral None-policy channel to a discovery URL (client design section 7.6 / section 8.1).
class DiscoveryChannelFactory
{
public:
  virtual ~DiscoveryChannelFactory() = default;

  /// The executor the factory's operations complete on; empty when it has none, and then a blocking
  /// wrapper never refuses.
  [[nodiscard]] virtual boost::asio::any_io_executor executor() const
  {
    return {};
  }

  /// Opens an ephemeral None-policy channel to @p discoveryUrl.
  ///
  /// @param discoveryUrl Target discovery endpoint URL.
  /// @param timeout      Per-call open timeout; `nullopt` uses the client default.
  /// @param callback     Receives the opened channel or a bad Result carrying an @ref ua::ErrorDetail.
  virtual void open_async(std::string discoveryUrl, std::optional<std::chrono::milliseconds> timeout,
    std::function<void(ua::Result<std::shared_ptr<DiscoveryChannel>>)> callback) = 0;

  /// Opens a fresh managed Connection for one GDS action sequence.
  virtual void open_gds_async(ua::client::ConnectionConfig config,
    std::function<void(ua::Result<std::shared_ptr<GdsConnection>>)> callback) = 0;

protected:
  DiscoveryChannelFactory() = default;
  DiscoveryChannelFactory(const DiscoveryChannelFactory&) = default;
  DiscoveryChannelFactory& operator=(const DiscoveryChannelFactory&) = default;
  DiscoveryChannelFactory(DiscoveryChannelFactory&&) = default;
  DiscoveryChannelFactory& operator=(DiscoveryChannelFactory&&) = default;
};

/// Builds the production factory backed by `CoreClientImpl::open_channel_async` (None policy) and the tier-0
/// `SecureChannel` session-less discovery ops.
///
/// @param client Weak reference to the owning client impl (the factory never extends its lifetime).
/// @param logger Logger for wire-boundary diagnostics.
/// @return A ready-to-use factory.
[[nodiscard]] std::shared_ptr<DiscoveryChannelFactory> make_secure_channel_discovery_factory(
  std::weak_ptr<CoreClientImpl> client, ua::Logger logger);

}  // namespace ua::client::detail

#endif  // !UA_DISCOVERY_CHANNEL_H
