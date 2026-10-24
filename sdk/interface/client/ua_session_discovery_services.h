// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_DISCOVERY_SERVICES_H
#define UA_SESSION_DISCOVERY_SERVICES_H

/// @file
/// @brief Discovery Service Set accessor exposed on a client Session.
/// @ingroup client

#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_on_network_response.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_result.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for OPC UA Discovery Service Set operations on a Session.
///
/// Groups the discovery services (GetEndpoints, FindServers, FindServersOnNetwork, RegisterServer,
/// RegisterServer2) into one handle obtained from a @ref Session. The accessor holds only a weak
/// reference to the owning session; it does not extend the session's lifetime. If the session has
/// been destroyed, async calls complete with an error @ref ErrorDetail and sync calls report the
/// same failure rather than dereferencing the expired session.
/// @ingroup client
class SessionDiscoveryServices
{
public:
  // GetEndpoints

  /// Result delivered by the GetEndpoints variants: a @ref GetEndpointsResponse or an error.
  using GetEndpointsResponseResult = ua::Result<ua::GetEndpointsResponse>;

  /// Completion callback for @ref get_endpoints_async.
  using GetEndpointsCallback = std::function<void(GetEndpointsResponseResult)>;

  /// Requests the endpoint descriptions of a server (GetEndpoints service).
  ///
  /// Sends the request over the session's secure channel and completes asynchronously. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  GetEndpoints request to send; consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref GetEndpointsResponse; on failure it carries an @ref ErrorDetail (including
  ///                 the case where the owning session has expired). This overload never throws.
  /// @see get_endpoints_sync, try_get_endpoints_sync
  void get_endpoints_async(ua::GetEndpointsRequest request, GetEndpointsCallback callback) noexcept;

  /// Requests the endpoint descriptions of a server, blocking until complete.
  /// @param request GetEndpoints request to send; consumed by value.
  /// @return The GetEndpoints response.
  /// @throws UaException if the request fails or the owning session has expired.
  /// @see get_endpoints_async, try_get_endpoints_sync
  /// A Good subcode on the answer is not returned; try_get_endpoints_sync() returns it.
  ua::GetEndpointsResponse get_endpoints_sync(ua::GetEndpointsRequest request);

  /// Requests the endpoint descriptions of a server, blocking until complete.
  /// @param request GetEndpoints request to send; consumed by value.
  /// @return The GetEndpoints response, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_endpoints_async, get_endpoints_sync
  GetEndpointsResponseResult try_get_endpoints_sync(ua::GetEndpointsRequest request) noexcept;

  // FindServers

  /// Result delivered by the FindServers variants: a @ref FindServersResponse or an error.
  using FindServersResponseResult = ua::Result<ua::FindServersResponse>;

  /// Completion callback for @ref find_servers_async.
  using FindServersCallback = std::function<void(FindServersResponseResult)>;

  /// Requests the set of servers known to a discovery server (FindServers service).
  ///
  /// Sends the request over the session's secure channel and completes asynchronously. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  FindServers request to send; consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref FindServersResponse; on failure it carries an @ref ErrorDetail (including
  ///                 the case where the owning session has expired). This overload never throws.
  /// @see find_servers_sync, try_find_servers_sync
  void find_servers_async(ua::FindServersRequest request, FindServersCallback callback) noexcept;

  /// Requests the set of servers known to a discovery server, blocking until complete.
  /// @param request FindServers request to send; consumed by value.
  /// @return The FindServers response.
  /// @throws UaException if the request fails or the owning session has expired.
  /// @see find_servers_async, try_find_servers_sync
  /// A Good subcode on the answer is not returned; try_find_servers_sync() returns it.
  ua::FindServersResponse find_servers_sync(ua::FindServersRequest request);

  /// Requests the set of servers known to a discovery server, blocking until complete.
  /// @param request FindServers request to send; consumed by value.
  /// @return The FindServers response, or an @ref ErrorDetail on failure. Never throws.
  /// @see find_servers_async, find_servers_sync
  FindServersResponseResult try_find_servers_sync(ua::FindServersRequest request) noexcept;

  // FindServersOnNetwork

  /// Result delivered by the FindServersOnNetwork variants: a @ref FindServersOnNetworkResponse or
  /// an error.
  using FindServersOnNetworkResponseResult = ua::Result<ua::FindServersOnNetworkResponse>;

  /// Completion callback for @ref find_servers_on_network_async.
  using FindServersOnNetworkCallback = std::function<void(FindServersOnNetworkResponseResult)>;

  /// Requests the servers registered with the network mDNS discovery server (FindServersOnNetwork
  /// service).
  ///
  /// Sends the request over the session's secure channel and completes asynchronously. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  FindServersOnNetwork request to send; consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref FindServersOnNetworkResponse; on failure it carries an @ref ErrorDetail
  ///                 (including the case where the owning session has expired). This overload never
  ///                 throws.
  /// @see find_servers_on_network_sync, try_find_servers_on_network_sync
  void find_servers_on_network_async(
    ua::FindServersOnNetworkRequest request, FindServersOnNetworkCallback callback) noexcept;

  /// Requests the servers registered with the network mDNS discovery server, blocking until
  /// complete.
  /// @param request FindServersOnNetwork request to send; consumed by value.
  /// @return The FindServersOnNetwork response.
  /// @throws UaException if the request fails or the owning session has expired.
  /// @see find_servers_on_network_async, try_find_servers_on_network_sync
  /// A Good subcode on the answer is not returned; try_find_servers_on_network_sync() returns it.
  ua::FindServersOnNetworkResponse find_servers_on_network_sync(ua::FindServersOnNetworkRequest request);

  /// Requests the servers registered with the network mDNS discovery server, blocking until
  /// complete.
  /// @param request FindServersOnNetwork request to send; consumed by value.
  /// @return The FindServersOnNetwork response, or an @ref ErrorDetail on failure. Never throws.
  /// @see find_servers_on_network_async, find_servers_on_network_sync
  FindServersOnNetworkResponseResult try_find_servers_on_network_sync(
    ua::FindServersOnNetworkRequest request) noexcept;

  // RegisterServer

  /// Result delivered by the RegisterServer variants: a @ref RegisterServerResponse or an error.
  using RegisterServerResponseResult = ua::Result<ua::RegisterServerResponse>;

  /// Completion callback for @ref register_server_async.
  using RegisterServerCallback = std::function<void(RegisterServerResponseResult)>;

  /// Registers a server with a discovery server (RegisterServer service).
  ///
  /// Sends the request over the session's secure channel and completes asynchronously. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  RegisterServer request to send; consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref RegisterServerResponse; on failure it carries an @ref ErrorDetail
  ///                 (including the case where the owning session has expired). This overload never
  ///                 throws.
  /// @see register_server_sync, try_register_server_sync
  void register_server_async(ua::RegisterServerRequest request, RegisterServerCallback callback) noexcept;

  /// Registers a server with a discovery server, blocking until complete.
  /// @param request RegisterServer request to send; consumed by value.
  /// @return The RegisterServer response.
  /// @throws UaException if the request fails or the owning session has expired.
  /// @see register_server_async, try_register_server_sync
  /// A Good subcode on the answer is not returned; try_register_server_sync() returns it.
  ua::RegisterServerResponse register_server_sync(ua::RegisterServerRequest request);

  /// Registers a server with a discovery server, blocking until complete.
  /// @param request RegisterServer request to send; consumed by value.
  /// @return The RegisterServer response, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_server_async, register_server_sync
  RegisterServerResponseResult try_register_server_sync(ua::RegisterServerRequest request) noexcept;

  // RegisterServer2

  /// Result delivered by the RegisterServer2 variants: a @ref RegisterServer2Response or an error.
  using RegisterServer2ResponseResult = ua::Result<ua::RegisterServer2Response>;

  /// Completion callback for @ref register_server2_async.
  using RegisterServer2Callback = std::function<void(RegisterServer2ResponseResult)>;

  /// Registers a server with a discovery server, carrying multicast discovery configuration
  /// (RegisterServer2 service).
  ///
  /// Sends the request over the session's secure channel and completes asynchronously. The callback
  /// runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  RegisterServer2 request to send; consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref RegisterServer2Response; on failure it carries an @ref ErrorDetail
  ///                 (including the case where the owning session has expired). This overload never
  ///                 throws.
  /// @see register_server2_sync, try_register_server2_sync
  void register_server2_async(ua::RegisterServer2Request request, RegisterServer2Callback callback) noexcept;

  /// Registers a server with a discovery server, carrying multicast discovery configuration,
  /// blocking until complete.
  /// @param request RegisterServer2 request to send; consumed by value.
  /// @return The RegisterServer2 response.
  /// @throws UaException if the request fails or the owning session has expired.
  /// @see register_server2_async, try_register_server2_sync
  /// A Good subcode on the answer is not returned; try_register_server2_sync() returns it.
  ua::RegisterServer2Response register_server2_sync(ua::RegisterServer2Request request);

  /// Registers a server with a discovery server, carrying multicast discovery configuration,
  /// blocking until complete.
  /// @param request RegisterServer2 request to send; consumed by value.
  /// @return The RegisterServer2 response, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_server2_async, register_server2_sync
  RegisterServer2ResponseResult try_register_server2_sync(ua::RegisterServer2Request request) noexcept;

private:
  friend class Session;
  explicit SessionDiscoveryServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_DISCOVERY_SERVICES_H
