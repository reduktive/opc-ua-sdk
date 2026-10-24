// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_discovery_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionDiscoveryServices::SessionDiscoveryServices(std::weak_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

// --- GetEndpoints ---

void SessionDiscoveryServices::get_endpoints_async(
  ua::GetEndpointsRequest request, GetEndpointsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(GetEndpointsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::GetEndpointsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::GetEndpointsResponse SessionDiscoveryServices::get_endpoints_sync(ua::GetEndpointsRequest request)
{
  return ua::detail::good_value(try_get_endpoints_sync(std::move(request)));
}

SessionDiscoveryServices::GetEndpointsResponseResult SessionDiscoveryServices::try_get_endpoints_sync(
  ua::GetEndpointsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return GetEndpointsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::GetEndpointsResponse>(std::move(impl), std::move(request));
}

// --- FindServers ---

void SessionDiscoveryServices::find_servers_async(
  ua::FindServersRequest request, FindServersCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(FindServersResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::FindServersResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::FindServersResponse SessionDiscoveryServices::find_servers_sync(ua::FindServersRequest request)
{
  return ua::detail::good_value(try_find_servers_sync(std::move(request)));
}

SessionDiscoveryServices::FindServersResponseResult SessionDiscoveryServices::try_find_servers_sync(
  ua::FindServersRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return FindServersResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::FindServersResponse>(std::move(impl), std::move(request));
}

// --- FindServersOnNetwork ---

void SessionDiscoveryServices::find_servers_on_network_async(
  ua::FindServersOnNetworkRequest request, FindServersOnNetworkCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(FindServersOnNetworkResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::FindServersOnNetworkResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::FindServersOnNetworkResponse SessionDiscoveryServices::find_servers_on_network_sync(
  ua::FindServersOnNetworkRequest request)
{
  return ua::detail::good_value(try_find_servers_on_network_sync(std::move(request)));
}

SessionDiscoveryServices::FindServersOnNetworkResponseResult
  SessionDiscoveryServices::try_find_servers_on_network_sync(ua::FindServersOnNetworkRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return FindServersOnNetworkResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::FindServersOnNetworkResponse>(
    std::move(impl), std::move(request));
}

// --- RegisterServer ---

void SessionDiscoveryServices::register_server_async(
  ua::RegisterServerRequest request, RegisterServerCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(RegisterServerResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::RegisterServerResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::RegisterServerResponse SessionDiscoveryServices::register_server_sync(ua::RegisterServerRequest request)
{
  return ua::detail::good_value(try_register_server_sync(std::move(request)));
}

SessionDiscoveryServices::RegisterServerResponseResult SessionDiscoveryServices::try_register_server_sync(
  ua::RegisterServerRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return RegisterServerResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::RegisterServerResponse>(std::move(impl), std::move(request));
}

// --- RegisterServer2 ---

void SessionDiscoveryServices::register_server2_async(
  ua::RegisterServer2Request request, RegisterServer2Callback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(RegisterServer2ResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::RegisterServer2Response>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::RegisterServer2Response SessionDiscoveryServices::register_server2_sync(
  ua::RegisterServer2Request request)
{
  return ua::detail::good_value(try_register_server2_sync(std::move(request)));
}

SessionDiscoveryServices::RegisterServer2ResponseResult SessionDiscoveryServices::try_register_server2_sync(
  ua::RegisterServer2Request request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return RegisterServer2ResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::RegisterServer2Response>(std::move(impl), std::move(request));
}

}  // namespace ua::client
