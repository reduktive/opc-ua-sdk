// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_view_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionViewServices::SessionViewServices(std::weak_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

// --- Browse ---

void SessionViewServices::browse_async(ua::BrowseRequest request, BrowseCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(BrowseResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::BrowseResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::BrowseResponse SessionViewServices::browse_sync(ua::BrowseRequest request)
{
  return ua::detail::good_value(try_browse_sync(std::move(request)));
}

SessionViewServices::BrowseResponseResult SessionViewServices::try_browse_sync(
  ua::BrowseRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return BrowseResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::BrowseResponse>(std::move(impl), std::move(request));
}

// --- BrowseNext ---

void SessionViewServices::browse_next_async(
  ua::BrowseNextRequest request, BrowseNextCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(BrowseNextResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::BrowseNextResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::BrowseNextResponse SessionViewServices::browse_next_sync(ua::BrowseNextRequest request)
{
  return ua::detail::good_value(try_browse_next_sync(std::move(request)));
}

SessionViewServices::BrowseNextResponseResult SessionViewServices::try_browse_next_sync(
  ua::BrowseNextRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return BrowseNextResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::BrowseNextResponse>(std::move(impl), std::move(request));
}

// --- TranslateBrowsePathsToNodeIds ---

void SessionViewServices::translate_browse_paths_async(
  ua::TranslateBrowsePathsToNodeIdsRequest request, TranslateCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(TranslateResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::TranslateBrowsePathsToNodeIdsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::TranslateBrowsePathsToNodeIdsResponse SessionViewServices::translate_browse_paths_sync(
  ua::TranslateBrowsePathsToNodeIdsRequest request)
{
  return ua::detail::good_value(try_translate_browse_paths_sync(std::move(request)));
}

SessionViewServices::TranslateResponseResult SessionViewServices::try_translate_browse_paths_sync(
  ua::TranslateBrowsePathsToNodeIdsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return TranslateResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::TranslateBrowsePathsToNodeIdsResponse>(
    std::move(impl), std::move(request));
}

// --- RegisterNodes ---

void SessionViewServices::register_nodes_async(
  ua::RegisterNodesRequest request, RegisterNodesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(RegisterNodesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::RegisterNodesResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::RegisterNodesResponse SessionViewServices::register_nodes_sync(ua::RegisterNodesRequest request)
{
  return ua::detail::good_value(try_register_nodes_sync(std::move(request)));
}

SessionViewServices::RegisterNodesResponseResult SessionViewServices::try_register_nodes_sync(
  ua::RegisterNodesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return RegisterNodesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::RegisterNodesResponse>(std::move(impl), std::move(request));
}

// --- UnregisterNodes ---

void SessionViewServices::unregister_nodes_async(
  ua::UnregisterNodesRequest request, UnregisterNodesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(UnregisterNodesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::UnregisterNodesResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::UnregisterNodesResponse SessionViewServices::unregister_nodes_sync(ua::UnregisterNodesRequest request)
{
  return ua::detail::good_value(try_unregister_nodes_sync(std::move(request)));
}

SessionViewServices::UnregisterNodesResponseResult SessionViewServices::try_unregister_nodes_sync(
  ua::UnregisterNodesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return UnregisterNodesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::UnregisterNodesResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
