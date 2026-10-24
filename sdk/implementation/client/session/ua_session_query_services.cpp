// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_query_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionQueryServices::SessionQueryServices(std::weak_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

// --- QueryFirst ---

void SessionQueryServices::query_first_async(
  ua::QueryFirstRequest request, QueryFirstCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(QueryFirstResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::QueryFirstResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::QueryFirstResponse SessionQueryServices::query_first_sync(ua::QueryFirstRequest request)
{
  return ua::detail::good_value(try_query_first_sync(std::move(request)));
}

SessionQueryServices::QueryFirstResponseResult SessionQueryServices::try_query_first_sync(
  ua::QueryFirstRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return QueryFirstResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::QueryFirstResponse>(std::move(impl), std::move(request));
}

// --- QueryNext ---

void SessionQueryServices::query_next_async(ua::QueryNextRequest request, QueryNextCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(QueryNextResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::QueryNextResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::QueryNextResponse SessionQueryServices::query_next_sync(ua::QueryNextRequest request)
{
  return ua::detail::good_value(try_query_next_sync(std::move(request)));
}

SessionQueryServices::QueryNextResponseResult SessionQueryServices::try_query_next_sync(
  ua::QueryNextRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return QueryNextResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::QueryNextResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
