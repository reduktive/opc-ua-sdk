// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_attribute_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionAttributeServices::SessionAttributeServices(std::weak_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

// --- Read ---

void SessionAttributeServices::read_async(ua::ReadRequest request, ReadCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(ReadResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::ReadResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::ReadResponse SessionAttributeServices::read_sync(ua::ReadRequest request)
{
  return ua::detail::good_value(try_read_sync(std::move(request)));
}

SessionAttributeServices::ReadResponseResult SessionAttributeServices::try_read_sync(
  ua::ReadRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return ReadResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::ReadResponse>(std::move(impl), std::move(request));
}

// --- HistoryRead ---

void SessionAttributeServices::history_read_async(
  ua::HistoryReadRequest request, HistoryReadCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(HistoryReadResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::HistoryReadResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::HistoryReadResponse SessionAttributeServices::history_read_sync(ua::HistoryReadRequest request)
{
  return ua::detail::good_value(try_history_read_sync(std::move(request)));
}

SessionAttributeServices::HistoryReadResponseResult SessionAttributeServices::try_history_read_sync(
  ua::HistoryReadRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return HistoryReadResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::HistoryReadResponse>(std::move(impl), std::move(request));
}

// --- Write ---

void SessionAttributeServices::write_async(ua::WriteRequest request, WriteCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(WriteResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::WriteResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::WriteResponse SessionAttributeServices::write_sync(ua::WriteRequest request)
{
  return ua::detail::good_value(try_write_sync(std::move(request)));
}

SessionAttributeServices::WriteResponseResult SessionAttributeServices::try_write_sync(
  ua::WriteRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return WriteResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::WriteResponse>(std::move(impl), std::move(request));
}

// --- HistoryUpdate ---

void SessionAttributeServices::history_update_async(
  ua::HistoryUpdateRequest request, HistoryUpdateCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(HistoryUpdateResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::HistoryUpdateResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::HistoryUpdateResponse SessionAttributeServices::history_update_sync(ua::HistoryUpdateRequest request)
{
  return ua::detail::good_value(try_history_update_sync(std::move(request)));
}

SessionAttributeServices::HistoryUpdateResponseResult SessionAttributeServices::try_history_update_sync(
  ua::HistoryUpdateRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return HistoryUpdateResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::HistoryUpdateResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
