// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_method_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionMethodServices::SessionMethodServices(std::weak_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

// --- Call ---

void SessionMethodServices::call_async(ua::CallRequest request, CallCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(CallResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::CallResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::CallResponse SessionMethodServices::call_sync(ua::CallRequest request)
{
  return ua::detail::good_value(try_call_sync(std::move(request)));
}

SessionMethodServices::CallResponseResult SessionMethodServices::try_call_sync(
  ua::CallRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return CallResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::CallResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
