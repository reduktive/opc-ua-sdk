// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Public client::SecureChannel method forwarding to SecureChannelImpl.
//
// NOTE: Raw send_request is intentionally not exposed in the public API.
// All service calls go through typed wrappers (discovery here, session services
// on client::Session). Apply the same pattern when adding session service methods.

#include "ua_sync_wait.h"
#include "ua_client_secure_channel.h"
#include "ua_client_secure_channel_impl.h"
#include "ua_date_time.h"

#include "ua_exceptions.h"
#include "ua_to_result.h"

#include <future>

namespace
{

[[noreturn]] void throw_invalid_state()
{
  throw ua::UaException{ua::Status::BadInvalidState, nullptr};
}

}  // namespace

namespace ua::client
{

SecureChannel::SecureChannel(std::shared_ptr<SecureChannelImpl> impl) : mImpl(std::move(impl))
{}

SecureChannel::~SecureChannel() = default;

// --- Close ---
//
// Foolproof shutdown: move mImpl into the completion lambda so the facade's
// strong-ref drops as the last action of the close. After close_async returns,
// the facade is empty; the impl is destroyed when its child operations drain.

void SecureChannel::close_async(CloseCallback callback) noexcept
{
  // This noexcept facade invokes `callback` directly (both the already-closed fast path below and the
  // impl.close completion). An empty CloseCallback would throw std::bad_function_call out of a noexcept
  // boundary -> std::terminate. Normalize a fire-and-forget close to an explicit no-op so an empty
  // callback is safe (fire-and-forget uses a no-op, never an empty std::function).
  if (!callback)
  {
    // The caller explicitly selected fire-and-forget close and has no use for the result.
    callback = [](ua::VoidResult) {
    };
  }
  auto impl = std::move(mImpl);
  if (!impl)
  {
    // Idempotent: closing an already-closed channel is a no-op success.
    callback(ua::VoidResult{});
    return;
  }
  auto& raw = *impl;
  raw.close(
    [impl = std::move(impl), callback = std::move(callback)](ua::VoidResult result) mutable
    {
      impl.reset();
      callback(std::move(result));
    });
}

void SecureChannel::close_sync()
{
  try_close_sync().value();
}

ua::VoidResult SecureChannel::try_close_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ua::VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ua::VoidResult)> complete) { close_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

// --- Session creation ---

void SecureChannel::create_session_async(CreateSessionConfig config, CreateSessionCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(SessionResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->create_session(std::move(config),
      [callback = std::move(callback)](SecureChannelImpl::CreateSessionImplResult result)
      {
        if (!result.has_value())
        {
          callback(SessionResult{result.status_code(), result.shared_detail()});
          return;
        }
        // A Good subcode or an Uncertain CreateSession ServiceResult stays with the Session.
        const ua::StatusCode status = result.status_code();
        callback(ua::detail::held(Session{std::move(result).value()}, status));
      });
  }
  catch (...)
  {
    callback(SessionResult{ua::exception_to_status_code(std::current_exception())});
  }
}

Session SecureChannel::create_session_sync(CreateSessionConfig config)
{
  return ua::detail::good_value(try_create_session_sync(std::move(config)));
}

SecureChannel::SessionResult SecureChannel::try_create_session_sync(CreateSessionConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SessionResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(SessionResult)> complete)
      { create_session_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return SessionResult{ua::exception_to_status_code(std::current_exception())};
  }
}

// --- Discovery services ---
//
// Typed helpers send a request through the channel impl and downcast the response.
// Raw send_request on SecureChannelImpl is the only entry point - no public untyped API.

namespace
{

/// Send a typed request through the channel impl and downcast the response.
template<typename ResponseT, typename RequestT>
void typed_request_async(std::shared_ptr<SecureChannelImpl> impl, RequestT request,
  std::function<void(ua::Result<ResponseT>)> callback) noexcept
{
  using SRR = SecureChannelImpl::ServiceResponseResult;
  using ResultT = ua::Result<ResponseT>;

  if (!impl)
  {
    callback(ResultT{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }

  try
  {
    // Session-less services (discovery, registration) have no Session to resolve the hint for them,
    // so the channel's own configured default is stamped here - same rule as the session path.
    auto timeoutMs = impl->timeout_hint_for(request.request_header().timeout_hint());
    request.request_header().timeout_hint() = timeoutMs;
    // Part 4 section 7.33: timestamp describes this dispatch, not request construction.
    request.request_header().timestamp() = ua::DateTime::now();
    auto erased = std::make_shared<RequestT>(std::move(request));

    impl->send_request(
      std::move(erased),
      [callback = std::move(callback)](SRR response) mutable
      {
        if (!response)
        {
          callback(ResultT{response.status_code(), response.shared_detail()});
          return;
        }
        auto* typed = dynamic_cast<ResponseT*>(response.value().get());
        if (!typed)
        {
          callback(ResultT{ua::Status::BadDecodingError});
          return;
        }
        callback(ResultT{std::move(*typed)});
      },
      timeoutMs);
  }
  catch (...)
  {
    callback(ResultT{ua::exception_to_status_code(std::current_exception())});
  }
}

template<typename ResponseT, typename RequestT>
ua::Result<ResponseT> typed_request_try_sync(
  std::shared_ptr<SecureChannelImpl> impl, RequestT request) noexcept
{
  using ResultT = ua::Result<ResponseT>;
  // Refused with Bad_WouldBlock before anything is sent when called on the executor that would deliver
  // the response (public API review item D8).
  const auto executor = impl ? impl->executor() : boost::asio::any_io_executor{};
  return ua::async::detail::blocking_call<ResultT>(executor,
    [&impl, &request](std::function<void(ResultT)> complete)
    { typed_request_async<ResponseT>(impl, std::move(request), std::move(complete)); });
}

}  // namespace

// GetEndpoints

void SecureChannel::get_endpoints_async(
  ua::GetEndpointsRequest request, GetEndpointsCallback callback) noexcept
{
  typed_request_async<ua::GetEndpointsResponse>(mImpl, std::move(request), std::move(callback));
}

ua::GetEndpointsResponse SecureChannel::get_endpoints_sync(ua::GetEndpointsRequest request)
{
  return ua::detail::good_value(try_get_endpoints_sync(std::move(request)));
}

SecureChannel::GetEndpointsResponseResult SecureChannel::try_get_endpoints_sync(
  ua::GetEndpointsRequest request) noexcept
{
  return typed_request_try_sync<ua::GetEndpointsResponse>(mImpl, std::move(request));
}

// FindServers

void SecureChannel::find_servers_async(ua::FindServersRequest request, FindServersCallback callback) noexcept
{
  typed_request_async<ua::FindServersResponse>(mImpl, std::move(request), std::move(callback));
}

ua::FindServersResponse SecureChannel::find_servers_sync(ua::FindServersRequest request)
{
  return ua::detail::good_value(try_find_servers_sync(std::move(request)));
}

SecureChannel::FindServersResponseResult SecureChannel::try_find_servers_sync(
  ua::FindServersRequest request) noexcept
{
  return typed_request_try_sync<ua::FindServersResponse>(mImpl, std::move(request));
}

// FindServersOnNetwork

void SecureChannel::find_servers_on_network_async(
  ua::FindServersOnNetworkRequest request, FindServersOnNetworkCallback callback) noexcept
{
  typed_request_async<ua::FindServersOnNetworkResponse>(mImpl, std::move(request), std::move(callback));
}

ua::FindServersOnNetworkResponse SecureChannel::find_servers_on_network_sync(
  ua::FindServersOnNetworkRequest request)
{
  return ua::detail::good_value(try_find_servers_on_network_sync(std::move(request)));
}

SecureChannel::FindServersOnNetworkResponseResult SecureChannel::try_find_servers_on_network_sync(
  ua::FindServersOnNetworkRequest request) noexcept
{
  return typed_request_try_sync<ua::FindServersOnNetworkResponse>(mImpl, std::move(request));
}

// --- LDS registration (no session required) ---
//
// Session-less marshalling: identical to the discovery triplets above. These route
// through the channel impl's send_request and never touch SessionImpl (which gates
// on SessionState::Active), so they work on a freshly-opened, session-less channel.

// RegisterServer

void SecureChannel::register_server_async(
  ua::RegisterServerRequest request, RegisterServerCallback callback) noexcept
{
  typed_request_async<ua::RegisterServerResponse>(mImpl, std::move(request), std::move(callback));
}

ua::RegisterServerResponse SecureChannel::register_server_sync(ua::RegisterServerRequest request)
{
  return ua::detail::good_value(try_register_server_sync(std::move(request)));
}

SecureChannel::RegisterServerResponseResult SecureChannel::try_register_server_sync(
  ua::RegisterServerRequest request) noexcept
{
  return typed_request_try_sync<ua::RegisterServerResponse>(mImpl, std::move(request));
}

// RegisterServer2

void SecureChannel::register_server2_async(
  ua::RegisterServer2Request request, RegisterServer2Callback callback) noexcept
{
  typed_request_async<ua::RegisterServer2Response>(mImpl, std::move(request), std::move(callback));
}

ua::RegisterServer2Response SecureChannel::register_server2_sync(ua::RegisterServer2Request request)
{
  return ua::detail::good_value(try_register_server2_sync(std::move(request)));
}

SecureChannel::RegisterServer2ResponseResult SecureChannel::try_register_server2_sync(
  ua::RegisterServer2Request request) noexcept
{
  return typed_request_try_sync<ua::RegisterServer2Response>(mImpl, std::move(request));
}

// --- Queries ---

uint32_t SecureChannel::secure_channel_id() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->secure_channel_id();
}

bool SecureChannel::is_open() const
{
  if (!mImpl)
    return false;
  return mImpl->is_open();
}

}  // namespace ua::client
