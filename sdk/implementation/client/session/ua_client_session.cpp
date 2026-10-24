// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Public client::Session method forwarding to SessionImpl.

#include "ua_sync_wait.h"
#include "ua_client_session.h"
#include "ua_client_secure_channel.h"
#include "ua_client_secure_channel_impl.h"
#include "ua_client_session_impl.h"
#include "ua_session_service_helpers.h"

#include "ua_exceptions.h"
#include "ua_session_attribute_services.h"
#include "ua_session_discovery_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_query_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
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

Session::Session(std::shared_ptr<SessionImpl> impl) : mImpl(std::move(impl))
{}

Session::~Session() = default;

void Session::set_return_diagnostics_override(std::optional<std::uint32_t> mask) noexcept
{
  if (mImpl)
  {
    mImpl->set_return_diagnostics_override(mask);
  }
}

// ==================== Service Set Accessors ====================

SessionDiscoveryServices Session::discovery() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionDiscoveryServices(mImpl);
}

SessionViewServices Session::view() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionViewServices(mImpl);
}

SessionAttributeServices Session::attributes() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionAttributeServices(mImpl);
}

SessionNodeManagementServices Session::node_management() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionNodeManagementServices(mImpl);
}

SessionMethodServices Session::methods() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionMethodServices(mImpl);
}

SessionSubscriptionServices Session::subscriptions() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionSubscriptionServices(mImpl);
}

SessionMonitoredItemServices Session::monitored_items() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionMonitoredItemServices(mImpl);
}

SessionQueryServices Session::query() const
{
  if (!mImpl)
    throw_invalid_state();
  return SessionQueryServices(mImpl);
}

// ==================== Session Lifecycle ====================

// --- Close ---
//
// Foolproof shutdown: move mImpl into the completion lambda so its destruction
// runs as the last action of the close. Releasing the facade's strong-ref here
// (the user-facing Session is drained synchronously) is what lets a subsequent
// pool.join() return - there is no dangling impl strong-ref left at the facade.

void Session::close_async(CloseOptions config, CloseCallback callback) noexcept
{
  close_impl(config.deleteSubscriptions, std::move(callback));
}

void Session::close_sync(CloseOptions config)
{
  try_close_sync(config).value();
}

ua::VoidResult Session::try_close_sync(CloseOptions config) noexcept
{
  try
  {
    boost::asio::any_io_executor executor;
    if (mImpl)
      executor = mImpl->executor();
    return ua::async::detail::blocking_call<ua::VoidResult>(executor,
      [&](std::function<void(ua::VoidResult)> complete) { close_async(config, std::move(complete)); });
  }
  catch (...)
  {
    return ua::VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

void Session::close_async(CloseCallback callback) noexcept
{
  close_impl(/*deleteSubscriptions=*/true, std::move(callback));
}

void Session::close_impl(bool deleteSubscriptions, CloseCallback callback) noexcept
{
  // This noexcept facade invokes `callback` directly (both the already-closed fast path below and the
  // impl.close completion). An empty CloseCallback would throw std::bad_function_call out of a noexcept
  // boundary -> std::terminate. Normalize a fire-and-forget close to an explicit no-op so an empty
  // callback is safe (fire-and-forget uses a no-op, never an empty std::function).
  if (!callback)
  {
    callback = [](ua::VoidResult) {
    };
  }
  auto impl = std::move(mImpl);
  if (!impl)
  {
    // Idempotent: closing an already-closed session is a no-op success.
    callback(ua::VoidResult{});
    return;
  }
  auto& raw = *impl;
  raw.close(deleteSubscriptions,
    [impl = std::move(impl), callback = std::move(callback)](ua::VoidResult result) mutable
    {
      impl.reset();
      callback(std::move(result));
    });
}

void Session::close_sync()
{
  try_close_sync().value();
}

ua::VoidResult Session::try_close_sync() noexcept
{
  return try_close_sync(CloseOptions{});
}

// --- Activate ---

void Session::activate_async(ActivateConfig config, ActivateCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  mImpl->activate(std::move(config), std::move(callback));
}

void Session::activate_sync(ActivateConfig config)
{
  try_activate_sync(std::move(config)).value();
}

ua::VoidResult Session::try_activate_sync(ActivateConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ua::VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ua::VoidResult)> complete)
      { activate_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

// --- Activate on new channel (reconnection) ---

void Session::activate_async(SecureChannel channel, ActivateConfig config, ActivateCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  if (!channel.mImpl)
  {
    callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  mImpl->activate(channel.mImpl, std::move(config), std::move(callback));
}

void Session::activate_sync(SecureChannel channel, ActivateConfig config)
{
  try_activate_sync(std::move(channel), std::move(config)).value();
}

ua::VoidResult Session::try_activate_sync(SecureChannel channel, ActivateConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ua::VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ua::VoidResult)> complete)
      { activate_async(std::move(channel), std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

// ==================== Session Service Set ====================

// --- Cancel ---

void Session::cancel_async(ua::CancelRequest request, CancelCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(CancelResponseResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  detail::typed_request_async<ua::CancelResponse>(mImpl, std::move(request), std::move(callback));
}

ua::CancelResponse Session::cancel_sync(ua::CancelRequest request)
{
  return ua::detail::good_value(try_cancel_sync(std::move(request)));
}

Session::CancelResponseResult Session::try_cancel_sync(ua::CancelRequest request) noexcept
{
  if (!mImpl)
    return CancelResponseResult{ua::StatusCode{ua::Status::BadInvalidState}};
  return detail::typed_request_try_sync<ua::CancelResponse>(mImpl, std::move(request));
}

// --- Queries ---

ua::NodeId Session::session_id() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->session_id();
}

double Session::revised_session_timeout_ms() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->revised_session_timeout_ms();
}

bool Session::is_created() const
{
  if (!mImpl)
    return false;
  return mImpl->is_created();
}

bool Session::is_active() const
{
  if (!mImpl)
    return false;
  return mImpl->is_active();
}

bool Session::is_disconnected() const
{
  if (!mImpl)
    return true;
  return mImpl->is_disconnected();
}

}  // namespace ua::client
