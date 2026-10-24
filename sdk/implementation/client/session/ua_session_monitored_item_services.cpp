// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_monitored_item_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionMonitoredItemServices::SessionMonitoredItemServices(std::weak_ptr<SessionImpl> impl)
  : mImpl(std::move(impl))
{}

// --- CreateMonitoredItems ---

void SessionMonitoredItemServices::create_monitored_items_async(
  ua::CreateMonitoredItemsRequest request, CreateMonitoredItemsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(CreateMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::CreateMonitoredItemsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::CreateMonitoredItemsResponse SessionMonitoredItemServices::create_monitored_items_sync(
  ua::CreateMonitoredItemsRequest request)
{
  return ua::detail::good_value(try_create_monitored_items_sync(std::move(request)));
}

SessionMonitoredItemServices::CreateMonitoredItemsResponseResult
  SessionMonitoredItemServices::try_create_monitored_items_sync(
    ua::CreateMonitoredItemsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return CreateMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::CreateMonitoredItemsResponse>(
    std::move(impl), std::move(request));
}

// --- ModifyMonitoredItems ---

void SessionMonitoredItemServices::modify_monitored_items_async(
  ua::ModifyMonitoredItemsRequest request, ModifyMonitoredItemsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(ModifyMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::ModifyMonitoredItemsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::ModifyMonitoredItemsResponse SessionMonitoredItemServices::modify_monitored_items_sync(
  ua::ModifyMonitoredItemsRequest request)
{
  return ua::detail::good_value(try_modify_monitored_items_sync(std::move(request)));
}

SessionMonitoredItemServices::ModifyMonitoredItemsResponseResult
  SessionMonitoredItemServices::try_modify_monitored_items_sync(
    ua::ModifyMonitoredItemsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return ModifyMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::ModifyMonitoredItemsResponse>(
    std::move(impl), std::move(request));
}

// --- SetMonitoringMode ---

void SessionMonitoredItemServices::set_monitoring_mode_async(
  ua::SetMonitoringModeRequest request, SetMonitoringModeCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(SetMonitoringModeResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::SetMonitoringModeResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::SetMonitoringModeResponse SessionMonitoredItemServices::set_monitoring_mode_sync(
  ua::SetMonitoringModeRequest request)
{
  return ua::detail::good_value(try_set_monitoring_mode_sync(std::move(request)));
}

SessionMonitoredItemServices::SetMonitoringModeResponseResult
  SessionMonitoredItemServices::try_set_monitoring_mode_sync(ua::SetMonitoringModeRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return SetMonitoringModeResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::SetMonitoringModeResponse>(std::move(impl), std::move(request));
}

// --- SetTriggering ---

void SessionMonitoredItemServices::set_triggering_async(
  ua::SetTriggeringRequest request, SetTriggeringCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(SetTriggeringResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::SetTriggeringResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::SetTriggeringResponse SessionMonitoredItemServices::set_triggering_sync(ua::SetTriggeringRequest request)
{
  return ua::detail::good_value(try_set_triggering_sync(std::move(request)));
}

SessionMonitoredItemServices::SetTriggeringResponseResult
  SessionMonitoredItemServices::try_set_triggering_sync(ua::SetTriggeringRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return SetTriggeringResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::SetTriggeringResponse>(std::move(impl), std::move(request));
}

// --- DeleteMonitoredItems ---

void SessionMonitoredItemServices::delete_monitored_items_async(
  ua::DeleteMonitoredItemsRequest request, DeleteMonitoredItemsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(DeleteMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::DeleteMonitoredItemsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::DeleteMonitoredItemsResponse SessionMonitoredItemServices::delete_monitored_items_sync(
  ua::DeleteMonitoredItemsRequest request)
{
  return ua::detail::good_value(try_delete_monitored_items_sync(std::move(request)));
}

SessionMonitoredItemServices::DeleteMonitoredItemsResponseResult
  SessionMonitoredItemServices::try_delete_monitored_items_sync(
    ua::DeleteMonitoredItemsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return DeleteMonitoredItemsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::DeleteMonitoredItemsResponse>(
    std::move(impl), std::move(request));
}

}  // namespace ua::client
