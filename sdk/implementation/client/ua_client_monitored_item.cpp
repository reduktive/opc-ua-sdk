// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Self-action forwarding for the unified @ref ua::client::MonitoredItem handle (client design
/// section 7.4).

#include "ua_client_monitored_item.h"

#include "ua_sync_wait.h"
#include "ua_error_detail.h"
#include "ua_status.h"

#include <utility>

namespace ua::client
{

namespace
{
/// The owner's executor, or empty once it has gone.
boost::asio::any_io_executor owner_executor(const std::weak_ptr<detail::MonitoredItemOwner>& owner)
{
  const auto locked = owner.lock();
  return locked ? locked->executor() : boost::asio::any_io_executor{};
}
}  // namespace

namespace
{

/// The status + source-tagged ErrorDetail a self-action completes with when the weak owner interface cannot
/// be locked. The owner is a CONNECTION-lifetime component, so a failed lock means the Connection itself is
/// gone
///  to  `Bad_ConnectionClosed` (section 7.4). This is DISTINCT from a registry-lookup miss (the item was
///  explicitly
/// deleted): that miss is detected inside the live owner and surfaces `Bad_SubscriptionIdInvalid` there.
ua::VoidResult owner_gone_result()
{
  return ua::VoidResult{ua::StatusCode{ua::Status::BadConnectionClosed},
    ua::make_error_detail("BadConnectionClosed",
      "MonitoredItem self-action could not reach its Connection (the Connection is closed)",
      "client.tier1.monitored_item.owner_gone")};
}

}  // namespace

void MonitoredItem::modify_async(
  MonitorRequest request, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto owner = mOwner.lock();
  if (!owner)
  {
    callback(owner_gone_result());
    return;
  }
  owner->mi_modify_async(mClientHandle, std::move(request), std::move(callback));
}

void MonitoredItem::set_mode_async(
  ua::MonitoringMode mode, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto owner = mOwner.lock();
  if (!owner)
  {
    callback(owner_gone_result());
    return;
  }
  owner->mi_set_mode_async(mClientHandle, mode, std::move(callback));
}

void MonitoredItem::delete_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto owner = mOwner.lock();
  if (!owner)
  {
    callback(owner_gone_result());
    return;
  }
  owner->mi_delete_async(mClientHandle, std::move(callback));
}

void MonitoredItem::modify_sync(MonitorRequest request)
{
  try_modify_sync(std::move(request)).value();
}

ua::VoidResult MonitoredItem::try_modify_sync(MonitorRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(owner_executor(mOwner),
    [this, request = std::move(request)](auto completion) mutable
    { modify_async(std::move(request), std::move(completion)); });
}

void MonitoredItem::set_mode_sync(ua::MonitoringMode mode)
{
  try_set_mode_sync(mode).value();
}

ua::VoidResult MonitoredItem::try_set_mode_sync(ua::MonitoringMode mode) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    owner_executor(mOwner), [this, mode](auto completion) { set_mode_async(mode, std::move(completion)); });
}

void MonitoredItem::delete_sync()
{
  try_delete_sync().value();
}

ua::VoidResult MonitoredItem::try_delete_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    owner_executor(mOwner), [this](auto completion) { delete_async(std::move(completion)); });
}

}  // namespace ua::client
