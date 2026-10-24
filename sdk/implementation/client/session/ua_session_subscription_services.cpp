// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_subscription_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionSubscriptionServices::SessionSubscriptionServices(std::weak_ptr<SessionImpl> impl)
  : mImpl(std::move(impl))
{}

// --- CreateSubscription ---

void SessionSubscriptionServices::create_subscription_async(
  ua::CreateSubscriptionRequest request, CreateSubscriptionCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(CreateSubscriptionResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::CreateSubscriptionResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::CreateSubscriptionResponse SessionSubscriptionServices::create_subscription_sync(
  ua::CreateSubscriptionRequest request)
{
  return ua::detail::good_value(try_create_subscription_sync(std::move(request)));
}

SessionSubscriptionServices::CreateSubscriptionResponseResult
  SessionSubscriptionServices::try_create_subscription_sync(ua::CreateSubscriptionRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return CreateSubscriptionResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::CreateSubscriptionResponse>(std::move(impl), std::move(request));
}

// --- ModifySubscription ---

void SessionSubscriptionServices::modify_subscription_async(
  ua::ModifySubscriptionRequest request, ModifySubscriptionCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(ModifySubscriptionResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::ModifySubscriptionResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::ModifySubscriptionResponse SessionSubscriptionServices::modify_subscription_sync(
  ua::ModifySubscriptionRequest request)
{
  return ua::detail::good_value(try_modify_subscription_sync(std::move(request)));
}

SessionSubscriptionServices::ModifySubscriptionResponseResult
  SessionSubscriptionServices::try_modify_subscription_sync(ua::ModifySubscriptionRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return ModifySubscriptionResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::ModifySubscriptionResponse>(std::move(impl), std::move(request));
}

// --- SetPublishingMode ---

void SessionSubscriptionServices::set_publishing_mode_async(
  ua::SetPublishingModeRequest request, SetPublishingModeCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(SetPublishingModeResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::SetPublishingModeResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::SetPublishingModeResponse SessionSubscriptionServices::set_publishing_mode_sync(
  ua::SetPublishingModeRequest request)
{
  return ua::detail::good_value(try_set_publishing_mode_sync(std::move(request)));
}

SessionSubscriptionServices::SetPublishingModeResponseResult
  SessionSubscriptionServices::try_set_publishing_mode_sync(ua::SetPublishingModeRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return SetPublishingModeResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::SetPublishingModeResponse>(std::move(impl), std::move(request));
}

// --- Publish ---

void SessionSubscriptionServices::publish_async(ua::PublishRequest request, PublishCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(PublishResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::PublishResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::PublishResponse SessionSubscriptionServices::publish_sync(ua::PublishRequest request)
{
  return ua::detail::good_value(try_publish_sync(std::move(request)));
}

SessionSubscriptionServices::PublishResponseResult SessionSubscriptionServices::try_publish_sync(
  ua::PublishRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return PublishResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::PublishResponse>(std::move(impl), std::move(request));
}

// --- Republish ---

void SessionSubscriptionServices::republish_async(
  ua::RepublishRequest request, RepublishCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(RepublishResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::RepublishResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::RepublishResponse SessionSubscriptionServices::republish_sync(ua::RepublishRequest request)
{
  return ua::detail::good_value(try_republish_sync(std::move(request)));
}

SessionSubscriptionServices::RepublishResponseResult SessionSubscriptionServices::try_republish_sync(
  ua::RepublishRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return RepublishResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::RepublishResponse>(std::move(impl), std::move(request));
}

// --- TransferSubscriptions ---

void SessionSubscriptionServices::transfer_subscriptions_async(
  ua::TransferSubscriptionsRequest request, TransferSubscriptionsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(TransferSubscriptionsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::TransferSubscriptionsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::TransferSubscriptionsResponse SessionSubscriptionServices::transfer_subscriptions_sync(
  ua::TransferSubscriptionsRequest request)
{
  return ua::detail::good_value(try_transfer_subscriptions_sync(std::move(request)));
}

SessionSubscriptionServices::TransferSubscriptionsResponseResult
  SessionSubscriptionServices::try_transfer_subscriptions_sync(
    ua::TransferSubscriptionsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return TransferSubscriptionsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::TransferSubscriptionsResponse>(
    std::move(impl), std::move(request));
}

// --- DeleteSubscriptions ---

void SessionSubscriptionServices::delete_subscriptions_async(
  ua::DeleteSubscriptionsRequest request, DeleteSubscriptionsCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(DeleteSubscriptionsResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::DeleteSubscriptionsResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::DeleteSubscriptionsResponse SessionSubscriptionServices::delete_subscriptions_sync(
  ua::DeleteSubscriptionsRequest request)
{
  return ua::detail::good_value(try_delete_subscriptions_sync(std::move(request)));
}

SessionSubscriptionServices::DeleteSubscriptionsResponseResult
  SessionSubscriptionServices::try_delete_subscriptions_sync(ua::DeleteSubscriptionsRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return DeleteSubscriptionsResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::DeleteSubscriptionsResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
