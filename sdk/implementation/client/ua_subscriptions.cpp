// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscriptions.h"

#include "ua_sync_wait.h"
#include "ua_connection_impl.h"
#include "ua_status.h"

#include <future>
#include <utility>

namespace ua::client
{

namespace
{

/// The status a create completes with on a moved-from handle (null pimpl).
constexpr ua::Status emptyHandleStatus = ua::Status::BadInvalidState;

}  // namespace

Subscriptions::Subscriptions(std::shared_ptr<detail::ConnectionImpl> impl) : mImpl(std::move(impl))
{}

void Subscriptions::create_async(
  SubscriptionConfig config, std::function<void(ua::Result<Subscription>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<Subscription>{emptyHandleStatus});
    return;
  }
  auto connection = mImpl;
  // Folded by the same function the modify and recreate paths use, so the OPC 10000-4 Table 90 lifetime
  // floor is applied identically wherever a parameter set is built.
  auto tuning =
    detail::ConnectionImpl::resolve_subscription_tuning(detail::ConnectionImpl::SubscriptionTuning{},
      config.lifetimeCount,
      config.maxKeepAliveCount,
      config.priority);
  tuning.publishingEnabled = config.publishingEnabled;
  connection->create_subscription_managed_async(config.publishingIntervalMs,
    tuning,
    config.maxNotificationsPerPublish,
    [connection, callback = std::move(callback)](ua::Result<detail::SubscriptionCreated> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<Subscription>{result.status_code(), result.shared_detail()});
        return;
      }
      const auto& created = result.value();
      // A Good subcode or an Uncertain CreateSubscription ServiceResult stays with the Subscription.
      callback(ua::detail::held(detail::SubscriptionFactory::create(std::move(connection),
                                  created.subscriptionId,
                                  created.revisedPublishingInterval,
                                  created.publishingEnabled),
        result.status_code()));
    });
}

Subscription Subscriptions::create_sync(SubscriptionConfig config)
{
  return ua::detail::good_value(try_create_sync(std::move(config)));
}

ua::Result<Subscription> Subscriptions::try_create_sync(SubscriptionConfig config) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<Subscription>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, config = std::move(config)](auto completion) mutable
    { create_async(std::move(config), std::move(completion)); });
}

void Subscriptions::list_async(
  std::function<void(ua::Result<std::vector<Subscription>>)> callback) const noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<Subscription>>{emptyHandleStatus});
    return;
  }
  auto connection = mImpl;
  connection->subscription_descriptors_async(
    [connection, callback = std::move(callback)](std::vector<detail::SubscriptionCreated> descriptors) mutable
    {
      std::vector<Subscription> subscriptions;
      subscriptions.reserve(descriptors.size());
      for (const auto& created : descriptors)
      {
        subscriptions.push_back(detail::SubscriptionFactory::create(
          connection, created.subscriptionId, created.revisedPublishingInterval, created.publishingEnabled));
      }
      callback(ua::Result<std::vector<Subscription>>{std::move(subscriptions)});
    });
}

std::vector<Subscription> Subscriptions::list_sync() const
{
  return ua::detail::good_value(try_list_sync());
}

ua::Result<std::vector<Subscription>> Subscriptions::try_list_sync() const noexcept
{
  boost::asio::any_io_executor executor;
  if (mImpl)
    executor = mImpl->executor();
  return ua::async::detail::blocking_call<ua::Result<std::vector<Subscription>>>(
    executor, [this](auto completion) { list_async(std::move(completion)); });
}

}  // namespace ua::client
