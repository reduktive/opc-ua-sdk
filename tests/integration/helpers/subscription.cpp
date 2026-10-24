// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "subscription.h"

#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitoring_parameters.h"
#include "ua_publish_request.h"
#include "ua_read_value_id.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_subscription_acknowledgement.h"

#include <chrono>
#include <memory>
#include <thread>
#include <utility>

namespace ua::test_helpers
{

namespace
{

ua::CreateSubscriptionRequest build_create_subscription(const SubscriptionOptions& opts)
{
  ua::CreateSubscriptionRequest req;
  req.requested_publishing_interval() = opts.publishingInterval;
  req.requested_lifetime_count() = opts.lifetimeCount;
  req.requested_max_keep_alive_count() = opts.keepAliveCount;
  req.max_notifications_per_publish() = opts.maxNotificationsPerPublish;
  req.publishing_enabled() = opts.publishingEnabled;
  req.priority() = opts.priority;
  return req;
}

ua::MonitoredItemCreateRequest build_create_mi(
  const ua::NodeId& node, const MonitoringOptions& opts, std::unique_ptr<ua::Structure> filter)
{
  ua::ReadValueId rv;
  rv.node_id() = node;
  rv.attribute_id() = static_cast<uint32_t>(opts.attribute);

  ua::MonitoringParameters params;
  params.client_handle() = opts.clientHandle;
  params.sampling_interval() = opts.samplingInterval;
  params.queue_size() = opts.queueSize;
  params.discard_oldest() = opts.discardOldest;
  if (filter)
  {
    params.filter() = std::move(filter);
  }

  ua::MonitoredItemCreateRequest miReq;
  miReq.item_to_monitor() = std::move(rv);
  miReq.monitoring_mode() = opts.mode;
  miReq.requested_parameters() = std::move(params);
  return miReq;
}

}  // namespace

ua::CreateSubscriptionRequest build_subscription_request(SubscriptionOptions opts)
{
  return build_create_subscription(opts);
}

ua::CreateMonitoredItemsRequest build_create_mi_request(
  uint32_t subscriptionId, const ua::NodeId& nodeId, MonitoringOptions opts)
{
  ua::CreateMonitoredItemsRequest req;
  req.subscription_id() = subscriptionId;
  req.timestamps_to_return() = ua::TimestampsToReturn::Both;
  req.items_to_create().push_back(build_create_mi(nodeId, opts, /*filter=*/nullptr));
  return req;
}

ua::CreateMonitoredItemsRequest build_create_mi_request(uint32_t subscriptionId, const ua::NodeId& nodeId,
  std::unique_ptr<ua::Structure> filter, MonitoringOptions opts)
{
  ua::CreateMonitoredItemsRequest req;
  req.subscription_id() = subscriptionId;
  req.timestamps_to_return() = ua::TimestampsToReturn::Both;
  req.items_to_create().push_back(build_create_mi(nodeId, opts, std::move(filter)));
  return req;
}

uint32_t create_subscription(ua::client::Session& session, SubscriptionOptions options)
{
  auto resp = session.subscriptions().create_subscription_sync(build_create_subscription(options));
  EXPECT_TRUE(resp.response_header().service_result().is_good())
    << "create_subscription service_result = 0x" << std::hex
    << resp.response_header().service_result().as_uint32();
  return resp.subscription_id();
}

SubscriptionWithMonitoredItem create_subscription_with_monitored_item(ua::client::Session& session,
  const ua::NodeId& node, SubscriptionOptions subOptions, MonitoringOptions miOptions)
{
  SubscriptionWithMonitoredItem out;
  out.subscriptionId = create_subscription(session, subOptions);
  if (out.subscriptionId == 0)
  {
    return out;
  }

  ua::CreateMonitoredItemsRequest miReq;
  miReq.subscription_id() = out.subscriptionId;
  miReq.timestamps_to_return() = ua::TimestampsToReturn::Both;
  miReq.items_to_create().push_back(build_create_mi(node, miOptions, /*filter=*/nullptr));

  auto miResp = session.monitored_items().create_monitored_items_sync(std::move(miReq));
  EXPECT_TRUE(miResp.response_header().service_result().is_good())
    << "create_monitored_items service_result = 0x" << std::hex
    << miResp.response_header().service_result().as_uint32();
  if (miResp.results().empty())
  {
    ADD_FAILURE() << "create_monitored_items returned empty results";
    return out;
  }
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "MI result status = 0x" << std::hex << miResp.results()[0].status_code().as_uint32();
  out.monitoredItemId = miResp.results()[0].monitored_item_id();
  return out;
}

uint32_t create_event_monitored_item(ua::client::Session& session, uint32_t subscriptionId,
  const ua::NodeId& eventSourceNode, ua::EventFilter filter, MonitoringOptions miOptions)
{
  // Event monitored items are sampled by the server's internal event pipeline,
  // not the variable sampler. The historical helpers passed samplingInterval=0
  // for event MIs (the default in MonitoringOptions is 100ms for data-change).
  // We do not override here: callers that care pass a custom samplingInterval.
  // The attribute is forced to EventNotifier regardless of the options struct.
  miOptions.attribute = ua::AttributeId::EventNotifier;

  ua::CreateMonitoredItemsRequest miReq;
  miReq.subscription_id() = subscriptionId;
  miReq.timestamps_to_return() = ua::TimestampsToReturn::Both;
  miReq.items_to_create().push_back(
    build_create_mi(eventSourceNode, miOptions, std::make_unique<ua::EventFilter>(std::move(filter))));

  auto miResp = session.monitored_items().create_monitored_items_sync(std::move(miReq));
  EXPECT_TRUE(miResp.response_header().service_result().is_good())
    << "create_event_monitored_item service_result = 0x" << std::hex
    << miResp.response_header().service_result().as_uint32();
  if (miResp.results().empty())
  {
    ADD_FAILURE() << "create_event_monitored_item returned empty results";
    return 0;
  }
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "Event MI result status = 0x" << std::hex << miResp.results()[0].status_code().as_uint32();
  return miResp.results()[0].monitored_item_id();
}

void acknowledge(ua::client::Session& session, uint32_t subscriptionId, uint32_t sequenceNumber)
{
  ua::PublishRequest req;
  ua::SubscriptionAcknowledgement ack;
  ack.subscription_id() = subscriptionId;
  ack.sequence_number() = sequenceNumber;
  req.subscription_acknowledgements().push_back(std::move(ack));

  // try_publish_sync because BadNoSubscription is a legitimate (race) outcome -
  // the helper still posts the ack, but the response itself may be empty.
  auto result = session.subscriptions().try_publish_sync(std::move(req));
  EXPECT_TRUE(result.is_good()) << "acknowledge publish failed: 0x" << std::hex
                                << result.status_code().as_uint32();
}

std::optional<ua::DataChangeNotification> wait_for_data_change(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout)
{
  return wait_for_data_change(session, subscriptionId, subscription_detail::AlwaysTrue{}, timeout);
}

std::optional<ua::EventFieldList> wait_for_event(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout)
{
  return wait_for_event(session, subscriptionId, subscription_detail::AlwaysTrue{}, timeout);
}

std::optional<ua::StatusChangeNotification> wait_for_status_change(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout)
{
  return wait_for_status_change(session, subscriptionId, subscription_detail::AlwaysTrue{}, timeout);
}

void drain_initial_publish(
  ua::client::Session& session, uint32_t subscriptionId, std::chrono::milliseconds timeout)
{
  (void)wait_for_data_change(session, subscriptionId, timeout);
}

void delete_subscription(ua::client::Session& session, uint32_t subscriptionId)
{
  ua::DeleteSubscriptionsRequest req;
  req.subscription_ids().push_back(subscriptionId);
  (void)session.subscriptions().try_delete_subscriptions_sync(std::move(req));
}

std::optional<ua::PublishResponse> try_publish_once(ua::client::Session& session, ua::PublishRequest request)
{
  auto result = session.subscriptions().try_publish_sync(std::move(request));
  if (!result.is_good())
  {
    return std::nullopt;
  }
  if (!result.value().response_header().service_result().is_good())
  {
    return std::nullopt;
  }
  return std::move(result.value());
}

void set_publishing_mode(ua::client::Session& session, uint32_t subscriptionId, bool enabled)
{
  ua::SetPublishingModeRequest req;
  req.publishing_enabled() = enabled;
  req.subscription_ids().push_back(subscriptionId);
  auto resp = session.subscriptions().set_publishing_mode_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "set_publishing_mode service_result = 0x" << std::hex
    << resp.response_header().service_result().as_uint32();
  ASSERT_FALSE(resp.results().empty()) << "set_publishing_mode returned empty results";
  EXPECT_TRUE(resp.results()[0].is_good())
    << "set_publishing_mode per-sub result = 0x" << std::hex << resp.results()[0].as_uint32();
}

const ua::DataChangeNotification* as_data_change(const ua::PublishResponse& resp)
{
  for (const auto& nd : resp.notification_message().notification_data())
  {
    if (const auto* ptr = dynamic_cast<const ua::DataChangeNotification*>(nd.get()))
    {
      return ptr;
    }
  }
  return nullptr;
}

const ua::StatusChangeNotification* as_status_change(const ua::PublishResponse& resp)
{
  for (const auto& nd : resp.notification_message().notification_data())
  {
    if (const auto* ptr = dynamic_cast<const ua::StatusChangeNotification*>(nd.get()))
    {
      return ptr;
    }
  }
  return nullptr;
}

const ua::EventNotificationList* as_event_notification(const ua::PublishResponse& resp)
{
  for (const auto& nd : resp.notification_message().notification_data())
  {
    if (const auto* ptr = dynamic_cast<const ua::EventNotificationList*>(nd.get()))
    {
      return ptr;
    }
  }
  return nullptr;
}

std::vector<ua::EventFieldList> collect_events(
  ua::client::Session& session, uint32_t subscriptionId, CollectEventsOptions options)
{
  std::vector<ua::EventFieldList> collected;
  const auto deadline = std::chrono::steady_clock::now() + options.timeout;
  do
  {
    auto result = session.subscriptions().try_publish_sync(ua::PublishRequest{});
    if (result.is_good() && result.value().response_header().service_result().is_good() &&
        result.value().subscription_id() == subscriptionId)
    {
      if (const auto* enl = as_event_notification(result.value()))
      {
        for (const auto& efl : enl->events())
        {
          collected.push_back(efl);
        }
      }
    }
    if (collected.size() >= options.minCount)
    {
      return collected;
    }
    if (std::chrono::steady_clock::now() >= deadline)
    {
      return collected;
    }
    std::this_thread::sleep_for(options.pollInterval);
  }
  while (std::chrono::steady_clock::now() < deadline);
  return collected;
}

}  // namespace ua::test_helpers
