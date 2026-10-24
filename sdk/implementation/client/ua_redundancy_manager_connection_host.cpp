// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_redundancy_manager_connection_host.h"

#include "ua_connection_impl.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_observer_sink.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_status.h"
#include "ua_subscription_factory.h"

#include <boost/asio/post.hpp>

#include <string>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client::detail
{

namespace
{
/// Source tags for the manufactured `client.tier1.redundancy.*` boundary failures (the design specification).
constexpr std::string_view readGoneSource = "client.tier1.redundancy.read.connection_gone";
constexpr std::string_view findServersProviderAbsentSource =
  "client.tier1.redundancy.find_servers.provider_absent";
constexpr std::string_view probeNotImplementedSource = "client.tier1.redundancy.probe.not_implemented";
constexpr std::string_view triggerGoneSource = "client.tier1.redundancy.trigger.connection_gone";
constexpr std::string_view monitorGoneSource = "client.tier1.redundancy.monitor.connection_gone";
constexpr std::string_view monitorFactoryGoneSource = "client.tier1.redundancy.monitor.factory_gone";
constexpr std::string_view monitorHostGoneSource = "client.tier1.redundancy.monitor.host_gone";

/// The reused redundancy ServiceLevel Subscription's parameters (section 8.11.4 install-monitor step). A
/// modest cadence: the manager scores off sample HISTORY, so a 1 s publishing interval is ample; publishing
/// starts enabled so the initial ServiceLevel sample flows without a separate SetPublishingMode.
constexpr double redundancySubscriptionIntervalMs = 1000.0;
constexpr bool redundancySubscriptionPublishingEnabled = true;

/// Completes @p callback on @p executor with @p status carrying a source-tagged ErrorDetail (posts, never
/// fires inline, so the callback runs on the executor  -  the design specification).
template<typename Value>
void complete_bad_on_executor(const boost::asio::any_io_executor& executor, ua::Status status,
  std::string code, std::string summary, std::string_view source,
  std::function<void(ua::Result<Value>)> callback)
{
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [status,
        code = std::move(code),
        summary = std::move(summary),
        source = std::string{source},
        callback = std::move(callback)]() mutable
      {
        callback(ua::Result<Value>{ua::StatusCode{status,
          ua::ErrorDetail::build(std::move(code), "Redundancy operation failed", std::move(source))
            .context(ua::ContextKeys::errorMessage, summary)}});
      }));
}
}  // namespace

RedundancyManagerConnectionHost::RedundancyManagerConnectionHost(std::weak_ptr<ConnectionImpl> connection,
  boost::asio::any_io_executor executor, std::shared_ptr<ObserverSink> sink,
  RedundancyDiscoveryProvider discovery, ua::Logger logger)
  : mConnection(std::move(connection)), mExecutor(std::move(executor)), mSink(std::move(sink)),
    mDiscovery(std::move(discovery)), mLogger(std::move(logger))
{}

// -------- Identity (synchronous; served off ConnectionImpl's lock-free cross-strand snapshots) --------

ua::NodeId RedundancyManagerConnectionHost::connection_id() const
{
  if (const auto connection = mConnection.lock())
  {
    if (const auto info = connection->info())
    {
      return info->sessionId;
    }
  }
  return {};
}

ua::EndpointDescription RedundancyManagerConnectionHost::current_endpoint() const
{
  if (const auto connection = mConnection.lock())
  {
    if (const auto endpoint = connection->active_endpoint_snapshot())
    {
      return *endpoint;
    }
  }
  return {};
}

std::string RedundancyManagerConnectionHost::current_application_uri() const
{
  if (const auto connection = mConnection.lock())
  {
    if (const auto endpoint = connection->active_endpoint_snapshot())
    {
      return static_cast<std::string>(endpoint->server().application_uri());
    }
  }
  return {};
}

// -------- Service primitives (forward to ConnectionImpl's strand; a gone Connection is source-tagged) -----

void RedundancyManagerConnectionHost::read_attributes_async(
  std::vector<ua::ReadValueId> reads, std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback)
{
  const auto connection = mConnection.lock();
  if (!connection)
  {
    complete_bad_on_executor<std::vector<ua::DataValue>>(mExecutor,
      ua::Status::BadConnectionClosed,
      "ConnectionGone",
      "the tier-1 Connection was destroyed before the redundancy Read could be dispatched",
      readGoneSource,
      std::move(callback));
    return;
  }
  ua::ReadRequest request;
  for (auto& read : reads)
  {
    request.nodes_to_read().push_back(std::move(read));
  }
  connection->read_async(std::move(request),
    [callback = std::move(callback)](ua::Result<ua::ReadResponse> result) mutable
    {
      if (!result.has_value())
      {
        // Propagate the funnel's service-level ErrorDetail unchanged (single-wrap).
        callback(ua::Result<std::vector<ua::DataValue>>{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode serviceStatus =
        ua::detail::combined_status(result.status_code(), result.value().response_header().service_result());
      if (serviceStatus.is_bad())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{serviceStatus});
        return;
      }
      std::vector<ua::DataValue> values;
      const auto& results = result.value().results();
      values.reserve(results.size());
      for (const auto& value : results)
      {
        values.push_back(value);
      }
      // A Good subcode or an Uncertain ServiceResult reaches the manager, which decides on the values.
      callback(ua::detail::held(std::move(values), serviceStatus));
    });
}

void RedundancyManagerConnectionHost::find_servers_async(
  ua::client::FindServersOptions request, std::function<void(FindServersResult)> callback)
{
  // Derive the discovery URL from the bound endpoint snapshot: prefer the server's advertised discovery
  // URL(s), else fall back to the endpoint URL. A gone Connection yields an empty URL (the provider decides
  // how to treat it); the primary failure mode this method guards is the ABSENT provider.
  std::string discoveryUrl;
  if (const auto connection = mConnection.lock())
  {
    if (const auto endpoint = connection->active_endpoint_snapshot())
    {
      if (!endpoint->server().discovery_urls().empty())
      {
        discoveryUrl = static_cast<std::string>(endpoint->server().discovery_urls()[0]);
      }
      else
      {
        discoveryUrl = static_cast<std::string>(endpoint->endpoint_url());
      }
    }
  }
  if (mDiscovery)
  {
    mDiscovery(std::move(discoveryUrl), std::move(request), std::move(callback));
    return;
  }
  complete_bad_on_executor<std::vector<ua::ApplicationDescription>>(mExecutor,
    ua::Status::BadNotImplemented,
    "FindServersProviderAbsent",
    "no RedundancyDiscoveryProvider was wired into this Connection (connect-path deferred)",
    findServersProviderAbsentSource,
    std::move(callback));
}

// -------- Subscription / MonitoredItem primitives --------

void RedundancyManagerConnectionHost::monitor_attribute_async(ua::client::MonitorRequest request,
  ua::client::DataChangeCallback onData, std::function<void(ua::Result<ua::client::MonitoredItem>)> callback)
{
  const auto connection = mConnection.lock();
  if (!connection)
  {
    complete_bad_on_executor<ua::client::MonitoredItem>(mExecutor,
      ua::Status::BadConnectionClosed,
      "ConnectionGone",
      "the tier-1 Connection was destroyed before the ServiceLevel monitor could be installed",
      monitorGoneSource,
      std::move(callback));
    return;
  }
  const auto factory = connection->subscription_factory();
  if (!factory)
  {
    complete_bad_on_executor<ua::client::MonitoredItem>(mExecutor,
      ua::Status::BadConnectionClosed,
      "SubscriptionFactoryGone",
      "the Connection's subscription factory is gone; cannot install the ServiceLevel monitor",
      monitorFactoryGoneSource,
      std::move(callback));
    return;
  }

  std::optional<std::uint32_t> cachedSubscriptionId;
  {
    const std::lock_guard<std::mutex> lock(mSubscriptionMutex);
    cachedSubscriptionId = mRedundancySubscriptionId;
  }
  if (cachedSubscriptionId)
  {
    // The reused redundancy Subscription already exists (a later discovery generation re-installs the MI):
    // attach the ServiceLevel MonitoredItem directly.
    factory->monitor_data_change_async(
      *cachedSubscriptionId, std::move(request), std::move(onData), std::move(callback));
    return;
  }

  // First install: create the ONE reused redundancy Subscription, cache its id, then attach the MI. The
  // completion weak-captures `self` (the manager holds this host strong, but a racing close resets it) so a
  // create reply that lands after teardown completes the boundary failure rather than dereferencing a gone
  // host (the design specification).
  const std::weak_ptr<RedundancyManagerConnectionHost> weakSelf = weak_from_this();
  factory->create_subscription_managed_async(redundancySubscriptionIntervalMs,
    redundancySubscriptionPublishingEnabled,
    [weakSelf,
      factory,
      request = std::move(request),
      onData = std::move(onData),
      callback = std::move(callback)](ua::Result<SubscriptionCreated> created) mutable
    {
      // A Subscription created with a Good subcode or an Uncertain code exists on the server and is used.
      if (!created.has_value())
      {
        callback(ua::Result<ua::client::MonitoredItem>{created.status_code(), created.shared_detail()});
        return;
      }
      const auto self = weakSelf.lock();
      if (!self)
      {
        callback(ua::Result<ua::client::MonitoredItem>{ua::StatusCode{ua::Status::BadConnectionClosed},
          ua::make_error_detail("RedundancyHostGone",
            "the redundancy host was torn down before the reused Subscription could be cached",
            std::string{monitorHostGoneSource})});
        return;
      }
      const std::uint32_t createdSubscriptionId = created.value().subscriptionId;
      std::uint32_t subscriptionId = createdSubscriptionId;
      std::optional<std::uint32_t> loserSubscriptionId;
      {
        const std::lock_guard<std::mutex> lock(self->mSubscriptionMutex);
        if (self->mRedundancySubscriptionId)
        {
          // A concurrent generation's create won the race and already cached the reused id: attach the MI to
          // the WINNER, and remember OUR just-created Subscription as the loser so it is deleted below (never
          // abandoned  -  an MI-less redundant Subscription would otherwise leak server-side).
          subscriptionId = *self->mRedundancySubscriptionId;
          loserSubscriptionId = createdSubscriptionId;
        }
        else
        {
          self->mRedundancySubscriptionId = createdSubscriptionId;
        }
      }
      // Fire-and-forget delete of the loser Subscription, off the mutex (never hold it across a Connection
      // call). The loser has no MonitoredItem attached yet, so it is a clean delete. Best-effort by design: a
      // gone Connection (lock fails) means teardown is already reclaiming everything, and a Bad delete result
      // on a live Connection is likewise non-fatal (the orphan is a bounded single subscription that the
      // session close will reclaim)  -  so the completion is swallowed rather than surfaced (the design
      // specification best-effort-skip; the loss is logged at the wire boundary by the delete path itself).
      if (loserSubscriptionId)
      {
        if (const auto liveConnection = self->mConnection.lock())
        {
          // This is best-effort loser cleanup; the caller has no use for the result because Session close
          // reclaims any bounded orphan and the delete path logs a live wire failure.
          liveConnection->delete_subscription_async(
            *loserSubscriptionId, [](ua::Result<ua::DeleteSubscriptionsResponse>) {});
        }
      }
      factory->monitor_data_change_async(
        subscriptionId, std::move(request), std::move(onData), std::move(callback));
    });
}

void RedundancyManagerConnectionHost::cancel_monitored_item_async(
  ua::client::MonitoredItem item, std::function<void(ua::VoidResult)> callback)
{
  // The unified MonitoredItem is self-acting: its delete routes through its own weak owner interface (a gone
  // Connection there completes Bad_ConnectionClosed itself), so no extra ConnectionImpl lock is needed here.
  item.delete_async(std::move(callback));
}

void RedundancyManagerConnectionHost::probe_backup_servicelevel_async(
  std::string /*discoveryUrl*/, std::function<void(ua::Result<std::uint8_t>)> callback)
{
  // DEFER-STUB (section 8.11, J47): the one-shot backup-probe channel (open None-policy channel + Session,
  // Read Server.ServiceLevel, close) lands in W9. Until then the primitive is source-tagged
  // Bad_NotImplemented so the manager's ScoringBackups path degrades explicitly rather than silently treating
  // a backup as healthy.
  complete_bad_on_executor<std::uint8_t>(mExecutor,
    ua::Status::BadNotImplemented,
    "BackupProbeNotImplemented",
    "the backup ServiceLevel probe channel is not yet wired (deferred to W9)",
    probeNotImplementedSource,
    std::move(callback));
}

// -------- Reconnection interface --------

void RedundancyManagerConnectionHost::trigger_reconnect_async(ua::client::ReconnectCause cause,
  ua::StatusCode degradeStatus, std::shared_ptr<const ua::ErrorDetail> chain,
  std::function<void(ua::VoidResult)> callback)
{
  if (const auto connection = mConnection.lock())
  {
    connection->trigger_redundancy_reconnect_async(
      std::move(cause), degradeStatus, std::move(chain), std::move(callback));
    return;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback)]() mutable
      {
        callback(ua::VoidResult{ua::StatusCode{ua::Status::BadConnectionClosed},
          ua::make_error_detail("ConnectionGone",
            "the tier-1 Connection was destroyed before the redundancy reconnect could be triggered",
            std::string{triggerGoneSource})});
      }));
}

// -------- Observer fan-out (routed to the sink; the sink posts each hook to the executor) --------

void RedundancyManagerConnectionHost::fire_observer_redundancy_degraded(
  std::string activeUri, ua::client::RedundancyDegradeReason reason)
{
  if (mSink)
  {
    mSink->fire_redundancy_degraded(std::move(activeUri), reason);
  }
}

void RedundancyManagerConnectionHost::fire_observer_redundancy_failover_started(
  std::string fromUri, std::string toUri, ua::client::ReconnectCause cause)
{
  if (mSink)
  {
    mSink->fire_redundancy_failover_started(std::move(fromUri), std::move(toUri), std::move(cause));
  }
}

void RedundancyManagerConnectionHost::fire_observer_redundancy_failover_completed(
  std::string nowActiveUri, ua::client::ReconnectOutcome outcome)
{
  if (mSink)
  {
    mSink->fire_redundancy_failover_completed(std::move(nowActiveUri), std::move(outcome));
  }
}

void RedundancyManagerConnectionHost::fire_observer_redundancy_recovered(std::string activeUri)
{
  if (mSink)
  {
    mSink->fire_redundancy_recovered(std::move(activeUri));
  }
}

void RedundancyManagerConnectionHost::fire_observer_advisory_diagnostic(
  std::shared_ptr<const ua::ErrorDetail> detail)
{
  if (mSink)
  {
    mSink->fire_advisory_diagnostic(std::move(detail));
  }
}

// -------- Rule 4 cross-strand snapshot --------

void RedundancyManagerConnectionHost::publish_info_snapshot(
  std::shared_ptr<const ua::client::RedundancyInfo> info)
{
  mInfoSnapshot.store(std::move(info), std::memory_order_release);
}

std::shared_ptr<const ua::client::RedundancyInfo>
  RedundancyManagerConnectionHost::info_snapshot() const noexcept
{
  return mInfoSnapshot.load(std::memory_order_acquire);
}

}  // namespace ua::client::detail
