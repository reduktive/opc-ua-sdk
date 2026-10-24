// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FAKE_REDUNDANCY_MANAGER_HOST_H
#define FAKE_REDUNDANCY_MANAGER_HOST_H

/// @file
/// @brief Scriptable @ref ua::client::detail::RedundancyManagerHost test double for the tier-2
///        @ref ua::client::detail::RedundancyManagerImpl (client design section 8.11). Lets every
///        section 8.11.4 state and transition be exercised with NO `ConnectionImpl`, Session, or wire stack:
///        each host primitive is scriptable (RedundancySupport / ServerUriArray Reads, FindServers, backup
///        probes, MI install), the MonitoredItem's `DataChangeCallback` is captured so a test can push
///        Good/Bad `ServiceLevel` deliveries into the manager, and every `trigger_reconnect_async` /
///        `fire_observer_*` / `publish_info_snapshot` call is captured for falsifiable assertions.

#include "ua_application_description.h"
#include "ua_array.h"
#include "ua_client_monitored_item.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_read_value_id.h"
#include "ua_reconnect_types.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_host.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::testing
{

/// The scriptable host. All results are delivered synchronously to the manager's post-borrowing wrappers,
/// which re-post onto the manager's strand - so replies land on strand turns (no re-entrancy); the test
/// drives them by draining the io_context.
class FakeRedundancyManagerHost : public ua::client::detail::RedundancyManagerHost
{
public:
  using RedundancySupport = ua::RedundancySupport;
  using DataValue = ua::DataValue;
  using ReadResult = ua::Result<std::vector<DataValue>>;

  // ================= identity (settable) =================
  ua::NodeId connectionId{ua::NodeId{1, 42}};
  ua::EndpointDescription endpoint;
  std::string applicationUri = "urn:server:a";

  [[nodiscard]] ua::NodeId connection_id() const override
  {
    return connectionId;
  }

  [[nodiscard]] ua::EndpointDescription current_endpoint() const override
  {
    return endpoint;
  }

  [[nodiscard]] std::string current_application_uri() const override
  {
    return applicationUri;
  }

  // ================= read_attributes (dispatched by node id) =================
  std::vector<std::vector<ua::ReadValueId>> readCalls;
  std::optional<ReadResult> redundancySupportResponse;
  std::optional<ReadResult> serverUriArrayResponse;

  void set_redundancy_support(RedundancySupport support)
  {
    redundancySupportResponse =
      ReadResult{std::vector<DataValue>{DataValue{ua::Variant{static_cast<std::int32_t>(support)}}}};
  }

  void fail_redundancy_support(ua::Status status)
  {
    redundancySupportResponse = ReadResult{ua::StatusCode{status}};
  }

  void set_server_uri_array(std::vector<std::string> uris)
  {
    ua::Array<ua::String> array;
    for (const auto& uri : uris)
    {
      array.push_back(ua::String{uri});
    }
    serverUriArrayResponse = ReadResult{std::vector<DataValue>{DataValue{ua::Variant{std::move(array)}}}};
  }

  void fail_server_uri_array(ua::Status status)
  {
    serverUriArrayResponse = ReadResult{ua::StatusCode{status}};
  }

  void read_attributes_async(
    std::vector<ua::ReadValueId> reads, std::function<void(ReadResult)> callback) override
  {
    readCalls.push_back(reads);
    const ua::NodeId node = reads.empty() ? ua::NodeId{} : reads.front().node_id();
    if (node == ua::NodeId{ua::VariableId::Server_ServerRedundancy_RedundancySupport})
    {
      callback(redundancySupportResponse.value_or(ReadResult{ua::StatusCode{ua::Status::BadNothingToDo}}));
      return;
    }
    if (node == ua::NodeId{ua::VariableId::Server_ServerRedundancy_ServerUriArray})
    {
      callback(serverUriArrayResponse.value_or(ReadResult{ua::StatusCode{ua::Status::BadNothingToDo}}));
      return;
    }
    callback(ReadResult{ua::StatusCode{ua::Status::BadNotSupported}});
  }

  // ================= find_servers =================
  int findServersCalls = 0;
  std::optional<FindServersResult> findServersResponse;

  /// Adds one `ApplicationDescription` (applicationUri + discoveryUrls) to the scripted FindServers reply.
  void add_find_server(const std::string& applicationUriValue, std::vector<std::string> discoveryUrls)
  {
    if (!findServersResponse.has_value())
    {
      findServersResponse = FindServersResult{std::vector<ua::ApplicationDescription>{}};
    }
    ua::ApplicationDescription description;
    description.application_uri() = ua::String{applicationUriValue};
    for (const auto& url : discoveryUrls)
    {
      description.discovery_urls().push_back(ua::String{url});
    }
    findServersResponse->value().push_back(std::move(description));
  }

  void fail_find_servers(ua::Status status)
  {
    findServersResponse = FindServersResult{ua::StatusCode{status}};
  }

  void find_servers_async(
    ua::client::FindServersOptions /*request*/, std::function<void(FindServersResult)> callback) override
  {
    ++findServersCalls;
    callback(findServersResponse.value_or(FindServersResult{std::vector<ua::ApplicationDescription>{}}));
  }

  // ================= monitor / cancel =================
  std::vector<ua::client::MonitorRequest> monitorCalls;
  ua::client::DataChangeCallback capturedOnData;
  ua::client::MonitoredItemId nextMonitoredItemHandle = 1000;
  int monitorInstallFailsRemaining = 0;  ///< fail this many installs, then succeed (retry-path testing)
  ua::Status monitorFailStatus = ua::Status::BadNodeIdUnknown;
  int cancelCalls = 0;
  bool holdMonitor = false;  ///< when set, a monitor install parks its completion (superseded-mid-install)
  std::function<void(ua::Result<ua::client::MonitoredItem>)> heldMonitorCallback;

  /// Enables / disables HOLD mode on monitor installs: while held, `monitor_attribute_async` captures its
  /// completion instead of firing it, so a test can bump the generation before completing the install (the
  /// section 8.11 superseded-mid-install path). @ref complete_held_monitor_good fires the parked completion.
  void set_hold_monitor(bool hold)
  {
    holdMonitor = hold;
  }

  void monitor_attribute_async(ua::client::MonitorRequest request, ua::client::DataChangeCallback onData,
    std::function<void(ua::Result<ua::client::MonitoredItem>)> callback) override
  {
    monitorCalls.push_back(request);
    if (monitorInstallFailsRemaining > 0)
    {
      --monitorInstallFailsRemaining;
      callback(ua::Result<ua::client::MonitoredItem>{ua::StatusCode{monitorFailStatus}});
      return;
    }
    capturedOnData = std::move(onData);
    if (holdMonitor)
    {
      heldMonitorCallback = std::move(callback);  // parked; a test drives complete_held_monitor_good later
      return;
    }
    callback(ua::Result<ua::client::MonitoredItem>{make_monitored_item(request)});
  }

  /// Completes a parked (held) monitor install with a fresh Good MonitoredItem - the reply that lands AFTER a
  /// generation bump so the manager must cancel it rather than orphan it.
  void complete_held_monitor_good()
  {
    if (!heldMonitorCallback)
    {
      return;
    }
    auto callback = std::move(heldMonitorCallback);
    heldMonitorCallback = nullptr;
    ua::client::MonitorRequest request;
    request.nodeId = ua::NodeId{ua::VariableId::Server_ServiceLevel};
    request.attribute = ua::AttributeId::Value;
    callback(ua::Result<ua::client::MonitoredItem>{make_monitored_item(request)});
  }

  void cancel_monitored_item_async(
    ua::client::MonitoredItem /*item*/, std::function<void(ua::VoidResult)> callback) override
  {
    ++cancelCalls;
    callback(ua::VoidResult{});
  }

  /// Stamps a fresh unified data-change MonitoredItem (distinct handle per call) for @p request.
  ua::client::MonitoredItem make_monitored_item(const ua::client::MonitorRequest& request)
  {
    return ua::client::detail::MonitoredItemFactory::create({},
      nextMonitoredItemHandle++,
      request.nodeId,
      request.attribute,
      ua::client::MonitoredItemKind::DataChange,
      ua::MonitoringMode::Reporting);
  }

  /// Pushes a Good `ServiceLevel` sample into the captured MI callback (posts onto the manager's strand).
  void deliver_service_level(std::uint8_t level)
  {
    if (!capturedOnData)
    {
      return;
    }
    ua::client::DataChangeEvent event;
    event.nodeId = ua::NodeId{ua::VariableId::Server_ServiceLevel};
    event.attribute = ua::AttributeId::Value;
    event.value = ua::DataValue{ua::Variant{std::uint8_t{level}}};
    capturedOnData(event);
  }

  /// Pushes a `ServiceLevel` sample holding @p level with the status @p status into the captured MI callback.
  void deliver_service_level_with_status(std::uint8_t level, ua::Status status)
  {
    if (!capturedOnData)
    {
      return;
    }
    ua::client::DataChangeEvent event;
    event.nodeId = ua::NodeId{ua::VariableId::Server_ServiceLevel};
    event.attribute = ua::AttributeId::Value;
    event.value = ua::DataValue{ua::Variant{std::uint8_t{level}}};
    event.value.status() = ua::StatusCode{status};
    capturedOnData(event);
  }

  /// Pushes a Bad-status `ServiceLevel` delivery into the captured MI callback.
  void deliver_service_level_bad(ua::Status status = ua::Status::BadNoCommunication)
  {
    if (!capturedOnData)
    {
      return;
    }
    ua::client::DataChangeEvent event;
    event.nodeId = ua::NodeId{ua::VariableId::Server_ServiceLevel};
    event.attribute = ua::AttributeId::Value;
    event.value = ua::DataValue{ua::StatusCode{status}};
    capturedOnData(event);
  }

  // ================= backup probes =================
  std::vector<std::string> probeCalls;  ///< discovery URLs probed
  std::vector<std::pair<std::string, ua::Result<std::uint8_t>>> probeScript;  ///< keyed by discovery URL
  std::vector<std::string> hungProbeUrls;  ///< probes for these URLs are captured, never answered (H1)
  /// Captured-but-unanswered probe callbacks, keyed by discovery URL (so a test can inspect / drive them).
  std::vector<std::pair<std::string, std::function<void(ua::Result<std::uint8_t>)>>> capturedProbes;

  void set_probe_result(const std::string& discoveryUrl, std::uint8_t level)
  {
    probeScript.emplace_back(discoveryUrl, ua::Result<std::uint8_t>{level});
  }

  void fail_probe(const std::string& discoveryUrl, ua::Status status = ua::Status::BadNoCommunication)
  {
    probeScript.emplace_back(discoveryUrl, ua::Result<std::uint8_t>{ua::StatusCode{status}});
  }

  /// Marks @p discoveryUrl as a hung backup: its probe is captured but the reply never lands. Exercises the
  /// probe-timeout wedge (a backup whose ServiceLevel probe never calls back must not pin ScoringBackups).
  void hang_probe(const std::string& discoveryUrl)
  {
    hungProbeUrls.push_back(discoveryUrl);
  }

  void probe_backup_servicelevel_async(
    std::string discoveryUrl, std::function<void(ua::Result<std::uint8_t>)> callback) override
  {
    probeCalls.push_back(discoveryUrl);
    if (std::find(hungProbeUrls.begin(), hungProbeUrls.end(), discoveryUrl) != hungProbeUrls.end())
    {
      capturedProbes.emplace_back(discoveryUrl, std::move(callback));  // never answered
      return;
    }
    for (const auto& entry : probeScript)
    {
      if (entry.first == discoveryUrl)
      {
        callback(entry.second);
        return;
      }
    }
    callback(ua::Result<std::uint8_t>{ua::StatusCode{ua::Status::BadNoCommunication}});
  }

  // ================= reconnection interface =================
  struct ReconnectCall
  {
    ua::client::ReconnectCause cause;
    ua::StatusCode degradeStatus;
    std::shared_ptr<const ua::ErrorDetail> chain;
  };

  std::vector<ReconnectCall> reconnectCalls;
  std::function<void(ua::VoidResult)> capturedReconnectCallback;

  void trigger_reconnect_async(ua::client::ReconnectCause cause, ua::StatusCode degradeStatus,
    std::shared_ptr<const ua::ErrorDetail> chain, std::function<void(ua::VoidResult)> callback) override
  {
    reconnectCalls.push_back(ReconnectCall{std::move(cause), degradeStatus, std::move(chain)});
    capturedReconnectCallback = std::move(callback);
  }

  /// Completes the outstanding failover kick (Good = FSM reached Active; Bad = FSM exhausted).
  void complete_reconnect(ua::VoidResult result)
  {
    if (capturedReconnectCallback)
    {
      auto callback = std::move(capturedReconnectCallback);
      capturedReconnectCallback = nullptr;
      callback(std::move(result));
    }
  }

  // ================= observer fan-out (captured) =================
  std::vector<std::pair<std::string, ua::client::RedundancyDegradeReason>> degradedFires;

  struct FailoverStarted
  {
    std::string fromUri;
    std::string toUri;
    ua::client::ReconnectCause cause;
  };

  std::vector<FailoverStarted> failoverStartedFires;

  struct FailoverCompleted
  {
    std::string nowActiveUri;
    ua::client::ReconnectOutcome outcome;
  };

  std::vector<FailoverCompleted> failoverCompletedFires;
  std::vector<std::string> recoveredFires;
  std::vector<std::shared_ptr<const ua::ErrorDetail>> advisoryFires;

  void fire_observer_redundancy_degraded(
    std::string activeUri, ua::client::RedundancyDegradeReason reason) override
  {
    degradedFires.emplace_back(std::move(activeUri), reason);
  }

  void fire_observer_redundancy_failover_started(
    std::string fromUri, std::string toUri, ua::client::ReconnectCause cause) override
  {
    failoverStartedFires.push_back(FailoverStarted{std::move(fromUri), std::move(toUri), std::move(cause)});
  }

  void fire_observer_redundancy_failover_completed(
    std::string nowActiveUri, ua::client::ReconnectOutcome outcome) override
  {
    failoverCompletedFires.push_back(FailoverCompleted{std::move(nowActiveUri), std::move(outcome)});
  }

  void fire_observer_redundancy_recovered(std::string activeUri) override
  {
    recoveredFires.push_back(std::move(activeUri));
  }

  void fire_observer_advisory_diagnostic(std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    advisoryFires.push_back(std::move(detail));
  }

  // ================= snapshot publish (captured) =================
  std::vector<std::shared_ptr<const ua::client::RedundancyInfo>> snapshots;

  void publish_info_snapshot(std::shared_ptr<const ua::client::RedundancyInfo> info) override
  {
    snapshots.push_back(std::move(info));
  }

  // ================= convenience for advisory assertions =================
  [[nodiscard]] bool has_advisory_source(std::string_view source) const
  {
    for (const auto& detail : advisoryFires)
    {
      if (detail && detail->source == source)
      {
        return true;
      }
    }
    return false;
  }
};

}  // namespace ua::testing

#endif  // FAKE_REDUNDANCY_MANAGER_HOST_H
