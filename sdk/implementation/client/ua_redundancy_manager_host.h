// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The narrow, mockable tier-1 interface the own-strand @ref ua::client::detail::RedundancyManagerImpl
///        (section 8.11) consumes. The manager NEVER reaches into `ConnectionImpl` directly  -  it holds an
///        abstract
///        @ref ua::client::detail::RedundancyManagerHost (the concrete impl is a thin shim on
///        `ConnectionImpl`; that wiring is Slice 10e-wire). The interface keeps the manager unit-testable in
///        isolation against `FakeRedundancyManagerHost` with no `ConnectionImpl`, Session, or wire stack.
/// @ingroup client

#ifndef UA_REDUNDANCY_MANAGER_HOST_H
#define UA_REDUNDANCY_MANAGER_HOST_H

#include "ua_application_description.h"
#include "ua_client_monitored_item.h"  // MonitorRequest, DataChangeCallback, MonitoredItem
#include "ua_data_value.h"
#include "ua_discovery.h"  // ua::client::FindServersOptions
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_read_value_id.h"
#include "ua_reconnect_types.h"  // ReconnectCause, ReconnectOutcome
#include "ua_redundancy_manager.h"  // RedundancyDegradeReason, RedundancyInfo
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua::client::detail
{

/// The abstract host interface for @ref RedundancyManagerImpl (section 8.11 lines 11192-11255).
///
/// Every service primitive posts internally to `ConnectionImpl`'s strand and delivers on the executor; the
/// manager's own strand picks up the reply via a post. Observer fan-out (`fire_observer_*`) is posted to the
/// executor by the host (the design specification  -  never the manager's strand). The identity reads are
/// synchronous and must be served from a cross-strand atomic snapshot (section 8.2A.7), never off
/// `ConnectionImpl`'s strand-owned state.
class RedundancyManagerHost
{
public:
  /// Result of the reactive backup probe / FindServers translation used by the manager.
  using FindServersResult = ua::Result<std::vector<ua::ApplicationDescription>>;

  RedundancyManagerHost() = default;
  RedundancyManagerHost(const RedundancyManagerHost&) = delete;
  RedundancyManagerHost& operator=(const RedundancyManagerHost&) = delete;
  RedundancyManagerHost(RedundancyManagerHost&&) = delete;
  RedundancyManagerHost& operator=(RedundancyManagerHost&&) = delete;
  virtual ~RedundancyManagerHost() = default;

  // -------- Identity (synchronous; cross-strand snapshot reads) --------

  /// The owning `Connection`'s id (snapshot / diagnostics).
  [[nodiscard]] virtual ua::NodeId connection_id() const = 0;
  /// The currently-active endpoint description.
  [[nodiscard]] virtual ua::EndpointDescription current_endpoint() const = 0;
  /// The currently-active server's `applicationUri` (the active candidate key).
  [[nodiscard]] virtual std::string current_application_uri() const = 0;

  // -------- Service primitives (each posts to ConnectionImpl's strand) --------

  /// Reads the given attributes (CL-REDUN-001/002 use this for RedundancySupport + ServerUriArray).
  virtual void read_attributes_async(std::vector<ua::ReadValueId> reads,
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) = 0;

  /// FindServers translation of the redundant `ServerUri` set (CL-REDUN-003).
  virtual void find_servers_async(
    ua::client::FindServersOptions request, std::function<void(FindServersResult)> callback) = 0;

  // -------- Subscription / MonitoredItem primitives (active server's ServiceLevel MI only) --------

  /// Installs the active server's `Server.ServiceLevel` MonitoredItem. @p onData fires per delivery on the
  /// executor; the manager re-posts it onto its own strand. (Backup levels are learned reactively via
  /// @ref probe_backup_servicelevel_async, NOT via parallel subscriptions  -  CL-REDUN-009.)
  virtual void monitor_attribute_async(ua::client::MonitorRequest request,
    ua::client::DataChangeCallback onData,
    std::function<void(ua::Result<ua::client::MonitoredItem>)> callback) = 0;

  /// Cancels the active `ServiceLevel` MonitoredItem (on mode flip / close).
  virtual void cancel_monitored_item_async(
    ua::client::MonitoredItem item, std::function<void(ua::VoidResult)> callback) = 0;

  /// Backup-probe primitive: opens a lightweight SecureChannel + Session against @p discoveryUrl, Reads
  /// `Server.ServiceLevel`, closes. One-shot  -  no Subscription, no lingering Session (CL-REDUN-009).
  virtual void probe_backup_servicelevel_async(
    std::string discoveryUrl, std::function<void(ua::Result<std::uint8_t>)> callback) = 0;

  // -------- Reconnection interface --------

  /// Kicks `ReconnectionFSM` (section 8.3) with the redundancy cause. The completion is the FSM outcome:
  /// `Good` = the FSM reached Active (the manager then awaits @ref
  /// RedundancyManagerImpl::on_reconnect_completed_async to enter RecoveryWindow); `Bad` = the FSM exhausted
  /// its attempts (terminal  -  the manager returns to Monitoring, section 8.11.5).
  virtual void trigger_reconnect_async(ua::client::ReconnectCause cause, ua::StatusCode degradeStatus,
    std::shared_ptr<const ua::ErrorDetail> chain, std::function<void(ua::VoidResult)> callback) = 0;

  // -------- Observer fan-out (host posts to the executor  -  never the manager's strand) --------

  virtual void fire_observer_redundancy_degraded(
    std::string activeUri, ua::client::RedundancyDegradeReason reason) = 0;
  virtual void fire_observer_redundancy_failover_started(
    std::string fromUri, std::string toUri, ua::client::ReconnectCause cause) = 0;
  virtual void fire_observer_redundancy_failover_completed(
    std::string nowActiveUri, ua::client::ReconnectOutcome outcome) = 0;
  virtual void fire_observer_redundancy_recovered(std::string activeUri) = 0;
  virtual void fire_observer_advisory_diagnostic(std::shared_ptr<const ua::ErrorDetail> detail) = 0;

  // -------- Rule 4 cross-strand snapshot (host owns the atomic backing store) --------

  virtual void publish_info_snapshot(std::shared_ptr<const ua::client::RedundancyInfo> info) = 0;
};

}  // namespace ua::client::detail

#endif  // UA_REDUNDANCY_MANAGER_HOST_H
