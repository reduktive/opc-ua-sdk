// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REDUNDANCY_MANAGER_CONNECTION_HOST_H
#define UA_REDUNDANCY_MANAGER_CONNECTION_HOST_H

/// @file
/// @brief The concrete tier-1 @ref ua::client::detail::RedundancyManagerHost shim (client design
/// section 8.11,
///        Slice 10e-wire): a leaf that IMPLEMENTS the narrow host interface by weak-referencing
///        @ref ua::client::detail::ConnectionImpl. The own-strand @ref
///        ua::client::detail::RedundancyManagerImpl consumes the abstract interface; this shim forwards its
///        service primitives onto `ConnectionImpl`'s strand (which owns the tier-1 ErrorDetail wrap), routes
///        observer fan-out through the per-Connection
///        @ref ua::client::detail::ObserverSink, and serves the synchronous identity reads off
///        `ConnectionImpl`'s lock-free cross-strand snapshots (never its strand-owned state, section 8.2A.7).
///
/// ## Ownership (the ONE intentional cycle-exception)
/// `RedundancyManagerImpl` holds THIS host STRONG (`shared_ptr<RedundancyManagerHost>`)  -  the single
/// intentional exception to the "no strong cycle" rule  -  because the host must outlive the manager so a
/// late reply always lands somewhere. That latent cycle is broken deterministically by the section 8.11.3
/// close ordering: `ConnectionImpl::begin_close` closes the manager (`close_async`  to  `do_close`  to
/// `mHost.reset()`) before the manager/host pair are torn down, so the strong edge is severed and no leak
/// forms. This shim in turn holds `ConnectionImpl` WEAK and the discovery provider BY VALUE, so no cycle
/// re-forms back into the orchestrator (the design specification).
/// @ingroup client

#include "ua_application_description.h"
#include "ua_discovery.h"  // ua::client::FindServersOptions
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_reconnect_types.h"  // ReconnectCause / ReconnectOutcome
#include "ua_redundancy_manager.h"  // RedundancyInfo / RedundancyDegradeReason
#include "ua_redundancy_manager_host.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ua::client::detail
{

class ConnectionImpl;
class ObserverSink;

/// The narrow, fakeable discovery interface the redundancy host uses to translate the redundant `ServerUri` set
/// (section 8.11, F2/J46). `Discovery`'s constructor is private (friended only to `Client`), so a `weak_ptr`
/// to it is neither viable nor mockable  -  the connect path supplies this `std::function` instead. Absent
/// (empty), the host completes `find_servers_async` with a source-tagged `Bad_NotImplemented` (never silent).
using RedundancyDiscoveryProvider = std::function<void(std::string discoveryUrl,
  ua::client::FindServersOptions, std::function<void(ua::Result<std::vector<ua::ApplicationDescription>>)>)>;

/// The concrete @ref RedundancyManagerHost bound to one @ref ConnectionImpl (section 8.11, F1/F2). A leaf: it
/// owns no strand, forwards each service primitive to `ConnectionImpl` (which posts to its strand and
/// delivers on the executor), and completes a manufactured boundary failure on the captured executor when the
/// weak `ConnectionImpl` is gone. Every such failure carries a `client.tier1.redundancy.*` source-tagged
/// @ref ua::ErrorDetail (the design specification  -  never a silent no-op).
class RedundancyManagerConnectionHost final
  : public RedundancyManagerHost,
    public std::enable_shared_from_this<RedundancyManagerConnectionHost>
{
public:
  /// @param connection The orchestrator this host forwards to (WEAK; the host must not own it).
  /// @param executor   The executor boundary failures + observer fan-out are delivered on (outlives
  ///                   `ConnectionImpl`).
  /// @param sink       The per-Connection observer fan-out sink (STRONG; the sink posts each hook to the
  ///                   executor, the design specification).
  /// @param discovery  The FindServers translation interface (by value; empty  to  `find_servers_async` is
  ///                   source-tagged `Bad_NotImplemented`).
  /// @param logger     Logger for the guarded async boundaries.
  RedundancyManagerConnectionHost(std::weak_ptr<ConnectionImpl> connection,
    boost::asio::any_io_executor executor, std::shared_ptr<ObserverSink> sink,
    RedundancyDiscoveryProvider discovery, ua::Logger logger);

  RedundancyManagerConnectionHost(const RedundancyManagerConnectionHost&) = delete;
  RedundancyManagerConnectionHost& operator=(const RedundancyManagerConnectionHost&) = delete;
  RedundancyManagerConnectionHost(RedundancyManagerConnectionHost&&) = delete;
  RedundancyManagerConnectionHost& operator=(RedundancyManagerConnectionHost&&) = delete;
  ~RedundancyManagerConnectionHost() override = default;

  // -------- Identity (synchronous; cross-strand snapshot reads) --------
  [[nodiscard]] ua::NodeId connection_id() const override;
  [[nodiscard]] ua::EndpointDescription current_endpoint() const override;
  [[nodiscard]] std::string current_application_uri() const override;

  // -------- Service primitives (each posts to ConnectionImpl's strand) --------
  void read_attributes_async(std::vector<ua::ReadValueId> reads,
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) override;
  void find_servers_async(
    ua::client::FindServersOptions request, std::function<void(FindServersResult)> callback) override;

  // -------- Subscription / MonitoredItem primitives --------
  void monitor_attribute_async(ua::client::MonitorRequest request, ua::client::DataChangeCallback onData,
    std::function<void(ua::Result<ua::client::MonitoredItem>)> callback) override;
  void cancel_monitored_item_async(
    ua::client::MonitoredItem item, std::function<void(ua::VoidResult)> callback) override;
  void probe_backup_servicelevel_async(
    std::string discoveryUrl, std::function<void(ua::Result<std::uint8_t>)> callback) override;

  // -------- Reconnection interface --------
  void trigger_reconnect_async(ua::client::ReconnectCause cause, ua::StatusCode degradeStatus,
    std::shared_ptr<const ua::ErrorDetail> chain, std::function<void(ua::VoidResult)> callback) override;

  // -------- Observer fan-out (routed to the sink; the sink posts to the executor) --------
  void fire_observer_redundancy_degraded(
    std::string activeUri, ua::client::RedundancyDegradeReason reason) override;
  void fire_observer_redundancy_failover_started(
    std::string fromUri, std::string toUri, ua::client::ReconnectCause cause) override;
  void fire_observer_redundancy_failover_completed(
    std::string nowActiveUri, ua::client::ReconnectOutcome outcome) override;
  void fire_observer_redundancy_recovered(std::string activeUri) override;
  void fire_observer_advisory_diagnostic(std::shared_ptr<const ua::ErrorDetail> detail) override;

  // -------- Rule 4 cross-strand snapshot (host owns the atomic backing store) --------
  void publish_info_snapshot(std::shared_ptr<const ua::client::RedundancyInfo> info) override;

  /// The last published cross-strand snapshot (lock-free load; Rule 4). Never a strand read. Used by the
  /// wiring layer + tests to read the host's backing store without touching a strand.
  [[nodiscard]] std::shared_ptr<const ua::client::RedundancyInfo> info_snapshot() const noexcept;

private:
  std::weak_ptr<ConnectionImpl> mConnection;  // WEAK  -  the host must not own the orchestrator.
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<ObserverSink> mSink;  // STRONG  -  the sink outlives the host; posts hooks to the executor.
  RedundancyDiscoveryProvider mDiscovery;  // by value  -  no cycle.
  ua::Logger mLogger;
  std::atomic<std::shared_ptr<const ua::client::RedundancyInfo>> mInfoSnapshot{
    std::make_shared<const ua::client::RedundancyInfo>()};
  std::mutex mSubscriptionMutex;  // guards the lazily-created, reused ServiceLevel-Subscription id.
  std::optional<std::uint32_t> mRedundancySubscriptionId;
};

}  // namespace ua::client::detail

#endif  // UA_REDUNDANCY_MANAGER_CONNECTION_HOST_H
