// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 non-transparent redundancy / failover surface (client design section 8.11): the public
///        @ref ua::client::RedundancyManager value handle, its consumer-facing @ref
///        ua::client::RedundancyInfo snapshot, and the @ref ua::client::RedundancyPolicy knobs. The
///        strand-bearing engine lives on the private `ua::client::detail::RedundancyManagerImpl`
///        (section 8.11.2), which this move-only pimpl forwards to.
/// @ingroup client

#ifndef UA_REDUNDANCY_MANAGER_H
#define UA_REDUNDANCY_MANAGER_H

#include "ua_application_description.h"  // ua::ApplicationDescription
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_reconnect_types.h"  // ReconnectCause / ReconnectOutcome, by value on RedundancyObserver
#include "ua_redundancy_support.h"  // ua::RedundancySupport
#include "ua_result.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::client
{

// RedundancyObserver takes it by const reference only, so the declaration suffices and this header
// stays free of the public Connection surface it was moved out of.
class Connection;

namespace detail
{
class ConnectionImpl;
class RedundancyManagerImpl;
struct RedundancyManagerFactory;
}  // namespace detail

/// The lifecycle state of the redundancy manager's monitoring FSM (section 8.11.4). Surfaced in
/// @ref ua::client::RedundancyInfo::state for diagnostics; the transition table is the authority.
enum class RedundancyManagerState
{
  Dormant,  ///< Pre-discovery, or the active server advertises `None` / `Transparent`.
  Discovering,  ///< Reading `RedundancySupport` + `ServerUriArray`, `FindServers`, installing the MI.
  Monitoring,  ///< Steady state: the active server's `ServiceLevel` MonitoredItem is delivering.
  ScoringBackups,  ///< Active degraded; probing backup `ServiceLevel`s and selecting a failover target.
  FailingOver,  ///< `trigger_reconnect_async` posted; awaiting the reconnect completion.
  RecoveryWindow,  ///< Post-failover stabilization; no further failover may fire.
  Closed  ///< Terminal.
};

/// Per-`Connection` redundancy knobs (section 8.11.1). Immutable after the manager is constructed.
struct RedundancyPolicy
{
  /// CL-REDUN-004: Healthy threshold (Part 4 section 6.6.2.4.2 = 200). The field surfaces the spec value.
  std::uint8_t healthyThreshold = 200;

  /// section 9.6.24.1  -  sample-based hysteresis: the manager only fails over when the ENTIRE ring of the
  /// last
  /// @ref hysteresisRingCapacity `ServiceLevel` samples is below @ref healthyThreshold (a single Healthy
  /// sample mid-ring resets the count). Prevents oscillation when the level jitters around the threshold.
  std::size_t hysteresisRingCapacity = 5;

  /// section 9.6.24.1  -  time-based hysteresis: the "MI delivering Bad status" degrade path fires only once
  /// the MI has been Bad continuously for at least this window. Millisecond-typed (like @ref probeTimeout) so
  /// sub-second windows are expressible; default 5 s.
  std::chrono::milliseconds hysteresisWindow{std::chrono::seconds{5}};

  /// section 9.6.24.3  -  backup-probe parallelism (ScoringBackups fans probes to up to N candidates at
  /// once).
  std::size_t probeFanout = 4;

  /// section 9.6.24.3  -  per-probe timeout (surfaced separately so a slow backup does not wedge scoring).
  std::chrono::milliseconds probeTimeout{5'000};

  /// section 9.6.24.5  -  post-failover RecoveryWindow during which no further failover can fire.
  std::chrono::seconds recoveryWindow{30};

  /// section 9.6.24.7  -  CL-REDUN-005's "may" clause: when no candidate is in the Healthy range, may we
  /// switch to a backup whose `ServiceLevel` is strictly above the current active's? Defaults to true.
  bool fallbackToDegraded = true;

  /// section 9.6.24.6  -  downgrade-only mode override (Cold <= Warm <= Hot <= HotAndMirrored). Upgrades, and
  /// any attempt to downgrade `HotAndMirrored`, are silently ignored (CL-REDUN-007).
  std::optional<ua::RedundancySupport> overrideMode;

  /// section 8.8 CL-AC-013 mirror: gates the Cold/Warm ConditionRefresh path (default true). The tracker
  /// reads it.
  bool issueConditionRefreshOnSwitch = true;
};

/// Why the manager entered @ref ua::client::RedundancyManagerState::ScoringBackups (delivered to the degrade
/// observer).
enum class RedundancyDegradeReason
{
  ServiceLevelBelowHealthy,  ///< the active's `ServiceLevel` dropped below the Healthy range (CL-REDUN-004)
  ServiceLevelInaccessible,  ///< the active `ServiceLevel` MI delivered a value that is not Good (Bad or
                             ///< Uncertain) for @ref RedundancyPolicy::hysteresisWindow
  TransportFatalWithBackups,  ///< transport fatally dropped and cached backup candidates are available
  ForceSwitchRequested  ///< an admin `force_switch_async` requested the change
};

/// One entry in the cached redundant server set (section 8.11.1). Keyed by `serverUri` in the manager.
struct RedundantCandidate
{
  std::string serverUri;  ///< CL-REDUN-002: the redundant server's `ApplicationDescription.applicationUri`.
  /// CL-REDUN-003: the resolved `ApplicationDescription` (`nullopt` = discovery pending / unresolved).
  std::optional<ua::ApplicationDescription> applicationDescription;
  std::vector<std::string> discoveryUrls;  ///< the candidate's discovery URLs (for the backup probe).
  std::optional<std::uint8_t> lastServiceLevel;  ///< last observed `ServiceLevel` (`nullopt` = unknown).
  std::optional<ua::DateTime> lastProbeAt;  ///< when the level was last observed (probe / MI sample).
  bool isActive = false;  ///< exactly one candidate is the active server.
};

/// The cross-strand redundancy diagnostics snapshot (section 8.11.1). Replaced atomically after every
/// state-affecting mutation; read lock-free by @ref RedundancyManager::redundancy_info.
struct RedundancyInfo
{
  /// The mode.
  ua::RedundancySupport mode = ua::RedundancySupport::None;
  /// The candidates.
  std::vector<RedundantCandidate> candidates;
  /// The active service level.
  std::optional<std::uint8_t> activeServiceLevel;
  /// The last failover at.
  std::optional<ua::DateTime> lastFailoverAt;
  /// The failover count.
  std::uint64_t failoverCount = 0;
  /// The state.
  RedundancyManagerState state = RedundancyManagerState::Dormant;
  /// section 8.11.5: the error chain from the most recent terminal failover failure (diagnostics only).
  std::shared_ptr<const ua::ErrorDetail> lastFailoverError;
};

/// The public, move-only value handle over the strand-bearing `detail::RedundancyManagerImpl`
/// (section 8.11.1, T23 / section 1.3). Returned by value from `Connection::redundancy()`. Exposes only the
/// consumer surface; the `ConnectionImpl`-driven lifecycle hooks live on the private Impl.
class RedundancyManager
{
public:
  /// Returns or updates the redundancy manager.
  RedundancyManager(RedundancyManager&&) noexcept;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  RedundancyManager& operator=(RedundancyManager&&) noexcept;
  RedundancyManager(const RedundancyManager&) = delete;  // move-only
  RedundancyManager& operator=(const RedundancyManager&) = delete;
  ~RedundancyManager();

  /// @return An immutable snapshot of the current state.
  /// Diagnostics  -  the cross-strand snapshot (lock-free; Rule 4). Never null.
  [[nodiscard]] std::shared_ptr<const RedundancyInfo> redundancy_info() const noexcept;

  /// @return The requested value.
  /// The `serverUri` of the currently-active server, or `nullopt` while `Dormant` / pre-`Active`.
  [[nodiscard]] std::optional<std::string> current_active_endpoint() const noexcept;

  /// @param targetServerUri The target server uri.
  /// @param callback Completion callback that receives the operation result.
  /// Admin override. @p targetServerUri MUST already appear in the server-uri array (`Bad_NotFound`
  /// otherwise). Rejected `Bad_InvalidState` during the RecoveryWindow. `Good` (no-op) if it is already the
  /// active server. Never throws.
  void force_switch_async(std::string targetServerUri, std::function<void(ua::VoidResult)> callback) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Stops the monitoring loop and fires `Cancelled` for any in-flight @ref force_switch_async. Idempotent.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

private:
  friend class detail::ConnectionImpl;
  friend struct detail::RedundancyManagerFactory;

  explicit RedundancyManager(std::shared_ptr<detail::RedundancyManagerImpl> impl) noexcept;

  std::shared_ptr<detail::RedundancyManagerImpl> mImpl;
};

// ---- RedundancyObserver -- failover / degrade lifecycle ----
//
// Moved here from the public `ua_client_observers.h` when the client redundancy surface was withdrawn
// from the public API for the initial release. The class is unchanged and
// `ObserverSink` still fires it; what went is the ability for an application to install one, because
// the feature it observes cannot be tested end to end while this SDK's own server publishes
// RedundancySupport = None and so can never be a redundancy peer.

// ---- RedundancyObserver  -  failover / degrade lifecycle ----

/// Observes redundancy failover / degrade lifecycle events (section 7.8, CL-REDUN-001..010; section 8.11).
class RedundancyObserver
{
public:
  RedundancyObserver() = default;
  RedundancyObserver(const RedundancyObserver&) = delete;
  RedundancyObserver& operator=(const RedundancyObserver&) = delete;
  RedundancyObserver(RedundancyObserver&&) = delete;
  RedundancyObserver& operator=(RedundancyObserver&&) = delete;
  virtual ~RedundancyObserver() = default;

  /// The active server degraded (ServiceLevel dropped / became inaccessible).
  ///
  /// @param connection Connection that emitted the notification.
  /// @param activeUri The URI of the (degraded) active server.
  /// @param reason    Why the manager entered scoring/degrade.
  virtual void on_redundancy_degraded([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::string activeUri, [[maybe_unused]] RedundancyDegradeReason reason)
  {}

  /// A failover to a backup server has started.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param fromUri The URI the connection was on.
  /// @param toUri   The URI the connection is switching to.
  /// @param cause   The reconnect cause driving the failover.
  virtual void on_redundancy_failover_started([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::string fromUri, [[maybe_unused]] std::string toUri,
    [[maybe_unused]] ReconnectCause cause)
  {}

  /// A failover completed.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param nowActiveUri The URI now active.
  /// @param outcome      What was preserved vs recreated across the failover.
  virtual void on_redundancy_failover_completed([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::string nowActiveUri, [[maybe_unused]] ReconnectOutcome outcome)
  {}

  /// The active server recovered to a healthy ServiceLevel.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param activeUri The URI of the recovered active server.
  virtual void on_redundancy_recovered(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] std::string activeUri)
  {}
};

}  // namespace ua::client

#endif  // UA_REDUNDANCY_MANAGER_H
