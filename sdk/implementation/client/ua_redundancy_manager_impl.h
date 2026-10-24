// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The strand-bearing private @ref ua::client::detail::RedundancyManagerImpl (client design
/// section 8.11):
///        the per-`Connection` non-transparent redundancy / failover engine. Owns its OWN private strand
///        (Rule 4; distinct from `ConnectionImpl`'s and `ReconnectionFSM`'s), runs the section 8.11.4
///        monitoring FSM, installs the active server's `ServiceLevel` MonitoredItem, reactively probes
///        backups on degrade, and kicks `ReconnectionFSM` with a `RedundancySwitch.*` cause. The public
///        move-only
///        @ref ua::client::RedundancyManager handle forwards its consumer surface here; the lifecycle hooks
///        are driven by `ConnectionImpl` (Slice 10e-wire).
/// @ingroup client

#ifndef UA_REDUNDANCY_MANAGER_IMPL_H
#define UA_REDUNDANCY_MANAGER_IMPL_H

#include "ua_client_monitored_item.h"
#include "ua_date_time.h"
#include "ua_logger.h"
#include "ua_reconnect_types.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_host.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::client::detail
{

struct RedundancyManagerTestAccess;

/// The strand-bearing redundancy engine (section 8.11.2). Every public method posts to @ref mStrand once on
/// entry; user-visible observer fan-out is delegated to the host (which posts to the executor). Constructed
/// lazily by `ConnectionImpl` on the first Session-`Active` transition.
class RedundancyManagerImpl : public std::enable_shared_from_this<RedundancyManagerImpl>
{
public:
  /// @param executor The io_context executor the private strand is made from.
  /// @param host     The tier-1 host interface (strong  -  host outlives the manager; section 8.11.3 close
  /// ordering breaks
  ///                 the latent cycle).
  /// @param logger   Logger for the guarded async boundaries.
  /// @param policy   Per-Connection knobs (const after ctor).
  [[nodiscard]] static std::shared_ptr<RedundancyManagerImpl> create(boost::asio::any_io_executor executor,
    std::shared_ptr<RedundancyManagerHost> host, ua::Logger logger, RedundancyPolicy policy = {});

  RedundancyManagerImpl(const RedundancyManagerImpl&) = delete;
  RedundancyManagerImpl& operator=(const RedundancyManagerImpl&) = delete;
  RedundancyManagerImpl(RedundancyManagerImpl&&) = delete;
  RedundancyManagerImpl& operator=(RedundancyManagerImpl&&) = delete;
  ~RedundancyManagerImpl() = default;

  // -------- Consumer surface (the RedundancyManager facade forwards to these) --------

  [[nodiscard]] std::shared_ptr<const RedundancyInfo> redundancy_info() const noexcept;
  [[nodiscard]] std::optional<std::string> current_active_endpoint() const noexcept;
  void force_switch_async(std::string targetServerUri, std::function<void(ua::VoidResult)> callback) noexcept;
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- Lifecycle hooks (driven by ConnectionImpl on its strand; hop to mStrand via post) --------

  void on_session_active_async(ua::NodeId sessionId, std::function<void(ua::VoidResult)> callback) noexcept;
  void on_session_closed_async(std::function<void(ua::VoidResult)> callback) noexcept;
  void on_reconnect_completed_async(
    ua::client::ReconnectOutcome outcome, std::function<void(ua::VoidResult)> callback) noexcept;
  void on_transport_fatal_async(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> chain,
    std::function<void(ua::VoidResult)> callback) noexcept;

private:
  friend struct RedundancyManagerTestAccess;

  RedundancyManagerImpl(boost::asio::any_io_executor executor, std::shared_ptr<RedundancyManagerHost> host,
    ua::Logger logger, RedundancyPolicy policy);

  /// One hysteresis-ring sample (section 8.11.2 `mServiceLevelHistory`).
  struct ServiceLevelSample
  {
    ua::DateTime at;
    std::uint8_t level = 0;
  };

  /// The single outstanding admin override (section 8.11.2 `mForceSwitchPending`).
  struct PendingForceSwitch
  {
    std::string targetUri;
    std::function<void(ua::VoidResult)> callback;
  };

  // ---- strand-private FSM steps (section 8.11.4) ----
  void run_discovery(std::uint64_t generation);
  void discovery_read_redundancy_support(std::uint64_t generation);
  void discovery_read_server_uri_array(std::uint64_t generation);
  void discovery_find_servers(std::uint64_t generation);
  void discovery_install_monitor(std::uint64_t generation, int attempt);
  void enter_monitoring(std::uint64_t generation);

  void on_servicelevel_sample(std::uint64_t generation, const ua::client::DataChangeEvent& event);
  void enter_scoring(RedundancyDegradeReason reason, std::optional<std::string> manualTarget,
    std::shared_ptr<const ua::ErrorDetail> causeChain = nullptr,
    std::optional<ua::StatusCode> reasonCode = std::nullopt);
  void probe_fanout(std::uint64_t generation);
  void on_probe_reply(std::uint64_t generation, std::string serverUri, ua::Result<std::uint8_t> result);
  void run_scoring();
  void begin_failover(std::string targetUri, RedundancyDegradeReason reason);
  void arm_recovery_window(std::uint64_t generation);
  void arm_probe_deadline(std::uint64_t generation);
  void arm_inaccessible_window(std::uint64_t generation);

  void do_force_switch(std::string targetServerUri, std::function<void(ua::VoidResult)> callback);
  void do_close(std::function<void(ua::VoidResult)> callback);

  /// Starts a discovery pass, remembering @p ack to fire at the terminal step (Dormant / Monitoring). A
  /// superseded ack (a new discovery beginning while one is pending) is fired `Good` first.
  void start_discovery(std::function<void(ua::VoidResult)> ack);
  void fire_discovery_ack(ua::VoidResult result);

  // ---- helpers ----
  [[nodiscard]] bool is_current(std::uint64_t generation) const noexcept;
  [[nodiscard]] ua::RedundancySupport derive_effective_mode(ua::RedundancySupport advertised) const;
  void set_state(RedundancyManagerState state);
  void publish_snapshot();
  void deliver_void(std::function<void(ua::VoidResult)> callback, ua::VoidResult result);
  void advisory(std::string code, std::string summary, std::string source);
  void advisory(std::shared_ptr<const ua::ErrorDetail> detail);
  [[nodiscard]] std::uint8_t active_service_level_or_zero() const;

  // ---- immutable ----
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::shared_ptr<RedundancyManagerHost> mHost;
  ua::Logger mLogger;
  RedundancyPolicy mPolicy;

  // ---- strand-owned mutable state (section 8.11.2) ----
  RedundancyManagerState mState = RedundancyManagerState::Dormant;
  ua::RedundancySupport mRedundancySupport = ua::RedundancySupport::None;
  ua::RedundancySupport mEffectiveMode = ua::RedundancySupport::None;
  std::string mActiveUri;
  std::vector<std::string> mServerUriArray;
  std::unordered_map<std::string, RedundantCandidate> mCandidates;
  std::optional<ua::client::MonitoredItem> mServiceLevelHandle;
  std::deque<ServiceLevelSample> mServiceLevelHistory;
  std::optional<ua::DateTime> mServiceLevelBadSince;
  std::unordered_set<std::string> mPendingProbes;
  boost::asio::steady_timer mRecoveryWindowTimer;
  boost::asio::steady_timer
    mProbeDeadlineTimer;  ///< H1: bounds a ScoringBackups probe fanout (mStrand-bound)
  boost::asio::steady_timer mInaccessibleTimer;  ///< H3: change-only-safe ServiceLevel-Bad window (mStrand)
  std::optional<PendingForceSwitch> mForceSwitchPending;
  std::optional<std::string> mFailoverTarget;
  RedundancyDegradeReason mCurrentDegradeReason = RedundancyDegradeReason::ServiceLevelBelowHealthy;
  /// H5: inner cause + reason threaded from the degrade trigger (e.g. the transport-fatal chain) into the
  /// failover degrade detail. Reset on every `enter_scoring` entry (null for the ServiceLevel-driven paths).
  std::shared_ptr<const ua::ErrorDetail> mDegradeCauseChain;
  std::optional<ua::StatusCode> mDegradeReasonCode;
  /// M7: whether `on_redundancy_degraded` has already fired for the current unresolved degrade episode
  /// (edge-only firing  -  cleared on recovery / a fresh healthy sample).
  bool mDegradedNotified = false;
  std::uint64_t mGeneration = 0;
  std::uint64_t mFailoverCount = 0;
  std::optional<ua::DateTime> mLastFailoverAt;
  std::shared_ptr<const ua::ErrorDetail> mLastFailoverError;
  std::function<void(ua::VoidResult)> mDiscoveryAck;  ///< fired at the terminal discovery step

  // ---- cross-strand snapshot (Rule 4; also published to the host) ----
  std::atomic<std::shared_ptr<const RedundancyInfo>> mInfoSnapshot{std::make_shared<const RedundancyInfo>()};

  // ---- test interface: injectable clock (deterministic hysteresisWindow / timestamps) ----
  std::function<ua::DateTime()> mNowFn = []
  {
    return ua::DateTime::now();
  };
};

/// Construction interface for the public @ref ua::client::RedundancyManager pimpl facade  -  `ConnectionImpl`
/// (Slice 10e-wire) and tests wrap an @ref RedundancyManagerImpl in the move-only handle through here,
/// keeping the facade's constructor private.
struct RedundancyManagerFactory
{
  [[nodiscard]] static ua::client::RedundancyManager wrap(std::shared_ptr<RedundancyManagerImpl> impl)
  {
    return ua::client::RedundancyManager{std::move(impl)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_REDUNDANCY_MANAGER_IMPL_H
