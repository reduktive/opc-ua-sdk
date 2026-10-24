// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The strand-bearing private @ref ua::client::detail::PullCertificateManagerImpl (client design
///        section 8.1A, Phase F): the per-`Client` Pull-Model certificate + trust-list refresh engine. Owns
///        its OWN private strand (Rule 4; distinct from any `Connection` strand), runs the section 8.1A.4
///        cycle FSM (GDS bootstrap  to  TrustList refresh  to  per-group cert renewal `Start`/`Finish` poll
///        loop  to  atomic persist  to  revalidation broadcast), drives the renew-before-expiry /
///        retry-backoff timers, and publishes the cross-strand diagnostics snapshot the parent `Client`
///        reads. The public
///        @ref ua::client::PullCertificateManager handle forwards its consumer surface here; the concrete
///        GDS transport + `Client` entry point (`start_pull_cert_management_sync`) are the deferred Slice
///        11b-wire.
/// @ingroup client

#ifndef UA_PULL_CERTIFICATE_MANAGER_IMPL_H
#define UA_PULL_CERTIFICATE_MANAGER_IMPL_H

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_pull_certificate_manager.h"
#include "ua_pull_certificate_manager_host.h"
#include "ua_result.h"
#include "ua_trust_list_data_type.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace ua::client::detail
{

struct PullCertificateManagerTestAccess;

/// The strand-bearing Pull-Model certificate manager (section 8.1A.2). Every public method posts to @ref
/// mStrand once on entry; user-visible observer fan-out is delegated to the host (which posts to the
/// executor). Constructed via @ref create; the GDS bootstrap runs immediately, the first steady-state cycle
/// fires once the bootstrap reaches @ref ua::client::PullCertManagementState::Idle.
class PullCertificateManagerImpl : public std::enable_shared_from_this<PullCertificateManagerImpl>
{
public:
  /// @param executor The io_context executor the private strand is made from.
  /// @param host     The host interface (strong  -  host outlives the manager; `Client` owns both).
  /// @param logger   Logger for the guarded async boundaries.
  /// @param config   Pull-management knobs (const after ctor).
  [[nodiscard]] static std::shared_ptr<PullCertificateManagerImpl> create(
    boost::asio::any_io_executor executor, std::shared_ptr<PullCertificateManagerHost> host,
    ua::Logger logger, ua::client::PullCertManagementConfig config);

  PullCertificateManagerImpl(const PullCertificateManagerImpl&) = delete;
  PullCertificateManagerImpl& operator=(const PullCertificateManagerImpl&) = delete;
  PullCertificateManagerImpl(PullCertificateManagerImpl&&) = delete;
  PullCertificateManagerImpl& operator=(PullCertificateManagerImpl&&) = delete;
  /// M5(c): fires any residual force_cycle / stop acks Cancelled if the last owner drops before a posted
  /// do_stop ran  -  a synchronous last-owner destruction never drops an owed
  /// completion. The section 8.1A.3 block-join dtor semantics remain deferred to the Client-wiring slice.
  ~PullCertificateManagerImpl();

  // -------- Consumer surface (the PullCertificateManager facade forwards to these) --------

  [[nodiscard]] std::shared_ptr<const ua::client::PullCertManagementInfo> pull_cert_info() const noexcept;
  void force_cycle_async(std::function<void(ua::VoidResult)> callback) noexcept;
  void stop_async(std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- Lifecycle hook (driven by the GDS-connection cert-rotation observer; hop to mStrand) --------

  /// Called when the manager's own GDS Connection observes an own-cert rotation mid-cycle (CL-PULLCRT-004).
  /// The concrete observer install on the GDS Connection is the deferred Slice 11b-wire; this hook is the
  /// strand-core interface the shim / tests drive.
  void notify_own_cert_rotated_async(
    std::string newThumbprintSha1, std::function<void(ua::VoidResult)> callback) noexcept;

private:
  friend struct PullCertificateManagerTestAccess;

  PullCertificateManagerImpl(boost::asio::any_io_executor executor,
    std::shared_ptr<PullCertificateManagerHost> host, ua::Logger logger,
    ua::client::PullCertManagementConfig config);

  using State = ua::client::PullCertManagementState;
  using LifecycleEvent = ua::client::PullCertLifecycleEvent;

  // ---- strand-private FSM steps (section 8.1A.4) ----
  void begin_bootstrap();
  void on_persisted_loaded(std::uint64_t generation, ua::Result<std::vector<PersistedRequest>> loaded);
  void open_gds(std::uint64_t generation);
  void on_gds_opened(std::uint64_t generation, ua::VoidResult result);

  void start_cycle(std::uint64_t generation);
  void enter_refreshing_trust_list(std::uint64_t generation);
  void on_last_update_time(std::uint64_t generation, ua::Result<std::optional<ua::DateTime>> result);
  void download_trust_list(std::uint64_t generation);
  void on_trust_list(std::uint64_t generation, ua::Result<ua::TrustListDataType> result);
  void continue_after_trust_list(std::uint64_t generation);
  // Figure 16 (OPC 10000-12 7.6): each configured group, in order - a pending request is finished, otherwise
  // GetCertificateStatus decides whether one is made; then the group's TrustList; then the commit.
  void begin_group(std::uint64_t generation);
  void on_certificate_status(std::uint64_t generation, ua::Result<bool> result);
  void after_certificate(std::uint64_t generation);
  void next_group(std::uint64_t generation);
  void end_of_cycle(std::uint64_t generation);
  void enter_requesting_cert(std::uint64_t generation);
  void on_start_request(std::uint64_t generation, ua::Result<ua::NodeId> result);
  void enter_polling(std::uint64_t generation);
  void do_poll(std::uint64_t generation);
  void on_finish_request(
    std::uint64_t generation, ua::Result<PullCertificateManagerHost::FinishCertificateResult> result);
  void enter_persisting(std::uint64_t generation);
  void on_apply(std::uint64_t generation, ua::VoidResult result);
  void enter_revalidating(std::uint64_t generation);
  void on_revalidated(std::uint64_t generation, ua::VoidResult result);

  void finish_cycle_success(std::uint64_t generation, std::shared_ptr<const ua::ErrorDetail> advisoryChain);
  void enter_failed(State failedState, ua::StatusCode stepStatus);

  void do_force_cycle(std::function<void(ua::VoidResult)> callback);
  void do_stop(std::function<void(ua::VoidResult)> callback);
  void finalize_stop(std::function<void(ua::VoidResult)> callback);
  void do_notify_own_cert_rotated(std::string newThumbprintSha1);

  // ---- timers ----
  void arm_cycle_timer(std::uint64_t generation, std::chrono::milliseconds delay);
  void arm_poll_timer(std::uint64_t generation);

  // ---- helpers ----
  [[nodiscard]] bool is_current(std::uint64_t generation) const noexcept;
  void set_state(State state);
  void publish_snapshot();
  void deliver_void(std::function<void(ua::VoidResult)> callback, ua::VoidResult result);
  void fire_force_cycle_acks(ua::VoidResult result);
  void lifecycle(LifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail);
  void advisory(std::string code, std::string summary, std::string_view source,
    std::shared_ptr<const ua::ErrorDetail> cause = nullptr);
  void persist_pending_requests();
  void clear_cycle_scratch();  ///< M6: wipe per-cycle cert/key/trust-list scratch at each cycle terminus.
  void clear_group_scratch();  ///< M6, per group: wipe the cert/key/trust-list scratch once it is committed.
  [[nodiscard]] const ua::client::CertificateGroupConfig& current_group() const;
  [[nodiscard]]  /// The pending request of the configured group (group + type) being processed.
  std::vector<PersistedRequest>::iterator
    find_current_pending();
  [[nodiscard]] std::chrono::milliseconds next_cycle_backoff();
  /// Nominal update period plus the mandatory Part 12 section 6.3 randomized 1%-10% cycle-start delay.
  [[nodiscard]] std::chrono::milliseconds regular_cycle_delay();
  [[nodiscard]] std::chrono::milliseconds poll_delay();  // M4: applies pollJitterPct (uses mJitterRng).

  // ---- immutable ----
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::shared_ptr<PullCertificateManagerHost> mHost;
  ua::Logger mLogger;
  ua::client::PullCertManagementConfig mPolicy;
  std::vector<ua::client::CertificateGroupConfig> mCertificateGroups;  ///< const after ctor.

  // ---- strand-owned mutable state (section 8.1A.2) ----
  State mState = State::Idle;
  bool mGdsConnected = false;
  std::vector<PersistedRequest> mPendingRequests;
  std::size_t mPollAttempt = 0;
  /// The LastUpdateTime of each group's last committed TrustList (CL-PULLCRT-005), per CertificateGroup.
  std::vector<std::pair<ua::NodeId, ua::DateTime>> mLastTrustListUpdates;
  std::optional<ua::DateTime> mLastSuccessfulCycleAt;
  std::optional<ua::DateTime> mLastTrustListCommitAt;
  std::optional<ua::DateTime> mLastCertCommitAt;
  std::uint32_t mFailureCount = 0;
  std::uint64_t mGeneration = 0;
  std::shared_ptr<const ua::ErrorDetail> mLastError;
  /// section 8.1A.6: a corrupt-persistence advisory captured during bootstrap, carried on the `Started`
  /// event.
  std::shared_ptr<const ua::ErrorDetail> mBootstrapAdvisory;

  // ---- per-cycle scratch (reset at each cycle entry) ----
  ua::NodeId mCurrentGroupId;  ///< the group being processed this cycle.
  ua::NodeId mCurrentRequestId;  ///< the requestId currently being polled.
  std::optional<ua::TrustListDataType> mCycleTrustList;  ///< a newly-downloaded trust list awaiting commit.
  std::optional<ua::DateTime> mCycleTrustListLastUpdate;
  std::shared_ptr<const ua::X509Certificate> mCycleNewCert;  ///< a freshly-issued cert awaiting commit.
  std::optional<ua::ByteString> mCycleNewKey;
  /// M9: the issuer chain delivered with a renewed cert; threaded into the atomic commit so the runtime store
  /// can validate the full chain (section 8.1A.7 sequence shows `issuerChain` on the FinishRequest result).
  std::vector<std::shared_ptr<const ua::X509Certificate>> mCycleIssuerChain;

  /// The configured group (group + type) the cycle is processing (Figure 16's CertificateGroup loop).
  std::size_t mGroupIndex = 0;
  /// The groups whose TrustList this cycle has already refreshed: several types of one group share it.
  std::vector<ua::NodeId> mCycleTrustListGroupsDone;
  bool mCycleOwnCertChanged = false;  ///< a certificate was committed this cycle (revalidation at the end).
  /// GetCertificateStatus is in flight (state RequestingCert): a certificate rotation then asks again rather
  /// than requesting a certificate the CertificateManager has not asked for.
  bool mAwaitingCertificateStatus = false;
  bool mCycleTrustListChanged = false;  ///< a TrustList was committed this cycle.
  std::shared_ptr<const ua::ErrorDetail> mCycleAdvisory;  ///< e.g. a request still pending approval.
  /// The first GetCertificateStatus failure of this cycle and its group: the cycle goes on refreshing every
  /// group's TrustList and ends Failed with it.
  std::optional<std::pair<ua::NodeId, StatusCode>> mCycleStatusFailure;
  /// M5(a): an `open_gds` was requested (tracked independently of @ref mGdsConnected so a stop still closes
  /// the GDS connection even if the open never completed / the bootstrap failed).
  bool mGdsOpenRequested = false;

  // ---- pending completions ----
  std::vector<std::function<void(ua::VoidResult)>> mForceCycleAcks;  ///< fired Good at every cycle terminus.
  bool mStopPending = false;  ///< a stop arrived during Revalidating; deferred until the broadcast completes.
  std::function<void(ua::VoidResult)> mStopAck;

  boost::asio::steady_timer mCycleTimer;  ///< long-period timer between cycles (Idle / Failed retry).
  boost::asio::steady_timer mPollTimer;  ///< short-delay between FinishRequest polls (Polling).

  // ---- diagnostics / test observability for the armed timer delays ----
  std::optional<std::chrono::milliseconds> mLastArmedCycleDelay;
  std::optional<std::chrono::milliseconds> mLastArmedPollDelay;
  // The generation the cycle timer captured at its last arm  -  lets a test prove the C1 re-arm bound the
  // timer to the CURRENT generation (not a stale one) deterministically, without a wall-clock timer wait.
  std::optional<std::uint64_t> mLastArmedCycleGeneration;

  std::mt19937 mJitterRng{std::random_device{}()};

  // ---- cross-strand snapshot (Rule 4; also published to the host) ----
  std::atomic<std::shared_ptr<const ua::client::PullCertManagementInfo>> mInfoSnapshot{
    std::make_shared<const ua::client::PullCertManagementInfo>()};

  // ---- test interface: injectable clock (deterministic timestamps) ----
  std::function<ua::DateTime()> mNowFn = []
  {
    return ua::DateTime::now();
  };
};

/// Construction interface for the public @ref ua::client::PullCertificateManager handle  -  tests and the
/// deferred `Client::start_pull_cert_management_sync` wrap a @ref PullCertificateManagerImpl in the shared handle
/// through here, keeping the facade's constructor private.
struct PullCertificateManagerFactory
{
  [[nodiscard]] static std::shared_ptr<ua::client::PullCertificateManager> wrap(
    std::shared_ptr<PullCertificateManagerImpl> impl)
  {
    return std::shared_ptr<ua::client::PullCertificateManager>(
      new ua::client::PullCertificateManager{std::move(impl)});
  }
};

}  // namespace ua::client::detail

#endif  // UA_PULL_CERTIFICATE_MANAGER_IMPL_H
