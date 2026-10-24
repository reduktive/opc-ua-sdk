// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RECONNECTION_FSM_H
#define UA_RECONNECTION_FSM_H

/// @file
/// @brief Strand-serialized reconnect state machine (client tier-1, section 8.3).
/// @ingroup client

#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_reconnect_fsm_logic.h"  // ReconnectFsmState
#include "ua_reconnect_policy.h"  // ReconnectPolicy
#include "ua_reconnect_types.h"  // ReconnectCause, ReconnectOutcome
#include "ua_result.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <chrono>

#include <cstdint>

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>

namespace ua::client::detail
{

/// The ReconnectionFSM's only channel back to `ConnectionImpl` (section 8.3 host interface).
///
/// The FSM never touches `ConnectionImpl` state directly; it calls these hooks, which the concrete
/// shim implements by posting to `ConnectionImpl`'s own strand. The shim holds only a
/// `weak_ptr<ConnectionImpl>`, so the FSM's strong reference to the host forms no ownership cycle.
///
/// @note This is the notify-hook surface. The service primitives the reconnect sequences drive
///       (GetEndpoints / OpenSecureChannel / (Create|Activate)Session / re-read / recover) are added
///       with the `trigger` sequence machinery.
class ReconnectionFSMHost
{
public:
  ReconnectionFSMHost() = default;
  ReconnectionFSMHost(const ReconnectionFSMHost&) = delete;
  ReconnectionFSMHost& operator=(const ReconnectionFSMHost&) = delete;
  ReconnectionFSMHost(ReconnectionFSMHost&&) = delete;
  ReconnectionFSMHost& operator=(ReconnectionFSMHost&&) = delete;
  virtual ~ReconnectionFSMHost() = default;

  /// Fired once per reconnect attempt (attempt-level), driving the observer `on_reconnecting` fan-out.
  ///
  /// Fires at the entry of each attempt (the initial attempt and each backoff retry / upgrade) with the
  /// attempt's entry state. Finer per-step state is observable via `ReconnectionFSM::info()`; the
  /// attempt-level signal is what `on_reconnecting(attempt, cause)` needs, so it is not fired per step.
  ///
  /// @param state   The entry state of the attempt.
  /// @param cause   The cause driving the current sequence.
  /// @param attempt The 1-based attempt number.
  virtual void on_fsm_state_changed(ReconnectFsmState state, ReconnectCause cause, std::size_t attempt) = 0;

  /// Fired when the FSM reaches `Active` again after a successful reconnect.
  ///
  /// @param outcome What the reconnect recovered (session preserved, subscriptions transferred, ...).
  virtual void on_fsm_reached_active(ReconnectOutcome outcome) = 0;

  /// Fired when reconnect has terminally failed (attempts exhausted / unrecoverable install failure).
  ///
  /// @param terminal The terminal status code (carries its detail).
  /// @param chain    The full error chain to attach beneath drained pending requests.
  virtual void on_fsm_failed(ua::StatusCode terminal, std::shared_ptr<const ua::ErrorDetail> chain) = 0;

  // --- Service primitives (section 8.3, orchestration-level) --------------------------------------------
  //
  // Each runs on the host's strand and posts its VoidResult back; the FSM re-enters on its own strand.
  // The result's status code is the classification the FSM branches on (e.g. Bad_SessionIdInvalid ->
  // CreatingSession, a security-class code -> GettingEndpoints). The host owns all request-building and
  // the ownership of the new channel/session it builds; the FSM only orders the steps (D6).

  /// Refreshes the endpoint + server certificate via `GetEndpoints` (security-failure recovery path).
  virtual void get_endpoints_async(std::function<void(ua::VoidResult)> done) = 0;

  /// Opens a fresh `SecureChannel` (the host stashes it for the pending reconnect).
  virtual void open_secure_channel_async(std::function<void(ua::VoidResult)> done) = 0;

  /// Activates the *existing* Session on the new channel; may report `Bad_SessionIdInvalid`.
  virtual void activate_session_async(std::function<void(ua::VoidResult)> done) = 0;

  /// Creates a fresh Session (the host stashes it) after an activate-on-existing failed / on cert rotate.
  virtual void create_session_async(std::function<void(ua::VoidResult)> done) = 0;

  /// Re-reads `Server.NamespaceArray` into a new snapshot (CL-SESS-028) before subscriptions recover.
  virtual void re_read_namespace_array_async(std::function<void(ua::VoidResult)> done) = 0;

  /// Recovers the Session's subscriptions (transfer / republish / recreate per @p recovery).
  virtual void recover_subscriptions_async(
    ua::client::SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done) = 0;

  /// Atomically installs the recovered channel + session into `ConnectionImpl` (ownership swap).
  virtual void commit_reconnect_async(std::function<void(ua::VoidResult)> done) = 0;
};

/// Cross-strand snapshot of FSM state (Rule 4). Read via `ReconnectionFSM::info()` (atomic-load).
struct ReconnectionFSMInfo
{
  /// The FSM's current state.
  ReconnectFsmState state = ReconnectFsmState::Idle;
  /// The 1-based attempt number for the current outage; 0 when no reconnect is in flight.
  std::size_t attempt = 0;
  /// The number of successful reconnects over this FSM's lifetime.
  std::size_t successfulRecoveries = 0;
};

/// The strand-serialized reconnect state machine (section 8.3).
///
/// Owned once by `ConnectionImpl`, driven via `start_async` (bootstrap) and (with the sequence
/// machinery) `trigger`. Every public method may be called from any thread: the component posts to its
/// own private strand internally, and cross-thread observation is via the atomic `info()` snapshot.
class ReconnectionFSM : public std::enable_shared_from_this<ReconnectionFSM>
{
public:
  /// Creates an FSM in the `Idle` state.
  ///
  /// @param executor The io_context executor the FSM's strand and callbacks run on.
  /// @param host     The host interface (kept alive by a strong reference; must outlive close).
  /// @param policy   The reconnect policy (immutable after construction).
  /// @param logger   Logger for the exception-guarded async boundaries.
  /// @return A shared FSM; call `start_async` from the `ConnectionImpl` bootstrap.
  [[nodiscard]] static std::shared_ptr<ReconnectionFSM> create(boost::asio::any_io_executor executor,
    std::shared_ptr<ReconnectionFSMHost> host, ReconnectPolicy policy, ua::Logger logger);

  ReconnectionFSM(const ReconnectionFSM&) = delete;
  ReconnectionFSM& operator=(const ReconnectionFSM&) = delete;
  ReconnectionFSM(ReconnectionFSM&&) = delete;
  ReconnectionFSM& operator=(ReconnectionFSM&&) = delete;
  ~ReconnectionFSM() = default;

  /// Bootstrap transition: `Idle`  to  `Active` (the initial connect already succeeded outside the FSM).
  ///
  /// Idempotent: a second call while not `Idle` delivers `Bad_InvalidState`. The callback runs on the
  /// executor.
  ///
  /// @param callback Receives `Good` on the transition, or `Bad_InvalidState` if not `Idle`.
  void start_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Requests a reconnect for @p cause (section 8.3). Posts to the FSM strand; no callback.
  ///
  /// From `Active`, starts the cause-keyed service sequence. While a reconnect is already in flight, a
  /// strictly-higher-priority cause upgrades the sequence; a same-or-lower cause is dropped. A trigger
  /// on a `Failed` or `Cancelled` FSM is a no-op.
  ///
  /// @param cause             The cause selecting the service sequence.
  /// @param triggerStatusCode The status code that prompted the reconnect (chained into terminal failure).
  /// @param chain             The error chain that prompted the reconnect (may be null).
  /// @param deferUntil        Consulted only for `ServerShutdown`: the first attempt is held in
  ///                          `ShutdownDeferred` until this wall-clock time (CL-SESS-025); unset = no defer.
  void trigger(ReconnectCause cause, ua::StatusCode triggerStatusCode,
    std::shared_ptr<const ua::ErrorDetail> chain,
    std::optional<ua::DateTime> deferUntil = std::nullopt) noexcept;

  /// Cancels the FSM: transitions to the terminal `Cancelled` state. The callback runs on the executor.
  ///
  /// Single-effect and repeatable: the first call performs the transition; every call (including
  /// repeats and a cancel before `start_async`) delivers `Good`.
  ///
  /// @param callback Receives `Good` once the FSM is `Cancelled`.
  void cancel_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Returns the current cross-strand state snapshot (atomic-load; safe from any thread).
  ///
  /// @return The latest published @ref ReconnectionFSMInfo.
  [[nodiscard]] std::shared_ptr<const ReconnectionFSMInfo> info() const noexcept;

private:
  ReconnectionFSM(boost::asio::any_io_executor executor, std::shared_ptr<ReconnectionFSMHost> host,
    ReconnectPolicy policy, ua::Logger logger);

  /// Rebuilds and atomically publishes the info snapshot from the current strand-owned state.
  void publish_info();

  /// Posts @p callback(@p result) onto the executor (never invoked inline).
  void deliver(std::function<void(ua::VoidResult)> callback, ua::VoidResult result) noexcept;

  // --- Sequence engine (strand only). Each step posts a host primitive and re-enters on its own
  //     strand, generation-guarded so a stale callback (post-cancel / post-retry) is dropped. ---
  void begin_attempt();  // enter the current attempt at its cause-specific first step
  void enter_shutdown_deferred();  // CL-SESS-025: hold the first ServerShutdown attempt until deferUntil
  void step_get_endpoints();  // CL-RECONN-005/008: refresh endpoint+cert on a security-class failure
  void step_open_channel();
  void step_activate_session();
  void step_create_session();  // CL-RECONN-003: recreate the Session after activate-on-existing fails
  void step_re_read_namespace();
  void step_recover_subscriptions();
  void step_commit();
  void reach_active();  // success terminal -> Active
  void enter_backoff();  // step failed -> arm the backoff timer (or Failed at max attempts)
  void enter_failed(ua::StatusCode terminal);  // terminal failure -> Failed + on_fsm_failed
  void arm_step_deadline();  // guard the in-flight step: a stuck host call times out into backoff

  /// Wraps a step-result handler: re-enters the FSM strand, drops if @p generation is stale, then on
  /// success calls @p next and on failure enters backoff. (`step_commit` uses its own callback because
  /// its failure is terminal, not recoverable; `step_recover_subscriptions` uses its own because a recovery
  /// that is not Bad, an Uncertain one included, restored the Subscriptions.)
  ///
  /// @param generation The attempt generation this step belongs to.
  /// @param next       The next step to run on success.
  /// @return A callback to hand to a host service primitive.
  std::function<void(ua::VoidResult)> on_step(std::uint64_t generation, void (ReconnectionFSM::*next)());

  [[nodiscard]] bool is_current(std::uint64_t generation) const noexcept;

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  boost::asio::steady_timer mBackoffTimer;
  boost::asio::steady_timer
    mStepTimer;  // per-step deadline (section 8.3.4): a stuck step -> timeout -> backoff
  std::shared_ptr<ReconnectionFSMHost> mHost;
  ReconnectPolicy mPolicy;
  ua::Logger mLogger;

  // Strand-only state.
  ReconnectFsmState mState = ReconnectFsmState::Idle;
  ReconnectCause mCurrentCause;  // meaningful only mid-sequence
  bool mSessionRecreated = false;  // per-attempt: true once CreateSession has run (blocks a re-loop)
  bool mEndpointsRefreshed = false;  // per-attempt: true once GetEndpoints has run (blocks a re-loop)
  std::optional<ua::DateTime> mDeferUntil;  // ServerShutdown: hold the first attempt until this time
  ua::StatusCode mTriggerStatusCode;  // first trigger's status (chained into terminal failure)
  std::shared_ptr<const ua::ErrorDetail> mTriggerChain;
  std::size_t mAttempt = 0;
  std::size_t mSuccessfulRecoveries = 0;
  std::uint64_t mGeneration = 0;  // bumped per attempt / upgrade / cancel; stale-drop key
  bool mCancelled = false;

  // Storm guard (section 8.3.4 / section 3.1): when a reconnect reached Active, and how many consecutive
  // reconnects have dropped again within mPolicy.minHealthyDwell (an unhealthy streak). A trigger that fires
  // before the dwell elapses is paced through the backoff at the streak's attempt index instead of an
  // immediate, budget-reset attempt; the streak resets once a reconnect stays healthy for the dwell.
  // Default-constructed (epoch); the real baseline is stamped on-strand in start_async/reach_active before
  // any trigger reads it, so the initializer value is never observed - no off-strand steady_clock::now()
  // call.
  std::chrono::steady_clock::time_point mLastActiveAt{};
  std::size_t mUnhealthyReconnectStreak = 0;
  bool mLastActiveWasReconnect = false;  // false for the initial connect: its first drop is never "storm"

  // Cross-strand snapshot (Rule 4): published on the strand, read from any thread.
  std::atomic<std::shared_ptr<const ReconnectionFSMInfo>> mInfoSnapshot;
};

}  // namespace ua::client::detail

#endif  // UA_RECONNECTION_FSM_H
