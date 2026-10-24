// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reconnection_fsm.h"

#include "ua_error_detail_keys.h"
#include "ua_on_strand.h"
#include "ua_status.h"

#include <boost/asio/strand.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace ua::client::detail
{
namespace
{

/// Default per-step deadline when `ReconnectPolicy.perStepTimeout` is unset (the service-timeout
/// default). A stuck reconnect step that exceeds this is treated as a recoverable per-attempt failure.
constexpr std::chrono::milliseconds defaultStepTimeout{10000};

/// Whether @p status is a security-class failure that reconnect recovers by refreshing endpoints first
/// (CL-RECONN-005; Bad_CertificateInvalid is the CL-RECONN-008 subcase).
bool is_security_class(ua::StatusCode status) noexcept
{
  switch (status.as_status())
  {
  case ua::Status::BadCertificateInvalid:
  case ua::Status::BadCertificateUntrusted:
  case ua::Status::BadCertificateChainIncomplete:
  case ua::Status::BadSecurityChecksFailed:
  case ua::Status::BadSecurityModeRejected:
  case ua::Status::BadSecurityPolicyRejected:
  case ua::Status::BadNoValidCertificates:
    return true;
  default:
    return false;
  }
}

}  // namespace

std::shared_ptr<ReconnectionFSM> ReconnectionFSM::create(boost::asio::any_io_executor executor,
  std::shared_ptr<ReconnectionFSMHost> host, ReconnectPolicy policy, ua::Logger logger)
{
  return std::shared_ptr<ReconnectionFSM>(
    new ReconnectionFSM(std::move(executor), std::move(host), std::move(policy), std::move(logger)));
}

ReconnectionFSM::ReconnectionFSM(boost::asio::any_io_executor executor,
  std::shared_ptr<ReconnectionFSMHost> host, ReconnectPolicy policy, ua::Logger logger)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)), mBackoffTimer(mExecutor),
    mStepTimer(mExecutor), mHost(std::move(host)), mPolicy(std::move(policy)), mLogger(std::move(logger))
{
  publish_info();  // Idle
}

void ReconnectionFSM::start_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  // Completion-owning post_borrowing: weak self-capture, noexcept boundary, and the completion is
  // delivered on exactly one path (handler if alive, goneResult if the FSM is gone by the strand turn).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{ua::Status::BadInvalidState},  // FSM destroyed before the hop -> start is moot
    [](ReconnectionFSM& self, std::function<void(ua::VoidResult)> completion)
    {
      if (self.mState != ReconnectFsmState::Idle)
      {
        self.deliver(std::move(completion), ua::VoidResult{ua::Status::BadInvalidState});
        return;
      }
      self.mState = ReconnectFsmState::Active;
      self.mLastActiveAt = std::chrono::steady_clock::now();  // storm-guard dwell baseline
      self.mLastActiveWasReconnect = false;  // the initial connect is not a reconnect
      self.publish_info();
      self.deliver(std::move(completion), ua::VoidResult{});
    })();
}

void ReconnectionFSM::cancel_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},  // FSM already gone -> effectively cancelled -> Good
    [](ReconnectionFSM& self, std::function<void(ua::VoidResult)> completion)
    {
      if (!self.mCancelled)
      {
        self.mCancelled = true;
        self.mState = ReconnectFsmState::Cancelled;
        self.mAttempt = 0;
        ++self.mGeneration;  // drop any in-flight step callback on arrival
        self.mBackoffTimer.cancel();  // abort a pending backoff wait (fires operation_aborted)
        self.mStepTimer.cancel();  // abort a pending step deadline
        self.publish_info();
      }
      self.deliver(std::move(completion), ua::VoidResult{});
    })();
}

void ReconnectionFSM::trigger(ReconnectCause cause, ua::StatusCode triggerStatusCode,
  std::shared_ptr<const ua::ErrorDetail> chain, std::optional<ua::DateTime> deferUntil) noexcept
{
  // post_borrowing_or_else: noexcept boundary, weak self-capture, no completion owed. The gone path is
  // a no-op (nothing to reconnect if the FSM is destroyed).
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [cause = std::move(cause),
      triggerStatusCode = std::move(triggerStatusCode),
      chain = std::move(chain),
      deferUntil = std::move(deferUntil)](ReconnectionFSM& self) mutable
    {
      if (self.mCancelled || self.mState == ReconnectFsmState::Failed ||
          self.mState == ReconnectFsmState::Idle)
      {
        return;  // terminal, or not yet started (start_async must run first) - drop
      }
      // ServerShutdown with a deadline holds the first attempt in ShutdownDeferred (CL-SESS-025);
      // everything else enters its cause-specific first step immediately.
      const auto enter = [&self]
      {
        if (std::holds_alternative<ua::client::ServerShutdown>(self.mCurrentCause) && self.mDeferUntil)
        {
          self.enter_shutdown_deferred();
        }
        else
        {
          self.begin_attempt();
        }
      };
      if (self.mState == ReconnectFsmState::Active)
      {
        self.mCurrentCause = std::move(cause);
        self.mTriggerStatusCode = std::move(triggerStatusCode);
        self.mTriggerChain = std::move(chain);
        self.mDeferUntil = std::move(deferUntil);
        ++self.mGeneration;

        // Storm guard (section 3.1): if the just-completed reconnect stayed Active for at least
        // minHealthyDwell it was a genuine recovery, so treat this as a fresh drop and reconnect immediately.
        // If it dropped again sooner, the peer is flapping (e.g. it accepts every handshake but fails
        // immediately) - pace this retry through the backoff at an escalating streak index rather than a
        // zero-delay, budget-reset attempt. ServerShutdown is exempt (it carries its own backoff multiplier).
        const auto dwell = std::chrono::steady_clock::now() - self.mLastActiveAt;
        // The initial connection's first drop is never a "storm" (only a reconnect that reached Active and
        // then re-dropped within the dwell counts). So pace only when the last Active was itself a reconnect.
        const bool stayedHealthy = !self.mLastActiveWasReconnect || dwell >= self.mPolicy.minHealthyDwell;
        const bool isShutdown = std::holds_alternative<ua::client::ServerShutdown>(self.mCurrentCause);
        if (stayedHealthy || isShutdown)
        {
          self.mUnhealthyReconnectStreak = 0;
          self.mAttempt = 1;
          enter();
        }
        else
        {
          ++self.mUnhealthyReconnectStreak;
          self.mAttempt = self.mUnhealthyReconnectStreak;
          // enter_backoff() checks `mAttempt >= maxAttempts` BEFORE arming, so a storm re-drop can fail
          // fast with zero further attempts: with maxAttempts==1 the first re-drop (streak==1) goes
          // straight to Failed. This is intentional - a healthy drop always earns at least one attempt,
          // but a flapping peer that already burned the whole budget on one bad cycle should not earn
          // another. (A caller who wants unbounded paced retries leaves maxAttempts unset.)
          self.enter_backoff();  // waits backoff(mAttempt); trips maxAttempts if exceeded
        }
        return;
      }
      // A reconnect is already in flight: upgrade only on a strictly-higher-priority cause (section 8.3.4).
      if (reconnect_cause_upgrades(self.mCurrentCause, cause))
      {
        self.mCurrentCause = std::move(cause);
        self.mTriggerStatusCode = std::move(triggerStatusCode);
        self.mTriggerChain = std::move(chain);
        self.mDeferUntil = std::move(deferUntil);
        self.mAttempt = 1;  // a new cause is a fresh sequence - do not inherit the burned attempt budget
        self.mBackoffTimer.cancel();
        ++self.mGeneration;  // drop the superseded sequence's in-flight callback
        enter();  // restart the (higher-priority) sequence from its entry step (deferring if ServerShutdown)
      }
    },
    []() {})();
}

void ReconnectionFSM::enter_shutdown_deferred()
{
  mState = ReconnectFsmState::ShutdownDeferred;
  publish_info();
  mHost->on_fsm_state_changed(ReconnectFsmState::ShutdownDeferred, mCurrentCause, mAttempt);

  // Hold the first attempt until the server's announced return time (clamped to >= 0).
  auto delay =
    std::chrono::duration_cast<std::chrono::milliseconds>(mDeferUntil->value() - ua::DateTime::now().value());
  if (delay < std::chrono::milliseconds{0})
  {
    delay = std::chrono::milliseconds{0};
  }
  const std::uint64_t generation = mGeneration;
  mBackoffTimer.expires_after(delay);
  mBackoffTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (cancel / upgrade) - drop
      }
      if (!self.is_current(generation))
      {
        return;
      }
      self.begin_attempt();  // the deferral elapsed - run the sequence
    }));
}

bool ReconnectionFSM::is_current(std::uint64_t generation) const noexcept
{
  return mGeneration == generation && mState != ReconnectFsmState::Cancelled &&
         mState != ReconnectFsmState::Failed;
}

std::function<void(ua::VoidResult)> ReconnectionFSM::on_step(
  std::uint64_t generation, void (ReconnectionFSM::*next)())
{
  return ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation, next](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;  // stale callback (cancelled / upgraded / retried since this step was issued)
      }
      if (result.is_good())
      {
        (self.*next)();
      }
      else
      {
        self.enter_backoff();
      }
    });
}

void ReconnectionFSM::begin_attempt()
{
  mSessionRecreated = false;  // each attempt re-activates the existing Session before any recreate
  mEndpointsRefreshed = false;  // ...and re-opens the channel before any endpoint refresh
  // Entry step is cause-specific: SecurityFailure starts by refreshing endpoints (CL-RECONN-005);
  // every other cause starts by opening a channel. (ServerShutdown defer arrives with its slice.)
  if (std::holds_alternative<ua::client::SecurityFailure>(mCurrentCause))
  {
    mHost->on_fsm_state_changed(ReconnectFsmState::GettingEndpoints, mCurrentCause, mAttempt);
    step_get_endpoints();
  }
  else
  {
    mHost->on_fsm_state_changed(ReconnectFsmState::OpeningChannel, mCurrentCause, mAttempt);
    step_open_channel();
  }
}

void ReconnectionFSM::step_get_endpoints()
{
  mState = ReconnectFsmState::GettingEndpoints;
  publish_info();
  arm_step_deadline();
  const std::uint64_t generation = mGeneration;
  mHost->get_endpoints_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;
      }
      if (result.is_good())
      {
        self.mEndpointsRefreshed = true;  // the next OPN uses the refreshed endpoint + cert
        self.step_open_channel();
      }
      else
      {
        self.enter_backoff();
      }
    }));
}

void ReconnectionFSM::step_open_channel()
{
  mState = ReconnectFsmState::OpeningChannel;
  publish_info();
  arm_step_deadline();
  const std::uint64_t generation = mGeneration;
  mHost->open_secure_channel_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;
      }
      if (result.is_good())
      {
        // CL-RECONN-006: a cert rotation needs a full new Session, so it goes straight to CreateSession
        // (skipping activate-on-existing); every other cause activates the existing Session first.
        if (std::holds_alternative<ua::client::CertRotated>(self.mCurrentCause))
        {
          self.step_create_session();
        }
        else
        {
          self.step_activate_session();
        }
        return;
      }
      // CL-RECONN-005/008: a security-class OPN failure refreshes endpoints first, then retries OPN -
      // once per attempt (a fresh endpoint that still fails security is a real failure).
      if (is_security_class(result.status_code()) && !self.mEndpointsRefreshed)
      {
        self.step_get_endpoints();
        return;
      }
      self.enter_backoff();
    }));
}

void ReconnectionFSM::step_activate_session()
{
  mState = ReconnectFsmState::ActivatingSession;
  publish_info();
  arm_step_deadline();
  const std::uint64_t generation = mGeneration;
  mHost->activate_session_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;
      }
      if (result.is_good())
      {
        self.step_re_read_namespace();
        return;
      }
      // CL-RECONN-003: the existing Session cannot be re-activated, so fall back to CreateSession - once per
      // attempt (mSessionRecreated), because a fresh Session that still cannot activate is a real failure,
      // not another recreate loop. Three statuses mean "the existing Session is gone, make a new one":
      //   - Bad_SessionIdInvalid: the SERVER no longer knows the Session (it was reaped - e.g. an outage past
      //     the server session timeout, or a server restart);
      //   - Bad_InvalidState: the CLIENT Session object timed out during a long outage (past the revised
      //     session timeout) and is now Closed, so the SessionImpl activate guard rejects re-activation - it
      //     can only ever fail (#25). Without this a long outage strands the reconnect looping open-channel
      //     -> activate-dead-session forever;
      //   - Bad_SessionClosed: the CLIENT Session was closed / destroyed mid-activate (a concurrent close).
      // Every one is a client- or server-side "this Session is unusable" verdict, never a transport-class
      // transient (a channel drop mid-activate surfaces the real transport status -> enter_backoff), so a
      // fresh CreateSession is always the right response.
      const ua::Status activateStatus = result.status_code().as_status();
      const bool existingSessionUnusable = activateStatus == ua::Status::BadSessionIdInvalid ||
                                           activateStatus == ua::Status::BadSessionClosed ||
                                           activateStatus == ua::Status::BadInvalidState;
      if (existingSessionUnusable && !self.mSessionRecreated)
      {
        self.step_create_session();
        return;
      }
      self.enter_backoff();
    }));
}

void ReconnectionFSM::step_create_session()
{
  mState = ReconnectFsmState::CreatingSession;
  publish_info();
  arm_step_deadline();
  const std::uint64_t generation = mGeneration;
  mHost->create_session_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;
      }
      if (result.is_good())
      {
        self.mSessionRecreated = true;  // the next activate is on the fresh Session
        self.step_activate_session();
      }
      else
      {
        self.enter_backoff();
      }
    }));
}

void ReconnectionFSM::step_re_read_namespace()
{
  mState = ReconnectFsmState::ReReadingNamespace;
  publish_info();
  arm_step_deadline();
  mHost->re_read_namespace_array_async(on_step(mGeneration, &ReconnectionFSM::step_recover_subscriptions));
}

void ReconnectionFSM::step_recover_subscriptions()
{
  mState = ReconnectFsmState::RecoveringSubscriptions;
  publish_info();
  arm_step_deadline();
  // A redundancy switch moves to a DIFFERENT server, so subscriptions cannot be transferred - force
  // RecreateOnly regardless of policy (CL-RECONN-007); every other cause honours the configured policy.
  const ua::client::SubscriptionRecovery recovery =
    std::holds_alternative<ua::client::RedundancySwitchInfo>(mCurrentCause)
      ? ua::client::SubscriptionRecovery::RecreateOnly
      : mPolicy.subscriptionRecovery;
  // The host restores the Subscriptions from the server's answers and completes with their code: a Good
  // subcode or an Uncertain code means they were restored, so the sequence proceeds; only a Bad one backs
  // off. No caller receives the code, so one that is not plain Good is logged.
  const std::uint64_t generation = mGeneration;
  mHost->recover_subscriptions_async(recovery,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](ReconnectionFSM& self, ua::VoidResult result)
      {
        if (!self.is_current(generation))
        {
          return;  // stale callback (cancelled / upgraded / retried since this step was issued)
        }
        if (result.is_bad())
        {
          self.enter_backoff();
          return;
        }
        if (result.status_code().value() != ua::StatusCode{ua::Status::Good}.value())
        {
          self.mLogger.warning("reconnect: the Subscriptions were restored from answers carrying 0x{:08x}",
            result.status_code().as_uint32());
        }
        self.step_commit();
      }));
}

void ReconnectionFSM::step_commit()
{
  mState = ReconnectFsmState::Installing;
  publish_info();
  arm_step_deadline();
  const std::uint64_t generation = mGeneration;
  mHost->commit_reconnect_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, ua::VoidResult result)
    {
      if (!self.is_current(generation))
      {
        return;
      }
      if (result.is_good())
      {
        self.reach_active();
      }
      else
      {
        // The host could not take ownership of the recovered channel/session - unrecoverable (section 8.3.4).
        self.enter_failed(result.status_code());
      }
    }));
}

void ReconnectionFSM::reach_active()
{
  mStepTimer.cancel();  // the final step resolved - stop its deadline
  mState = ReconnectFsmState::Active;
  mLastActiveAt = std::chrono::steady_clock::now();  // storm-guard dwell baseline (section 8.3.4)
  mLastActiveWasReconnect = true;  // a reconnect reached Active - a quick re-drop is a storm
  mAttempt = 0;
  // Deliberately do NOT reset mUnhealthyReconnectStreak here. Every paced storm retry reaches Active on its
  // way to re-dropping, so zeroing the streak on reach_active would defeat storm bounding entirely (the
  // streak could never grow toward maxAttempts). The streak is cleared only by a genuinely-healthy trigger
  // in trigger()'s Active branch (dwell >= minHealthyDwell). Removing this omission silently unbounds the
  // storm; StormOfQuickReconnectRedropsHitsMaxAttemptsAndFails is the regression guard.
  // Bump the generation on Installing->Active (section 8.3.4 transition table): the just-completed sequence's
  // generation is retired, so any late/duplicate step callback bearing it drops via is_current() rather
  // than re-entering a step on the now-Active FSM (defense-in-depth with the generation-drop discipline).
  ++mGeneration;
  ++mSuccessfulRecoveries;
  publish_info();
  // sessionPreserved iff this attempt re-activated the existing Session (no CreateSession ran). The
  // subscription-recovery fields are host-side (D6) and are populated by the host from its own state.
  ReconnectOutcome outcome;
  outcome.sessionPreserved = !mSessionRecreated;
  // Thread the cause through for the tier-2 RedundancyManager (W3/W4): a RedundancySwitch failover must be
  // distinguishable at `on_reconnected` from an unrelated reconnect that merely completed while the manager
  // was FailingOver (and it learns which server was landed on via RedundancySwitchInfo::toUri). A plain
  // reconnect (transport drop / keep-alive miss / ...) leaves `cause` nullopt - nothing tier-2 consumes it.
  if (std::holds_alternative<ua::client::RedundancySwitchInfo>(mCurrentCause))
  {
    outcome.cause = mCurrentCause;
  }
  mHost->on_fsm_reached_active(outcome);
}

void ReconnectionFSM::arm_step_deadline()
{
  // Cancel any prior step's deadline (advancing to the next step) and arm this step's. The
  // KeepAliveTimer is disarmed during reconnect, so this is the only liveness on a half-built
  // channel/session: a step whose host callback never returns (e.g. an OPN that succeeds but an
  // activate that hangs) times out into an ordinary recoverable backoff instead of hanging the FSM -
  // and, with it, the ConnectionImpl pending-queue drain (which only flushes on reaching Active).
  mStepTimer.cancel();
  const std::chrono::milliseconds timeout = mPolicy.perStepTimeout.value_or(defaultStepTimeout);
  const std::uint64_t generation = mGeneration;
  mStepTimer.expires_after(timeout);
  mStepTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (step completed / advanced) - drop
      }
      if (!self.is_current(generation))
      {
        return;
      }
      ++self.mGeneration;  // drop the stuck step's eventual late callback
      self.enter_backoff();  // a stuck step is a recoverable per-attempt failure
    }));
}

void ReconnectionFSM::enter_backoff()
{
  mStepTimer.cancel();  // the step is resolved (failed) - stop its deadline
  // The attempt just failed. Terminate if the attempt budget is exhausted; otherwise wait out the
  // backoff and retry as a fresh attempt.
  if (mPolicy.maxAttempts && mAttempt >= *mPolicy.maxAttempts)
  {
    enter_failed(mTriggerStatusCode);
    return;
  }
  mState = ReconnectFsmState::BackingOff;
  publish_info();
  auto delay = mPolicy.backoff.next(mAttempt);
  if (std::holds_alternative<ua::client::ServerShutdown>(mCurrentCause) &&
      mPolicy.shutdownBackoffMultiplier > 1)
  {
    // Widen the spacing while a server-announced shutdown is in effect (CL-SESS-025 / section 8.3.4).
    delay *= static_cast<std::chrono::milliseconds::rep>(mPolicy.shutdownBackoffMultiplier);
  }
  const std::uint64_t generation = mGeneration;
  mBackoffTimer.expires_after(delay);
  mBackoffTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](ReconnectionFSM& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (cancel / upgrade) or a timer error - drop
      }
      if (!self.is_current(generation))
      {
        return;
      }
      ++self.mAttempt;
      ++self.mGeneration;  // the retry is a new attempt generation
      self.begin_attempt();
    }));
}

void ReconnectionFSM::enter_failed(ua::StatusCode terminal)
{
  mStepTimer.cancel();
  const std::string_view causeName = reconnect_cause_name(mCurrentCause);
  mState = ReconnectFsmState::Failed;
  publish_info();

  // Build the rich terminal chain (section 8.3.5): a tier-1 reconnection-fsm wrap whose cause is the specific
  // failure (@p terminal - the last step's status, which itself may chain the server's wire error). The
  // full causal history reaches the user callback via on_fsm_failed -> the pending-queue drain.
  std::shared_ptr<const ua::ErrorDetail> chain =
    ua::ErrorDetail::build(
      "ReconnectFailed", "Reconnect attempts were exhausted", "client.tier1.reconnection_fsm")
      .context(ua::ContextKeys::countTotal, mAttempt)
      .context(ua::ContextKeys::errorMessage, std::string{causeName})
      .cause(terminal);
  ua::StatusCode terminalStatus{ua::Status::BadConnectionClosed, chain};
  mHost->on_fsm_failed(terminalStatus, terminalStatus.shared_detail());
}

void ReconnectionFSM::deliver(std::function<void(ua::VoidResult)> callback, ua::VoidResult result) noexcept
{
  // Precondition: `callback` is non-empty. Both the alive and gone paths of the completion-owning
  // post_borrowing below invoke it unconditionally (an empty std::function would throw there); every
  // caller (start_async / cancel_async) supplies a real completion. The helper asserts this in debug on
  // the gone path; the alive-path invocation is not asserted (an empty completion there would throw and be
  // swallowed by `guarded`), so callers must not rely on that path to surface an empty completion.
  // Hop the user callback onto the raw executor (not the strand) so it never runs under the strand's
  // serialization. Weak, noexcept, exactly-once - both the alive and gone paths deliver `result`.
  ua::async::post_borrowing(this,
    mExecutor,
    mLogger,
    std::move(callback),
    result,
    [result](ReconnectionFSM&, std::function<void(ua::VoidResult)> completion) { completion(result); })();
}

void ReconnectionFSM::publish_info()
{
  mInfoSnapshot.store(std::make_shared<const ReconnectionFSMInfo>(
    ReconnectionFSMInfo{mState, mAttempt, mSuccessfulRecoveries}));
}

std::shared_ptr<const ReconnectionFSMInfo> ReconnectionFSM::info() const noexcept
{
  return mInfoSnapshot.load();
}

}  // namespace ua::client::detail
