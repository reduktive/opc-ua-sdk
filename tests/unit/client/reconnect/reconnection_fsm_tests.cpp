// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ReconnectionFSM (section 8.3): the strand-component shell (create /
// start_async / cancel_async / info + Idle/Active/Cancelled lifecycle) AND the trigger-driven reconnect
// sequence engine (happy path, step-failure backoff + retry, max-attempts terminal failure, cancel).
//
// Falsifiability: the tests drive a real io_context so the strand hops and executor-side callbacks run.
// A scriptable FakeReconnectionFSMHost records the exact service-step order and lets a step be scripted
// to fail, so a broken sequence order, a missing backoff/retry, or a wrong terminal transition all fail.
//
// @verifies CL-RECONN-001
// @relation(CL-RECONN-001, scope=file)

#include "ua_reconnection_fsm.h"

#include "ua_date_time.h"
#include "ua_logger.h"
#include "ua_reconnect_policy.h"
#include "ua_reconnect_types.h"
#include "ua_result.h"
#include "ua_status.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using ua::client::ReconnectCause;
using ua::client::ReconnectOutcome;
using ua::client::ReconnectPolicy;
using ua::client::SubscriptionRecovery;
using ua::client::TransportDropped;
using ua::client::detail::ReconnectFsmState;
using ua::client::detail::ReconnectionFSM;
using ua::client::detail::ReconnectionFSMHost;

// Scriptable host: records the notify hooks and the service-step call order; each service primitive
// returns a scripted result (Good by default; `<step>Failures` makes the first N calls return Bad),
// then invokes the FSM's callback (the FSM re-posts it onto its own strand).
class FakeReconnectionFSMHost : public ReconnectionFSMHost
{
public:
  void on_fsm_state_changed(ReconnectFsmState, ReconnectCause, std::size_t) override
  {
    ++stateChangedCalls;
  }

  void on_fsm_reached_active(ReconnectOutcome outcome) override
  {
    ++reachedActiveCalls;
    lastOutcome = outcome;
  }

  void on_fsm_failed(ua::StatusCode terminal, std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++failedCalls;
    lastFailed = terminal;
  }

  void get_endpoints_async(std::function<void(ua::VoidResult)> done) override
  {
    step("get_endpoints", getEndpointsFailures, std::move(done));
  }

  void open_secure_channel_async(std::function<void(ua::VoidResult)> done) override
  {
    ++openChannelCalls;
    openChannelTimes.push_back(std::chrono::steady_clock::now());
    // Hold mode: capture the callback and never fire it, parking the FSM in OpeningChannel. FromCall
    // holds this call and every later one; ExactCall holds only that one call (so a retry can proceed).
    if ((openChannelHoldFromCall > 0 && openChannelCalls >= openChannelHoldFromCall) ||
        (openChannelHoldExactCall > 0 && openChannelCalls == openChannelHoldExactCall))
    {
      calls.push_back("open_channel");
      heldOpenChannelDones.push_back(std::move(done));
      return;
    }
    step("open_channel", openChannelFailures, std::move(done), openChannelFailStatus);
  }

  void activate_session_async(std::function<void(ua::VoidResult)> done) override
  {
    step("activate_session", activateFailures, std::move(done), activateFailStatus);
  }

  void create_session_async(std::function<void(ua::VoidResult)> done) override
  {
    step("create_session", createFailures, std::move(done));
  }

  void re_read_namespace_array_async(std::function<void(ua::VoidResult)> done) override
  {
    step("re_read_namespace", reReadFailures, std::move(done));
  }

  void recover_subscriptions_async(
    SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done) override
  {
    lastRecovery = recovery;
    if (recoverFailures == 0 && !recoverStatus.is_good())
    {
      calls.push_back("recover_subscriptions");
      done(ua::VoidResult{recoverStatus});
      return;
    }
    step("recover_subscriptions", recoverFailures, std::move(done));
  }

  void commit_reconnect_async(std::function<void(ua::VoidResult)> done) override
  {
    step("commit", commitFailures, std::move(done));
  }

  // Scripted failure counts (first N calls of a step return Bad).
  int getEndpointsFailures = 0;
  int openChannelFailures = 0;
  ua::StatusCode openChannelFailStatus{
    ua::Status::BadConnectionClosed};  // status a scripted OPN fail returns
  int openChannelHoldFromCall = 0;  // 0 = never hold; else hold this call and all later
  int openChannelHoldExactCall = 0;  // 0 = never; else hold only this exact call number
  int openChannelCalls = 0;
  std::vector<std::chrono::steady_clock::time_point> openChannelTimes;
  std::vector<std::function<void(ua::VoidResult)>> heldOpenChannelDones;
  int activateFailures = 0;
  ua::StatusCode activateFailStatus{
    ua::Status::BadConnectionClosed};  // status a scripted activate fail returns
  int createFailures = 0;
  int reReadFailures = 0;
  int recoverFailures = 0;
  ua::StatusCode recoverStatus{ua::Status::Good};  ///< the code a recovery that does not fail answers
  int commitFailures = 0;

  std::vector<std::string> calls;
  int stateChangedCalls = 0;
  int reachedActiveCalls = 0;
  int failedCalls = 0;
  ua::StatusCode lastFailed;
  ReconnectOutcome lastOutcome;
  SubscriptionRecovery lastRecovery = SubscriptionRecovery::TransferThenRecreate;

  int count(const std::string& name) const
  {
    int total = 0;
    for (const auto& call : calls)
    {
      if (call == name)
      {
        ++total;
      }
    }
    return total;
  }

private:
  void step(const std::string& name, int& failuresRemaining, std::function<void(ua::VoidResult)> done,
    ua::StatusCode failStatus = ua::Status::BadConnectionClosed)
  {
    calls.push_back(name);
    if (failuresRemaining > 0)
    {
      --failuresRemaining;
      done(ua::VoidResult{failStatus});
      return;
    }
    done(ua::VoidResult{});
  }
};

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeReconnectionFSMHost> host = std::make_shared<FakeReconnectionFSMHost>();

  std::shared_ptr<ReconnectionFSM> make(ReconnectPolicy policy = {})
  {
    return ReconnectionFSM::create(ctx.get_executor(), host, std::move(policy), ua::Logger{});
  }
};

// A wall-clock DateTime `ahead` in the future (for ServerShutdown deferral).
ua::DateTime future_datetime(std::chrono::milliseconds ahead)
{
  return ua::DateTime{
    ua::DateTime::now().value() + std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(ahead)};
}

// A policy with a near-zero backoff so retry timers fire immediately under ctx.run().
ReconnectPolicy fast_backoff(std::optional<std::size_t> maxAttempts = std::nullopt)
{
  ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  policy.maxAttempts = maxAttempts;
  return policy;
}

// --- lifecycle (slice 1) ----------------------------------------------------

TEST(ReconnectionFsmShell, StartsIdle)
{
  Fixture f;
  auto fsm = f.make();
  ASSERT_NE(fsm->info(), nullptr);
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Idle);
}

TEST(ReconnectionFsmShell, StartTransitionsIdleToActive)
{
  Fixture f;
  auto fsm = f.make();
  ua::VoidResult result{ua::Status::BadInternalError};
  fsm->start_async([&](ua::VoidResult r) { result = r; });
  f.ctx.run();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
}

TEST(ReconnectionFsmShell, DoubleStartReturnsBadInvalidState)
{
  Fixture f;
  auto fsm = f.make();
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  ua::VoidResult second{ua::Status::BadInternalError};
  fsm->start_async([&](ua::VoidResult r) { second = r; });
  f.ctx.run();
  EXPECT_EQ(second.status_code().value(), static_cast<uint32_t>(ua::Status::BadInvalidState));
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
}

TEST(ReconnectionFsmShell, CancelTransitionsToCancelledAndReportsGood)
{
  Fixture f;
  auto fsm = f.make();
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  ua::VoidResult result{ua::Status::BadInternalError};
  fsm->cancel_async([&](ua::VoidResult r) { result = r; });
  f.ctx.run();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Cancelled);
}

TEST(ReconnectionFsmShell, RepeatedCancelIsGood)
{
  Fixture f;
  auto fsm = f.make();
  fsm->cancel_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  ua::VoidResult second{ua::Status::BadInternalError};
  fsm->cancel_async([&](ua::VoidResult r) { second = r; });
  f.ctx.run();
  EXPECT_TRUE(second.is_good());
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Cancelled);
}

// --- trigger + sequence engine (this slice) ---------------------------------

TEST(ReconnectionFsmSequence, TriggerBeforeStartIsIgnored)
{
  Fixture f;
  auto fsm = f.make();
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Idle);
  EXPECT_TRUE(f.host->calls.empty());
}

// @verifies CL-SESS-028
// Part 4 6.7 / Part 3 8.2: on reconnect the client reuses the Session and must re-read Server.NamespaceArray
// (NamespaceIndex is per-session-ephemeral; NamespaceUri is the stable identifier). This asserts the
// reconnect FSM orchestrates the re_read_namespace step in the correct order - after activate_session and
// BEFORE recover_subscriptions - so a refreshed namespace snapshot is in place before subscriptions (and
// their NodeIds) are recovered. Scope note: this verifies the client PERFORMS the re-read step in sequence;
// the URI-keyed NodeId remapping itself lives in the NamespaceTable (see namespace_table_tests).
// @relation(CL-SESS-028, scope=function)
TEST(ReconnectionFsmSequence, HappyPathRunsAllStepsInOrderAndReachesActive)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  const std::vector<std::string> expected{
    "open_channel", "activate_session", "re_read_namespace", "recover_subscriptions", "commit"};
  EXPECT_EQ(f.host->calls, expected);
  EXPECT_EQ(fsm->info()->attempt, 0u) << "attempt resets to 0 on reaching Active";
}

// A recovery that restored the Subscriptions from answers carrying an Uncertain code is not a failure: the
// sequence commits and reaches Active once, without backing off or recovering again.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ReconnectionFsmSequence, AnUncertainRecoveryCommitsAndReachesActive)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->recoverStatus = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_EQ(f.host->count("recover_subscriptions"), 1) << "an Uncertain recovery is not retried";
  EXPECT_EQ(f.host->count("commit"), 1);
}

TEST(ReconnectionFsmSequence, StepFailureBacksOffAndRetriesToSuccess)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 1;  // first OPN fails, second succeeds
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_EQ(f.host->count("open_channel"), 2) << "OPN retried after backoff";
  EXPECT_EQ(f.host->count("commit"), 1);
}

TEST(ReconnectionFsmSequence, MaxAttemptsExhaustedEntersFailed)
{
  Fixture f;
  auto fsm = f.make(fast_backoff(/*maxAttempts=*/2));
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 100;  // always fails
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Failed);
  EXPECT_EQ(f.host->reachedActiveCalls, 0);
  EXPECT_EQ(f.host->failedCalls, 1);
  EXPECT_EQ(f.host->count("open_channel"), 2) << "exactly maxAttempts OPN attempts";
  // section 8.3.5: the terminal status carries the rich reconnection-fsm chain whose cause is the last
  // failure.
  ASSERT_NE(f.host->lastFailed.shared_detail(), nullptr) << "terminal failure must carry an ErrorDetail";
  EXPECT_EQ(f.host->lastFailed.shared_detail()->source, "client.tier1.reconnection_fsm");
  EXPECT_EQ(f.host->lastFailed.shared_detail()->code, "ReconnectFailed");
  EXPECT_EQ(
    f.host->lastFailed.shared_detail()->innerStatus, static_cast<uint32_t>(ua::Status::BadConnectionClosed))
    << "the chain's inner status is the causing failure";
}

TEST(ReconnectionFsmSequence, CommitFailureIsTerminalNotRetried)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->commitFailures = 1;  // install cannot take ownership -> unrecoverable
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Failed);
  EXPECT_EQ(f.host->failedCalls, 1);
  EXPECT_EQ(f.host->count("commit"), 1) << "commit failure must not retry the whole sequence";
  EXPECT_EQ(f.host->count("open_channel"), 1);
}

// Adversarial-review regression (section 3.1, spec-conformance lens): a strictly-higher-priority cause that
// upgrades an in-flight reconnect must restart with a FRESH attempt budget, not inherit the attempts
// already burned by the superseded cause.
// section 3.1 storm guard: a peer that accepts every handshake but drops again within minHealthyDwell drives
// a reconnect/re-drop storm. Each re-drop is PACED (backoff) and counted against the attempt budget, so with
// a finite maxAttempts the storm terminates in Failed instead of spinning zero-delay reconnects forever.
TEST(ReconnectionFsmSequence, StormOfQuickReconnectRedropsHitsMaxAttemptsAndFails)
{
  Fixture f;
  ReconnectPolicy policy = fast_backoff(/*maxAttempts=*/3);
  policy.minHealthyDwell =
    std::chrono::hours{1};  // no reconnect stays healthy long enough -> every re-drop storms
  auto fsm = f.make(policy);
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  // Every trigger drives a full reconnect to Active (all steps Good), then we immediately re-drop. The
  // first drop (from the initial connection) is a genuine drop; each subsequent quick re-drop escalates the
  // storm streak, and after maxAttempts of them the FSM must give up. Record exactly which iteration Fails
  // so a streak/maxAttempts off-by-one (failing one cycle too early or too late) is caught, not tolerated.
  int failingIteration = -1;
  for (int i = 0; i < 8; ++i)
  {
    fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
    f.ctx.run();
    f.ctx.restart();
    if (f.host->failedCalls != 0)
    {
      failingIteration = i;
      break;
    }
  }

  EXPECT_EQ(f.host->failedCalls, 1) << "a storm of quick reconnect/re-drop cycles must terminate in Failed";
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Failed);
  // Exact accounting (catches a streak/maxAttempts off-by-one): with maxAttempts=N the storm reconnects to
  // Active exactly N times (1 for the initial drop, N-1 paced) before giving up, and Fails on the N-th
  // unhealthy re-drop - the (N+1)-th trigger, i.e. 0-based iteration index N.
  EXPECT_EQ(f.host->reachedActiveCalls, static_cast<int>(*policy.maxAttempts))
    << "storm reconnects to Active exactly maxAttempts times before giving up";
  EXPECT_EQ(failingIteration, static_cast<int>(*policy.maxAttempts))
    << "the storm must Fail on precisely the (maxAttempts+1)-th trigger, not sooner or later";
}

// The storm guard must NOT throttle genuine drops: when each reconnect is treated as healthy
// (minHealthyDwell = 0), every drop reconnects fresh and the budget never accumulates, so a long series of
// real drops never Fails.
TEST(ReconnectionFsmSequence, HealthyReconnectsNeverStorm)
{
  Fixture f;
  ReconnectPolicy policy = fast_backoff(/*maxAttempts=*/3);
  policy.minHealthyDwell = std::chrono::milliseconds{0};  // any dwell counts as healthy
  auto fsm = f.make(policy);
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  for (int i = 0; i < 10; ++i)
  {
    fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
    f.ctx.run();
    f.ctx.restart();
  }

  EXPECT_EQ(f.host->failedCalls, 0) << "genuine (healthy) drops must each reconnect fresh, never Failing";
  EXPECT_EQ(f.host->reachedActiveCalls, 10) << "all ten drops reconnected to Active";
}

TEST(ReconnectionFsmSequence, UpgradeResetsAttemptBudget)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 2;  // attempts 1 and 2 fail (each backs off and retries)
  f.host->openChannelHoldFromCall = 3;  // attempt 3's OPN parks the FSM in OpeningChannel
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  // run_for (not run): the held OPN leaves the per-step deadline timer pending, so run() would block on
  // it; run_for lets the two 1ms backoffs fire and returns with the FSM parked at attempt 3.
  f.ctx.run_for(50ms);
  f.ctx.restart();
  ASSERT_EQ(fsm->info()->attempt, 3u) << "two backoff retries should have advanced to attempt 3";

  // CertRotated (priority 3) strictly outranks TransportDropped (0), so it upgrades the sequence.
  fsm->trigger(ua::client::CertRotated{}, ua::Status::BadSecurityChecksFailed, nullptr);
  f.ctx.run_for(50ms);
  EXPECT_EQ(fsm->info()->attempt, 1u) << "an upgrade must reset the attempt budget, not inherit 3";
}

// CL-RECONN-003: an activate-on-existing that returns Bad_SessionIdInvalid falls back to CreateSession,
// then re-activates on the fresh Session and continues - only CreateSession, no full backoff.
// @verifies CL-RECONN-003
// @relation(AC-CL-RECONN-003-01, CL-RECONN-003, scope=function)
TEST(ReconnectionFsmSequence, SessionInvalidFallsBackToCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->activateFailures = 1;  // first activate fails...
  f.host->activateFailStatus = ua::Status::BadSessionIdInvalid;  // ...specifically with SessionIdInvalid
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  const std::vector<std::string> expected{"open_channel",
    "activate_session",
    "create_session",
    "activate_session",
    "re_read_namespace",
    "recover_subscriptions",
    "commit"};
  EXPECT_EQ(f.host->calls, expected) << "SessionIdInvalid must insert CreateSession then re-activate";
  EXPECT_EQ(f.host->count("open_channel"), 1) << "no full backoff/retry - the fallback is in-attempt";
}

// CL-RECONN-003 negative: a good activate does NOT create a new Session.
// @verifies CL-RECONN-003
// @relation(AC-CL-RECONN-003-01, CL-RECONN-003, scope=function)
TEST(ReconnectionFsmSequence, ActivateSuccessDoesNotCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();
  EXPECT_EQ(f.host->count("create_session"), 0);
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
}

// A non-SessionIdInvalid activate failure backs off and retries the whole attempt (not CreateSession).
// @relation(AC-CL-RECONN-003-01, CL-RECONN-003, scope=function)
TEST(ReconnectionFsmSequence, ActivateOtherFailureBacksOffNotCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->activateFailures = 1;
  f.host->activateFailStatus = ua::Status::BadConnectionClosed;  // not SessionIdInvalid
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->count("create_session"), 0) << "a transport-class activate failure must not recreate";
  EXPECT_EQ(f.host->count("open_channel"), 2) << "it backs off and retries the whole attempt";
}

// #25: a LONG outage (past the revised session timeout) times out the CLIENT Session object itself, so
// re-activating it returns Bad_SessionClosed / Bad_InvalidState (not Bad_SessionIdInvalid). These mean the
// existing Session is unusable and must fall back to CreateSession too - otherwise the reconnect loops
// forever re-opening a channel and activating a dead client session, never recovering after the link heals.
// @verifies CL-RECONN-003
// @relation(CL-RECONN-003, scope=function)
TEST(ReconnectionFsmSequence, ClientSessionClosedFallsBackToCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->activateFailures = 1;
  f.host->activateFailStatus = ua::Status::BadSessionClosed;  // the CLIENT session closed during the outage
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->count("create_session"), 1)
    << "a closed client session must fall back to CreateSession, not loop re-opening";
  EXPECT_EQ(f.host->count("open_channel"), 1) << "the fallback is in-attempt (no full backoff/retry)";
}

// @verifies CL-RECONN-003
// @relation(CL-RECONN-003, scope=function)
TEST(ReconnectionFsmSequence, ClientSessionInvalidStateFallsBackToCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->activateFailures = 1;
  f.host->activateFailStatus = ua::Status::BadInvalidState;  // timed-out client session: not activatable
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->count("create_session"), 1)
    << "a client session in a non-activatable (timed-out) state must fall back to CreateSession";
  EXPECT_EQ(f.host->count("open_channel"), 1) << "the fallback is in-attempt (no full backoff/retry)";
}

// A fresh Session that STILL cannot activate (create_session already ran this attempt) is a real failure -
// it must NOT trigger a second CreateSession (mSessionRecreated guards the one-shot fallback).
TEST(ReconnectionFsmSequence, RecreatedSessionUnusableDoesNotRecreateAgain)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  // Both the activate-on-existing AND the activate-on-fresh fail with an unusable-session status: the first
  // triggers CreateSession, the second (mSessionRecreated already set) must back off, not recreate again.
  f.host->activateFailures = 2;
  f.host->activateFailStatus = ua::Status::BadInvalidState;
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(f.host->count("create_session"), 1)
    << "CreateSession runs at most once per attempt even when the fresh Session also fails to activate";
  EXPECT_EQ(f.host->count("open_channel"), 2) << "the second unusable-session failure backs off and retries";
}

// CL-RECONN-005: the SecurityFailure cause starts the sequence by refreshing endpoints (GetEndpoints)
// before opening the channel.
// @verifies CL-RECONN-005
// @relation(CL-RECONN-005, scope=function)
TEST(ReconnectionFsmSequence, SecurityFailureCauseStartsWithGetEndpoints)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(ua::client::SecurityFailure{}, ua::Status::BadSecurityChecksFailed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  ASSERT_FALSE(f.host->calls.empty());
  EXPECT_EQ(f.host->calls.front(), "get_endpoints") << "SecurityFailure refreshes endpoints first";
  const std::vector<std::string> expected{"get_endpoints",
    "open_channel",
    "activate_session",
    "re_read_namespace",
    "recover_subscriptions",
    "commit"};
  EXPECT_EQ(f.host->calls, expected);
}

// CL-RECONN-008: a security-class OPN failure (Bad_CertificateInvalid) prepends GetEndpoints, then
// retries OPN in-attempt (no full backoff) using the refreshed cert.
// @verifies CL-RECONN-008
// @relation(CL-RECONN-008, scope=function)
TEST(ReconnectionFsmSequence, SecurityClassOpenFailurePrependsGetEndpoints)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 1;
  f.host->openChannelFailStatus = ua::Status::BadCertificateInvalid;  // security-class
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  const std::vector<std::string> expected{"open_channel",
    "get_endpoints",
    "open_channel",
    "activate_session",
    "re_read_namespace",
    "recover_subscriptions",
    "commit"};
  EXPECT_EQ(f.host->calls, expected) << "security-class OPN failure inserts GetEndpoints, then retries OPN";
}

// A server certificate whose issuer the client does not hold now reports Bad_CertificateChainIncomplete
// (Part 4 Table 106) where it reported Bad_CertificateUntrusted; it is still a security-class failure, so
// it refreshes the endpoints before the OPN is retried, as the Untrusted one did.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-05-CHAIN-INCOMPLETE-KEEPS-ITS-CONSUMERS, scope=function)
TEST(ReconnectionFsmSequence, ChainIncompleteOpenFailureIsSecurityClass)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 1;
  f.host->openChannelFailStatus = ua::Status::BadCertificateChainIncomplete;
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  const std::vector<std::string> expected{"open_channel",
    "get_endpoints",
    "open_channel",
    "activate_session",
    "re_read_namespace",
    "recover_subscriptions",
    "commit"};
  EXPECT_EQ(f.host->calls, expected)
    << "a chain-incomplete OPN failure inserts GetEndpoints, then retries OPN";
}

// A non-security OPN failure backs off (does NOT refresh endpoints).
TEST(ReconnectionFsmSequence, NonSecurityOpenFailureDoesNotGetEndpoints)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 1;
  f.host->openChannelFailStatus = ua::Status::BadConnectionClosed;  // transport-class
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->count("get_endpoints"), 0);
  EXPECT_EQ(f.host->count("open_channel"), 2) << "transport-class OPN failure backs off and retries";
}

// section 8.3.4 per-step deadline: a step whose host callback never returns (a stuck OPN) must time out into
// an ordinary backoff and retry, never hang the FSM. Without the deadline the FSM would park in
// OpeningChannel forever (reachedActive stays 0).
TEST(ReconnectionFsmSequence, StuckStepTimesOutAndBacksOff)
{
  Fixture f;
  auto policy = fast_backoff();
  policy.perStepTimeout = 5ms;  // short step deadline so the stuck step times out quickly
  auto fsm = f.make(policy);
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelHoldExactCall = 1;  // attempt 1's OPN hangs (host never calls back)
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();  // deadline fires -> backoff -> attempt 2's OPN succeeds -> the sequence completes

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_EQ(f.host->count("open_channel"), 2) << "the stuck OPN timed out and the retry succeeded";
}

// CL-RECONN-006: a CertRotated cause forces a full new Session - OPN then CreateSession directly
// (no activate-on-existing first), then activate on the fresh Session and continue.
// @verifies CL-RECONN-006
// @relation(CL-RECONN-006, scope=function)
// @relation(AC-CL-RECONN-006-01, scope=function)
TEST(ReconnectionFsmSequence, CertRotatedForcesCreateSession)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(ua::client::CertRotated{}, ua::Status::BadCertificateInvalid, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  const std::vector<std::string> expected{"open_channel",
    "create_session",
    "activate_session",
    "re_read_namespace",
    "recover_subscriptions",
    "commit"};
  EXPECT_EQ(f.host->calls, expected) << "CertRotated must CreateSession before activating";
}

// The reconnect outcome reports whether the existing Session was preserved (activate-on-existing) vs.
// recreated (CreateSession ran).
TEST(ReconnectionFsmSequence, OutcomeReportsSessionPreservedWhenNotRecreated)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();
  ASSERT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_TRUE(f.host->lastOutcome.sessionPreserved) << "a plain reconnect activates the existing Session";
}

TEST(ReconnectionFsmSequence, OutcomeReportsSessionNotPreservedAfterRecreate)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();
  f.host->activateFailures = 1;
  f.host->activateFailStatus = ua::Status::BadSessionIdInvalid;  // forces CreateSession
  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();
  ASSERT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_FALSE(f.host->lastOutcome.sessionPreserved) << "a recreated Session is not preserved";
}

// W3: the completed reconnect's outcome carries the driving cause when it is a RedundancySwitch, so the
// tier-2 RedundancyManager can tell its OWN failover (and the server it landed on) apart from an unrelated
// reconnect that merely completed while it was FailingOver. Falsifiable: reach_active previously left
// outcome.cause default (nullopt) - this asserts the RedundancySwitchInfo (with its toUri) is threaded out.
TEST(ReconnectionFsmSequence, OutcomeCarriesRedundancySwitchCauseOnReachActive)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  ua::client::RedundancySwitchInfo info;
  info.fromUri = "opc.tcp://primary";
  info.toUri = "opc.tcp://backup";
  fsm->trigger(info, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  ASSERT_EQ(f.host->reachedActiveCalls, 1);
  ASSERT_TRUE(f.host->lastOutcome.cause.has_value()) << "a RedundancySwitch reconnect reports its cause";
  ASSERT_TRUE(std::holds_alternative<ua::client::RedundancySwitchInfo>(*f.host->lastOutcome.cause));
  EXPECT_EQ(std::get<ua::client::RedundancySwitchInfo>(*f.host->lastOutcome.cause).toUri, "opc.tcp://backup")
    << "the landed-on server URI is threaded through so a diverged fallback is learnable";
}

// W3: a plain (non-redundancy) reconnect leaves outcome.cause unset - nothing tier-2 consumes it, and a
// populated cause on every reconnect would mislead the RedundancyManager into treating an unrelated recovery
// as its own failover completion.
TEST(ReconnectionFsmSequence, OutcomePlainReconnectLeavesCauseUnset)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  ASSERT_EQ(f.host->reachedActiveCalls, 1);
  EXPECT_FALSE(f.host->lastOutcome.cause.has_value())
    << "a plain transport-drop reconnect leaves cause nullopt";
}

// CL-SESS-025: ServerShutdown with a deadline holds the first attempt in ShutdownDeferred until the
// announced return time - no reconnect service call is issued during the deferral.
// @verifies CL-SESS-025
// @relation(CL-SESS-025, scope=function)
TEST(ReconnectionFsmSequence, ServerShutdownEntersDeferredAndHoldsOff)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(
    ua::client::ServerShutdown{}, ua::Status::BadConnectionClosed, nullptr, future_datetime(200ms));
  f.ctx.run_for(20ms);  // process the trigger -> ShutdownDeferred; the 200ms deadline has not elapsed

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::ShutdownDeferred);
  EXPECT_TRUE(f.host->calls.empty()) << "no reconnect service call during the shutdown deferral";
}

// After the deferral elapses the normal sequence runs to Active.
TEST(ReconnectionFsmSequence, ServerShutdownRunsSequenceAfterDeferral)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(ua::client::ServerShutdown{}, ua::Status::BadConnectionClosed, nullptr, future_datetime(5ms));
  f.ctx.run();  // ~5ms deferral, then the sequence runs

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->reachedActiveCalls, 1);
  ASSERT_FALSE(f.host->calls.empty());
  EXPECT_EQ(f.host->calls.front(), "open_channel");
}

// When no future EstimatedReturnTime is usable, maintenance enters immediately but failed attempts use the
// configured shutdown multiplier. The relative attempt spacing is the oracle, so scheduler overshoot cannot
// false-fail the test; removing the multiplier yields ~20ms and violates the 70ms lower bound.
// @verifies CL-BASE-005
// @relation(CL-BASE-005, scope=function)
TEST(ReconnectionFsmSequence, ServerShutdownWithoutFutureHintUsesSlowRetryMultiplier)
{
  Fixture f;
  ReconnectPolicy policy;
  policy.backoff.base = 20ms;
  policy.backoff.max = 20ms;
  policy.backoff.jitterPct = 0.0;
  policy.shutdownBackoffMultiplier = 4;
  auto fsm = f.make(policy);
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  f.host->openChannelFailures = 1;
  fsm->trigger(ua::client::ServerShutdown{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  ASSERT_GE(f.host->openChannelTimes.size(), 2u);
  const auto retrySpacing = std::chrono::duration_cast<std::chrono::milliseconds>(
    f.host->openChannelTimes[1] - f.host->openChannelTimes[0]);
  EXPECT_GE(retrySpacing, 70ms)
    << "shutdown retry spacing must reflect 20ms * 4, not the normal 20ms backoff";
  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
}

// CL-RECONN-007: a redundancy switch moves to a different server, so subscriptions must be recreated
// (not transferred) regardless of the configured recovery policy.
// @verifies CL-RECONN-007
// @relation(CL-RECONN-007, scope=function)
TEST(ReconnectionFsmSequence, RedundancySwitchForcesRecreateOnly)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(ua::client::RedundancySwitchInfo{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(fsm->info()->state, ReconnectFsmState::Active);
  EXPECT_EQ(f.host->lastRecovery, SubscriptionRecovery::RecreateOnly);
}

TEST(ReconnectionFsmSequence, DefaultCauseHonoursConfiguredRecovery)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());  // default policy: TransferThenRecreate
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();

  EXPECT_EQ(f.host->lastRecovery, SubscriptionRecovery::TransferThenRecreate);
}

TEST(ReconnectionFsmSequence, TriggerOnActiveFsmFiresStateChanged)
{
  Fixture f;
  auto fsm = f.make(fast_backoff());
  fsm->start_async([](ua::VoidResult) {});
  f.ctx.run();
  f.ctx.restart();

  fsm->trigger(TransportDropped{}, ua::Status::BadConnectionClosed, nullptr);
  f.ctx.run();
  EXPECT_GE(f.host->stateChangedCalls, 1) << "entering a reconnect fires on_fsm_state_changed";
}

}  // namespace
