// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// DiscoveryRegistration - strand-serialized driver that keeps the server registered with
// one or more discovery servers (LDS).
//
// Topology: a private boost::asio::strand serializes all mutable state. Each target runs an
// INDEPENDENT linear Step machine (Open -> Register -> Close) projected onto RegistrationState.
// The Step field is READ by continuation entry guards (every register-cycle continuation
// re-checks the target's expected Step and bails if the machine moved on, e.g. stop_async
// cancelled it) and TRANSITIONED at phase boundaries - it is never write-only.
//
// CONNECT-PER-CYCLE: there is no persistent channel. The injected LdsRegistrar opens a fresh
// session-less channel, sends RegisterServer2 (or the memoised RegisterServer fallback) and
// closes - all inside one register_async call. The driver only sequences cadence/backoff and
// flips RegisteredServer::is_online per cycle.
//
// Cadence: 60s steady. On failure: backoff backoffInitial, doubling, capped at backoffCap,
// RESET to cadence on success. Connect failure == registration failure for retry.
//
// Fallback: RS2 -> RS is memoised per target (the registrar reports usedFallback); re-probe
// RS2 on the next reconnect IS the design, but since each cycle is a fresh connection we
// re-probe RS2 every cycle unless the previous cycle reported fallback was needed - that memo
// is reset whenever a non-fallback cycle later succeeds.
//
// Observer callbacks are EDGE-TRIGGERED (only on state transitions, never on the steady 60s
// heartbeat), posted OFF the strand with weak capture. An always-on LogSink line is emitted
// per attempt including ErrorDetail.

#include "ua_discovery_registration.h"

#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_on_strand.h"
#include "ua_to_result.h"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <utility>

namespace ua::app
{

namespace
{

/// What a cycle reports for a registrar outcome that is not Good: a Bad outcome's own code, or
/// Bad_InternalError (RegistrationAnswerUncertain) for an Uncertain one, which the driver does not count as a
/// registration or a deregistration, with that code as the cause.
ua::StatusCode outcome_failure(const ua::StatusCode& outcome)
{
  if (outcome.is_bad())
    return outcome;
  return ua::StatusCode{ua::Status::BadInternalError,
    ua::ErrorDetail::build("RegistrationAnswerUncertain",
      "The SDK does not act on an answer that is uncertain",
      "app.discovery.registration.cycle_failed")
      .cause(outcome)};
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-target state machine (strand-owned)
// ---------------------------------------------------------------------------

struct DiscoveryRegistration::TargetState
{
  explicit TargetState(DiscoveryTarget targetIn) : target(std::move(targetIn))
  {}

  DiscoveryTarget target;

  // Step projection - read by continuation entry guards, transitioned at phase boundaries.
  RegistrationState step{RegistrationState::Idle};

  // True while a register_async cycle is outstanding (guards against overlap).
  bool inFlight{false};

  // RS2->RS fallback memo: once RS2 proved unsupported, prefer RS until a non-fallback cycle
  // succeeds again (re-probe). Re-probed on every fresh connection when false.
  bool fallbackMemo{false};

  // True while the current/last cycle used the RegisterServer v1 fallback (for Status).
  bool fallbackActive{false};

  // Backoff curve: reset to cadence on success.
  std::chrono::seconds currentBackoff{1};

  std::optional<std::chrono::steady_clock::time_point> lastSuccess;
  std::optional<std::chrono::steady_clock::time_point> nextAttempt;
  ua::StatusCode lastError{};

  // Edge-trigger guard: the last observer-visible state we notified for.
  RegistrationState lastNotifiedState{RegistrationState::Idle};

  ua::Timer timer;
};

// ---------------------------------------------------------------------------
// Construction / factory
// ---------------------------------------------------------------------------

DiscoveryRegistration::DiscoveryRegistration(boost::asio::any_io_executor executor,
  std::shared_ptr<LdsRegistrar> registrar, ua::RegisteredServer serverIdentity,
  DiscoveryRegistrationConfig config)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)),
    mRegistrar(std::move(registrar)), mServerIdentity(std::move(serverIdentity)), mConfig(std::move(config))
{}

DiscoveryRegistration::~DiscoveryRegistration() = default;

std::shared_ptr<DiscoveryRegistration> DiscoveryRegistration::create(boost::asio::any_io_executor executor,
  std::shared_ptr<LdsRegistrar> registrar, ua::RegisteredServer serverIdentity,
  DiscoveryRegistrationConfig config)
{
  auto self = std::shared_ptr<DiscoveryRegistration>(new DiscoveryRegistration(
    std::move(executor), std::move(registrar), std::move(serverIdentity), std::move(config)));
  for (const auto& target : self->mConfig.targets)
    self->mTargets.push_back(std::make_unique<TargetState>(target));
  return self;
}

// ---------------------------------------------------------------------------
// Public API (posts to strand)
// ---------------------------------------------------------------------------

void DiscoveryRegistration::start_async(std::function<void(ua::VoidResult)> completionHandler) noexcept
{
  // The completion overload owns `done` and fires it exactly once: on the live path the handler
  // completes it after starting the cycles; on the driver-gone (or post-failed) path the helper
  // delivers the good VoidResult goneResult (starting an absent driver is a benign no-op).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ua::VoidResult{},
    [](DiscoveryRegistration& self, std::function<void(ua::VoidResult)> done) mutable
    {
      if (!self.mRunning)
      {
        self.mRunning = true;
        for (std::size_t index = 0; index < self.mTargets.size(); ++index)
          self.begin_cycle(index);
      }

      ua::detail::invoke_user_callback(self.mLogger, done, ua::VoidResult{});
    })();
}

void DiscoveryRegistration::stop_async(std::function<void(ua::VoidResult)> completionHandler) noexcept
{
  // The completion overload owns `done` and fires it exactly once. On the running path the handler
  // does NOT complete inline: it hands `done` to begin_shutdown_deregister, which fires it later via
  // the shared barrier (or its deadline timer). On the not-running path it completes inline. On the
  // driver-gone (or post-failed) path the helper delivers the good VoidResult goneResult.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ua::VoidResult{},
    [](DiscoveryRegistration& self, std::function<void(ua::VoidResult)> done) mutable
    {
      if (!self.mRunning)
      {
        ua::detail::invoke_user_callback(self.mLogger, done, ua::VoidResult{});
        return;
      }

      self.mRunning = false;

      // Cancel all pending cadence/backoff timers; in-flight register cycles will see the
      // Step guard fail and become no-ops.
      for (const auto& target : self.mTargets)
      {
        target->timer.cancel();
        target->step = RegistrationState::Idle;
      }

      self.begin_shutdown_deregister(std::move(done));
    })();
}

void DiscoveryRegistration::status_async(std::function<void(std::vector<Status>)> completionHandler) noexcept
{
  // The completion overload owns `done` and fires it exactly once. The live handler builds and
  // delivers a per-target snapshot; on the driver-gone (or post-failed) path the helper delivers the
  // empty-snapshot goneResult - the failure mode mirrors a dead driver: no targets to report.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::vector<Status>{},
    [](DiscoveryRegistration& self, std::function<void(std::vector<Status>)> done) mutable
    {
      std::vector<Status> snapshot;
      snapshot.reserve(self.mTargets.size());
      for (const auto& target : self.mTargets)
      {
        Status status;
        status.discoveryUrl = target->target.discoveryUrl;
        status.state = target->step;
        status.lastSuccess = target->lastSuccess;
        status.nextAttempt = target->nextAttempt;
        status.fallbackActive = target->fallbackActive;
        status.lastError = target->lastError;
        snapshot.push_back(std::move(status));
      }
      ua::detail::invoke_user_callback(done, std::move(snapshot));
    })();
}

void DiscoveryRegistration::set_observer(std::shared_ptr<DiscoveryRegistrationObserver> observer) noexcept
{
  try
  {
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [observer = std::move(observer)](DiscoveryRegistration& self) mutable
      { self.mObserver = std::move(observer); })();
  }
  catch (...)
  {
    // Closure construction or post() failed (e.g. bad_alloc). There is no callback to report
    // through (set_observer has no completion channel), so the only safe action that keeps the
    // function noexcept is to log the failure rather than let it escape. The prior observer (if
    // any) remains in effect.
    const auto status = ua::exception_to_status_code(std::current_exception());
    mLogger.warning("Failed to post discovery-registration observer update: {}",
      status.shared_detail() ? status.shared_detail()->summary
                             : std::string{"app.discovery.registration.set_observer_post_failed"});
  }
}

// ---------------------------------------------------------------------------
// Per-target cycle (strand-serialized)
// ---------------------------------------------------------------------------

void DiscoveryRegistration::begin_cycle(std::size_t index)
{
  // Entry guard: only run a cycle while running and when this target is idle (no overlap).
  if (!mRunning || index >= mTargets.size())
    return;

  auto& target = *mTargets[index];
  if (target.inFlight)
    return;

  target.step = RegistrationState::Opening;
  target.inFlight = true;
  target.fallbackActive = false;

  ua::RegisteredServer server = mServerIdentity;
  server.is_online() = true;

  const bool preferFallback = target.fallbackMemo;

  mLogger.info({{"discovery_url", target.target.discoveryUrl}, {"prefer_fallback", preferFallback}},
    "Discovery registration attempt");

  // The registrar's completion may fire on any thread; post_borrowing re-enters the strand and
  // re-checks lifetime before invoking on_cycle_complete (a stale cycle no-ops on the strand turn).
  mRegistrar->register_async(target.target,
    std::move(server),
    /*discoveryConfiguration=*/{},
    preferFallback,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [index](DiscoveryRegistration& self, ua::Result<LdsRegistrar::RegisterOutcome> result) mutable
      { self.on_cycle_complete(index, std::move(result)); }));
}

void DiscoveryRegistration::on_cycle_complete(
  std::size_t index, ua::Result<LdsRegistrar::RegisterOutcome> result)
{
  if (index >= mTargets.size())
    return;
  auto& target = *mTargets[index];

  target.inFlight = false;

  // Entry guard: if stop_async cancelled this target (step reset to Idle) while the cycle was
  // outstanding, drop the result - do not re-arm.
  if (!mRunning || target.step != RegistrationState::Opening)
    return;

  target.step = RegistrationState::Closing;

  // The driver acts on the outcome, so only a Good one counts as registered: an Uncertain outcome, with
  // or without a RegisterOutcome, is a failed cycle, refused as outcome_failure says, and is retried.
  if (!result.is_good())
  {
    handle_cycle_failure(index, outcome_failure(result.status_code()));
    return;
  }

  const bool usedFallback = result.value().usedFallback;
  handle_cycle_success(index, usedFallback);
}

void DiscoveryRegistration::handle_cycle_success(std::size_t index, bool usedFallback)
{
  auto& target = *mTargets[index];

  const auto now = std::chrono::steady_clock::now();
  target.lastSuccess = now;
  target.lastError = ua::StatusCode{};
  target.currentBackoff = mConfig.backoffInitial;  // reset backoff on success
  target.fallbackActive = usedFallback;
  // Memoise fallback need; clear it when a fresh (non-fallback) cycle succeeds.
  target.fallbackMemo = usedFallback;

  // Edge-triggered notifications: established once, fallback edge once.
  const bool wasEstablished = (target.lastNotifiedState == RegistrationState::Registering) ||
                              (target.lastNotifiedState == RegistrationState::FallbackRegistering);

  const RegistrationState successState =
    usedFallback ? RegistrationState::FallbackRegistering : RegistrationState::Registering;

  mLogger.info({{"discovery_url", target.target.discoveryUrl}, {"used_fallback", usedFallback}},
    "Discovery registration succeeded");

  if (usedFallback && target.lastNotifiedState != RegistrationState::FallbackRegistering)
    notify_fallback(index);

  if (!wasEstablished || target.lastNotifiedState != successState)
    notify_established(index, usedFallback);

  target.lastNotifiedState = successState;

  // Part 4 requires recurring LDS registration at least once every 10 minutes. A longer
  // configured cadence would allow a live server to disappear from discovery.
  schedule_next(index, std::min(mConfig.cadence, std::chrono::seconds{600}));
}

void DiscoveryRegistration::handle_cycle_failure(std::size_t index, ua::StatusCode status)
{
  auto& target = *mTargets[index];

  target.lastError = status;

  const auto delay = target.currentBackoff;
  // Double for next time, capped.
  target.currentBackoff =
    std::min(std::chrono::seconds{target.currentBackoff.count() * 2}, mConfig.backoffCap);

  const auto nextAttempt = std::chrono::steady_clock::now() + delay;
  target.nextAttempt = nextAttempt;

  mLogger.warning({{"discovery_url", target.target.discoveryUrl},
                    {"status", static_cast<int64_t>(status.value())},
                    {"backoff_seconds", static_cast<int64_t>(delay.count())}},
    "Discovery registration failed: {}",
    status.shared_detail() ? status.shared_detail()->summary : std::string{});

  // Every failed attempt is a distinct event carrying its own (growing) nextAttempt, so notify on
  // each failure - the host needs to track ongoing failures and when the next retry is due. (The
  // "edge-triggered, not a 60s heartbeat" rule is about SUCCESS: on_registration_established fires
  // once on the success transition, not on every steady cadence cycle.)
  notify_failed(index, status, nextAttempt);

  target.lastNotifiedState = RegistrationState::BackingOff;

  schedule_next(index, delay);
}

void DiscoveryRegistration::schedule_next(std::size_t index, std::chrono::seconds delay)
{
  auto& target = *mTargets[index];

  if (!mRunning)
  {
    target.step = RegistrationState::Idle;
    return;
  }

  target.step = RegistrationState::BackingOff;
  target.nextAttempt = std::chrono::steady_clock::now() + delay;

  auto weak = weak_from_this();
  target.timer = ua::Timer::schedule_after(mStrand,
    delay,
    [weak, index](boost::system::error_code ec)
    {
      if (ec)
        return;  // cancelled
      auto self = weak.lock();
      if (!self)
        return;
      // Already on the strand (timer bound to mStrand). Entry guard: still running + backing off.
      if (index >= self->mTargets.size())
        return;
      auto& scheduledTarget = *self->mTargets[index];
      if (!self->mRunning || scheduledTarget.step != RegistrationState::BackingOff)
        return;
      scheduledTarget.step = RegistrationState::Idle;
      self->begin_cycle(index);
    });
}

// ---------------------------------------------------------------------------
// Bounded shutdown deregister (isOnline=false), then complete
// ---------------------------------------------------------------------------

void DiscoveryRegistration::begin_shutdown_deregister(std::function<void(ua::VoidResult)> done)
{
  if (mTargets.empty())
  {
    if (done)
      done(ua::VoidResult{});
    return;
  }

  // Shared completion: fire once when all deregisters report OR the deadline fires.
  auto remaining = std::make_shared<std::size_t>(mTargets.size());
  auto finalDone = std::make_shared<std::function<void(ua::VoidResult)>>(std::move(done));
  auto fired = std::make_shared<bool>(false);

  auto complete = [weak = weak_from_this(), finalDone, fired]()
  {
    // Must run on the strand.
    if (*fired)
      return;
    *fired = true;
    if (*finalDone)
      (*finalDone)(ua::VoidResult{});
  };

  // Bounded deadline timer: do NOT hang if the LDS is unreachable.
  mShutdownTimer = ua::Timer::schedule_after(mStrand,
    mConfig.shutdownDeregisterTimeout,
    [weak = weak_from_this(), complete](boost::system::error_code ec)
    {
      if (ec)
        return;
      auto self = weak.lock();
      if (!self)
        return;
      complete();  // on strand
    });

  for (std::size_t index = 0; index < mTargets.size(); ++index)
  {
    auto& target = *mTargets[index];
    ua::RegisteredServer server = mServerIdentity;
    server.is_online() = false;

    const bool preferFallback = target.fallbackMemo;

    mLogger.info({{"discovery_url", target.target.discoveryUrl}}, "Discovery deregister (isOnline=false)");

    // Re-enter the strand on the registrar's completion (any thread). post_borrowing drops the work
    // if the driver is gone - intentionally: a gone driver means the stop completion is moot, unlike
    // stop_async's entry which delivers a goneResult to a still-present caller.
    mRegistrar->register_async(target.target,
      std::move(server),
      /*discoveryConfiguration=*/{},
      preferFallback,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [index, remaining, complete](
          DiscoveryRegistration& self, ua::Result<LdsRegistrar::RegisterOutcome> result) mutable
        {
          if (index < self.mTargets.size())
          {
            auto& deregisterTarget = *self.mTargets[index];
            // Only a Good outcome is a deregistration: an Uncertain one is a failed deregister, refused as
            // outcome_failure says.
            if (!result.is_good())
            {
              const ua::StatusCode failure = outcome_failure(result.status_code());
              deregisterTarget.lastError = failure;
              self.mLogger.warning({{"discovery_url", deregisterTarget.target.discoveryUrl},
                                     {"status", static_cast<int64_t>(failure.value())}},
                "Discovery shutdown deregister failed: {}",
                failure.shared_detail() ? failure.shared_detail()->summary
                                        : std::string{"app.discovery.registration."
                                                      "shutdown_deregister_failed"});
            }
            else
            {
              self.notify_deregistered(index);
            }
          }
          if (*remaining > 0)
          {
            --(*remaining);
            if (*remaining == 0)
            {
              self.mShutdownTimer.cancel();
              complete();
            }
          }
        }));
  }
}

// ---------------------------------------------------------------------------
// Observer notifications - posted OFF the strand with weak capture, edge-triggered
// ---------------------------------------------------------------------------

void DiscoveryRegistration::notify_established(std::size_t index, bool usedFallback)
{
  auto observer = mObserver;
  if (!observer)
    return;
  DiscoveryRegistrationInfo info{mTargets[index]->target.discoveryUrl, usedFallback};
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger,
      [observer, info = std::move(info)]() mutable { observer->on_registration_established(info); }));
}

void DiscoveryRegistration::notify_fallback(std::size_t index)
{
  auto observer = mObserver;
  if (!observer)
    return;
  DiscoveryRegistrationInfo info{mTargets[index]->target.discoveryUrl, true};
  boost::asio::post(mExecutor,
    ua::async::guarded(
      mLogger, [observer, info = std::move(info)]() mutable { observer->on_registration_fallback(info); }));
}

void DiscoveryRegistration::notify_failed(
  std::size_t index, ua::StatusCode status, std::chrono::steady_clock::time_point nextAttempt)
{
  auto observer = mObserver;
  if (!observer)
    return;
  DiscoveryRegistrationInfo info{mTargets[index]->target.discoveryUrl, mTargets[index]->fallbackActive};
  auto detail = status.shared_detail();
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger,
      [observer, info = std::move(info), status, detail = std::move(detail), nextAttempt]() mutable
      { observer->on_registration_failed(info, status, std::move(detail), nextAttempt); }));
}

void DiscoveryRegistration::notify_deregistered(std::size_t index)
{
  auto observer = mObserver;
  if (!observer)
    return;
  DiscoveryRegistrationInfo info{mTargets[index]->target.discoveryUrl, mTargets[index]->fallbackActive};
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger,
      [observer, info = std::move(info)]() mutable { observer->on_registration_deregistered(info); }));
}

}  // namespace ua::app
