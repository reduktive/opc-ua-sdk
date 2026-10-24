// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Socket-free unit tests for ua::app::DiscoveryRegistration - the strand-serialized driver
// that keeps a server registered with one or more discovery servers (LDS).
//
// What is exercised (all through the real driver code path):
//   1. Steady cadence  - success re-arms the next cycle after ~cadence; steady cycles send
//                         is_online == true.
//   2. Backoff curve   - consecutive failures grow the delay (initial, x2, x4 ... capped) and a
//                         success resets the next delay back to cadence.
//   3. RS2 -> RS fallback - a success outcome carrying usedFallback=true memoises fallback
//                         (subsequent cycles send preferFallback=true) and fires the fallback
//                         observer edge exactly once.
//   4. Bounded shutdown - stop_async sends exactly one final register_async with
//                         is_online()==false per target and completes the done-callback within
//                         shutdownDeregisterTimeout EVEN IF the registrar never responds.
//   5. Observer edges  - established fires once on first success (not on repeats); failed carries
//                         the StatusCode + ErrorDetail + a nextAttempt; deregistered fires on
//                         shutdown.
//   6. status_async()  - reflects state / lastSuccess / nextAttempt / fallbackActive / lastError.
//   7. Independent targets - one target backing off does not stall another target's cadence.
//
// Time control: the driver uses real wall-clock ua::Timer on the executor and its config is in
// whole seconds. There is no manual-clock infra for Timer-driven strand components (the sibling
// RegisteredServerStore unit tests drive the real timer too), so this suite uses the smallest
// real config durations (cadence / backoff = 1s) and asserts ORDERING, COUNTS and the SHAPE of
// the recorded calls with generous polling budgets - never wall-clock equality. All .get()/wait
// happen on the main test thread only; the pool is shut down explicitly in TearDown.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include "certificate_validation_request_helpers.h"
#include "ua_discovery_registration.h"
#include "ua_error_detail.h"
#include "ua_lds_registrar.h"
#include "ua_registered_server.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include "test_utilities.h"

using namespace std::chrono_literals;

namespace ua::test::app::discovery
{
namespace
{

using ua::app::DiscoveryRegistration;
using ua::app::DiscoveryRegistrationConfig;
using ua::app::DiscoveryRegistrationInfo;
using ua::app::DiscoveryRegistrationObserver;
using ua::app::DiscoveryTarget;
using ua::app::LdsRegistrar;

// ---------------------------------------------------------------------------
// FakeLdsRegistrar - records every register_async call and lets the test script the outcome.
// ---------------------------------------------------------------------------
class FakeLdsRegistrar : public LdsRegistrar
{
public:
  struct Call
  {
    std::string discoveryUrl;
    bool isOnline{false};
    bool preferFallback{false};
  };

  // How a recorded call should be completed.
  struct ScriptedOutcome
  {
    enum class Kind
    {
      Success,  // good Result, outcome.usedFallback = usedFallback
      Error,  // Result holding no outcome, with `status` (+ ErrorDetail)
      Held,  // Result holding the outcome with `status`: a Good subcode or an Uncertain code
      NeverRespond  // drop the callback (driver must not hang / must time out)
    };
    Kind kind{Kind::Success};
    bool usedFallback{false};
    ua::StatusCode status{};
  };

  // Outcome selection: a per-target default keyed by discoveryUrl, overridable.
  void set_default_outcome(ScriptedOutcome outcome)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mDefault = outcome;
  }

  void set_outcome_for(const std::string& discoveryUrl, ScriptedOutcome outcome)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mPerUrl[discoveryUrl] = outcome;
  }

  // Online-call (is_online==true) records + auto-completes synchronously per the script.
  void register_async(DiscoveryTarget target, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>> /*discoveryConfiguration*/, bool preferFallback,
    RegisterResultCallback callback) noexcept override
  {
    const bool isOnline = server.is_online();
    ScriptedOutcome outcome;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mCalls.push_back(Call{target.discoveryUrl, isOnline, preferFallback});
      auto it = mPerUrl.find(target.discoveryUrl);
      outcome = (it != mPerUrl.end()) ? it->second : mDefault;
    }

    // A deregister (offline) cycle answers the scripted outcome; one told never to respond drops its
    // callback.
    if (outcome.kind == ScriptedOutcome::Kind::NeverRespond)
      return;  // drop callback - simulate an unreachable LDS

    if (outcome.kind == ScriptedOutcome::Kind::Error)
    {
      if (callback)
        callback(ua::Result<RegisterOutcome>{outcome.status});
      return;
    }

    if (outcome.kind == ScriptedOutcome::Kind::Held)
    {
      if (callback)
        callback(ua::Result<RegisterOutcome>{RegisterOutcome{outcome.usedFallback}, outcome.status});
      return;
    }

    if (callback)
      callback(ua::Result<RegisterOutcome>{RegisterOutcome{outcome.usedFallback}});
  }

  std::vector<Call> calls() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCalls;
  }

  // Count of online (is_online==true) calls - i.e. steady/backoff registration cycles.
  std::size_t online_call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    std::size_t count = 0;
    for (const auto& call : mCalls)
      if (call.isOnline)
        ++count;
    return count;
  }

  std::size_t online_call_count_for(const std::string& url) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    std::size_t count = 0;
    for (const auto& call : mCalls)
      if (call.isOnline && call.discoveryUrl == url)
        ++count;
    return count;
  }

  std::size_t offline_call_count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    std::size_t count = 0;
    for (const auto& call : mCalls)
      if (!call.isOnline)
        ++count;
    return count;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Call> mCalls;
  ScriptedOutcome mDefault{};
  std::map<std::string, ScriptedOutcome> mPerUrl;
};

// ---------------------------------------------------------------------------
// RecordingObserver - counts edge notifications and captures the last failure payload.
// ---------------------------------------------------------------------------
class RecordingObserver : public DiscoveryRegistrationObserver
{
public:
  void on_registration_established(const DiscoveryRegistrationInfo& info) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mEstablished;
    mLastEstablishedUrl = info.discoveryUrl;
  }

  void on_registration_failed(const DiscoveryRegistrationInfo& info, ua::StatusCode status,
    std::shared_ptr<const ua::ErrorDetail> detail, std::chrono::steady_clock::time_point nextAttempt) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mFailed;
    mLastFailedUrl = info.discoveryUrl;
    mLastFailedStatus = status;
    mLastFailedDetail = std::move(detail);
    mLastFailedNextAttempt = nextAttempt;
  }

  void on_registration_fallback(const DiscoveryRegistrationInfo& info) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mFallback;
    mLastFallbackUrl = info.discoveryUrl;
  }

  void on_registration_deregistered(const DiscoveryRegistrationInfo& info) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDeregistered;
    mLastDeregisteredUrl = info.discoveryUrl;
  }

  int established() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mEstablished;
  }

  int failed() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mFailed;
  }

  int fallback() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mFallback;
  }

  int deregistered() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mDeregistered;
  }

  ua::StatusCode last_failed_status() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailedStatus;
  }

  std::shared_ptr<const ua::ErrorDetail> last_failed_detail() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailedDetail;
  }

  std::chrono::steady_clock::time_point last_failed_next_attempt() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailedNextAttempt;
  }

  std::string last_established_url() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastEstablishedUrl;
  }

  std::string last_fallback_url() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFallbackUrl;
  }

private:
  mutable std::mutex mMutex;
  int mEstablished{0};
  int mFailed{0};
  int mFallback{0};
  int mDeregistered{0};
  std::string mLastEstablishedUrl;
  std::string mLastFailedUrl;
  std::string mLastFallbackUrl;
  std::string mLastDeregisteredUrl;
  ua::StatusCode mLastFailedStatus{};
  std::shared_ptr<const ua::ErrorDetail> mLastFailedDetail;
  std::chrono::steady_clock::time_point mLastFailedNextAttempt{};
};

ua::RegisteredServer make_server_identity()
{
  ua::RegisteredServer server;
  server.server_uri() = ua::String{"urn:test:registering-server"};
  server.product_uri() = ua::String{"urn:test:product"};
  server.server_type() = ua::ApplicationType::Server;
  server.server_names().payload().push_back(ua::LocalizedText{ua::String{"en"}, ua::String{"Test Server"}});
  server.discovery_urls().payload().push_back(ua::String{"opc.tcp://localhost:4840"});
  return server;
}

DiscoveryTarget make_target(const std::string& url)
{
  DiscoveryTarget target;
  target.discoveryUrl = url;
  return target;
}

class DiscoveryRegistrationTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/2);
    mRegistrar = std::make_shared<FakeLdsRegistrar>();
  }

  void TearDown() override
  {
    if (mDriver)
    {
      // Bounded on-strand stop so cadence/backoff timers are cancelled before the pool joins.
      std::promise<void> done;
      mDriver->stop_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(8s);  // > shutdownDeregisterTimeout to allow the bounded path
      mDriver.reset();
    }
    if (mPool)
      ua::test_utils::drain_with_timeout(*mPool);
  }

  std::shared_ptr<DiscoveryRegistration> make_driver(DiscoveryRegistrationConfig config)
  {
    mDriver =
      DiscoveryRegistration::create(mPool->executor(), mRegistrar, make_server_identity(), std::move(config));
    return mDriver;
  }

  // Default config: 1s cadence/backoff (smallest real granularity), 5s shutdown budget.
  DiscoveryRegistrationConfig default_config(std::vector<std::string> urls)
  {
    DiscoveryRegistrationConfig config;
    for (const auto& url : urls)
      config.targets.push_back(make_target(url));
    config.cadence = 1s;
    config.backoffInitial = 1s;
    config.backoffCap = 4s;
    config.shutdownDeregisterTimeout = 3s;
    return config;
  }

  void start_sync()
  {
    std::promise<void> started;
    mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
    ASSERT_EQ(started.get_future().wait_for(2s), std::future_status::ready);
  }

  std::vector<DiscoveryRegistration::Status> status_sync()
  {
    std::promise<std::vector<DiscoveryRegistration::Status>> p;
    auto fut = p.get_future();
    mDriver->status_async([&p](std::vector<DiscoveryRegistration::Status> s) { p.set_value(std::move(s)); });
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready);
    return fut.get();
  }

  // Poll a predicate on the MAIN test thread until satisfied or deadline. Returns success.
  template<typename Pred>
  bool poll_until(Pred pred, std::chrono::milliseconds budget)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (pred())
        return true;
      std::this_thread::sleep_for(25ms);
    }
    return pred();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeLdsRegistrar> mRegistrar;
  std::shared_ptr<DiscoveryRegistration> mDriver;
};

// ---------------------------------------------------------------------------
// 1. Steady cadence
// ---------------------------------------------------------------------------

// A successful cycle re-arms the next cycle after ~cadence, so repeated success drives repeated
// online registrations. Each steady cycle sends is_online == true.
// Covers SVR-DISC-RS-007 (coverage-audit retag).
// @verifies AC-SVR-DISC-RS-007-PERIODIC-REREGISTRATION
TEST_F(DiscoveryRegistrationTest, SuccessRearmsAtCadenceWithOnlineRegistrations)
{
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  start_sync();

  // With 1s cadence, at least 3 online cycles must occur within ~4s.
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 3; }, 5000ms))
    << "expected repeated cadence cycles; got " << mRegistrar->online_call_count();

  // Every recorded cadence cycle sent is_online == true (driver flips it per cycle).
  for (const auto& call : mRegistrar->calls())
    EXPECT_TRUE(call.isOnline) << "steady cadence cycle must register with is_online=true";
}

// ---------------------------------------------------------------------------
// 2. Backoff curve
// ---------------------------------------------------------------------------

// Consecutive failures grow the inter-cycle delay (initial, x2, x4 ... capped). With cadence 1s,
// after N failures the next-attempt gap must exceed cadence - i.e. the cycle count grows SLOWER
// than the steady-success case over the same window.
// Covers SVR-DISC-RS-011 (coverage-audit retag).
TEST_F(DiscoveryRegistrationTest, ConsecutiveFailuresBackOffSlowerThanCadence)
{
  mRegistrar->set_default_outcome(
    {FakeLdsRegistrar::ScriptedOutcome::Kind::Error, false, ua::StatusCode{ua::Status::BadConnectionClosed}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  start_sync();

  // backoff: 1s, 2s, 4s(cap), 4s ... In a 6s window a steady (1s cadence) run would fire ~6 cycles;
  // a backing-off run fires at t=0,1,3,7 -> roughly 3 cycles. Assert it stays well below steady.
  std::this_thread::sleep_for(5500ms);
  const auto cycles = mRegistrar->online_call_count();
  EXPECT_GE(cycles, 3u) << "expected at least the first few backoff cycles";
  EXPECT_LE(cycles, 5u) << "backoff must space cycles wider than the 1s cadence; got " << cycles;
}

// A success after failures resets the backoff: the very next inter-cycle delay returns to cadence.
// Proven by switching the script to Success mid-flight and observing the cadence speed up.
TEST_F(DiscoveryRegistrationTest, SuccessResetsBackoffToCadence)
{
  mRegistrar->set_default_outcome(
    {FakeLdsRegistrar::ScriptedOutcome::Kind::Error, false, ua::StatusCode{ua::Status::BadConnectionClosed}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  start_sync();

  // Let backoff grow to the cap (a couple of cycles).
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 2; }, 4000ms));

  // Now make cycles succeed: backoff resets, so cadence returns to 1s and cycles accelerate.
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  const auto baseline = mRegistrar->online_call_count();

  // Within ~3.5s of 1s cadence we expect at least 3 more cycles (would be ~1 under the 4s cap).
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= baseline + 3; }, 4500ms))
    << "success must reset backoff to cadence; cycles since reset: "
    << (mRegistrar->online_call_count() - baseline);
}

// ---------------------------------------------------------------------------
// 3. RS2 -> RS fallback
// ---------------------------------------------------------------------------

// A success outcome carrying usedFallback=true memoises fallback so subsequent cycles send
// preferFallback=true, and the fallback observer edge fires exactly once.
TEST_F(DiscoveryRegistrationTest, FallbackOutcomeMemoisesPreferFallbackAndFiresEdgeOnce)
{
  const std::string url = "opc.tcp://lds:4840";
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success, /*usedFallback=*/true});
  make_driver(default_config({url}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  // Wait for several fallback cycles.
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count_for(url) >= 3; }, 5000ms));

  const auto calls = mRegistrar->calls();
  // First cycle re-probes RS2 (preferFallback=false); after the usedFallback success is memoised,
  // every subsequent cycle must request preferFallback=true.
  ASSERT_GE(calls.size(), 3u);
  EXPECT_FALSE(calls.front().preferFallback) << "first cycle must re-probe RS2 (preferFallback=false)";
  EXPECT_TRUE(calls.back().preferFallback) << "after a fallback success, later cycles prefer fallback";

  // Fallback observer edge is triggered exactly once despite repeated fallback cycles.
  EXPECT_EQ(observer->fallback(), 1);
  EXPECT_EQ(observer->last_fallback_url(), url);
}

// ---------------------------------------------------------------------------
// 4. Bounded shutdown
// ---------------------------------------------------------------------------

// stop_async sends exactly one final register_async with is_online()==false per target.
// Covers SVR-DISC-RS-009 (coverage-audit retag).
// @verifies AC-SVR-DISC-RS-009-OFFLINE-REGISTRATION
TEST_F(DiscoveryRegistrationTest, StopSendsExactlyOneOfflineDeregisterPerTarget)
{
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  std::promise<void> stopped;
  auto fut = stopped.get_future();
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(fut.wait_for(5s), std::future_status::ready) << "stop_async must complete";

  EXPECT_EQ(mRegistrar->offline_call_count(), 1u) << "exactly one offline (deregister) per target";
  mDriver.reset();  // already stopped; avoid a second stop in TearDown
}

// stop_async completes its done-callback within shutdownDeregisterTimeout EVEN IF the registrar
// never responds to the final deregister - the bounded deadline must fire and not hang.
TEST_F(DiscoveryRegistrationTest, StopCompletesWithinTimeoutWhenRegistrarNeverResponds)
{
  // Online cycles succeed; the offline deregister at stop will be dropped (NeverRespond).
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  auto config = default_config({"opc.tcp://lds:4840"});
  config.shutdownDeregisterTimeout = 2s;
  make_driver(std::move(config));
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  // From now on (including the shutdown deregister) the registrar never replies.
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::NeverRespond});

  std::promise<void> stopped;
  auto fut = stopped.get_future();
  const auto before = std::chrono::steady_clock::now();
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });

  // Hard deadline: the bounded path (2s) plus slack must complete; if it hangs, the test fails.
  ASSERT_EQ(fut.wait_for(4s), std::future_status::ready)
    << "stop_async MUST NOT hang when the registrar never responds";
  const auto elapsed = std::chrono::steady_clock::now() - before;
  EXPECT_GE(elapsed, 1500ms) << "should wait roughly the bounded timeout, not return instantly";

  mDriver.reset();  // already stopped
}

// ---------------------------------------------------------------------------
// 5. Observer edge-triggering
// ---------------------------------------------------------------------------

// established fires once on first success and NOT again on repeated successes (edge, not level).
TEST_F(DiscoveryRegistrationTest, EstablishedFiresOnceAcrossRepeatedSuccesses)
{
  const std::string url = "opc.tcp://lds:4840";
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({url}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  // Drive several successful cadence cycles.
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 4; }, 6000ms));
  // Allow any pending off-strand observer posts to drain.
  ASSERT_TRUE(poll_until([&] { return observer->established() >= 1; }, 1000ms));

  EXPECT_EQ(observer->established(), 1) << "established is an edge - must not refire on the heartbeat";
  EXPECT_EQ(observer->last_established_url(), url);
}

// failed fires on the failure edge and carries the StatusCode, the ErrorDetail, and a future
// nextAttempt time.
TEST_F(DiscoveryRegistrationTest, FailedCarriesStatusDetailAndNextAttempt)
{
  std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("app.discovery.registration.connect_failed", "LDS unreachable", "FakeLdsRegistrar");
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Error,
    false,
    ua::StatusCode{ua::Status::BadConnectionRejected, std::move(detail)}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);

  const auto beforeStart = std::chrono::steady_clock::now();
  start_sync();

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 4000ms))
    << "failure must raise the failed observer edge";

  EXPECT_EQ(
    observer->last_failed_status().value(), ua::StatusCode{ua::Status::BadConnectionRejected}.value());
  ASSERT_NE(observer->last_failed_detail(), nullptr) << "failed must carry the ErrorDetail";
  EXPECT_EQ(observer->last_failed_detail()->code, "app.discovery.registration.connect_failed");
  EXPECT_GT(observer->last_failed_next_attempt(), beforeStart) << "nextAttempt must be in the future";
}

// Each failed ATTEMPT raises the failed edge - not just the first transition into backoff. Every
// failure carries its own (growing) nextAttempt, so a host can track ongoing retries. Regression
// guard for the per-attempt fix: a revert to once-per-backoff-entry would leave failed() stuck at 1.
TEST_F(DiscoveryRegistrationTest, FailedFiresPerAttemptNotOncePerBackoff)
{
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Error,
    false,
    ua::StatusCode{ua::Status::BadConnectionRejected}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  // cadence/backoff = 1s, doubling and capped - three consecutive failures land within a few seconds.
  EXPECT_TRUE(poll_until([&] { return observer->failed() >= 3; }, 8000ms))
    << "every failed attempt must raise the failed edge, not just the first transition into backoff";
  EXPECT_EQ(observer->established(), 0) << "with no success, established must never fire";
}

// Checks that @p status and @p detail report a registrar outcome given as Uncertain_LastUsableValue: refused
// as Bad_InternalError whose ErrorDetail (RegistrationAnswerUncertain) has the Uncertain code as its inner
// status.
void expect_uncertain_outcome_refusal(
  const ua::StatusCode& status, const std::shared_ptr<const ua::ErrorDetail>& detail)
{
  EXPECT_EQ(status.as_status(), ua::Status::BadInternalError)
    << "the failure must be Bad: an Uncertain code means a partial success";
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "RegistrationAnswerUncertain");
  EXPECT_EQ(detail->innerStatus, ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
}

// The driver acts on a registrar's outcome, so only a Good one is a registration. An Uncertain outcome
// holding no RegisterOutcome is a failed cycle: failed carries Bad_InternalError
// (RegistrationAnswerUncertain, whose inner status is the Uncertain code), lastError holds the same, and
// established never fires.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(DiscoveryRegistrationTest, AnUncertainOutcomeWithoutARegisterOutcomeIsAFailedCycle)
{
  const ua::StatusCode uncertain{ua::Status::UncertainLastUsableValue};
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Error, false, uncertain});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 4000ms))
    << "an Uncertain outcome must raise the failed edge";
  expect_uncertain_outcome_refusal(observer->last_failed_status(), observer->last_failed_detail());
  EXPECT_EQ(observer->established(), 0) << "an Uncertain outcome is not a registration";
  const auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  expect_uncertain_outcome_refusal(status[0].lastError, status[0].lastError.shared_detail());
}

// An Uncertain outcome that holds a RegisterOutcome is refused like one that holds none.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(DiscoveryRegistrationTest, AnUncertainOutcomeHoldingARegisterOutcomeIsAFailedCycle)
{
  const ua::StatusCode uncertain{ua::Status::UncertainLastUsableValue};
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Held, false, uncertain});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 4000ms))
    << "an Uncertain outcome must raise the failed edge even when it holds a RegisterOutcome";
  expect_uncertain_outcome_refusal(observer->last_failed_status(), observer->last_failed_detail());
  EXPECT_EQ(observer->established(), 0) << "an Uncertain outcome is not a registration";
}

// The control for the two tests above: an outcome held with a Good subcode is Good, so it is a
// registration.
TEST_F(DiscoveryRegistrationTest, AGoodSubcodeOutcomeIsARegistration)
{
  mRegistrar->set_default_outcome(
    {FakeLdsRegistrar::ScriptedOutcome::Kind::Held, false, ua::StatusCode{ua::Status::GoodClamped}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();

  ASSERT_TRUE(poll_until([&] { return observer->established() >= 1; }, 4000ms))
    << "an outcome held with a Good subcode must establish the registration";
  EXPECT_EQ(observer->failed(), 0);
}

// deregistered fires on shutdown when the offline deregister succeeds.
TEST_F(DiscoveryRegistrationTest, DeregisteredFiresOnShutdown)
{
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  std::promise<void> stopped;
  auto fut = stopped.get_future();
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);

  ASSERT_TRUE(poll_until([&] { return observer->deregistered() >= 1; }, 1000ms));
  EXPECT_EQ(observer->deregistered(), 1);
  mDriver.reset();
}

// A shutdown deregister answered Uncertain is not a deregistration: deregistered does not fire, and lastError
// holds the refusal (Bad_InternalError, RegistrationAnswerUncertain), not the Uncertain code. The control is
// DeregisteredFiresOnShutdown above.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(DiscoveryRegistrationTest, AnUncertainShutdownDeregisterIsNotADeregistration)
{
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  auto observer = std::make_shared<RecordingObserver>();
  mDriver->set_observer(observer);
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  // From now on (the shutdown deregister) the registrar answers Uncertain, holding a RegisterOutcome.
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Held,
    false,
    ua::StatusCode{ua::Status::UncertainLastUsableValue}});

  std::promise<void> stopped;
  auto fut = stopped.get_future();
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);
  EXPECT_GE(mRegistrar->offline_call_count(), 1u) << "the shutdown deregister was sent";

  EXPECT_FALSE(poll_until([&] { return observer->deregistered() >= 1; }, 500ms))
    << "an Uncertain deregister must not raise the deregistered edge";
  const auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  expect_uncertain_outcome_refusal(status[0].lastError, status[0].lastError.shared_detail());
  mDriver.reset();
}

// ---------------------------------------------------------------------------
// 6. status_async()
// ---------------------------------------------------------------------------

// After a successful cycle, status reflects lastSuccess set, fallbackActive false, lastError good.
TEST_F(DiscoveryRegistrationTest, StatusReflectsSuccessState)
{
  const std::string url = "opc.tcp://lds:4840";
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  make_driver(default_config({url}));
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  ASSERT_TRUE(poll_until(
    [&]
    {
      auto s = status_sync();
      return s.size() == 1 && s[0].lastSuccess.has_value();
    },
    3000ms));

  auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  EXPECT_EQ(status[0].discoveryUrl, url);
  EXPECT_TRUE(status[0].lastSuccess.has_value()) << "status must record lastSuccess after a good cycle";
  EXPECT_FALSE(status[0].fallbackActive) << "non-fallback success must report fallbackActive=false";
  EXPECT_TRUE(status[0].lastError.is_good());
  EXPECT_TRUE(status[0].nextAttempt.has_value()) << "a re-armed cadence sets nextAttempt";
}

// After a failure, status reflects lastError, a nextAttempt, and no lastSuccess.
TEST_F(DiscoveryRegistrationTest, StatusReflectsFailureState)
{
  mRegistrar->set_default_outcome(
    {FakeLdsRegistrar::ScriptedOutcome::Kind::Error, false, ua::StatusCode{ua::Status::BadConnectionClosed}});
  make_driver(default_config({"opc.tcp://lds:4840"}));
  start_sync();

  ASSERT_TRUE(poll_until(
    [&]
    {
      auto s = status_sync();
      return s.size() == 1 && s[0].lastError.is_bad();
    },
    4000ms));

  auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  EXPECT_EQ(status[0].lastError.value(), ua::StatusCode{ua::Status::BadConnectionClosed}.value());
  EXPECT_TRUE(status[0].nextAttempt.has_value()) << "a backing-off target must report nextAttempt";
  EXPECT_FALSE(status[0].lastSuccess.has_value()) << "never-succeeded target must not report lastSuccess";
}

// After a fallback success, status reports fallbackActive=true.
TEST_F(DiscoveryRegistrationTest, StatusReflectsFallbackActive)
{
  const std::string url = "opc.tcp://lds:4840";
  mRegistrar->set_default_outcome({FakeLdsRegistrar::ScriptedOutcome::Kind::Success, /*usedFallback=*/true});
  make_driver(default_config({url}));
  start_sync();
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count() >= 1; }, 3000ms));

  ASSERT_TRUE(poll_until(
    [&]
    {
      auto s = status_sync();
      return s.size() == 1 && s[0].fallbackActive;
    },
    3000ms))
    << "fallback success must surface fallbackActive=true in status";
}

// ---------------------------------------------------------------------------
// 7. Independent targets
// ---------------------------------------------------------------------------

// One target failing/backing-off must not stall another target's cadence.
TEST_F(DiscoveryRegistrationTest, TargetsAdvanceIndependently)
{
  const std::string goodUrl = "opc.tcp://good-lds:4840";
  const std::string badUrl = "opc.tcp://bad-lds:4840";
  mRegistrar->set_outcome_for(goodUrl, {FakeLdsRegistrar::ScriptedOutcome::Kind::Success});
  mRegistrar->set_outcome_for(badUrl,
    {FakeLdsRegistrar::ScriptedOutcome::Kind::Error, false, ua::StatusCode{ua::Status::BadConnectionClosed}});
  make_driver(default_config({goodUrl, badUrl}));
  start_sync();

  // The healthy target keeps a fast 1s cadence regardless of the other target backing off.
  ASSERT_TRUE(poll_until([&] { return mRegistrar->online_call_count_for(goodUrl) >= 4; }, 6000ms))
    << "the good target must keep cadence; got " << mRegistrar->online_call_count_for(goodUrl);

  // The bad target also kept retrying (it is not stuck), but slower due to backoff.
  EXPECT_GE(mRegistrar->online_call_count_for(badUrl), 2u)
    << "the failing target must keep retrying independently";
  EXPECT_LT(mRegistrar->online_call_count_for(badUrl), mRegistrar->online_call_count_for(goodUrl))
    << "the backing-off target must lag the steady-cadence target";
}

}  // namespace
}  // namespace ua::test::app::discovery

#include "fake_certificate_store.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_transport_address.h"
#include "test_components.h"
#include "ua_application_configuration.h"
#include "ua_certificate_store_files.h"
#include "test_pki_helpers.h"
#include "ua_owner_only_directory.h"
#include "ua_server_with_discovery.h"
#include "ua_registration_endpoint_choice.h"
#include "ua_utilities.h"
#include "ua_server_with_discovery_test_access.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <filesystem>
#include <fstream>
#include <optional>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ua::test::app::discovery
{

// The LDS registration client's trust store lives in a per-user, owner-only directory: created 0700
// when absent, and the same directory on a second call.
// @verifies AC-SVR-SECADMIN-072-THE-LDS-CLIENT-TRUST-STORE-IS-PRIVATE-TO-THE-USER
TEST(PrivateUserDirectory, IsCreatedOwnerOnlyAndReused)
{
  const std::string name =
    "uasdk-private-dir-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const auto directory = ua::security::private_user_directory(name, "ServerWithDiscovery");
  ASSERT_TRUE(std::filesystem::is_directory(directory));
#ifndef _WIN32
  EXPECT_TRUE(directory.filename().string().ends_with("-" + std::to_string(::geteuid())));

  struct stat info
  {};

  ASSERT_EQ(::lstat(directory.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 077, 0u) << "owner-only from creation";
#endif
  EXPECT_EQ(ua::security::private_user_directory(name, "ServerWithDiscovery"), directory);
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);
}

#ifndef _WIN32
// A directory another local user pre-created accessible to others (the planting scenario) is refused,
// not adopted; so is a link planted at the path.
// @verifies AC-SVR-SECADMIN-072-THE-LDS-CLIENT-TRUST-STORE-IS-PRIVATE-TO-THE-USER
TEST(PrivateUserDirectory, AnAccessibleOrLinkedPathIsRefused)
{
  const std::string name = "uasdk-private-dir-refused-" + std::to_string(::getpid());
  const auto expected = std::filesystem::temp_directory_path() / (name + "-" + std::to_string(::geteuid()));
  std::error_code ignored;
  std::filesystem::remove_all(expected, ignored);
  ASSERT_EQ(::mkdir(expected.c_str(), 0755), 0);
  ASSERT_EQ(::chmod(expected.c_str(), 0755), 0);  // whatever the process umask
  try
  {
    ua::security::private_user_directory(name, "ServerWithDiscovery");
    FAIL() << "a directory accessible to others must be refused";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "PrivateDirectoryRejected");
  }
  std::filesystem::remove_all(expected, ignored);

  const auto elsewhere = std::filesystem::temp_directory_path() / (name + "-elsewhere");
  std::filesystem::create_directories(elsewhere);
  std::filesystem::create_directory_symlink(elsewhere, expected);
  try
  {
    ua::security::private_user_directory(name, "ServerWithDiscovery");
    FAIL() << "a planted link must be refused";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "PrivateDirectoryRejected");
  }
  std::filesystem::remove(expected, ignored);
  std::filesystem::remove_all(elsewhere, ignored);
}
#endif

namespace
{

/// Seeds the server's application-group store with a CA, a certificate it issued to an LDS, and a CRL
/// of that CA - revoking the LDS certificate when @p revokeLds - then runs the wrapper's trust seeding
/// and validates the LDS certificate through the registration client's store with the options that
/// store was created with: the server configuration's application-group validation options, which are
/// @p configured when given and the defaults (CheckRevocationStatusOffline) otherwise.
///
/// Each wrapper's registration store is a new directory of its own, removed with the wrapper, so the
/// test leaves nothing behind and parallel runs cannot see each other's certificates.
ua::StatusCode validate_lds_certificate_through_registration_store(
  bool revokeLds, std::optional<ua::TrustListValidationOptions> configured = std::nullopt)
{
  boost::asio::thread_pool pool{2};
  auto executor = pool.get_executor();
  const auto crypto = ua::test_helpers::test_crypto();
  const auto serverStoreRoot = ua::test_utils::unique_temp_path("lds_revocation_server_store");
  std::error_code ignored;
  std::filesystem::remove_all(serverStoreRoot, ignored);
  auto serverStore = ua::CertificateStoreFiles::create(
    executor, crypto, {.trustListPath = serverStoreRoot, .storeRejectedCertificates = false});

  ua::TestPki pki{crypto};
  const std::string unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const auto caKeys = crypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  const auto ca = pki.create_root_ca(caKeys, "LDS CA " + unique, unique);
  const auto ldsKeys = crypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  const auto lds = pki.create_leaf_cert(ldsKeys,
    caKeys,
    ca,
    ua::DateTime::now(),
    ua::DateTime{ua::DateTime::now().value() + std::chrono::days{10}},
    {},
    {},
    "LDS " + unique);
  std::vector<std::string> revoked;
  if (revokeLds)
  {
    revoked.push_back(lds->serial_number());
  }
  serverStore->add_to_trusted_certificates_sync(ca);
  serverStore->add_to_trusted_crls_sync(pki.create_crl(ca, caKeys, std::move(revoked)));

  ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::ApplicationConfig::load_default(),
    .server = ua::server::ServerConfig{}};
  config.application.application_description_part().applicationUri = "urn:test:lds-client-revocation";
  if (configured)
  {
    config.application.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions =
      *configured;
  }
  auto created = ua::app::ServerWithDiscovery::try_create(executor,
    std::move(config),
    {.crypto = crypto, .applicationGroupCertificateStore = serverStore},
    ua::app::DiscoveryRegistrationConfig{});
  EXPECT_TRUE(created.is_good()) << to_string(created.status_code().as_status());
  ua::StatusCode status{ua::Status::BadInternalError};
  if (created.is_good())
  {
    auto& wrapper = created.value();
    const auto clientStore =
      ua::test_helpers::ServerWithDiscoveryTestAccess::client_certificate_store(wrapper);
    EXPECT_TRUE(clientStore->get_trusted_certificates_sync().empty())
      << "a new wrapper's registration store must start empty, not with an earlier run's trust";

    // Shared, so a completion arriving after a timed-out wait still has a promise to write to.
    auto seeded = std::make_shared<std::promise<ua::VoidResult>>();
    auto seededFuture = seeded->get_future();
    ua::test_helpers::ServerWithDiscoveryTestAccess::seed_client_trust(
      wrapper, [seeded](ua::VoidResult result) { seeded->set_value(std::move(result)); });
    EXPECT_EQ(seededFuture.wait_for(10s), std::future_status::ready);
    if (seededFuture.wait_for(0s) == std::future_status::ready)
    {
      EXPECT_TRUE(seededFuture.get().is_good());
      status =
        clientStore->try_validate_certificate_sync(ua::test::make_validation_request(lds, {}, std::nullopt))
          .status_code();
    }

    wrapper.server().shutdown_sync();
  }
  ::ua::test_utils::drain_with_timeout(pool);
  std::filesystem::remove_all(serverStoreRoot, ignored);
  return status;
}

}  // namespace

// The registrar checks the LDS certificate's revocation status with the server's policy, and the
// server's CRLs reach its store: an LDS certificate the server's CA revoked is refused.
// @verifies AC-SVR-SECADMIN-016-LDS-REGISTRAR-STORE-USES-THE-SERVER-REVOCATION-POLICY
TEST(ServerWithDiscoveryClientTrust, ARevokedLdsCertificateIsRefusedThroughTheRegistrationStore)
{
  EXPECT_EQ(validate_lds_certificate_through_registration_store(/*revokeLds=*/true).as_status(),
    Status::BadCertificateRevoked);
}

// Control: with the CA's CRL mirrored and not revoking it, the same CA-issued LDS certificate is
// accepted - revocation checking does not refuse an LDS whose CA publishes a CRL.
// @verifies AC-SVR-SECADMIN-016-LDS-REGISTRAR-STORE-USES-THE-SERVER-REVOCATION-POLICY
TEST(ServerWithDiscoveryClientTrust, AnUnrevokedCaIssuedLdsCertificateIsAcceptedThroughTheRegistrationStore)
{
  const auto status = validate_lds_certificate_through_registration_store(/*revokeLds=*/false);
  EXPECT_TRUE(status.is_good()) << to_string(status.as_status());
}

// The registration client validates LDS certificates with the server's application-group trust-list
// policy, revocation checking included, not with an empty option set that skips CRL checks: under a
// configured, non-default option set that checks revocation, the revoked LDS certificate is refused.
// @verifies AC-SVR-SECADMIN-016-LDS-REGISTRAR-STORE-USES-THE-SERVER-REVOCATION-POLICY
TEST(ServerWithDiscoveryClientTrust, RegistrationStoreUsesTheServerApplicationGroupValidationOptions)
{
  const ua::TrustListValidationOptions configured{
    ua::TrustListValidationOptions::Bit::CheckRevocationStatusOffline,
    ua::TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown};
  EXPECT_EQ(validate_lds_certificate_through_registration_store(/*revokeLds=*/true, configured).as_status(),
    Status::BadCertificateRevoked);
}

// Control: with empty configured options the same revoked LDS certificate validates Good, so the
// policy the registration store applies is the configuration's and not a constant the wrapper supplies.
// @verifies AC-SVR-SECADMIN-016-LDS-REGISTRAR-STORE-USES-THE-SERVER-REVOCATION-POLICY
TEST(ServerWithDiscoveryClientTrust, RegistrationStoreFollowsEmptyConfiguredValidationOptions)
{
  const auto status =
    validate_lds_certificate_through_registration_store(/*revokeLds=*/true, ua::TrustListValidationOptions{});
  EXPECT_TRUE(status.is_good()) << to_string(status.as_status());
}

namespace
{

ua::app::ServerWithDiscovery make_wrapper(boost::asio::any_io_executor executor)
{
  ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::ApplicationConfig::load_default(),
    .server = ua::server::ServerConfig{}};
  config.application.application_description_part().applicationUri = "urn:test:lds-client-instance";
  return ua::app::ServerWithDiscovery::create(std::move(executor),
    std::move(config),
    {.crypto = ua::test_helpers::test_crypto()},
    ua::app::DiscoveryRegistrationConfig{});
}

}  // namespace

namespace
{

ua::EndpointDescription registration_endpoint(
  ua::MessageSecurityMode mode, ua::SecurityPolicyId policy, uint8_t securityLevel, std::string url)
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = ua::String{std::move(url)};
  endpoint.security_mode() = mode;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(policy);
  endpoint.security_level() = securityLevel;
  return endpoint;
}

ua::Array<ua::EndpointDescription> lds_endpoints()
{
  using ua::MessageSecurityMode;
  using ua::SecurityPolicyId;
  ua::Array<ua::EndpointDescription> endpoints;
  endpoints.push_back(
    registration_endpoint(MessageSecurityMode::None, SecurityPolicyId::None, 0, "opc.tcp://lds/a"));
  endpoints.push_back(registration_endpoint(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256, 9, "opc.tcp://lds/b"));
  endpoints.push_back(
    registration_endpoint(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256, 8, "opc.tcp://lds/c"));
  endpoints.push_back(registration_endpoint(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 3, "opc.tcp://lds/d"));
  endpoints.push_back(registration_endpoint(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 5, "opc.tcp://lds/e"));
  return endpoints;
}

std::string chosen_url(const ua::Array<ua::EndpointDescription>& endpoints, const DiscoveryTarget& target)
{
  const ua::EndpointDescription* chosen = ua::app::detail::choose_registration_endpoint(endpoints, target);
  if (chosen == nullptr)
  {
    return "(none)";
  }
  return std::string{chosen->endpoint_url()};
}

}  // namespace

// The registration cycle learns the discovery server's certificate from its GetEndpoints answer, inside the
// client's completion; a certificate field that does not parse must come back as a failure the cycle can
// report and retry on, not an exception the completion swallows.
// @relation(AC-SVR-DISC-RS-011-UNPARSABLE-LDS-CERTIFICATE-IS-A-FAILURE, scope=function)
TEST(RegistrationEndpointChoice, AnUnparsableServerCertificateIsAFailureNotAnException)
{
  const auto crypto = ua::create_default_crypto(
    []()
    {
      constexpr std::string_view password{"password"};
      return ua::SecureString{password.data(), password.size()};
    });
  ASSERT_TRUE(crypto);
  auto endpoint = registration_endpoint(
    ua::MessageSecurityMode::SignAndEncrypt, ua::SecurityPolicyId::Basic256Sha256, 3, "opc.tcp://lds/d");

  endpoint.server_certificate() = ua::ByteString{0x30, 0x03, 0x01};  // a DER SEQUENCE cut short
  ua::Result<std::shared_ptr<const ua::X509Certificate>> unparsable{
    std::shared_ptr<const ua::X509Certificate>{}};
  EXPECT_NO_THROW(unparsable = ua::app::detail::registration_server_certificate(*crypto, endpoint));
  EXPECT_EQ(unparsable.status_code(), ua::Status::BadCertificateInvalid);

  endpoint.server_certificate() = ua::ByteString{};
  const auto empty = ua::app::detail::registration_server_certificate(*crypto, endpoint);
  ASSERT_TRUE(empty.is_good());
  EXPECT_EQ(empty.value(), nullptr);
}

// Public API review item 9 (API-9.3, D9): an unset policy registers over the strongest non-deprecated
// policy offered for the target's mode, ranked as the client ranks endpoints, with the advertised
// securityLevel breaking a tie; a named policy is used as named, a deprecated one included.
TEST(RegistrationEndpointChoice, AnUnsetPolicyTakesTheStrongestNonDeprecatedPolicyForTheMode)
{
  const auto endpoints = lds_endpoints();
  EXPECT_EQ(chosen_url(endpoints, DiscoveryTarget{.discoveryUrl = "opc.tcp://lds"}), "opc.tcp://lds/e")
    << "SignAndEncrypt + Basic256Sha256, the higher securityLevel of the two; Basic256 is deprecated";
  EXPECT_EQ(
    chosen_url(endpoints,
      DiscoveryTarget{.discoveryUrl = "opc.tcp://lds", .messageSecurityMode = ua::MessageSecurityMode::Sign}),
    "opc.tcp://lds/c")
    << "the target's mode is never traded for a stronger one";
  EXPECT_EQ(
    chosen_url(endpoints,
      DiscoveryTarget{.discoveryUrl = "opc.tcp://lds", .securityPolicyId = ua::SecurityPolicyId::Basic256}),
    "opc.tcp://lds/b")
    << "a deprecated policy is used when the target names it";
  EXPECT_EQ(chosen_url(endpoints,
              DiscoveryTarget{.discoveryUrl = "opc.tcp://lds",
                .messageSecurityMode = ua::MessageSecurityMode::None,
                .securityPolicyId = ua::SecurityPolicyId::None}),
    "opc.tcp://lds/a");
}

TEST(RegistrationEndpointChoice, NothingIsChosenWhenOnlyADeprecatedPolicyIsOffered)
{
  ua::Array<ua::EndpointDescription> endpoints;
  endpoints.push_back(registration_endpoint(
    ua::MessageSecurityMode::SignAndEncrypt, ua::SecurityPolicyId::Basic256, 9, "opc.tcp://lds/b"));
  EXPECT_EQ(chosen_url(endpoints, DiscoveryTarget{.discoveryUrl = "opc.tcp://lds"}), "(none)")
    << "an unset policy never falls back to a deprecated one";
}

// Public API review item 9 (API-9.2): before start has created the driver, registration() refuses with
// Bad_InvalidState and an ErrorDetail instead of dereferencing a null driver.
TEST(ServerWithDiscoveryRegistration, RegistrationBeforeStartThrowsInvalidState)
{
  boost::asio::thread_pool pool{2};
  auto wrapper = make_wrapper(pool.get_executor());
  try
  {
    (void)wrapper.registration();
    ADD_FAILURE() << "registration() returned a driver before start";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status(), ua::Status::BadInvalidState);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "RegistrationNotStarted");
  }
  wrapper.server().shutdown_sync();
}

// Each wrapper's registration store is a new, empty, owner-only directory of its own, removed with the
// wrapper: seeding only adds, so a shared or reused store would keep trusting certificates and CRLs
// an earlier run or another instance had trusted.
// @verifies AC-SVR-SECADMIN-016-LDS-REGISTRAR-STORE-USES-THE-SERVER-REVOCATION-POLICY
TEST(ServerWithDiscoveryClientTrust, EachWrapperHasItsOwnRegistrationStoreRemovedWithIt)
{
  boost::asio::thread_pool pool{2};
  std::filesystem::path first;
  std::filesystem::path second;
  {
    auto a = make_wrapper(pool.get_executor());
    auto b = make_wrapper(pool.get_executor());
    first = ua::test_helpers::ServerWithDiscoveryTestAccess::client_trust_directory(a);
    second = ua::test_helpers::ServerWithDiscoveryTestAccess::client_trust_directory(b);
    EXPECT_NE(first, second) << "two wrappers share one registration store";
    EXPECT_TRUE(std::filesystem::is_directory(first));
    EXPECT_EQ(first.parent_path(),
      ua::security::private_user_directory("uasdk-lds-client-trust", "ServerWithDiscovery"))
      << "the instance store must live inside the owner-only per-user directory";
#ifndef _WIN32
    const auto permissions = std::filesystem::status(first).permissions();
    EXPECT_EQ(permissions & (std::filesystem::perms::group_all | std::filesystem::perms::others_all),
      std::filesystem::perms::none)
      << "the instance store must be owner-only";
#endif
    EXPECT_TRUE(ua::test_helpers::ServerWithDiscoveryTestAccess::client_certificate_store(a)
                  ->get_trusted_certificates_sync()
                  .empty());
    a.server().shutdown_sync();
    b.server().shutdown_sync();
  }
  EXPECT_FALSE(std::filesystem::exists(first)) << "the registration store outlived its wrapper";
  EXPECT_FALSE(std::filesystem::exists(second)) << "the registration store outlived its wrapper";
  ::ua::test_utils::drain_with_timeout(pool);
}

namespace
{

/// A wrapper over @p store with one None endpoint on an ephemeral loopback port, so a real start binds
/// without colliding with anything else.
std::unique_ptr<ua::app::ServerWithDiscovery> make_listening_wrapper(
  boost::asio::any_io_executor executor, std::shared_ptr<ua::CertificateStore> store)
{
  ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::ApplicationConfig::load_default(),
    .server = ua::server::ServerConfig{}};
  config.application.application_description_part().applicationUri = "urn:test:lds-client-lifecycle";
  // The loopback endpoint below is SecurityPolicy None, which the default configuration refuses.
  config.application.allowInsecureEndpoints = true;
  auto wrapper =
    std::make_unique<ua::app::ServerWithDiscovery>(ua::app::ServerWithDiscovery::create(std::move(executor),
      std::move(config),
      ua::server::ServerComponents{
        .crypto = ua::test_helpers::test_crypto(), .applicationGroupCertificateStore = std::move(store)},
      ua::app::DiscoveryRegistrationConfig{}));
  ua::transport::BindAddress bind;
  bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  const auto listener = wrapper->server().listen_sync(std::move(bind), {});
  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
  endpoint.securityPolicyId = ua::SecurityPolicyId::None;
  wrapper->server().add_endpoint(listener, std::move(endpoint));
  return wrapper;
}

/// Waits for @p future; true when it became ready.
template<typename T>
bool ready_within(std::future<T>& future, std::chrono::seconds limit)
{
  return future.wait_for(limit) == std::future_status::ready;
}

}  // namespace

// A shutdown begun while start is still seeding trust must not let start create the driver: the
// shutdown releases the registrar, and a driver created afterwards would register the server as online
// after the shutdown had reported success. Driven through the public API: start_async runs while the
// server's trust store holds the seeding's first read, shutdown_async runs to completion, then the read
// is released. Start must complete with Bad_Shutdown and leave no driver. Control: the same start with
// no shutdown completes Good and creates the driver.
// @verifies AC-SVR-LDS-REGISTRATION-START-AFTER-SHUTDOWN-CREATES-NO-DRIVER
TEST(ServerWithDiscoveryClientTrust, AStartThatSeesShutdownBegunCompletesWithBadShutdownAndCreatesNoDriver)
{
  boost::asio::thread_pool pool{2};
  {
    auto store = ua::test_helpers::FakeCertificateStore::create();
    store->trustedReadDeferral.defer = true;
    auto wrapper = make_listening_wrapper(pool.get_executor(), store);

    // Shared, so a completion arriving after a failed expectation still has a promise to write to.
    auto started = std::make_shared<std::promise<ua::VoidResult>>();
    auto startedFuture = started->get_future();
    wrapper->start_async([started](ua::VoidResult result) { started->set_value(std::move(result)); });

    bool held = false;
    for (int attempt = 0; attempt < 1000 && !held; ++attempt)
    {
      held = store->trustedReadDeferral.has_pending();
      if (!held)
      {
        std::this_thread::sleep_for(10ms);
      }
    }
    EXPECT_TRUE(held) << "start never reached the trust seeding";

    auto shutDown = std::make_shared<std::promise<ua::VoidResult>>();
    auto shutDownFuture = shutDown->get_future();
    wrapper->shutdown_async([shutDown](ua::VoidResult result) { shutDown->set_value(std::move(result)); });
    const bool shutDownReady = ready_within(shutDownFuture, 15s);
    EXPECT_TRUE(shutDownReady) << "shutdown_async never completed";

    store->release_pending_trusted_read();
    const bool startedReady = ready_within(startedFuture, 10s);
    EXPECT_TRUE(startedReady) << "start never completed after the seeding was released";
    if (startedReady)
    {
      const auto result = startedFuture.get();
      EXPECT_TRUE(result.is_bad()) << "start reported success after the shutdown had completed";
      EXPECT_EQ(result.status_code().as_status(), Status::BadShutdown);
    }
    EXPECT_FALSE(ua::test_helpers::ServerWithDiscoveryTestAccess::has_registration(*wrapper))
      << "start created the registration driver after the shutdown had completed";

    if (!shutDownReady || !startedReady)
    {
      // Continuations may still hold the wrapper's state; leaking it keeps a failure a failure.
      (void)wrapper.release();
    }
  }
  {
    auto wrapper =
      make_listening_wrapper(pool.get_executor(), ua::test_helpers::FakeCertificateStore::create());
    auto started = std::make_shared<std::promise<ua::VoidResult>>();
    auto startedFuture = started->get_future();
    wrapper->start_async([started](ua::VoidResult result) { started->set_value(std::move(result)); });
    const bool startedReady = ready_within(startedFuture, 10s);
    EXPECT_TRUE(startedReady);
    if (startedReady)
    {
      const auto result = startedFuture.get();
      EXPECT_TRUE(result.is_good()) << "without a shutdown the start must succeed: "
                                    << to_string(result.status_code().as_status());
    }
    EXPECT_TRUE(ua::test_helpers::ServerWithDiscoveryTestAccess::has_registration(*wrapper))
      << "without a shutdown the start creates the driver";
    auto shutDown = std::make_shared<std::promise<ua::VoidResult>>();
    auto shutDownFuture = shutDown->get_future();
    wrapper->shutdown_async([shutDown](ua::VoidResult result) { shutDown->set_value(std::move(result)); });
    const bool shutDownReady = ready_within(shutDownFuture, 15s);
    EXPECT_TRUE(shutDownReady);
    if (!shutDownReady || !startedReady)
    {
      (void)wrapper.release();
    }
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// API-4.5: the blocking forms run the whole lifecycle from an application thread.
TEST(ServerWithDiscoveryLifecycle, TheSyncFormsStartAndStopFromAnApplicationThread)
{
  boost::asio::thread_pool pool{2};
  {
    auto wrapper =
      make_listening_wrapper(pool.get_executor(), ua::test_helpers::FakeCertificateStore::create());
    wrapper->start_sync();
    EXPECT_FALSE(wrapper->server().discovery_urls().empty()) << "start_sync must bind the server";
    EXPECT_TRUE(ua::test_helpers::ServerWithDiscoveryTestAccess::has_registration(*wrapper))
      << "start_sync must create the registration driver";
    const auto stopped = wrapper->try_shutdown_sync();
    EXPECT_TRUE(stopped.is_good()) << to_string(stopped.status_code());
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// API-4.5: on a thread of the wrapper's executor the blocking forms refuse with Bad_WouldBlock before
// doing anything, and start_async, the form for that thread, starts the server and the driver without
// waiting there.
TEST(ServerWithDiscoveryLifecycle, OnTheExecutorTheSyncFormsRefuseAndStartAsyncStarts)
{
  boost::asio::thread_pool pool{2};
  {
    auto wrapper =
      make_listening_wrapper(pool.get_executor(), ua::test_helpers::FakeCertificateStore::create());
    auto refusedStart = std::make_shared<std::promise<ua::StatusCode>>();
    auto refusedShutdown = std::make_shared<std::promise<ua::StatusCode>>();
    auto started = std::make_shared<std::promise<ua::VoidResult>>();
    auto refusedStartFuture = refusedStart->get_future();
    auto refusedShutdownFuture = refusedShutdown->get_future();
    auto startedFuture = started->get_future();
    boost::asio::post(pool.get_executor(),
      [raw = wrapper.get(), refusedStart, refusedShutdown, started]
      {
        refusedStart->set_value(raw->try_start_sync().status_code());
        refusedShutdown->set_value(raw->try_shutdown_sync().status_code());
        raw->start_async([started](ua::VoidResult result) { started->set_value(std::move(result)); });
      });

    ASSERT_TRUE(ready_within(refusedStartFuture, 10s)) << "try_start_sync blocked the executor";
    EXPECT_EQ(refusedStartFuture.get(), ua::StatusCode{Status::BadWouldBlock});
    ASSERT_TRUE(ready_within(refusedShutdownFuture, 10s)) << "try_shutdown_sync blocked the executor";
    EXPECT_EQ(refusedShutdownFuture.get(), ua::StatusCode{Status::BadWouldBlock});
    const bool startedReady = ready_within(startedFuture, 10s);
    EXPECT_TRUE(startedReady) << "start_async never completed";
    if (startedReady)
    {
      const auto result = startedFuture.get();
      EXPECT_TRUE(result.is_good()) << "start_async on the executor must start the server: "
                                    << to_string(result.status_code());
      EXPECT_TRUE(ua::test_helpers::ServerWithDiscoveryTestAccess::has_registration(*wrapper));
    }
    const auto stopped = wrapper->try_shutdown_sync();
    EXPECT_TRUE(stopped.is_good()) << to_string(stopped.status_code());
    if (!startedReady)
    {
      // A continuation may still hold the wrapper's state; leaking it keeps a failure a failure.
      (void)wrapper.release();
    }
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

}  // namespace ua::test::app::discovery
