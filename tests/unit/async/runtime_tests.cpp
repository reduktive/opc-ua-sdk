// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// ua::Runtime - one lifetime for the executor and everything running on it.
///
/// The rule this type removes is "shut down everything that owns a timer, in the right order,
/// before joining the executor you handed it". Nothing in the type system could express it, and
/// getting it wrong produces a process that never exits with nothing in the log - which is exactly
/// what four of the book's eighteen example programs did, in code written by this SDK's authors.
///
/// So the headline test is the one none of those examples had: attach something that runs work,
/// let the runtime go out of scope, and assert that the next line is reached.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "ua_address_space.h"
#include "ua_built_in_authenticators.h"
#include "ua_runtime.h"
#include "ua_server_observer.h"
#include "ua_server.h"
#include "ua_server_with_discovery.h"

#include <boost/asio/executor_work_guard.hpp>

#include "test_components.h"
using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Records the order in which the runtime stopped things.
struct Recorder
{
  std::string name;
  std::shared_ptr<std::vector<std::string>> log;
  std::shared_ptr<std::mutex> logMutex;
};

void runtime_shutdown(Recorder& recorder, const ua::ShutdownContext& /*context*/)
{
  const std::lock_guard lock{*recorder.logMutex};
  recorder.log->push_back(recorder.name);
}

/// Reports the grace period it was given, so the policy plumbing can be observed.
struct GraceReporter
{
  std::shared_ptr<std::atomic<int>> seconds;
};

void runtime_shutdown(GraceReporter& reporter, const ua::ShutdownContext& context)
{
  // -1 distinguishes "the runtime stated no period" from "the runtime stated zero".
  reporter.seconds->store(context.policy.grace ? static_cast<int>(context.policy.grace->count()) : -1);
}

/// Deliberately does NOT release its claim on the executor: the case the drain budget exists
/// for. The work guard is held outside the attachment too, so releasing the attachment cannot
/// clear it either - which is exactly the shape of a component that forgot to stop its timers.
struct StubbornWorker
{
  std::shared_ptr<boost::asio::executor_work_guard<boost::asio::any_io_executor>> work;
};

void runtime_shutdown(StubbornWorker& /*worker*/, const ua::ShutdownContext& /*context*/)
{
  // Nothing. A component that gets this wrong is what pins an executor open forever.
}

}  // namespace

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, DestructionStopsAttachmentsAndReturns)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};
    runtime.attach(Recorder{"only", log, logMutex});
  }  // ~Runtime: stops the attachment, then joins. Reaching the next line IS the assertion.
  ASSERT_EQ(log->size(), 1u);
  EXPECT_EQ(log->front(), "only");
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AttachmentsAreStoppedNewestFirst)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};
    runtime.attach(Recorder{"first", log, logMutex});
    runtime.attach(Recorder{"second", log, logMutex});
    runtime.attach(Recorder{"third", log, logMutex});
  }
  // Reverse of attachment: the safe answer when a later attachment depends on an earlier one.
  ASSERT_EQ(log->size(), 3u);
  EXPECT_EQ((*log)[0], "third");
  EXPECT_EQ((*log)[1], "second");
  EXPECT_EQ((*log)[2], "first");
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AttachAfterShutdownThrows)
{
  Runtime runtime{RuntimeConfig{.threads = 2}};
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();

  EXPECT_TRUE(runtime.shutdown().is_good());

  // Accepting work that will never be torn down is worse than refusing it - and there is no such
  // thing as a dead reference to hand back, so this has to fail loudly.
  EXPECT_THROW(static_cast<void>(runtime.attach(Recorder{"late", log, logMutex})), UaException);
  EXPECT_TRUE(log->empty()) << "a refused attachment must not be stopped, because it never ran";
}

// The reference attach() hands back stays valid for as long as the Runtime does: shutdown STOPS
// an attachment, destruction destroys it. That rule is what lets attach() return a reference at
// all, so it is pinned here rather than left to the header comment.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, TheReferenceStaysValidAfterShutdown)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();

  Runtime runtime{RuntimeConfig{.threads = 2}};
  Recorder& recorder = runtime.attach(Recorder{"watched", log, logMutex});
  EXPECT_EQ(recorder.name, "watched");

  EXPECT_TRUE(runtime.shutdown().is_good());
  ASSERT_EQ(log->size(), 1u) << "shutdown must have stopped it";

  // Still there, still readable: stopped is not destroyed.
  EXPECT_EQ(recorder.name, "watched");
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, ShutdownIsIdempotent)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();
  Runtime runtime{RuntimeConfig{.threads = 2}};
  runtime.attach(Recorder{"once", log, logMutex});

  EXPECT_TRUE(runtime.shutdown().is_good());
  EXPECT_TRUE(runtime.shutdown().is_good()) << "the destructor calls this again unconditionally";
  EXPECT_EQ(log->size(), 1u) << "the attachment must be stopped exactly once";
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, DetachTakesAnAttachmentBackOut)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};
    Recorder& attached = runtime.attach(Recorder{"leaving", log, logMutex});
    auto taken = runtime.detach(attached);
    ASSERT_TRUE(taken.has_value());
    EXPECT_EQ(taken->name, "leaving");
  }
  EXPECT_TRUE(log->empty()) << "a detached attachment is the caller's to stop, not the runtime's";
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, PerAttachmentPolicyOverridesTheRuntimeDefault)
{
  auto defaulted = std::make_shared<std::atomic<int>>(-1);
  auto overridden = std::make_shared<std::atomic<int>>(-1);
  {
    Runtime runtime{RuntimeConfig{.threads = 2, .shutdown = {.grace = 3s}}};
    runtime.attach(GraceReporter{defaulted});
    runtime.attach(GraceReporter{overridden}, ShutdownPolicy{.grace = 11s});
  }
  EXPECT_EQ(defaulted->load(), 3) << "the runtime default applies where nothing overrides it";
  EXPECT_EQ(overridden->load(), 11) << "a per-attachment policy wins";
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, ConcurrentShutdownStopsEveryAttachment)
{
  auto log = std::make_shared<std::vector<std::string>>();
  auto logMutex = std::make_shared<std::mutex>();
  {
    Runtime runtime{RuntimeConfig{.threads = 4, .concurrentShutdown = true}};
    for (int index = 0; index < 6; ++index)
    {
      runtime.attach(Recorder{"n" + std::to_string(index), log, logMutex});
    }
  }
  // Order is deliberately unspecified here - that is what the caller opted into - but nothing
  // may be skipped.
  EXPECT_EQ(log->size(), 6u);
}

// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AnAttachmentThatDoesNotStopIsReportedRatherThanHangingForever)
{
  std::shared_ptr<boost::asio::executor_work_guard<boost::asio::any_io_executor>> work;
  VoidResult result{};
  {
    Runtime runtime{RuntimeConfig{.threads = 2, .shutdown = {.drainBudget = 300ms}}};
    // Something is holding the executor open, and its shutdown step will not release it.
    work = std::make_shared<boost::asio::executor_work_guard<boost::asio::any_io_executor>>(
      boost::asio::make_work_guard(runtime.executor()));
    runtime.attach(StubbornWorker{work});

    result = runtime.shutdown();
    // Drop the test's external owner while the executor it refers to is still alive. The
    // attachment keeps its own copy until Runtime destruction, where attachments are destroyed
    // before the pool.
    work.reset();
  }
  EXPECT_TRUE(result.is_bad()) << "a runtime that cannot drain must say so";
  EXPECT_EQ(result.status_code().as_status(), Status::BadTimeout)
    << "and it must be a bounded wait, not a hang";
}

// The test none of the eighteen example programs had.
//
// Four of them joined an executor while a server was still alive and hung forever, with nothing
// logged. This is that scenario, written the way the runtime intends: attach the server, let the
// scope end, and assert that the next line is reached. If the runtime ever stops shutting an
// attachment down before it joins, this test hangs rather than fails - which is the honest shape
// for the defect it guards, and the suite's timeout catches it.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AServerAttachedToARuntimeDoesNotPinTheExecutor)
{
  bool reachedTheNextLine = false;
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};

    auto config = ua::ApplicationConfig::load_default();
    config.application_description_part().applicationUri = "urn:reduktive:test:runtime";

    ua::server::CreateConfig createConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = config,
      .server = ua::server::ServerConfig{}};

    ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
    components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();

    // `.` reads as it always has: attach hands back the server itself, not a wrapper.
    ua::server::Server& server = runtime.attach(
      ua::server::Server::create(runtime.executor(), std::move(createConfig), std::move(components)));
    static_cast<void>(server.address_space());
  }
  reachedTheNextLine = true;
  EXPECT_TRUE(reachedTheNextLine);
}

namespace
{

/// Captures the grace period a server actually advertised when it was shut down.
struct ShutdownGraceObserver : ua::server::ServerObserver
{
  std::shared_ptr<std::atomic<int>> advertised = std::make_shared<std::atomic<int>>(-1);

  void on_shutdown_initiated(uint32_t secondsTillShutdown, const ua::LocalizedText& /*reason*/) override
  {
    advertised->store(static_cast<int>(secondsTillShutdown));
  }
};

/// The configuration of a server that listens on nothing and has @p configuredGraceSeconds as its own
/// shutdown grace period; only the shutdown path is under test.
ua::server::CreateConfig config_with_grace(uint32_t configuredGraceSeconds)
{
  auto config = ua::ApplicationConfig::load_default();
  config.application_description_part().applicationUri = "urn:reduktive:test:runtime:grace";

  ua::server::ServerConfig serverConfig;
  serverConfig.defaultShutdownGracePeriodSeconds = configuredGraceSeconds;

  return ua::server::CreateConfig{
    .identity = ua::ApplicationIdentity::load_default(), .application = config, .server = serverConfig};
}

ua::server::ServerComponents anonymous_components()
{
  ua::server::ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
  return components;
}

ua::server::Server make_server_with_grace(
  const boost::asio::any_io_executor& executor, uint32_t configuredGraceSeconds)
{
  return ua::server::Server::create(
    executor, config_with_grace(configuredGraceSeconds), anonymous_components());
}

/// The same server inside a ServerWithDiscovery that has no discovery targets.
ua::app::ServerWithDiscovery make_wrapper_with_grace(
  const boost::asio::any_io_executor& executor, uint32_t configuredGraceSeconds)
{
  return ua::app::ServerWithDiscovery::create(executor,
    config_with_grace(configuredGraceSeconds),
    anonymous_components(),
    ua::app::DiscoveryRegistrationConfig{});
}

}  // namespace

// A server carries its own shutdown grace period in its configuration. Attaching it to a
// Runtime must not silently replace that with the runtime's own default, because a policy
// that was never set is not the same statement as a policy explicitly set to zero.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, ADefaultPolicyLeavesTheServersConfiguredGracePeriodInPlace)
{
  auto observer = std::make_shared<ShutdownGraceObserver>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};
    ua::server::Server& server = runtime.attach(make_server_with_grace(runtime.executor(), 7));
    server.set_observer(observer);
  }
  EXPECT_EQ(observer->advertised->load(), 7);
}

// The other half of the same contract: an explicit zero still means "stop now", and must
// override whatever the server was configured with.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AnExplicitZeroGraceOverridesTheServersConfiguredPeriod)
{
  auto observer = std::make_shared<ShutdownGraceObserver>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2, .shutdown = {.grace = 0s}}};
    ua::server::Server& server = runtime.attach(make_server_with_grace(runtime.executor(), 7));
    server.set_observer(observer);
  }
  EXPECT_EQ(observer->advertised->load(), 0);
}

// And an explicit non-zero policy still wins over the server's configuration.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AnExplicitNonZeroGraceOverridesTheServersConfiguredPeriod)
{
  auto observer = std::make_shared<ShutdownGraceObserver>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2, .shutdown = {.grace = 2s}}};
    ua::server::Server& server = runtime.attach(make_server_with_grace(runtime.executor(), 7));
    server.set_observer(observer);
  }
  EXPECT_EQ(observer->advertised->load(), 2);
}

// API-4.5: a ServerWithDiscovery attaches like a Server, and the runtime's policy reaches the server it
// wraps the same way: an explicit grace period wins over the server's configuration...
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AServerWithDiscoveryPassesAnExplicitGraceToItsServer)
{
  auto observer = std::make_shared<ShutdownGraceObserver>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2, .shutdown = {.grace = 2s}}};
    ua::app::ServerWithDiscovery& wrapper = runtime.attach(make_wrapper_with_grace(runtime.executor(), 7));
    wrapper.server().set_observer(observer);
  }
  EXPECT_EQ(observer->advertised->load(), 2);
}

// ...and an unset one leaves the server's own in place.
// @relation(AC-COMP-SDK-POST-RUNTIME, scope=function)
TEST(RuntimeTests, AServerWithDiscoveryUnderADefaultPolicyKeepsItsServersGracePeriod)
{
  auto observer = std::make_shared<ShutdownGraceObserver>();
  {
    Runtime runtime{RuntimeConfig{.threads = 2}};
    ua::app::ServerWithDiscovery& wrapper = runtime.attach(make_wrapper_with_grace(runtime.executor(), 7));
    wrapper.server().set_observer(observer);
  }
  EXPECT_EQ(observer->advertised->load(), 7);
}
