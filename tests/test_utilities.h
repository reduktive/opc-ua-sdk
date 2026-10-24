// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef TEST_UTILITIES_H
#define TEST_UTILITIES_H

#include <gtest/gtest.h>

#include "ua_includes.h"
#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_error_detail.h"
#include "ua_guid.h"
#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <filesystem>
#include <future>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ua::test_utils
{

/// Returns a unique, collision-free path under the *system* temp directory:
/// `<tmp>/ua_<prefix>_<guid><suffix>`.
///
/// Use this for any test that writes a scratch file under
/// `std::filesystem::temp_directory_path()`. The parallel-shard test wrapper isolates
/// *cwd-relative* writes by
/// giving each shard a private working directory - but the system temp dir is
/// global and shared by every shard. A fixed temp filename therefore races
/// across shards (one shard's SetUp/TearDown removes a file another shard is
/// mid-write on), producing exactly the kind of non-deterministic flake that
/// destroys CI's credibility as a gate. The embedded GUID makes every path
/// unique per test instance, so no two shards (or tests) ever collide.
inline std::filesystem::path unique_temp_path(std::string_view prefix, std::string_view suffix = "")
{
  return std::filesystem::temp_directory_path() /
         ("ua_" + std::string{prefix} + "_" + ::ua::Guid::create_and_generate().as_string() +
           std::string{suffix});
}

/// Looks up a structured-context value by key, walking the ErrorDetail cause
/// chain (outermost layer first). Returns "" if the key is absent on every
/// layer. Use to assert facts that the structured-context migration moved out
/// of prose (summary/mDetail) into mContext.
inline std::string error_context(const ::ua::ErrorDetail* detail, std::string_view key)
{
  for (; detail != nullptr; detail = detail->cause.get())
  {
    for (const auto& fact : detail->context)
    {
      if (fact.key == key)
      {
        return fact.value;
      }
    }
  }
  return {};
}

::ua::ApplicationConfig create_test_config();

namespace detail
{

/// Deletes each path in @p roots recursively, then removes each path in @p parents
/// non-recursively, in the order given.
///
/// Split out from @ref cleanup_process_trust_list_dirs purely so the removal policy
/// is testable: the public entry point drains a process-global registry, so calling
/// it from a test would delete the trust lists of fixtures still running.
///
/// Every filesystem error is swallowed - a path that is absent, locked, or already
/// reclaimed must not fail the run.
void remove_trust_list_dirs(
  const std::vector<std::filesystem::path>& roots, const std::vector<std::filesystem::path>& parents);

}  // namespace detail

/// Removes every trust-list directory allocated by @ref create_test_config in *this*
/// process. Called once from a gtest global environment (tests/test_main.cpp), so
/// individual fixtures never need to opt in.
///
/// Deletes only paths this process registered, and prunes the shared scaffolding
/// (`./temp/test_pki/{app,user}`, `./temp/test_pki`, `./temp`) with
/// `std::filesystem::remove`, which fails rather than recurses on a non-empty
/// directory. That is the concurrency guard: when several test processes share a
/// working directory, each reclaims its own GUID subtrees and the last one out
/// removes the parents. `remove_all` on the parents would instead delete a
/// sibling process's live trust lists mid-run.
///
/// Best-effort by design - every filesystem error is swallowed. A crashed or
/// signalled run leaks its directories, which is why the parents are pruned
/// opportunistically on later runs rather than assumed empty.
void cleanup_process_trust_list_dirs();

/// Client `CreateConfig` for a fixture that drives a **None** endpoint.
///
/// A Client refuses to create a Session over an unsecured channel unless its ApplicationConfig
/// opts in, so the no-config `Client::create` / `CoreClient::create` overloads - which build a default
/// configuration - cannot talk to a None endpoint at all. Every fixture that drives one must pass a
/// configuration, and this is it: @ref create_test_config with the opt-in already set.
///
/// Reach for the no-config overload only when the fixture never opens a Session, or when the refusal
/// itself is what the test asserts.
::ua::client::CreateConfig create_test_client_config();

/// Drain a thread_pool with a hard timeout, surfacing leaked async work as
/// gtest failures instead of letting them hang the suite.
///
/// Mechanism: boost::asio::thread_pool::join() returns when the pool's queue
/// is empty and no thread is executing a handler. It does NOT wait on
/// executor-handle lifetimes - `thread_pool::get_executor()` is already
/// `outstanding_work::untracked`, so bare executors and strands do not pin
/// the pool by themselves. The pin in practice is always an *armed* timer
/// or queued I/O handler inside a still-alive impl - typically a
/// SecureChannelImpl/SessionImpl whose destructor has not run because the
/// owning shared_ptr is still on the stack. Cancelling the timer / clearing
/// the queue is what unblocks join; the impl destructor is what does that.
///
/// This helper makes the leak visible: if drain takes longer than `timeout`
/// the test fails with a diagnostic, the pool is forcibly stopped so the
/// test still terminates cleanly, and the rest of the suite runs.
inline constexpr std::chrono::seconds default_pool_drain_timeout()
{
#if defined(UASDK_TSAN_INSTRUMENTED_TESTS)
  // TSan separately, and higher. Its shadow-memory bookkeeping costs several times what gcov's counters
  // do, and at 15s three integration tests failed the drain in pipeline 2855965130 -
  // ComplianceSession.EveryCreateSessionResponseCarriesAFreshServerNonceOfAtLeast32Bytes,
  // ComplianceWithNodes.LifetimeResetsOnBothAServiceCallAndAProcessedPublish and
  // SeededBranchingAlarmTest.ConfiguredBranchCapRetractsTheOldestBranchOverTheWire - while `coverage`,
  // which is instrumented too and shares that 15s, passed the same tests in the same pipeline. A real
  // leaked timer would fail under both, so what 15s measures under TSan is TSan.
  //
  // Still finite, and still a hard failure: a genuine leak reports here, it just takes 45s to say so.
  return std::chrono::seconds{45};
#elif defined(UASDK_COVERAGE_INSTRUMENTED_TESTS) || defined(UASDK_ASAN_INSTRUMENTED_TESTS)
  // gcov or ASan instrumentation plus several integration shards can delay legitimate final handlers
  // beyond the ordinary watchdog without indicating a leak. Keep a finite hard failure, but account for
  // those instrumented modes.
  return std::chrono::seconds{15};
#else
  return std::chrono::seconds{5};
#endif
}

/// Default wall-clock budget for a test that polls for an asynchronous effect (a server-side method call,
/// a delivered notification) to become observable.
///
/// The budget exists to bound a hang, not to assert a latency: nothing under test promises to settle in
/// any particular time, so the only failure it should ever report is "this never happened". Under gcov,
/// TSan or ASan - and with several integration shards competing for the same runner - an effect that
/// ordinarily lands in milliseconds can legitimately take seconds, so a budget sized for an uninstrumented
/// build reports absence when it is really measuring the instrumentation.
inline constexpr std::chrono::milliseconds default_poll_budget()
{
#if defined(UASDK_COVERAGE_INSTRUMENTED_TESTS) || defined(UASDK_TSAN_INSTRUMENTED_TESTS) || \
  defined(UASDK_ASAN_INSTRUMENTED_TESTS)
  return std::chrono::milliseconds{20000};
#else
  return std::chrono::milliseconds{5000};
#endif
}

inline void drain_with_timeout(::boost::asio::thread_pool& pool,
  std::chrono::seconds timeout = default_pool_drain_timeout(), std::string_view poolName = {})
{
  std::promise<void> done;
  auto fut = done.get_future();
  std::thread joiner(
    [&pool, &done]()
    {
      pool.join();
      done.set_value();
    });
  if (fut.wait_for(timeout) == std::future_status::ready)
  {
    joiner.join();
    return;
  }
  ADD_FAILURE() << "pool drain timed out after " << timeout.count()
                << "s (pool=" << (poolName.empty() ? std::string_view{"unnamed"} : poolName)
                << ") - most likely an armed timer or pending I/O handler inside an impl "
                << "(SecureChannelImpl, SessionImpl, etc.) that is still alive at join time. "
                << "Drop the owning impl shared_ptr (or call its close/shutdown) before pool.join() "
                << "so the impl destructor cancels its timers and clears its pending handlers.";
  pool.stop();
  joiner.join();
}

/// Gracefully stop a thread pool used by a test fixture by joining the
/// workers. Waits for queued handlers to drain.
inline void stop_pool_in_teardown(::boost::asio::thread_pool& pool, std::string_view name)
{
  drain_with_timeout(pool, default_pool_drain_timeout(), name);
}

}  // namespace ua::test_utils

#endif  // TEST_UTILITIES_H
