// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::server::RegisteredServerStore - the strand-serialized registry of
// servers that registered with this server acting as a Local Discovery Server (LDS).
//
// Requirement coverage:
//   SVR-DISC-LDS-006 / SVR-DISC-RS-021 - online-registration storage + expiry / removal.
//   SVR-DISC-RS-022                - isOnline=false evicts immediately (deregister).
//   SVR-DISC-LDS-002               - snapshot feeds the FindServers aggregation.
//   (capacity cap)             - maxRegistrations rejection with the locked ErrorDetail tag.
//
// The store uses ua::Timer (real wall-clock) for its periodic expiry sweep, clamped to a
// 1s minimum. The expiry test drives that real timer and polls the lock-free snapshot, the
// same deterministic-wall-clock approach used by tests/unit/async/timer_tests.cpp. All
// blocking (.get()) happens on the main test thread only; the pool is shut down explicitly.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include "ua_error_detail.h"
#include "ua_registered_server.h"
#include "ua_registered_server_store.h"
#include "ua_server_configuration.h"

#include "registered_server_store_test_access.h"
#include "test_utilities.h"

using namespace std::chrono_literals;

namespace ua::test::server::discovery::lds
{
namespace
{

using ua::server::RegisteredServerStore;
using Config = ua::server::ServerConfig::LocalDiscoveryServer;
using ua::test_helpers::RegisteredServerStoreTestAccess;

/// Removes a directory tree when the test scope ends, whichever way it ends.
struct ScopedRemoval
{
  std::filesystem::path path;

  ~ScopedRemoval()
  {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
};

// Build a fully-populated online RegisteredServer keyed by `serverUri`.
ua::RegisteredServer make_registered_server(const std::string& serverUri, bool online = true)
{
  ua::RegisteredServer server;
  server.server_uri() = ua::String{serverUri};
  server.product_uri() = ua::String{"urn:test:product"};
  server.server_type() = ua::ApplicationType::Server;
  server.server_names().payload().push_back(ua::LocalizedText{ua::String{"en"}, ua::String{"Test Server"}});
  server.discovery_urls().payload().push_back(ua::String{"opc.tcp://localhost:4840"});
  server.is_online() = online;
  return server;
}

class RegisteredServerStoreTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
  }

  void TearDown() override
  {
    if (mStore)
    {
      // Bounded, on-strand shutdown so the expiry timer is cancelled before the pool joins.
      std::promise<void> done;
      mStore->shutdown_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(2s);
      mStore.reset();
    }
    if (mPool)
    {
      ua::test_utils::drain_with_timeout(*mPool);
    }
  }

  std::shared_ptr<RegisteredServerStore> make_store(Config config)
  {
    mStore = RegisteredServerStore::create(mPool->executor(), config);
    return mStore;
  }

  // Synchronous register helper: blocks the result back to the MAIN test thread only.
  ua::VoidResult register_sync(const ua::RegisteredServer& server)
  {
    std::promise<ua::VoidResult> p;
    auto fut = p.get_future();
    mStore->register_async(
      ua::RegisteredServer{server}, [&p](ua::VoidResult r) { p.set_value(std::move(r)); });
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "register_async callback did not fire";
    return fut.get();
  }

  // Run a query on the store's strand and return the result to the main test thread. Used for
  // strand-confined TestAccess reads so we never touch mEntries off-strand.
  template<typename Fn>
  auto on_strand(Fn&& fn)
  {
    using R = decltype(fn(std::declval<RegisteredServerStoreTestAccess&>()));
    std::promise<R> p;
    auto fut = p.get_future();
    auto store = mStore;
    boost::asio::post(mPool->executor(),
      [store, fn = std::forward<Fn>(fn), &p]() mutable
      {
        RegisteredServerStoreTestAccess access{*store};
        p.set_value(fn(access));
      });
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready);
    return fut.get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<RegisteredServerStore> mStore;
};

// SVR-DISC-LDS-006 / SVR-DISC-RS-021 - an online registration is stored and appears in the snapshot.
// @relation(AC-COMP-SVR-REGISTERED-SERVER-STORE-01-RICH-SHUTDOWN, scope=function)
TEST_F(RegisteredServerStoreTest, RegisterAddsOnlineEntry)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  auto result = register_sync(make_registered_server("urn:server:a"));
  EXPECT_TRUE(result.is_good()) << ua::to_string(result.status_code().as_status());

  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, "urn:server:a");
}

// @relation(AC-COMP-SVR-REGISTERED-SERVER-STORE-01-RICH-SHUTDOWN, scope=function)
TEST_F(RegisteredServerStoreTest, RegisterAfterShutdownReturnsRichBadShutdownExactlyOnce)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  std::promise<ua::VoidResult> shutdownPromise;
  auto shutdownFuture = shutdownPromise.get_future();
  mStore->shutdown_async(
    [&shutdownPromise](ua::VoidResult result) { shutdownPromise.set_value(std::move(result)); });
  ASSERT_EQ(shutdownFuture.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(shutdownFuture.get().is_good());

  std::promise<ua::VoidResult> registrationPromise;
  auto registrationFuture = registrationPromise.get_future();
  std::atomic<std::size_t> callbackCount{0};
  mStore->register_async(make_registered_server("urn:server:stopped"),
    [&registrationPromise, &callbackCount](ua::VoidResult result)
    {
      if (callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
        registrationPromise.set_value(std::move(result));
    });

  ASSERT_EQ(registrationFuture.wait_for(2s), std::future_status::ready);
  auto result = registrationFuture.get();

  std::promise<ua::VoidResult> barrierPromise;
  auto barrierFuture = barrierPromise.get_future();
  mStore->shutdown_async(
    [&barrierPromise](ua::VoidResult barrierResult) { barrierPromise.set_value(std::move(barrierResult)); });
  ASSERT_EQ(barrierFuture.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(barrierFuture.get().is_good());

  EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(result.status_code(), ua::Status::BadShutdown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "RegisteredServerStoreStopped");
  EXPECT_EQ(result.shared_detail()->source, "RegisteredServerStore::register_async");
  ASSERT_EQ(result.shared_detail()->context.size(), 1u);
  EXPECT_EQ(result.shared_detail()->context[0].key, std::string{ua::ContextKeys::applicationUri.value()});
  EXPECT_EQ(result.shared_detail()->context[0].value, "urn:server:stopped");
  EXPECT_TRUE(mStore->snapshot().empty());
}

// @relation(AC-COMP-SVR-REGISTERED-SERVER-STORE-01-RICH-SHUTDOWN, scope=function)
TEST_F(RegisteredServerStoreTest, RegisterAfterOwnerDestructionReturnsRichBadShutdownExactlyOnce)
{
  boost::asio::io_context context;
  std::optional<ua::VoidResult> observedResult;
  std::size_t callbackCount = 0;

  {
    auto store = RegisteredServerStore::create(
      context.get_executor(), Config{.enabled = true, .registrationExpiry = 600s});
    store->register_async(make_registered_server("urn:server:gone"),
      [&observedResult, &callbackCount](ua::VoidResult result)
      {
        ++callbackCount;
        observedResult.emplace(std::move(result));
      });
  }

  context.run();

  ASSERT_EQ(callbackCount, 1u);
  ASSERT_TRUE(observedResult.has_value());
  EXPECT_EQ(observedResult->status_code(), ua::Status::BadShutdown);
  ASSERT_NE(observedResult->shared_detail(), nullptr);
  EXPECT_EQ(observedResult->shared_detail()->code, "RegisteredServerStoreUnavailable");
  EXPECT_EQ(observedResult->shared_detail()->source, "RegisteredServerStore::register_async");
  EXPECT_TRUE(observedResult->shared_detail()->context.empty());
}

// Re-registering the same serverUri updates the existing entry rather than duplicating it.
TEST_F(RegisteredServerStoreTest, ReRegisterSameUriUpdatesInPlace)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());

  // Re-register the same URI with a different discovery URL.
  auto updated = make_registered_server("urn:server:a");
  updated.discovery_urls().payload().clear();
  updated.discovery_urls().payload().push_back(ua::String{"opc.tcp://localhost:4999"});
  ASSERT_TRUE(register_sync(updated).is_good());

  EXPECT_EQ(on_strand([](RegisteredServerStoreTestAccess& a) { return a.entry_count(); }), 1u);

  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  ASSERT_EQ(snapshot[0].discovery_urls().payload().size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].discovery_urls().payload()[0]}, "opc.tcp://localhost:4999");
}

// SVR-DISC-RS-022 - isOnline=false evicts the matching entry immediately (no expiry wait).
TEST_F(RegisteredServerStoreTest, OfflineRegistrationEvictsImmediately)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());
  ASSERT_EQ(mStore->snapshot().size(), 1u);

  // A deregister (isOnline=false) for the known URI succeeds and removes the entry.
  auto result = register_sync(make_registered_server("urn:server:a", /*online=*/false));
  EXPECT_TRUE(result.is_good()) << ua::to_string(result.status_code().as_status());
  EXPECT_TRUE(mStore->snapshot().empty());
  EXPECT_FALSE(on_strand([](RegisteredServerStoreTestAccess& a) { return a.contains("urn:server:a"); }));
}

// A deregister for an unknown serverUri reports Bad_NothingToDo and changes no state.
TEST_F(RegisteredServerStoreTest, DeregisterUnknownReportsNothingToDo)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  auto result = register_sync(make_registered_server("urn:server:unknown", /*online=*/false));
  EXPECT_EQ(result.status_code(), ua::Status::BadNothingToDo);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// SVR-DISC-LDS-006 - an online entry expires after registrationExpiry and is swept from the snapshot.
// Drives the real ua::Timer (1s clamp) and polls the lock-free snapshot from the main thread.
TEST_F(RegisteredServerStoreTest, OnlineEntryExpiresAfterRegistrationExpiry)
{
  // 1s expiry -> sweep period clamps to 1s; expect the entry gone within a few sweep cycles.
  make_store(Config{.enabled = true, .registrationExpiry = 1s});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());
  ASSERT_EQ(mStore->snapshot().size(), 1u) << "entry must be present immediately after register";

  // Poll the snapshot until the sweep removes the expired entry (generous 6s budget).
  const auto deadline = std::chrono::steady_clock::now() + 6s;
  bool evicted = false;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (mStore->snapshot().empty())
    {
      evicted = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(evicted) << "expired online registration must be swept from the snapshot";
}

// maxRegistrations cap - a new entry beyond the cap is rejected with the locked status + tag.
TEST_F(RegisteredServerStoreTest, MaxRegistrationsCapRejectsWithErrorDetail)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s, .maxRegistrations = 1u});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());

  // Second distinct registration exceeds the cap of 1.
  std::promise<ua::VoidResult> p;
  auto fut = p.get_future();
  mStore->register_async(
    make_registered_server("urn:server:b"), [&p](ua::VoidResult r) { p.set_value(std::move(r)); });
  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto result = fut.get();

  EXPECT_EQ(result.status_code(), ua::Status::BadTooManyMatches);
  ASSERT_NE(result.shared_detail(), nullptr) << "capacity rejection must carry an ErrorDetail";
  EXPECT_EQ(result.shared_detail()->code, "TooManyRegistrations");

  // The capped entry must not be inserted.
  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, "urn:server:a");
}

// SVC-15: with a semaphore directory configured, a registrant cannot name an arbitrary host path as
// its semaphore file (the expiry sweep's existence check would otherwise answer whether that path
// exists). Outside the directory the registration is refused at RegisterServer with the Part 4
// 5.4.5.2 code; inside it is honoured.
// @verifies AC-SVR-DISC-RS-019-SEMAPHORE-FILE-PATH-IS-CONFINED-TO-THE-CONFIGURED-DIRECTORY
TEST_F(RegisteredServerStoreTest, SemaphoreFileOutsideTheConfiguredDirectoryIsRefused)
{
  // A relative path that WOULD land inside the directory once resolved against the working directory
  // is still refused: the registrant does not get to name the server's working directory.
  const auto cwdRoot = std::filesystem::current_path() / "uasdk-lds-semaphores-relative";
  std::filesystem::create_directories(cwdRoot);
  const ScopedRemoval cleanup{cwdRoot};
  make_store(Config{.enabled = true,
    .registrationExpiry = 600s,
    .maxRegistrations = 10u,
    .semaphoreFileDirectory = cwdRoot.string()});
  for (const std::string probe : {std::string{"/etc/shadow"},
         (cwdRoot / ".." / "elsewhere" / "probe").string(),
         std::string{"uasdk-lds-semaphores-relative/probe.sem"}})
  {
    auto server = make_registered_server("urn:server:probe");
    server.semaphore_file_path() = ua::String{probe};
    std::promise<ua::VoidResult> p;
    auto fut = p.get_future();
    mStore->register_async(std::move(server), [&p](ua::VoidResult r) { p.set_value(std::move(r)); });
    ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
    const auto result = fut.get();
    EXPECT_EQ(result.status_code(), ua::Status::BadSemaphoreFileMissing) << probe;
    ASSERT_NE(result.shared_detail(), nullptr) << probe;
    EXPECT_EQ(result.shared_detail()->code, "SemaphoreFileOutsideConfiguredDirectory") << probe;
  }
  EXPECT_TRUE(mStore->snapshot().empty()) << "a refused registration is not stored";
}

// @verifies AC-SVR-DISC-RS-019-SEMAPHORE-FILE-PATH-IS-CONFINED-TO-THE-CONFIGURED-DIRECTORY
TEST_F(RegisteredServerStoreTest, SemaphoreFileInsideTheConfiguredDirectoryIsHonoured)
{
  const auto root = std::filesystem::temp_directory_path() / "uasdk-lds-semaphores";
  std::filesystem::create_directories(root);
  const ScopedRemoval cleanup{root};
  make_store(Config{.enabled = true,
    .registrationExpiry = 600s,
    .maxRegistrations = 10u,
    .semaphoreFileDirectory = root.string()});

  auto server = make_registered_server("urn:server:inside");
  server.semaphore_file_path() = ua::String{(root / "inside.sem").string()};
  ASSERT_TRUE(register_sync(std::move(server)).is_good());
  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, "urn:server:inside");
}

// @verifies AC-SVR-DISC-RS-019-SEMAPHORE-FILE-PATH-IS-CONFINED-TO-THE-CONFIGURED-DIRECTORY
TEST_F(RegisteredServerStoreTest, AnySemaphoreFilePathIsHonouredWhenNoDirectoryIsConfigured)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s, .maxRegistrations = 10u});
  auto server = make_registered_server("urn:server:legacy");
  server.semaphore_file_path() = ua::String{"/etc/shadow"};
  ASSERT_TRUE(register_sync(std::move(server)).is_good()) << "the legacy default honours any path";
  EXPECT_EQ(mStore->snapshot().size(), 1u);
}

#ifndef _WIN32
// SVC-15: the confinement holds at the sweep too. A symlink planted inside the directory after
// registration must not turn the existence check into a probe of a path outside it: the registration
// naming `<dir>/link/x.sem` expires although `<dir>/link -> <elsewhere>` and `<elsewhere>/x.sem` exists.
// @verifies AC-SVR-DISC-RS-019-SEMAPHORE-FILE-PATH-IS-CONFINED-TO-THE-CONFIGURED-DIRECTORY
TEST_F(RegisteredServerStoreTest, ASymlinkPlantedAfterRegistrationDoesNotKeepTheRecordAlive)
{
  const auto root = std::filesystem::temp_directory_path() / "uasdk-lds-semaphores-sweep";
  const auto elsewhere = std::filesystem::temp_directory_path() / "uasdk-lds-semaphores-elsewhere";
  std::filesystem::remove_all(root);
  std::filesystem::remove_all(elsewhere);
  std::filesystem::create_directories(root);
  std::filesystem::create_directories(elsewhere);
  const ScopedRemoval cleanupRoot{root};
  const ScopedRemoval cleanupElsewhere{elsewhere};
  {
    std::ofstream target{(elsewhere / "x.sem").string()};
    target << "present";
  }
  make_store(Config{.enabled = true, .registrationExpiry = 1s, .semaphoreFileDirectory = root.string()});

  auto server = make_registered_server("urn:server:planted");
  server.semaphore_file_path() = ua::String{(root / "link" / "x.sem").string()};
  ASSERT_TRUE(register_sync(std::move(server)).is_good()) << "lexically inside the directory: accepted";
  std::filesystem::create_directory_symlink(elsewhere, root / "link");
  ASSERT_TRUE(std::filesystem::exists(root / "link" / "x.sem")) << "the raw path now resolves outside";

  const auto deadline = std::chrono::steady_clock::now() + 6s;
  bool evicted = false;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (mStore->snapshot().empty())
    {
      evicted = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(evicted)
    << "a semaphore file reached only through a symlink out of the directory does not hold";
}
#endif  // !_WIN32

// Re-registering an existing URI is a refresh, not a new insert, so it is NOT capacity-rejected.
TEST_F(RegisteredServerStoreTest, ReRegisterAtCapacityIsAllowedAsRefresh)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s, .maxRegistrations = 1u});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());
  // Same URI again - refresh path, must succeed even though the store is at capacity.
  EXPECT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());
  EXPECT_EQ(mStore->snapshot().size(), 1u);
}

// snapshot() returns only the live online entries and stays consistent across mutations.
TEST_F(RegisteredServerStoreTest, SnapshotReflectsLiveOnlineEntriesOnly)
{
  make_store(Config{.enabled = true, .registrationExpiry = 600s});

  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a")).is_good());
  ASSERT_TRUE(register_sync(make_registered_server("urn:server:b")).is_good());
  EXPECT_EQ(mStore->snapshot().size(), 2u);

  // Evicting one online entry leaves exactly the other in the snapshot.
  ASSERT_TRUE(register_sync(make_registered_server("urn:server:a", /*online=*/false)).is_good());
  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, "urn:server:b");
}

}  // namespace
}  // namespace ua::test::server::discovery::lds
