// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REGISTERED_SERVER_STORE_H
#define UA_REGISTERED_SERVER_STORE_H

#include "ua_logger.h"
#include "ua_registered_server.h"
#include "ua_result.h"
#include "ua_server_configuration.h"
#include "ua_timer.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ua::test_helpers
{
class RegisteredServerStoreTestAccess;
}  // namespace ua::test_helpers

namespace ua::server
{

/// Strand-serialized store of registered servers, populated by inbound RegisterServer /
/// RegisterServer2 requests and read by the FindServers hook.
///
/// Keyed by serverUri; `isOnline == false` evicts immediately; entries expire per
/// `LocalDiscoveryServer::registrationExpiry`; the store is capped by `maxRegistrations`.
/// Mirrors the ReverseConnectListener strand-component shape: private strand, create()
/// factory, enable_shared_from_this, ua::Timer expiry, cross-strand atomic-backed snapshot().
class RegisteredServerStore : public std::enable_shared_from_this<RegisteredServerStore>
{
public:
  static std::shared_ptr<RegisteredServerStore> create(
    boost::asio::any_io_executor executor, ServerConfig::LocalDiscoveryServer config, ua::Logger logger = {});

  RegisteredServerStore() = delete;
  RegisteredServerStore(const RegisteredServerStore&) = delete;
  RegisteredServerStore(RegisteredServerStore&&) noexcept = delete;
  RegisteredServerStore& operator=(const RegisteredServerStore&) = delete;
  RegisteredServerStore& operator=(RegisteredServerStore&&) noexcept = delete;
  ~RegisteredServerStore();

  /// Ingest a RegisteredServer. `is_online() == true` inserts/refreshes (subject to the
  /// `maxRegistrations` cap); `is_online() == false` evicts the entry immediately. The
  /// callback fires on the store's strand with the outcome:
  ///   - Good: registered / refreshed / evicted as applicable.
  ///   - Bad_TooManyMatches: store at capacity (server.tier1.lds.inbound.too_many_registrations).
  ///   - Bad_NothingToDo: deregister request for an unknown serverUri.
  ///   - Bad_Shutdown: the store is stopped or unavailable, with source-specific ErrorDetail.
  void register_async(ua::RegisteredServer server, std::function<void(ua::VoidResult)> done) noexcept;

  /// Cross-strand cheap read for the FindServers aggregation hook. Returns the most-recently
  /// published snapshot of live (non-expired, online) registrations without touching the strand.
  std::vector<ua::RegisteredServer> snapshot() const;

  /// Cancel the expiry timer and drop all entries. The callback fires on the strand.
  void shutdown_async(std::function<void(ua::VoidResult)> done) noexcept;

private:
  friend class ::ua::test_helpers::RegisteredServerStoreTestAccess;

  RegisteredServerStore(
    boost::asio::any_io_executor executor, ServerConfig::LocalDiscoveryServer config, ua::Logger logger);

  void initialise();

  // --- strand-confined ---
  void do_register(ua::RegisteredServer server, std::function<void(ua::VoidResult)> done);
  void evict_expired();
  /// Whether the registrant's semaphore file exists, re-confined to the configured directory on the
  /// canonical path when one is configured (SVC-15).
  bool semaphore_file_present(const std::string& semaphoreFilePath) const;
  void schedule_expiry_sweep();
  void publish_snapshot();

  struct Entry
  {
    ua::RegisteredServer server;
    std::chrono::steady_clock::time_point expiresAt;
  };

  boost::asio::any_io_executor mExecutor;
  ServerConfig::LocalDiscoveryServer mConfig;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  bool mRunning{true};

  // Strand-confined registry keyed by serverUri.
  std::unordered_map<std::string, Entry> mEntries;

  // Periodic expiry sweep.
  ua::Timer mExpiryTimer;

  // Cross-strand snapshot: published on every mutation, read lock-free by snapshot()
  // (atomic-backed cross-strand read).
  std::atomic<std::shared_ptr<const std::vector<ua::RegisteredServer>>> mPublishedSnapshot{
    std::make_shared<const std::vector<ua::RegisteredServer>>()};
};

}  // namespace ua::server

#endif  // !UA_REGISTERED_SERVER_STORE_H
