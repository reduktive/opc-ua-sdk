// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// RegisteredServerStore - strand-serialized registry of servers that registered with this
// server acting as a Local Discovery Server (LDS). Populated by inbound RegisterServer /
// RegisterServer2 requests; read by the FindServers aggregation hook.
//
// Lifecycle: create() -> register_async(...) [repeatedly] -> shutdown_async()
//
// Keyed by serverUri. `is_online() == false` evicts immediately (a deregister cycle).
// Online entries expire after `LocalDiscoveryServer::registrationExpiry`; a periodic sweep
// removes stale entries. The store is capped by `maxRegistrations`. snapshot() reads a
// lock-free published copy so the FindServers hook never
// touches the strand.

#include "ua_registered_server_store.h"
#include "ua_on_strand.h"

#include "ua_error_detail.h"
#include "ua_callback_safety.h"

#include <boost/asio/post.hpp>

#include <filesystem>
#include <optional>
#include <utility>

namespace ua::server
{
namespace
{

const ua::StatusCode ownerGoneRegistrationFailure{ua::Status::BadShutdown,
  ua::make_error_detail("RegisteredServerStoreUnavailable", "Registered server store is unavailable",
    "RegisteredServerStore::register_async")};

}  // namespace

std::shared_ptr<RegisteredServerStore> RegisteredServerStore::create(
  boost::asio::any_io_executor executor, ServerConfig::LocalDiscoveryServer config, ua::Logger logger)
{
  struct Wrapper : public RegisteredServerStore
  {
    Wrapper(
      boost::asio::any_io_executor executor, ServerConfig::LocalDiscoveryServer config, ua::Logger logger)
      : RegisteredServerStore(std::move(executor), config, std::move(logger))
    {}
  };

  auto store = std::make_shared<Wrapper>(std::move(executor), config, std::move(logger));
  store->initialise();
  return store;
}

RegisteredServerStore::RegisteredServerStore(
  boost::asio::any_io_executor executor, ServerConfig::LocalDiscoveryServer config, ua::Logger logger)
  : mExecutor(std::move(executor)), mConfig(config), mStrand(boost::asio::make_strand(mExecutor)),
    mLogger(std::move(logger))
{}

RegisteredServerStore::~RegisteredServerStore() = default;

void RegisteredServerStore::initialise()
{
  mLogger = mLogger.with_category("lds");
  // Arm the periodic expiry sweep from the strand so the timer is bound to it.
  ua::async::post_borrowing(
    this, mStrand, mLogger, [](RegisteredServerStore& self) { self.schedule_expiry_sweep(); })();
}

void RegisteredServerStore::register_async(
  ua::RegisteredServer server, std::function<void(ua::VoidResult)> completionHandler) noexcept
{
  // post_borrowing's completion overload owns `done` and fires it exactly once: on the live path the
  // handler hands it to do_register; on the store-gone path it delivers a diagnostic BadShutdown.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ua::VoidResult{ownerGoneRegistrationFailure},
    [server = std::move(server)](
      RegisteredServerStore& self, std::function<void(ua::VoidResult)> done) mutable
    { self.do_register(std::move(server), std::move(done)); })();
}

namespace
{
/// The canonical form of `candidate` when it names a location inside `directory` once both are
/// normalised and any existing symlink prefix is resolved; nullopt otherwise. A relative candidate
/// never qualifies: the registrant chooses the file, the server chooses the directory. Two
/// normalisations per call.
std::optional<std::filesystem::path> canonical_semaphore_path_within(
  const std::string& candidate, const std::string& directory)
{
  // A relative path is refused before canonicalisation: weakly_canonical would resolve it against the
  // server's working directory, and a registrant does not get to name that.
  if (std::filesystem::path{candidate}.is_relative())
    return std::nullopt;
  std::error_code error;
  auto file = std::filesystem::weakly_canonical(std::filesystem::path{candidate}, error);
  if (error || file.is_relative())
    return std::nullopt;
  const auto root = std::filesystem::weakly_canonical(std::filesystem::path{directory}, error);
  if (error || root.is_relative())
    return std::nullopt;
  const auto fileText = file.lexically_normal().generic_string();
  auto rootText = root.lexically_normal().generic_string();
  if (rootText.empty())
    return std::nullopt;
  if (rootText.back() != '/')
    rootText.push_back('/');
  if (fileText.size() > rootText.size() && fileText.compare(0, rootText.size(), rootText) == 0)
    return file;
  return std::nullopt;
}

bool semaphore_path_is_within(const std::string& candidate, const std::string& directory)
{
  return canonical_semaphore_path_within(candidate, directory).has_value();
}
}  // namespace

void RegisteredServerStore::do_register(ua::RegisteredServer server, std::function<void(ua::VoidResult)> done)
{
  if (!mRunning)
  {
    if (done)
      done(ua::VoidResult{ua::Status::BadShutdown,
        ua::ErrorDetail::build("RegisteredServerStoreStopped",
          "Registered server store is stopped",
          "RegisteredServerStore::register_async")
          .context(ua::ContextKeys::applicationUri, std::string{server.server_uri()})});
    return;
  }

  std::string serverUri{server.server_uri()};

  // is_online() == false is a deregister request: evict immediately.
  if (!server.is_online())
  {
    auto erased = mEntries.erase(serverUri);
    publish_snapshot();
    if (erased == 0)
    {
      mLogger.debug({{"server_uri", serverUri}}, "Deregister for unknown server (nothing to do)");
      if (done)
        done(ua::VoidResult{ua::Status::BadNothingToDo});
      return;
    }
    mLogger.info({{"server_uri", serverUri}}, "Server deregistered (isOnline=false)");
    if (done)
      done(ua::VoidResult{});
    return;
  }

  // SVC-15: while a semaphore directory is configured, the expiry sweep's existence check must not be
  // usable as a probe of arbitrary host paths; a path outside the directory is refused here, at
  // RegisterServer, with the code Part 4 5.4.5.2 reserves for an unusable semaphore file. Cost: two
  // path normalisations per registration, and two per expired entry per sweep (semaphore_file_present).
  if (mConfig.semaphoreFileDirectory && !server.semaphore_file_path().empty() &&
      !semaphore_path_is_within(std::string{server.semaphore_file_path()}, *mConfig.semaphoreFileDirectory))
  {
    mLogger.warning(
      {{"server_uri", serverUri}}, "Registration rejected: semaphore file outside the configured directory");
    if (done)
      done(ua::VoidResult{ua::Status::BadSemaphoreFileMissing,
        ua::ErrorDetail::build("SemaphoreFileOutsideConfiguredDirectory",
          "The semaphore file must lie within the configured semaphore directory",
          "server.tier1.lds.inbound.semaphore_file_outside_directory")
          .context(ua::ContextKeys::applicationUri, serverUri)});
    return;
  }

  // Online registration / refresh.
  const auto now = std::chrono::steady_clock::now();
  const auto expiresAt = now + mConfig.registrationExpiry;

  auto existing = mEntries.find(serverUri);
  if (existing == mEntries.end())
  {
    // New entry - enforce the capacity cap.
    if (mConfig.maxRegistrations.has_value() && mEntries.size() >= *mConfig.maxRegistrations)
    {
      mLogger.warning({{"server_uri", serverUri}, {"max_registrations", uint64_t(*mConfig.maxRegistrations)}},
        "Registration rejected: store at capacity");
      if (done)
        done(ua::VoidResult{ua::Status::BadTooManyMatches,
          ua::ErrorDetail::build("TooManyRegistrations",
            "RegisteredServerStore at capacity; registration rejected",
            "server.tier1.lds.inbound.too_many_registrations")
            .context(ua::ContextKeys::applicationUri, serverUri)
            .context(ua::ContextKeys::sizeMax, std::to_string(*mConfig.maxRegistrations))
            .context(ua::ContextKeys::sizeActual, std::to_string(mEntries.size()))});
      return;
    }
    mEntries.emplace(serverUri, Entry{std::move(server), expiresAt});
    mLogger.info({{"server_uri", serverUri}}, "Server registered");
  }
  else
  {
    existing->second.server = std::move(server);
    existing->second.expiresAt = expiresAt;
    mLogger.debug({{"server_uri", serverUri}}, "Server registration refreshed");
  }

  publish_snapshot();
  if (done)
    done(ua::VoidResult{});
}

bool RegisteredServerStore::semaphore_file_present(const std::string& semaphoreFilePath) const
{
  // SVC-15: with a directory configured the check is repeated on the sweep, on the canonical path, so a
  // symlink planted inside the directory AFTER registration cannot redirect the existence probe outside
  // it (the registrant is normally allowed to write there). Cost: two normalisations per expired entry
  // per sweep (the file and the directory); the legacy any-path check otherwise.
  std::error_code error;
  if (mConfig.semaphoreFileDirectory)
  {
    const auto canonical =
      canonical_semaphore_path_within(semaphoreFilePath, *mConfig.semaphoreFileDirectory);
    return canonical && std::filesystem::exists(*canonical, error) && !error;
  }
  return std::filesystem::exists(std::filesystem::path{semaphoreFilePath}, error);
}

void RegisteredServerStore::evict_expired()
{
  if (!mRunning)
    return;

  const auto now = std::chrono::steady_clock::now();
  bool changed = false;
  for (auto it = mEntries.begin(); it != mEntries.end();)
  {
    if (it->second.expiresAt <= now)
    {
      const auto& semaphoreFilePath = it->second.server.semaphore_file_path();
      const bool semaphoreExists =
        !semaphoreFilePath.empty() && semaphore_file_present(std::string{semaphoreFilePath});
      if (semaphoreExists)
      {
        ++it;
        continue;
      }

      mLogger.info({{"server_uri", it->first}}, "Registration expired");
      it = mEntries.erase(it);
      changed = true;
    }
    else
    {
      ++it;
    }
  }
  if (changed)
    publish_snapshot();

  schedule_expiry_sweep();
}

void RegisteredServerStore::schedule_expiry_sweep()
{
  if (!mRunning)
    return;

  // Sweep on the expiry granularity; clamp to a sane minimum so a tiny configured expiry
  // (e.g. in tests) does not busy-spin the executor.
  auto period = mConfig.registrationExpiry;
  if (period < std::chrono::seconds{1})
    period = std::chrono::seconds{1};

  auto me = weak_from_this();
  mExpiryTimer = ua::Timer::schedule_after(mStrand,
    period,
    [me](boost::system::error_code ec)
    {
      if (ec)
        return;  // cancelled (shutdown)
      auto self = me.lock();
      if (!self)
        return;
      self->evict_expired();
    });
}

void RegisteredServerStore::publish_snapshot()
{
  auto live = std::make_shared<std::vector<ua::RegisteredServer>>();
  live->reserve(mEntries.size());
  for (const auto& [uri, entry] : mEntries)
  {
    live->push_back(entry.server);
  }
  mPublishedSnapshot.store(
    std::shared_ptr<const std::vector<ua::RegisteredServer>>(std::move(live)), std::memory_order_release);
}

std::vector<ua::RegisteredServer> RegisteredServerStore::snapshot() const
{
  auto published = mPublishedSnapshot.load(std::memory_order_acquire);
  if (!published)
    return {};
  return *published;
}

void RegisteredServerStore::shutdown_async(std::function<void(ua::VoidResult)> completionHandler) noexcept
{
  // Owns `done` and fires it exactly once. The store-gone (or post-failed) path delivers Good - if
  // the store is already gone, shutdown is effectively complete.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ua::VoidResult{},
    [](RegisteredServerStore& self, std::function<void(ua::VoidResult)> done) mutable
    {
      self.mRunning = false;
      self.mExpiryTimer.cancel();
      self.mEntries.clear();
      self.publish_snapshot();
      done(ua::VoidResult{});
    })();
}

}  // namespace ua::server
