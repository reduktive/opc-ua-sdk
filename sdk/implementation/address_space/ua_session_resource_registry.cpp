// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_resource_registry.h"

#include "ua_log_exception.h"
#include "ua_to_result.h"

#include <utility>

namespace ua::detail
{

struct SessionResourceRegistry::Registration::Entry
{
  explicit Entry(Cleanup cleanupAction) : cleanup(std::move(cleanupAction))
  {}

  Cleanup cleanup;
  std::atomic_bool active{true};
};

SessionResourceRegistry::Registration::Registration(
  std::weak_ptr<SessionResourceRegistry> registry, uint64_t id, std::shared_ptr<Entry> entry)
  : mRegistry(std::move(registry)), mId(id), mEntry(std::move(entry))
{}

SessionResourceRegistry::Registration::~Registration()
{
  mEntry->active.store(false, std::memory_order_release);
  if (auto registry = mRegistry.lock())
    registry->unregister(mId);
}

std::shared_ptr<SessionResourceRegistry::Registration> SessionResourceRegistry::register_cleanup(
  Cleanup cleanup)
{
  auto entry = std::make_shared<Entry>(std::move(cleanup));
  uint64_t id = 0;
  {
    const std::lock_guard lock{mMutex};
    id = mNextId++;
    mEntries.emplace(id, entry);
  }
  return std::shared_ptr<Registration>{new Registration{weak_from_this(), id, std::move(entry)}};
}

void SessionResourceRegistry::release_session(const NodeId& sessionId) noexcept
{
  uint64_t currentId = 0;
  uint64_t lastId = 0;
  Logger logger;
  {
    const std::lock_guard lock{mMutex};
    lastId = mNextId - 1;
    logger = mLogger;
  }

  while (currentId < lastId)
  {
    std::shared_ptr<Entry> entry;
    {
      const std::lock_guard lock{mMutex};
      auto it = mEntries.upper_bound(currentId);
      if (it == mEntries.end() || it->first > lastId)
        break;
      currentId = it->first;
      entry = it->second.lock();
      if (!entry)
        mEntries.erase(it);
    }

    if (!entry || !entry->active.load(std::memory_order_acquire))
      continue;

    try
    {
      entry->cleanup(sessionId);
    }
    catch (...)
    {
      log_exception(logger,
        LogLevel::Error,
        "SessionResourceRegistry cleanup callback",
        exception_to_status_code(std::current_exception()));
    }
  }
}

void SessionResourceRegistry::set_logger(Logger logger)
{
  const std::lock_guard lock{mMutex};
  mLogger = std::move(logger);
}

void SessionResourceRegistry::unregister(uint64_t id) noexcept
{
  const std::lock_guard lock{mMutex};
  mEntries.erase(id);
}

}  // namespace ua::detail
