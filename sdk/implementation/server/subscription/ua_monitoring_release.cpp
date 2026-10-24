// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_monitoring_release.h"

#include "ua_callback_safety.h"
#include "ua_monitoring_entry.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_on_strand.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>

#include <map>
#include <memory>
#include <string>
#include <utility>

namespace ua::server
{

void release_monitoring_handles(const WeakAddressSpace& addressSpace,
  std::vector<IssuedMonitoringHandle> handles, const Logger& logger) noexcept
{
  try
  {
    std::map<uint16_t, std::vector<MonitoringHandle>> byNamespace;
    for (const auto& issued : handles)
    {
      if (issued.handle != 0)
      {
        byNamespace[issued.namespaceIndex].push_back(issued.handle);
      }
    }
    if (byNamespace.empty())
    {
      return;
    }
    auto lockedAddressSpace = addressSpace.lock();
    if (!lockedAddressSpace)
    {
      return;
    }
    for (auto& [namespaceIndex, namespaceHandles] : byNamespace)
    {
      try
      {
        auto nameSpace = lockedAddressSpace->namespace_array().get_namespace(namespaceIndex);
        if (!nameSpace)
        {
          continue;
        }
        // The namespace views the handles until it answers, so they live in the answer's capture. The entry
        // guards the call (NR-45 rule 3); the release is the server's own, since it outlives its request.
        auto owned = std::make_shared<const std::vector<MonitoringHandle>>(std::move(namespaceHandles));
        ua::detail::MonitoringEntry::remove(nameSpace,
          RequestInfo{},
          *owned,
          [owned, logger, namespaceIndex](BatchResult<VoidResult> answer)
          {
            size_t failed = answer.batchStatus.is_bad() ? owned->size() : 0;
            for (const auto& item : answer.items)
            {
              if (item.is_bad())
              {
                ++failed;
              }
            }
            if (failed == 0)
            {
              return;
            }
            try
            {
              logger.with_category("subscription")
                .warning({{"namespace_index", std::to_string(namespaceIndex)},
                           {"failed", std::to_string(failed)},
                           {"status", to_string(answer.batchStatus.status_code())}},
                  "A namespace did not release monitoring handles the server no longer uses");
            }
            catch (...)
            {
              ua::detail::ignore_expected_exception();
            }
          });
      }
      catch (...)
      {
        // Nothing was released (the namespace lookup or the copy failed): logged as a failed release. A throw
        // from the namespace itself is answered by the entry.
        try
        {
          logger.with_category("subscription")
            .warning({{"namespace_index", std::to_string(namespaceIndex)},
                       {"status", to_string(ua::exception_to_status_code(std::current_exception()))}},
              "A namespace did not release monitoring handles the server no longer uses");
        }
        catch (...)
        {
          ua::detail::ignore_expected_exception();
        }
      }
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void post_release_monitoring_handles(const WeakAddressSpace& addressSpace,
  std::vector<IssuedMonitoringHandle> handles, const Logger& logger) noexcept
{
  try
  {
    auto lockedAddressSpace = addressSpace.lock();
    if (!lockedAddressSpace || handles.empty())
    {
      return;
    }
    boost::asio::post(lockedAddressSpace->executor(),
      ua::async::guarded(logger,
        [addressSpace, handles = std::move(handles), logger]() mutable
        { release_monitoring_handles(addressSpace, std::move(handles), logger); }));
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

UnclaimedMonitoringHandles::UnclaimedMonitoringHandles(Logger logger) : mLogger(std::move(logger))
{}

uint64_t UnclaimedMonitoringHandles::open_ticket()
{
  const std::lock_guard lock{mMutex};
  const uint64_t ticket = mNextTicket++;
  mUnanswered.insert(ticket);
  return ticket;
}

bool UnclaimedMonitoringHandles::hold(
  uint64_t ticket, const WeakAddressSpace& addressSpace, std::vector<IssuedMonitoringHandle> handles)
{
  bool first = false;
  {
    const std::lock_guard lock{mMutex};
    first = mUnanswered.erase(ticket) > 0;
    if (first && !mEnded)
    {
      mHeld.emplace(ticket, Held{addressSpace, std::move(handles)});
      return true;
    }
  }
  // After the end, or a later answer to a call that has answered: the create never uses these handles.
  // Called from the namespace's own answer: posted, so the namespace is not called back from inside it.
  post_release_monitoring_handles(addressSpace, std::move(handles), mLogger);
  return first;
}

std::optional<std::vector<IssuedMonitoringHandle>> UnclaimedMonitoringHandles::claim(uint64_t ticket)
{
  const std::lock_guard lock{mMutex};
  if (mEnded)
  {
    return std::nullopt;
  }
  if (mUnanswered.erase(ticket) > 0)
  {
    return std::vector<IssuedMonitoringHandle>{};
  }
  const auto held = mHeld.find(ticket);
  if (held == mHeld.end())
  {
    return std::nullopt;  // abandoned, or claimed already
  }
  auto handles = std::move(held->second.handles);
  mHeld.erase(held);
  return handles;
}

void UnclaimedMonitoringHandles::abandon(uint64_t ticket) noexcept
{
  std::optional<Held> held;
  {
    const std::lock_guard lock{mMutex};
    mUnanswered.erase(ticket);
    if (const auto found = mHeld.find(ticket); found != mHeld.end())
    {
      held.emplace(std::move(found->second));
      mHeld.erase(found);
    }
  }
  if (held)
  {
    // Torn down with the create, possibly while the Subscription is destroyed: posted, as hold() does.
    post_release_monitoring_handles(held->addressSpace, std::move(held->handles), mLogger);
  }
}

void UnclaimedMonitoringHandles::end() noexcept
{
  std::unordered_map<uint64_t, Held> held;
  {
    const std::lock_guard lock{mMutex};
    if (mEnded)
    {
      return;
    }
    mEnded = true;
    held.swap(mHeld);
  }
  for (auto& [ticket, entry] : held)
  {
    release_monitoring_handles(entry.addressSpace, std::move(entry.handles), mLogger);
  }
}

}  // namespace ua::server
