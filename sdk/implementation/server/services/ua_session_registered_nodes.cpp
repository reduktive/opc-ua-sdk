// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_registered_nodes.h"

#include "ua_callback_safety.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_service_delegates.h"
#include "ua_on_strand.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>

#include <string>
#include <utility>

namespace ua::server
{

SessionRegisteredNodes::SessionRegisteredNodes(Logger logger) : mLogger(std::move(logger))
{}

void SessionRegisteredNodes::add(
  const WeakAddressSpace& addressSpace, uint16_t namespaceIndex, std::span<const NodeId> nodeIds)
{
  {
    const std::lock_guard lock{mMutex};
    if (!mEnded)
    {
      auto& registered = mRegistered[namespaceIndex];
      for (const auto& nodeId : nodeIds)
      {
        ++registered[nodeId];
      }
      return;
    }
  }
  // The Session ended before its namespace answered: no Client can unregister these.
  unregister_now(addressSpace, namespaceIndex, std::vector<NodeId>{nodeIds.begin(), nodeIds.end()});
}

std::vector<bool> SessionRegisteredNodes::take(uint16_t namespaceIndex, std::span<const NodeId> nodeIds)
{
  std::vector<bool> taken(nodeIds.size(), false);
  const std::lock_guard lock{mMutex};
  const auto registered = mRegistered.find(namespaceIndex);
  if (registered == mRegistered.end())
  {
    return taken;
  }
  for (size_t index = 0; index < nodeIds.size(); ++index)
  {
    const auto entry = registered->second.find(nodeIds[index]);
    if (entry == registered->second.end())
    {
      continue;
    }
    taken[index] = true;
    if (--entry->second == 0)
    {
      registered->second.erase(entry);
    }
  }
  if (registered->second.empty())
  {
    mRegistered.erase(registered);
  }
  return taken;
}

std::vector<std::optional<uint16_t>> SessionRegisteredNodes::take(std::span<const NodeId> nodeIds)
{
  std::vector<std::optional<uint16_t>> registeredBy(nodeIds.size());
  const std::lock_guard lock{mMutex};
  const auto takeFrom = [this](decltype(mRegistered)::iterator registered, const NodeId& nodeId)
  {
    const auto entry = registered->second.find(nodeId);
    if (entry == registered->second.end())
    {
      return false;
    }
    if (--entry->second == 0)
    {
      registered->second.erase(entry);
    }
    if (registered->second.empty())
    {
      mRegistered.erase(registered);
    }
    return true;
  };
  for (size_t index = 0; index < nodeIds.size(); ++index)
  {
    const uint16_t own = nodeIds[index].namespace_index();
    if (const auto registered = mRegistered.find(own);
        registered != mRegistered.end() && takeFrom(registered, nodeIds[index]))
    {
      registeredBy[index] = own;
      continue;
    }
    for (auto registered = mRegistered.begin(); registered != mRegistered.end(); ++registered)
    {
      const uint16_t namespaceIndex = registered->first;
      if (namespaceIndex != own && takeFrom(registered, nodeIds[index]))
      {
        registeredBy[index] = namespaceIndex;
        break;
      }
    }
  }
  return registeredBy;
}

void SessionRegisteredNodes::release(
  const WeakAddressSpace& addressSpace, uint16_t namespaceIndex, std::span<const NodeId> nodeIds)
{
  const auto taken = take(namespaceIndex, nodeIds);
  std::vector<NodeId> released;
  for (size_t index = 0; index < nodeIds.size(); ++index)
  {
    if (taken[index])
    {
      released.push_back(nodeIds[index]);
    }
  }
  if (!released.empty())
  {
    unregister_now(addressSpace, namespaceIndex, std::move(released));
  }
}

void SessionRegisteredNodes::release_all(const WeakAddressSpace& addressSpace) noexcept
{
  std::unordered_map<uint16_t, std::unordered_map<NodeId, size_t>> remaining;
  {
    const std::lock_guard lock{mMutex};
    if (mEnded)
    {
      return;
    }
    mEnded = true;
    remaining.swap(mRegistered);
  }
  for (auto& [namespaceIndex, registered] : remaining)
  {
    try
    {
      std::vector<NodeId> nodeIds;
      for (const auto& [nodeId, count] : registered)
      {
        nodeIds.insert(nodeIds.end(), count, nodeId);
      }
      unregister_now(addressSpace, namespaceIndex, std::move(nodeIds));
    }
    catch (...)
    {
      ua::detail::ignore_expected_exception();
    }
  }
}

void SessionRegisteredNodes::unregister_now(
  const WeakAddressSpace& addressSpace, uint16_t namespaceIndex, std::vector<NodeId> nodeIds) const noexcept
{
  try
  {
    auto lockedAddressSpace = addressSpace.lock();
    if (!lockedAddressSpace)
    {
      return;
    }
    // A namespace that is gone, or no longer delegates RegisterNodes, holds nothing to release.
    auto nameSpace = lockedAddressSpace->namespace_array().get_namespace(namespaceIndex);
    auto delegate = nameSpace ? nameSpace->register_nodes_delegate() : nullptr;
    if (!delegate)
    {
      return;
    }
    std::vector<NamespaceRegisterNodesDelegate::Item> items;
    items.reserve(nodeIds.size());
    for (size_t index = 0; index < nodeIds.size(); ++index)
    {
      items.push_back(NamespaceRegisterNodesDelegate::Item{index, std::move(nodeIds[index])});
    }
    boost::asio::post(lockedAddressSpace->executor(),
      ua::async::guarded(mLogger,
        [delegate = std::move(delegate), items = std::move(items), logger = mLogger, namespaceIndex]() mutable
        {
          try
          {
            delegate->unregister_nodes_async(NamespaceRegisterNodesDelegate::Context{},
              std::move(items),
              [logger, namespaceIndex](VoidResult result)
              {
                if (result.is_good())
                {
                  return;
                }
                try
                {
                  logger.with_category("service").warning(
                    {{"namespace_index", std::to_string(namespaceIndex)},
                      {"status", to_string(result.status_code())}},
                    "Could not unregister NodeIds that a Session registered and no Client can unregister any "
                    "more");
                }
                catch (...)
                {
                  ua::detail::ignore_expected_exception();
                }
              });
          }
          catch (...)
          {
            ua::detail::ignore_expected_exception();
          }
        }));
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

RegisterRequestAnswers::RegisterRequestAnswers(
  std::shared_ptr<SessionRegisteredNodes> registry, WeakAddressSpace addressSpace)
  : mRegistry(std::move(registry)), mAddressSpace(std::move(addressSpace))
{}

bool RegisterRequestAnswers::take_answer(uint16_t namespaceIndex, bool good, std::span<const NodeId> nodeIds)
{
  bool first = false;
  {
    const std::lock_guard lock{mMutex};
    first = mAnswered.insert(namespaceIndex).second;
    if (!good)
    {
      return first;
    }
    if (first && mState == State::Open)
    {
      mRegistry->add(mAddressSpace, namespaceIndex, nodeIds);
      mRecorded.emplace_back(namespaceIndex, std::vector<NodeId>{nodeIds.begin(), nodeIds.end()});
      return true;
    }
  }
  // A later answer, or one after the request ended with its response or without: no Client receives these
  // NodeIds.
  mRegistry->unregister_now(
    mAddressSpace, namespaceIndex, std::vector<NodeId>{nodeIds.begin(), nodeIds.end()});
  return first;
}

void RegisterRequestAnswers::release(uint16_t namespaceIndex) noexcept
{
  try
  {
    std::vector<NodeId> recorded;
    {
      const std::lock_guard lock{mMutex};
      mAnswered.insert(namespaceIndex);
      if (mState != State::Open)
      {
        return;
      }
      for (auto it = mRecorded.begin(); it != mRecorded.end();)
      {
        if (it->first == namespaceIndex)
        {
          recorded.insert(recorded.end(), it->second.begin(), it->second.end());
          it = mRecorded.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }
    if (recorded.empty())
    {
      return;
    }
    // Only what the Session still holds of them, as in discard().
    mRegistry->release(mAddressSpace, namespaceIndex, recorded);
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void RegisterRequestAnswers::keep() noexcept
{
  const std::lock_guard lock{mMutex};
  if (mState == State::Open)
  {
    mState = State::Kept;
    mRecorded.clear();
  }
}

void RegisterRequestAnswers::discard() noexcept
{
  std::vector<std::pair<uint16_t, std::vector<NodeId>>> recorded;
  {
    const std::lock_guard lock{mMutex};
    if (mState != State::Open)
    {
      return;
    }
    mState = State::Discarded;
    recorded.swap(mRecorded);
  }
  for (const auto& [namespaceIndex, nodeIds] : recorded)
  {
    try
    {
      // Only what the Session still holds of them: an UnregisterNodes may already have taken some.
      mRegistry->release(mAddressSpace, namespaceIndex, nodeIds);
    }
    catch (...)
    {
      ua::detail::ignore_expected_exception();
    }
  }
}

}  // namespace ua::server
