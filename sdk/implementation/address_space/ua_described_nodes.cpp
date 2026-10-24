// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_described_nodes.h"

#include "ua_attribute_wire.h"
#include "ua_call_method_result.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace ua
{

namespace
{

using Clock = std::chrono::steady_clock;

}  // namespace

// The NodeIds of the Nodes held, each to its Node. An entry whose Node has gone is erased by that Node's
// destructor, so the map holds nothing once the last holder lets go.
struct DescribedNodes::State
{
  class DescribedNode;

  std::mutex mutex;
  std::unordered_map<NodeId, std::weak_ptr<DescribedNode>> nodes;  // guarded by mutex

  // Erases the entry for @p nodeId if its Node has gone. A Node made for the NodeId since is left alone.
  void forget_if_gone(const NodeId& nodeId)
  {
    const std::lock_guard lock{mutex};
    if (const auto entry = nodes.find(nodeId); entry != nodes.end() && entry->second.expired())
    {
      nodes.erase(entry);
    }
  }
};

// A Node that holds one description and serves nothing else. Every change of its description happens under
// its own lock; a reader gets a copy of the handle, so a description taken before a change keeps its body.
class DescribedNodes::State::DescribedNode final : public Node
{
public:
  DescribedNode(NodeDescription description, std::weak_ptr<State> store)
    : mStore{std::move(store)}, mNodeId{description.node_id()}, mDescription{std::move(description)},
      mSetAt{Clock::now()}
  {}

  ~DescribedNode() override
  {
    try
    {
      if (const auto store = mStore.lock())
      {
        store->forget_if_gone(mNodeId);
      }
    }
    catch (...)
    {
      // Only taking the store's lock can throw. The expired entry then stays until a node_for for this
      // NodeId replaces it; held already answers null for it.
      ua::detail::ignore_expected_exception();
    }
  }

  DescribedNode(const DescribedNode&) = delete;
  DescribedNode& operator=(const DescribedNode&) = delete;
  DescribedNode(DescribedNode&&) = delete;
  DescribedNode& operator=(DescribedNode&&) = delete;

  NodeDescription attributes() const override
  {
    const std::lock_guard lock{mMutex};
    return mDescription;
  }

  bool deleted() const noexcept override
  {
    return mDeleted.load(std::memory_order_acquire);
  }

  // Carries @p description from now on; its age starts now.
  void describe(NodeDescription description)
  {
    const std::lock_guard lock{mMutex};
    mDescription = std::move(description);
    mSetAt = Clock::now();
  }

  // Reads the current description, builds the written one and stores it, under one lock, so that two
  // concurrent writes both land. A refused value leaves the description unchanged.
  VoidResult apply_write(AttributeId attributeId, const Variant& value) noexcept
  {
    try
    {
      const std::lock_guard lock{mMutex};
      auto written = mDescription.try_with_attribute(attributeId, value);
      if (!written.is_good())
      {
        return VoidResult{written.status_code(), written.shared_detail()};
      }
      mDescription = std::move(written).value();
      return VoidResult{};
    }
    catch (...)
    {
      return VoidResult{exception_to_status_code(std::current_exception())};
    }
  }

  // Whether the description was set no longer ago than @p maxAge milliseconds. A maxAge of 0 asks for a
  // new value from the source (OPC 10000-4 5.10.2.2), so it accepts no held description.
  bool set_within(Duration maxAge) const
  {
    if (maxAge <= 0)
    {
      return false;
    }
    const std::lock_guard lock{mMutex};
    const std::chrono::duration<double, std::milli> age{Clock::now() - mSetAt};
    return age.count() <= maxAge;
  }

  void mark_deleted() noexcept
  {
    mDeleted.store(true, std::memory_order_release);
  }

private:
  const std::weak_ptr<State> mStore;
  const NodeId mNodeId;
  mutable std::mutex mMutex;
  NodeDescription mDescription;  // guarded by mMutex
  Clock::time_point mSetAt;  // guarded by mMutex
  std::atomic<bool> mDeleted{false};
};

DescribedNodes::DescribedNodes() : mState{std::make_shared<State>()}
{}

DescribedNodes::~DescribedNodes() = default;

shared_ptr<Node> DescribedNodes::node_for(NodeDescription description)
{
  // Every Node taken from the map is held past the end of the lock, so that its last holder never lets go
  // inside the lock, where the Node's destructor would take the lock again.
  shared_ptr<State::DescribedNode> node;
  {
    const std::lock_guard lock{mState->mutex};
    auto& entry = mState->nodes[description.node_id()];
    node = entry.lock();
    if (!node)
    {
      node = std::make_shared<State::DescribedNode>(std::move(description), mState);
      entry = node;
      return node;
    }
  }
  // The Node's own lock orders this description against concurrent writes to it.
  node->describe(std::move(description));
  return node;
}

VoidResult DescribedNodes::record_write(
  const NodeId& nodeId, AttributeId attributeId, const Variant& value) noexcept
{
  try
  {
    shared_ptr<State::DescribedNode> node;
    {
      const std::lock_guard lock{mState->mutex};
      if (const auto entry = mState->nodes.find(nodeId); entry != mState->nodes.end())
      {
        node = entry->second.lock();
      }
    }
    if (!node)
    {
      return VoidResult{};
    }
    return node->apply_write(attributeId, value);
  }
  catch (...)
  {
    return VoidResult{exception_to_status_code(std::current_exception())};
  }
}

shared_ptr<Node> DescribedNodes::held(const NodeId& nodeId, std::optional<Duration> maxAge) const
{
  shared_ptr<State::DescribedNode> node;
  {
    const std::lock_guard lock{mState->mutex};
    if (const auto entry = mState->nodes.find(nodeId); entry != mState->nodes.end())
    {
      node = entry->second.lock();
    }
  }
  if (!node || (maxAge.has_value() && !node->set_within(*maxAge)))
  {
    return nullptr;
  }
  return node;
}

void DescribedNodes::remove(const NodeId& nodeId)
{
  shared_ptr<State::DescribedNode> node;
  {
    const std::lock_guard lock{mState->mutex};
    if (const auto entry = mState->nodes.find(nodeId); entry != mState->nodes.end())
    {
      node = entry->second.lock();
      mState->nodes.erase(entry);
    }
    if (node)
    {
      node->mark_deleted();
    }
  }
  // Released here, outside the lock: this may be the Node's last holder.
}

}  // namespace ua
