// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A test namespace that answers lookups with Nodes a test holds in it.

#ifndef UA_TEST_NODE_HOLDING_NAMESPACE_H
#define UA_TEST_NODE_HOLDING_NAMESPACE_H

#include "ua_address_space.h"
#include "ua_error_detail.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <utility>

namespace ua::test
{

/// A namespace that holds the Nodes a test gives it and answers every lookup of one of them with that Node.
/// Registered with an address space, it lets the test take the accessor the address space builds over it, as
/// over a namespace's own lookup answer. It owns nothing else: it creates, deletes, writes and monitors
/// nothing, and answers each Reference query and each Value read `Bad_NotSupported`. A test that scripts
/// those operations holds its Nodes in a namespace that answers them, such as the behaviour pins'
/// `FakeAsyncNamespace` (`hold`).
class NodeHoldingNamespace final : public Namespace
{
public:
  explicit NodeHoldingNamespace(String uri) : mUri(std::move(uri))
  {}

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    resolve_each(nodeIds,
      std::move(complete),
      [this](const NodeId& nodeId, std::function<void(NodeResult)> one) { one(held(nodeId)); });
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration>) override
  {
    return held(nodeId);
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    answer.items.assign(queries.size(), NodeReferencesResult{holds_nothing_else()});
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    answer.items.assign(items.size(), DataValueResult{holds_nothing_else()});
    complete(std::move(answer));
  }

  /// Holds @p node, answering lookups of @p nodeId.
  void hold(const NodeId& nodeId, std::shared_ptr<Node> node)
  {
    const std::lock_guard lock{mMutex};
    mNodes[nodeId] = std::move(node);
  }

private:
  NodeResult held(const NodeId& nodeId)
  {
    const std::lock_guard lock{mMutex};
    if (const auto found = mNodes.find(nodeId); found != mNodes.end())
    {
      return NodeResult{found->second};
    }
    return NodeResult{StatusCode{Status::BadNodeIdUnknown}};
  }

  static StatusCode holds_nothing_else()
  {
    return StatusCode{Status::BadNotSupported,
      ErrorDetail::build("NodeHoldingNamespaceHoldsNoData",
        "NodeHoldingNamespace holds Nodes only, with no References or Values",
        "NodeHoldingNamespace")};
  }

  String mUri;
  std::mutex mMutex;
  std::map<NodeId, std::shared_ptr<Node>> mNodes;
};

/// An address space with a NodeHoldingNamespace registered, for a test that needs the accessor of a Node it
/// made itself (a Node of a test class, say) to come from an address space.
class NodeHoldingAddressSpace
{
public:
  explicit NodeHoldingAddressSpace(String applicationUri = "urn:test:node-holding-address-space")
    : mAddressSpace(AddressSpace::create(std::move(applicationUri), mPool.get_executor())),
      mHolder(std::make_shared<NodeHoldingNamespace>("urn:test:node-holding-namespace")),
      mIndex(mAddressSpace.add_namespace_sync(mHolder))
  {}

  /// The holding namespace's index: a Node held here reports a NodeId of this index, because the address
  /// space routes an accessor's operations by its Node's own NodeId.
  std::uint16_t index() const noexcept
  {
    return mIndex;
  }

  /// The accessor the address space hands out for @p node, held under the NodeId it reports, which is of
  /// @ref index. A Node held earlier under the same NodeId is replaced.
  NodeAccessor accessor_for(std::shared_ptr<Node> node)
  {
    const NodeDescription described = node->attributes();
    const NodeId key = described.node_id();
    mHolder->hold(key, std::move(node));
    return mAddressSpace.find_node_sync(key);
  }

  AddressSpace& address_space() noexcept
  {
    return mAddressSpace;
  }

private:
  boost::asio::thread_pool mPool{1};
  AddressSpace mAddressSpace;
  std::shared_ptr<NodeHoldingNamespace> mHolder;
  std::uint16_t mIndex;
};

}  // namespace ua::test

#endif
