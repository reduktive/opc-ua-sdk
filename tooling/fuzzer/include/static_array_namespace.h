// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_STATIC_ARRAY_NAMESPACE_H
#define FUZZ_STATIC_ARRAY_NAMESPACE_H

/// @file
/// @brief A namespace with no locks, no hashing and no mutable state, for measuring what the read
///        path costs when the address space costs nothing.
///
/// **Why this exists.** Measurement on `.200` (Ryzen 9 5950X, sixteen cores over two CCDs) established
/// that the read path's scaling loss is stall rather than work: instructions per attribute are flat
/// within 2.2% from one thread to sixteen, while IPC falls 2.33 to 1.12 and cycles per attribute
/// double. Every coherency indicator rises with thread count, and eight threads spanning two CCDs
/// deliver 26.4% less than eight inside one, with identical instruction and fill counts - the same
/// fills simply cost more, which is only possible if other cores hold those lines. The cache-miss
/// profile names `shared_ptr` reference counting and the namespace's `shared_mutex` as the symbols
/// that gain miss share as threads are added.
///
/// All of that is inference from counters. This settles it by removal instead. The store here is a
/// flat array of immutable Nodes, the identifier IS the index, and resolution is three integer
/// comparisons and a dereference:
///
///   * no lock - nothing is mutable, so nothing needs guarding; a Node's description is built once and
///     `attributes()` returns it without a lock (a `DescribedNodes` store would take its per-Node lock
///     on every read, which is the very cost this namespace exists to remove);
///   * no hash table - the identifier indexes the array directly;
///   * `read_values_async` completes inline, on the calling stack;
///   * `effective_permissions` is answered from a constant.
///
/// If per-core efficiency at sixteen threads recovers against this namespace, the address space was
/// the source of the coherency traffic. If it does not, the cost is above the address space - in
/// dispatch, authorisation or encoding - and no amount of namespace work would have helped.
///
/// **The costs that cannot be removed.** A lookup answers a `shared_ptr<Node>` (@ref ua::NodeResult)
/// and the address space builds the accessor from it, so every resolution copies one: an atomic
/// increment and decrement on a control block, per attribute read. Every Attribute read copies the
/// Node's @ref ua::NodeDescription, a handle to one immutable body, which is a second such pair on
/// the body's control block. Those are imposed by the interface and no storage design avoids them.
/// @ref StaticArrayNamespace therefore takes a @ref Sharing mode so the reference counts can be
/// measured as a variable rather than assumed:
///
///   * `Sharing::PerNode`  - one Node, and one description body, per array slot, so reference-count
///                           traffic is spread over N lines. This is what a real namespace looks like.
///   * `Sharing::OneNode`  - every identifier resolves to the SAME Node, so every core hammers one
///                           pair of control blocks. This is the worst case, deliberately.
///
/// Same protocol path, same storage, only the sharing of the reference counts differs. If `PerNode`
/// scales and `OneNode` does not, the reference count is measured as a coherency source rather than
/// argued for from a profile.
///
/// Not conformant and not meant to be: no hierarchy, no writes, no events. Each Node holds one
/// Reference, its HasTypeDefinition. It exists to be read from, at speed, by the performance harness.

#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_numeric_range_parser.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_status_code.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace fuzz
{

/// One immutable scalar Int32 Variable. Its description and Value are set at construction and never
/// change, so `attributes()` returns the description without a lock.
class StaticNode final : public ua::Node
{
public:
  StaticNode(const ua::NodeId& nodeId, const std::string& browseName, int32_t value)
    : mDescription(ua::NodeDescription::variable(
        nodeId, ua::QualifiedName(nodeId.namespace_index(), browseName), ua::NodeId{ua::DataTypeId::Int32})),
      mValue(value)
  {}

  ua::NodeDescription attributes() const override
  {
    return mDescription;
  }

  int32_t value() const
  {
    return mValue;
  }

private:
  const ua::NodeDescription mDescription;
  const int32_t mValue;
};

/// A namespace whose store is a flat array indexed by the node identifier.
class StaticArrayNamespace final : public ua::Namespace
{
public:
  /// How the `shared_ptr<Node>` that every lookup answers is shared between resolutions.
  enum class Sharing
  {
    PerNode,  ///< one control block per slot - refcount traffic spread over N lines
    OneNode  ///< every identifier resolves to one node - all refcount traffic on one line
  };

  StaticArrayNamespace(
    std::string uri, uint32_t count, uint32_t identifierBase, Sharing sharing = Sharing::PerNode)
    : mUri(std::move(uri)), mCount(count), mBase(identifierBase), mSharing(sharing)
  {}

  ua::String uri() const override
  {
    return ua::String{mUri};
  }

  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
  }

  /// The fast lane, and the whole reason this class exists.
  ///
  /// Namespace index, numeric form, bounds - then index the array. No lock is taken because there is
  /// nothing mutable to guard, and no lookup is performed because the identifier IS the index. It never
  /// declines.
  std::optional<ua::NodeResult> find_node(
    const ua::NodeId& nodeId, std::optional<ua::Duration> maxAge) override
  {
    UA_UNUSED(maxAge);
    return found(nodeId);
  }

  /// A real batch: one call, N bounds-checked dereferences, no per-id lock and no per-id lookup.
  void find_nodes_async(const ua::RequestInfo& request, std::span<const ua::NodeId> nodeIds,
    std::optional<ua::Duration> maxAge,
    std::function<void(ua::BatchResult<ua::NodeResult>)> complete) override
  {
    UA_UNUSED(request);
    UA_UNUSED(maxAge);
    ua::BatchResult<ua::NodeResult> result;
    result.items.reserve(nodeIds.size());
    for (const auto& nodeId : nodeIds)
    {
      result.items.push_back(found(nodeId));
    }
    complete(std::move(result));
  }

  void enumerate_nodes_async(const ua::RequestInfo& request,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> complete) override
  {
    UA_UNUSED(request);
    std::vector<ua::NodeId> ids;
    ids.reserve(mCount);
    for (uint32_t i = 0; i < mCount; ++i)
    {
      ids.emplace_back(mIndex, mBase + i);
    }
    complete(ua::Result<std::vector<ua::NodeId>>{std::move(ids)});
  }

  /// Each Node's one Reference, its HasTypeDefinition, in one page whatever the page size.
  void read_references_async(const ua::RequestInfo& request, std::span<const ua::ReferenceQuery> queries,
    std::function<void(ua::BatchResult<ua::NodeReferencesResult>)> complete) override
  {
    UA_UNUSED(request);
    ua::BatchResult<ua::NodeReferencesResult> result;
    result.items.reserve(queries.size());
    for (const auto& query : queries)
    {
      if (resolve_slot(query.nodeId) == nullptr)
      {
        result.items.push_back(ua::NodeReferencesResult{ua::StatusCode{ua::Status::BadNodeIdUnknown}});
        continue;
      }
      ua::NodeReferences page;
      page.references = mReferences;
      result.items.push_back(ua::NodeReferencesResult{std::move(page)});
    }
    complete(std::move(result));
  }

  /// Completes inline, on the calling stack: the Value is immutable and the same for every caller, so the
  /// awaiting flow has nothing to suspend for.
  void read_values_async(const ua::RequestInfo& request, const ua::CallerInfo* caller,
    std::span<const ua::ValueReadItem> items, ua::Duration maxAge, bool setSourceTimestamp,
    std::function<void(ua::BatchResult<ua::DataValueResult>)> complete) override
  {
    UA_UNUSED(request);
    UA_UNUSED(caller);
    UA_UNUSED(maxAge);
    UA_UNUSED(setSourceTimestamp);
    ua::BatchResult<ua::DataValueResult> result;
    result.items.reserve(items.size());
    for (const auto& item : items)
    {
      const auto* slot = resolve_slot(item.value.node_id());
      if (slot == nullptr)
      {
        result.items.push_back(ua::DataValueResult{ua::StatusCode{ua::Status::BadNodeIdUnknown}});
        continue;
      }
      ua::DataValue value{ua::Variant{(*slot)->value()}};
      ua::index_range_utils::apply_to_value(value, item.value.index_range());
      result.items.push_back(ua::DataValueResult{std::move(value)});
    }
    complete(std::move(result));
  }

  /// Answered from a constant. Every read authorises, and the default reads the Node's description.
  std::optional<ua::PermissionType> effective_permissions(
    const ua::AccessIdentity& identity, const ua::Node* node) const override
  {
    UA_UNUSED(identity);
    UA_UNUSED(node);
    return ua::PermissionType{ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read};
  }

  uint32_t node_count() const
  {
    return mCount;
  }

  uint16_t index() const
  {
    return mIndex;
  }

private:
  ua::VoidResult on_attached(const ua::NamespaceContext& context) override
  {
    // The Nodes need the index, which is known only now, so they are built once, here, at startup.
    // Nothing on the read path ever writes.
    mIndex = context.index();
    const uint32_t built = (mSharing == Sharing::OneNode) ? 1U : mCount;
    mNodes.reserve(built);
    for (uint32_t i = 0; i < built; ++i)
    {
      mNodes.push_back(std::make_shared<StaticNode>(
        ua::NodeId{mIndex, mBase + i}, "PerfVar" + std::to_string(i), static_cast<int32_t>(i)));
    }
    return {};
  }

  // The one copy of the Node's shared_ptr a lookup makes.
  ua::NodeResult found(const ua::NodeId& nodeId) const
  {
    const auto* slot = resolve_slot(nodeId);
    if (slot == nullptr)
    {
      return ua::NodeResult{ua::StatusCode{ua::Status::BadNodeIdUnknown}};
    }
    return ua::NodeResult{std::shared_ptr<ua::Node>{*slot}};
  }

  // The slot holding the Node for @p nodeId, or null; borrowed, so resolving copies no shared_ptr.
  const std::shared_ptr<StaticNode>* resolve_slot(const ua::NodeId& nodeId) const
  {
    if (nodeId.namespace_index() != mIndex || !nodeId.identifier().is_numeric())
    {
      return nullptr;
    }
    const auto numeric = nodeId.identifier().get_numeric();
    if (numeric < mBase || numeric - mBase >= mCount)
    {
      return nullptr;
    }
    const auto slot = (mSharing == Sharing::OneNode) ? 0U : (numeric - mBase);
    return &mNodes[slot];
  }

  const std::string mUri;
  const uint32_t mCount;
  const uint32_t mBase;
  const Sharing mSharing;
  uint16_t mIndex{0};
  std::vector<std::shared_ptr<StaticNode>> mNodes;
  const ua::References mReferences{
    std::vector<ua::Reference>{ua::Reference{ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
      ua::ExpandedNodeId{ua::NodeId{ua::VariableTypeId::BaseDataVariableType}},
      true}}};
};

}  // namespace fuzz

#endif  // FUZZ_STATIC_ARRAY_NAMESPACE_H
