// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DESCRIBED_CONFORMANCE_NAMESPACE_H
#define UA_DESCRIBED_CONFORMANCE_NAMESPACE_H

// A namespace written as an application writes one, from the public headers alone: it has no Node class of
// its own and hands out the Nodes of a DescribedNodes store. Every other fact of its Nodes it holds itself:
// their descriptions, References, Variables' Values, Methods' handlers, Views' members, and the NodeVersion
// and ViewVersion Properties it advances. The namespace conformance suite runs every arm against it beside
// the in-memory namespace (namespace_refactor.md rule R3 and D2).
//
// Every member answers inline, from state held under one mutex, and calls its completion with that mutex
// released. A Method's handler may answer later; the call completes when the last handler has answered.

#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_described_nodes.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_string.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::test
{

class DescribedConformanceNamespace final : public Namespace
{
public:
  /// @param uri The namespace URI.
  explicit DescribedConformanceNamespace(String uri);

  ~DescribedConformanceNamespace() override;

  DescribedConformanceNamespace(const DescribedConformanceNamespace&) = delete;
  DescribedConformanceNamespace& operator=(const DescribedConformanceNamespace&) = delete;
  DescribedConformanceNamespace(DescribedConformanceNamespace&&) = delete;
  DescribedConformanceNamespace& operator=(DescribedConformanceNamespace&&) = delete;

  /// Installs the handler the calls of @p method run. The Nodes this namespace hands out offer no
  /// `MethodCallSource`, so the application installs handlers through the namespace.
  ///
  /// @param method  A Method this namespace holds.
  /// @param handler Invoked for each call of @p method; it answers through its completion, inline or later.
  /// @return Good; `Bad_NodeIdUnknown` for a NodeId this namespace does not hold; `Bad_NodeClassInvalid` for
  ///         a Node that is not a Method.
  StatusCode set_call_handler(const NodeId& method, MethodCallSource::CallHandler handler);

  String uri() const override;
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override;

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override;
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override;
  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete) override;

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override;
  void release_resume_token(ByteString token) override;

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override;

  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override;
  void add_to_view_async(const RequestInfo& request, const NodeId& view, std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override;
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override;

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override;

private:
  // Everything this namespace holds of one Node.
  struct Entry
  {
    explicit Entry(NodeDescription described);

    NodeDescription description;
    // The Reference halves the Node holds; replaced whole on a change, so that a read keeps its snapshot.
    std::shared_ptr<const std::vector<Reference>> references;
    // A Variable's Value; empty until the Variable is first given one.
    std::optional<DataValue> value;
    // A View's members.
    std::unordered_set<NodeId> viewMembers;
    // A Method's handler; null until one is installed.
    std::shared_ptr<const MethodCallSource::CallHandler> handler;
  };

  // The rest of a paged References read, kept until its token is passed back or released.
  struct PagedRead
  {
    NodeId nodeId;
    References remaining;
  };

  // Whether @p node is the Node this namespace hands out for @p nodeId: Good, `Bad_NodeIdUnknown`
  // (NodeDeleted) for one it has deleted, `Bad_InvalidArgument` (ForeignNode) for any other.
  VoidResult own(const Node& node, const NodeId& nodeId) const;

  // The Node for @p nodeId: the one held, or a new one carrying its description. Requires mMutex.
  NodeResult resolve_locked(const NodeId& nodeId);

  // The Property @p owner names by a HasProperty Reference to a Variable of this namespace whose BrowseName
  // is 0:@p name and that has no ModellingRule (VersionedNode), or null. Requires mMutex.
  Entry* version_property_locked(const Entry& owner, std::string_view name);

  // Advances a NodeVersion Property's String Value. Requires mMutex.
  VoidResult advance_node_version_locked(Entry& property);

  // Advances a ViewVersion Property's UInt32 Value (OPC 10000-3 5.4, Table 10). Requires mMutex.
  static VoidResult advance_view_version_locked(Entry& property);

  // Applies a Variable's Value write to @p entry. Requires mMutex.
  static VoidResult write_value_locked(Entry& entry, const WriteValue& write, bool serversOwn);

  // The Node that owns @p property by a HasProperty Reference, when this namespace holds it. Requires mMutex.
  std::optional<NodeId> property_owner_locked(const Entry& property) const;

  // Adds or removes Reference halves, advancing and reporting the versioned sources.
  void change_references(std::span<const ReferenceChange> changes, bool add,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  const String mUri;
  // The Nodes handed out; their descriptions are set from mEntries, under mMutex.
  DescribedNodes mStore;

  mutable std::mutex mMutex;
  std::unordered_map<NodeId, Entry> mEntries;  // guarded by mMutex
  std::unordered_map<uint64_t, PagedRead> mPagedReads;  // guarded by mMutex
  uint64_t mNextToken{1};  // guarded by mMutex
  uint64_t mNodeVersionCounter{0};  // guarded by mMutex
};

}  // namespace ua::test

#endif  // UA_DESCRIBED_CONFORMANCE_NAMESPACE_H
