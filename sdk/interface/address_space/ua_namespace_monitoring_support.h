// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_MONITORING_SUPPORT_H
#define UA_NAMESPACE_MONITORING_SUPPORT_H

/// @file
/// @brief The monitoring helper the SDK gives each namespace registration.
/// @ingroup address_space

#include <boost/asio/any_io_executor.hpp>
#include "ua_logger.h"
#include "ua_namespace_monitoring.h"
#include "ua_node.h"
#include "ua_sinks.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace ua
{
class Namespace;

namespace detail
{
class MonitoringSupportAccess;
}  // namespace detail
}  // namespace ua

namespace ua::default_ns
{

class SamplingEngine;

/// The monitoring helper the SDK gives each namespace registration.
///
/// A namespace reaches it through `context().monitoring()`; the address space creates one per
/// registration, runs its sampling on the address space's executor, and shuts it down before it shuts
/// the namespaces down (`AddressSpace::shutdown_async`). A namespace neither creates nor shuts it.
///
/// The namespace puts in each item the Node it resolved for it (`MonitoringCreateItem::node`), decides
/// how each item is fed - read by the helper at its interval (@ref Delivery::Sampled) or told of each
/// change by the namespace (@ref Delivery::Reported) - and passes the items here. From then on the
/// helper delivers to each item's sink: a Sampled item from what it reads at each tick, a Reported item
/// from what @ref attribute_changed reported since its last tick. At the first tick that finds an item's
/// Node deleted (`Node::deleted()`), the item receives the changes reported before the deletion and not
/// yet delivered, then `Bad_NodeIdUnknown` once, and nothing after it; it can still be modified and
/// deleted (Part 4 5.12.1.6).
///
/// At each tick of an interval the helper reads the Sampled items on a Variable's Value through the
/// registered namespace's `Namespace::read_values_async`: one call per distinct caller of the items'
/// sinks (`SampleSink::caller()`), with the server's own `RequestInfo` (never cancelled, no deadline),
/// maxAge 0 and the SourceTimestamp requested, each item carrying its registration's Node. The calls of
/// one tick are started before any is awaited, and each is split by the address space's MaxNodesPerRead
/// as it stands at the tick. The tick gives up its thread between calls, so a namespace that answers
/// inline holds an executor thread for one call at a time, not across the tick's calls: one call runs
/// as long as the namespace takes to answer it, and MaxNodesPerRead, when it is set, bounds its size. A
/// Sampled item on any other attribute, or on a VariableType's Value, is read from the Node's
/// description (`Node::attributes()`). A tick that finds the registered namespace gone delivers nothing.
///
/// Every value the helper delivers is narrowed to its registration's IndexRange
/// (`MonitoringCreateItem::indexRange`), as a Read of that range answers, so that registrations with
/// different ranges on one attribute each receive their own part. A Sampled read through
/// `Namespace::read_values_async` carries the range, and the namespace narrows the Value; a value read from
/// the description, and a value reported through @ref attribute_changed, is narrowed by the helper before
/// it is compared with the last value delivered, so a change outside the range is not delivered unless its
/// status or timestamps changed too. A namespace reports whole values; it does not narrow them.
///
/// Before the namespace is registered, `context().monitoring()` answers a helper that refuses every
/// create, modify and delete with `Bad_NotSupported` and the ErrorDetail `NamespaceNotRegistered`, and
/// ignores @ref attribute_changed and @ref structure_changed. A namespace calls `context().monitoring()`
/// each time rather than keeping the reference, so that it reaches its registration's helper once it has
/// one.
///
/// Thread-safety: every member is synchronous and may be called from any thread. No member but
/// @ref structure_changed calls a sink; sinks are called from the helper's ticks and from
/// @ref structure_changed, with no lock of the helper held.
///
/// @ingroup address_space
class NamespaceMonitoringSupport : public std::enable_shared_from_this<NamespaceMonitoringSupport>
{
public:
  /// How an item is fed.
  enum class Delivery
  {
    /// The helper reads the item's attribute at each tick of the item's interval and delivers a changed
    /// value.
    Sampled,
    /// The namespace reports each change through @ref attribute_changed; the helper delivers it at the
    /// item's next tick. An item on the Value whose interval is 0 receives every change reported (up to
    /// its queue size); any other receives the latest change reported in each interval.
    Reported,
  };

  /// Stops the helper's sampling if the address space has not already shut it down.
  ~NamespaceMonitoringSupport();

  NamespaceMonitoringSupport(const NamespaceMonitoringSupport&) = delete;
  NamespaceMonitoringSupport& operator=(const NamespaceMonitoringSupport&) = delete;
  NamespaceMonitoringSupport(NamespaceMonitoringSupport&&) = delete;
  NamespaceMonitoringSupport& operator=(NamespaceMonitoringSupport&&) = delete;

  /// A create request and the delivery the namespace chose for it.
  struct ResolvedMonitoringItem
  {
    /// The create request. Its `node` is the Node the namespace resolved and trusts for the item's NodeId,
    /// or null when the NodeId is unknown; the helper keeps it for the registration's life and reads it.
    MonitoringCreateItem item;
    Delivery delivery{Delivery::Sampled};  ///< How the item is fed.
  };

  /// The outcome of one create.
  struct CreateResult
  {
    MonitoringCreateItemResult result{StatusCode{Status::BadInternalError}};  ///< Per-item create result.
  };

  /// Creates one registration per item.
  ///
  /// Each item's `indexRange` is parsed here, once, for the registration's life. An item on the Value,
  /// Sampled or Reported, has the larger of its requested interval and the Node's
  /// MinimumSamplingInterval (Part 4 5.12.1.2). A Reported Value item whose interval is then 0 is
  /// revised to 0; any other item is revised to its interval rounded up to a sampling bucket. How a
  /// Sampled item on the Value is read - through the namespace for a Variable, from the description for
  /// a VariableType - is decided here, from the Node's description, for the registration's life.
  ///
  /// @param items The resolved items, in request order.
  /// @return One result per item, in order: Good with the handle and revised interval;
  ///         `Bad_NodeIdUnknown` (ErrorDetail `NodeIdUnknown`) for an item with no Node;
  ///         `Bad_IndexRangeInvalid` for an item whose `indexRange` is not a NumericRange;
  ///         `Bad_NotSupported` (`NamespaceNotRegistered`) before registration, for every item; or
  ///         `Bad_Shutdown` (`MonitoringShutDown`) once the address space has shut the helper down.
  std::vector<CreateResult> create_monitoring(std::span<const ResolvedMonitoringItem> items);

  /// A modify request with the delivery the namespace chose for it, which may differ from the
  /// delivery the item was created with.
  struct ResolvedMonitoringModifyItem
  {
    MonitoringModifyItem item;  ///< The modify request.
    Delivery delivery{Delivery::Sampled};  ///< How the item is fed from now on.
  };

  /// The outcome of one modify.
  struct ModifyResult
  {
    MonitoringModifyItemResult result{StatusCode{Status::BadInternalError}};  ///< Per-item modify result.
  };

  /// Changes each registration's interval, queue size and delivery, revising the interval as
  /// @ref create_monitoring does. A registration whose Node was found deleted answers Good with the
  /// requested interval and stays inactive.
  ///
  /// @param items The modify requests, in request order.
  /// @return One result per item, in order: Good with the revised interval;
  ///         `Bad_MonitoredItemIdInvalid` for an unknown handle; `Bad_NotSupported`
  ///         (`NamespaceNotRegistered`) before registration; `Bad_Shutdown` (`MonitoringShutDown`) once
  ///         shut down.
  std::vector<ModifyResult> modify_monitoring(std::span<const ResolvedMonitoringModifyItem> items);

  /// Deletes registrations; nothing is delivered to them afterwards.
  ///
  /// @param handles The handles @ref create_monitoring issued.
  /// @return One result per handle, in order: Good; `Bad_MonitoredItemIdInvalid` for an unknown
  ///         handle, or one deleted already; `Bad_NotSupported` (`NamespaceNotRegistered`) before
  ///         registration.
  std::vector<VoidResult> delete_monitoring(std::span<const MonitoringHandle> handles);

  /// Reports that @p attribute of the Node @p node now holds @p value.
  ///
  /// Every Reported registration on that attribute of that Node is given @p value for its next tick;
  /// Sampled registrations, other attributes and other Nodes are not affected. A namespace calls it
  /// after the change is committed, from any thread, and may call it while it holds its own locks: it
  /// takes only the helper's internal mutex, calls nothing while holding it, and calls no sink.
  /// Does nothing before registration, after shutdown, when no Reported registration is on the
  /// attribute, or for a registration whose Node reports `deleted()`: a change reported after a Node's
  /// deletion is not delivered, while one reported before it is delivered ahead of the deletion's
  /// `Bad_NodeIdUnknown`.
  ///
  /// @param node      The NodeId of the Node that changed.
  /// @param attribute The attribute that changed.
  /// @param value     The attribute's new value, as a Read of it returns it.
  void attribute_changed(const NodeId& node, AttributeId attribute, const DataValue& value);

  /// Reports that the structure of the Value of the Variable @p variable changed: the DataTypeEncoding its
  /// Value is serialized with, as when its DataType changes (OPC 10000-4 7.39.1 Table 180).
  ///
  /// Every registration on that Variable's Value, Sampled or Reported, is marked through its sink
  /// (`SampleSink::mark_structure_changed`), so that one data change notification of each monitored item
  /// carries the StructureChanged bit; registrations on other attributes are not marked. A namespace calls it
  /// once per change, after the change is committed, from any thread. It calls the sinks with no lock of the
  /// helper held; a sink does not block (`SampleSink`), so a namespace may call it while it holds its own
  /// locks. Does nothing before registration, after shutdown, or when nothing monitors the Value.
  ///
  /// The SDK's in-memory namespace calls it when the DataType of a Variable whose Value its own
  /// `create_monitoring` registered changes. Every other namespace calls it itself when the structure of a
  /// Value it serves changes: one that implements its own monitoring, one that relies on the base
  /// `Namespace`'s default monitoring, and a subclass of the in-memory namespace that overrides
  /// `create_monitoring` without calling it.
  ///
  /// @param variable The NodeId of the Variable whose Value's structure changed.
  void structure_changed(const NodeId& variable);

  /// Reports that the Value of the Property @p property, which belongs to the Node @p owner, changed, by any
  /// path (NR-37, NR-38).
  ///
  /// When the Property is semantic (`data_access_utils::is_semantic_property`: the SemanticChange flag, or a
  /// BrowseName for which OPC 10000-8 requires it), every registration on the Value of @p owner, Sampled or
  /// Reported, is marked through its sink (`SampleSink::mark_semantics_changed`), so that the next data
  /// change notification of each monitored item carries the SemanticsChanged bit (OPC 10000-4 7.39.1). The
  /// Property's first Value marks them too: a client that monitors the owner has seen it without that Value.
  ///
  /// A namespace calls it after the change is committed, from any thread, also while it holds its own locks,
  /// as @ref structure_changed. The SDK's in-memory namespace calls it for every Value change of a Property
  /// it holds whose owner it holds, whoever made the change. A Property held in another namespace than its
  /// owner gets no bit: that namespace does not hold the owner's registrations.
  ///
  /// @param owner    The NodeId of the Node that owns the Property, the source of its HasProperty Reference.
  /// @param property The Property.
  /// @param initial  Whether the change gave the Property its first Value (NR-38 rule 1).
  /// @return True when a SemanticChangeEvent is due: the Property has the SemanticChange flag of
  /// AccessLevelEx
  ///         (OPC 10000-3 5.6.2) and @p initial is false. The namespace then reports @p owner through
  ///         `NamespaceContext::semantics_changed`. The answer does not depend on registrations, so it is the
  ///         same before registration and after shutdown, when nothing is marked.
  /// @throws UaException when @p property's `attributes()` throws.
  bool property_value_changed(const NodeId& owner, const Node& property, bool initial);

private:
  friend class ua::detail::MonitoringSupportAccess;

  struct Record
  {
    MonitoringHandle engineHandle{0};
    std::weak_ptr<Node> node;
    AttributeId attributeId{AttributeId::Value};
    Delivery delivery{Delivery::Sampled};
  };

  /// The helper before registration: no engine, refuses every create, modify and delete.
  NamespaceMonitoringSupport();

  /// A registration's helper, sampling on @p executor and reading through @p owner, each read split by
  /// what @p maxNodesPerRead answers at the tick (unset: not split).
  NamespaceMonitoringSupport(boost::asio::any_io_executor executor, ua::Logger logger,
    std::weak_ptr<ua::Namespace> owner, std::function<std::optional<uint32_t>()> maxNodesPerRead);

  /// Samples the registrations; reads through the registered namespace, which it holds weakly.
  std::shared_ptr<SamplingEngine> mEngine;
  mutable std::mutex mMutex;
  std::unordered_map<MonitoringHandle, Record> mRecords;
  MonitoringHandle mNextHandle{1};
  bool mShutDown{false};
};

}  // namespace ua::default_ns

#endif  // !UA_NAMESPACE_MONITORING_SUPPORT_H
