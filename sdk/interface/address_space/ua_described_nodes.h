// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DESCRIBED_NODES_H
#define UA_DESCRIBED_NODES_H

/// @file
/// @brief A ready-made store of Nodes for a namespace that does not write its own Node class.
/// @ingroup address_space

#include "ua_attribute_id.h"
#include "ua_defines.h"
#include "ua_duration.h"
#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_variant.h"

#include <optional>

namespace ua
{

/// A ready-made Node store for a namespace that does not write its own Node class: it holds one Node
/// per NodeId while anyone holds it, and nothing once the last holder lets go.
///
/// A gateway or a computed namespace answers its lookups with @ref node_for and its writes with
/// @ref record_write, and so meets the `Node` contract without writing a Node class: one Node per
/// NodeId, `attributes()` answered at once and safe during a write, writes visible to every holder once
/// they complete, `deleted()` set by a delete.
///
/// It holds Nodes weakly. A namespace that wants to keep a Node's description longer than any caller
/// holds the Node (a cache) keeps the `shared_ptr<Node>` itself; the store still guarantees one Node per
/// NodeId while it is held.
///
/// Thread-safe: every member may be called from any thread, concurrently, also while the namespace
/// holds its own locks. No member calls back into the namespace or into the SDK.
///
/// The Nodes it hands out return `nullptr` from both probes (`external_value_source()`,
/// `method_call_source()`): their Values and Methods are served by the namespace's batched members.
/// @ingroup address_space
class DescribedNodes
{
public:
  DescribedNodes();
  ~DescribedNodes();

  DescribedNodes(const DescribedNodes&) = delete;
  DescribedNodes& operator=(const DescribedNodes&) = delete;
  DescribedNodes(DescribedNodes&&) = delete;
  DescribedNodes& operator=(DescribedNodes&&) = delete;

  /// The Node for `description.node_id()`: the one already held, now carrying this description, or a
  /// new one.
  ///
  /// Used both to answer a lookup and to apply a change the namespace learned of from its source: every
  /// holder of the Node sees the new description from then on. The description's age, for @ref held,
  /// starts now.
  ///
  /// @param description The Node's current Attributes.
  /// @return The Node; never null.
  [[nodiscard]] shared_ptr<Node> node_for(NodeDescription description);

  /// Applies a successful write to the held Node, if one is held; otherwise does nothing.
  ///
  /// Call it once the source has confirmed the write and before completing the write, so that every
  /// getter sees the new value when the completion runs. LocalizedText is merged per OPC 10000-4
  /// 5.10.4.1 (`LocalizedText::merged_with`); every other Attribute is replaced whole
  /// (`NodeDescription::try_with_attribute`). The read of the current description and the store of the
  /// new one happen under the Node's lock, so two concurrent writes to one Node both land.
  ///
  /// @param nodeId      The Node written.
  /// @param attributeId The Attribute written; not a Variable's Value.
  /// @param value       The written value in wire form.
  /// @return Good, also when no Node is held; or the status of `NodeDescription::try_with_attribute`
  ///         when the value cannot be applied, in which case the Node is unchanged. Never throws.
  ///
  /// A failure means the source accepted a value the Node cannot hold, so the Node no longer shows what
  /// the source holds. The Write service checks every value before the call, so this indicates a defect
  /// in the namespace or its source. The namespace logs the returned status with its ErrorDetail, reads
  /// the Node's Attributes from its source again and applies them with @ref node_for, and answers the
  /// write item with its source's answer, because the source holds the written value.
  [[nodiscard]] VoidResult record_write(
    const NodeId& nodeId, AttributeId attributeId, const Variant& value) noexcept;

  /// The Node held for @p nodeId, if one is held and its description was set no longer ago than
  /// @p maxAge; otherwise null, and the namespace asks its source.
  ///
  /// The namespace's immediate `find_node` answers from this, passing on the lookup's maxAge.
  ///
  /// @param nodeId The NodeId looked up.
  /// @param maxAge The oldest description acceptable, in milliseconds; `nullopt` accepts any age.
  /// @return The held Node, or null.
  [[nodiscard]] shared_ptr<Node> held(const NodeId& nodeId, std::optional<Duration> maxAge) const;

  /// Marks the held Node for @p nodeId deleted and forgets it, so that a later @ref node_for for the
  /// same NodeId makes a new Node and old holders keep seeing a deleted Node, never the new one's
  /// Attributes. Does nothing when no Node is held.
  ///
  /// A namespace calls it from its delete before the delete completes.
  ///
  /// @param nodeId The NodeId deleted.
  void remove(const NodeId& nodeId);

private:
  struct State;
  shared_ptr<State> mState;
};

}  // namespace ua

#endif  // UA_DESCRIBED_NODES_H
