// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BASE_NODE_DEFAULT_H
#define UA_BASE_NODE_DEFAULT_H

#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_data_value.h"
#include "ua_node_description.h"
#include "ua_instance_tracker.h"
#include "ua_reference.h"

#include <unordered_set>
#include <atomic>
#include <functional>
#include <optional>
#include <shared_mutex>

namespace ua::default_ns
{

class Namespace;
class NamespaceMonitoringSupport;
class BaseNode;

namespace base_node_details
{

using SharedReferences = std::shared_ptr<const std::vector<ua::Reference>>;

struct MutationSnapshot
{
  NodeId nodeId;
  NodeClass nodeClass{NodeClass::Unspecified};
  SharedReferences references;
};

}  // namespace base_node_details

/// How a Node reaches the namespace that created it, for the changes made on the Node directly: the steps of
/// a Value change, made by a write or reported by a value source's `notify_value_changed` (NR-37, NR-38,
/// NR-40), and a Reference change (NR-27). The namespace sets @ref owner when it creates the Link and clears
/// it, under the lock, when it is destroyed; a Node reads it under the shared lock, for the length of its
/// call.
struct NamespaceLink
{
  std::shared_mutex mutex;
  Namespace* owner{nullptr};
};

class BaseNode : public Node
{
public:
  BaseNode() = delete;
  BaseNode(const BaseNode&) = delete;
  BaseNode(BaseNode&&) noexcept = delete;
  BaseNode& operator=(const BaseNode&) = delete;
  BaseNode& operator=(BaseNode&&) noexcept = delete;
  ~BaseNode() override = default;

  // The completions of the members below, which the in-memory namespace's batched members run on its own
  // Nodes. They are the accessor's completions.
  using GetReferencesCallback = NodeAccessor::GetReferencesCallback;
  using ReferenceModifyCallback = NodeAccessor::ReferenceModifyCallback;
  using WriteAttributeCompleteCallback = NodeAccessor::WriteAttributeCompleteCallback;
  using ReadValueCompleteCallback = NodeAccessor::ReadValueCompleteCallback;
  using WriteValueCompleteCallback = NodeAccessor::WriteValueCompleteCallback;
  using IsNodeInViewCallback = NodeAccessor::IsNodeInViewCallback;
  using ViewModifyCallback = NodeAccessor::ViewModifyCallback;

  void get_references_async(GetReferencesCallback callback) const noexcept;

  void add_reference_async(
    NodeId type, ExpandedNodeId target, bool isForward, ReferenceModifyCallback callback) noexcept;
  void add_references_async(std::vector<ua::Reference> references, ReferenceModifyCallback callback) noexcept;

  void remove_reference_async(
    NodeId type, ExpandedNodeId target, bool isForward, ReferenceModifyCallback callback) noexcept;
  void remove_references_async(
    std::vector<ua::Reference> references, ReferenceModifyCallback callback) noexcept;

  virtual NodeClass get_node_class() const = 0;

  /// The description this Node holds, copied under its lock: a reference-count increment (NR-21 rule 5). A
  /// write replaces the held description with a new one, so a holder of an earlier copy keeps reading one
  /// body. A deleted node keeps describing its last Attributes; holders learn of the delete from
  /// @ref deleted. @see Node::attributes
  NodeDescription attributes() const override;

  /// An Attribute of the held description in its wire form; an empty Variant for one the Node does not
  /// carry.
  Variant read_attribute(AttributeId attributeId) const;

  /// The NodeId this node was built with.
  NodeId node_id() const;

  /// The BrowseName of the held description; the null QualifiedName when the node was created without one.
  QualifiedName browse_name() const;

  virtual void write_attribute_async(
    AttributeId attributeId, Variant attributeValue, WriteAttributeCompleteCallback callback);

  virtual void call(const CallMethodRequest& methodToCall, shared_ptr<const MethodCallContext> context,
    CallMethodCompleteCallback callback) const;

  virtual void read_value(Duration maxAge, bool setSourceTimestamp, const ReadValueId& nodeToRead,
    const AccessIdentity* identity, ReadValueCompleteCallback) const;

  virtual void write_value_async(
    const WriteValue& nodeToWrite, const AccessIdentity* identity, WriteValueCompleteCallback);

  virtual void is_node_in_view_async(NodeId nodeId, IsNodeInViewCallback callback) const noexcept;
  virtual void add_node_to_view_async(NodeId nodeId, ViewModifyCallback callback) noexcept;

  /// Answers from the flag the namespace sets when it deletes this node; a plain atomic load, so a
  /// holder can ask without taking the node's lock. @see Node::deleted
  bool deleted() const noexcept override
  {
    return mDeleted.load(std::memory_order_acquire);
  }

protected:
  mutable std::shared_mutex mMutex;

  /// Holds the description `NodeDescription::try_from_attributes` builds for @p nodeClass from no
  /// Attributes; the namespace replaces it with the one it built from the creation's Attributes before it
  /// publishes the Node.
  BaseNode(const NodeId& nodeId, NodeClass nodeClass);

  virtual bool is_attribute_id_valid(AttributeId attributeId) const;

  /// What a committed write to an attribute of this node owes its monitoring, taken by the write path under
  /// mMutex.
  struct ChangeObservers
  {
    /// The helper of the registration that monitors this node; set only while a Reported registration is on
    /// it.
    std::shared_ptr<NamespaceMonitoringSupport> helper;
    /// The helper of the registrations made on this Variable's Value, told when a DataType replaces the one
    /// stored; set only for the DataType of a Variable.
    std::shared_ptr<NamespaceMonitoringSupport> structureHelper;
  };

  /// The caller holds mMutex.
  ChangeObservers change_observers_locked(AttributeId attributeId) const;

  /// Reports @p value as the new value of @p attributeId to the helper. Called while the lock that committed
  /// the change is held, where the in-memory namespace holds that lock, so that changes are reported in the
  /// order they were committed (NR-48 rule 4); the helper takes only its own mutex and calls no sink.
  void report_change(const ChangeObservers& observers, AttributeId attributeId, const DataValue& value) const;

private:
  friend class Namespace;
  friend class VariableNode;
  friend class ViewNode;

  // Atomic so that deleted() reads it without the lock; written under mMutex by
  // mark_as_deleted, and read under it by every operation as before.
  std::atomic<bool> mDeleted{false};
  // Reported registrations created on this Node object (DL-68 (6)): the namespace raises the count before a
  // Reported registration exists and lowers it after one is gone, so the write paths report a change to
  // @ref mMonitoringHelper only while the count is above 0. Kept on the Node object, never looked up by
  // NodeId, so a Node added again under the same NodeId starts at 0.
  std::atomic<uint32_t> mReportedRegistrations{0};
  // Guarded by mMutex. Set before a Reported registration, or a registration on the Value, is created on this
  // Node, so before the count first rises, and kept after the registrations end: a change reported to a
  // helper with no registration on the Node delivers nothing. Weak, so a Node that outlives its namespace and
  // registration reaches nothing when written.
  std::weak_ptr<NamespaceMonitoringSupport> mMonitoringHelper;
  NodeId mNodeId;
  // The namespace that created this node, set once before the node is published and only compared, never
  // followed (Namespace::own_node, NR-43 rule 2). The NodeId's namespace index is not enough: after a failed
  // registration another namespace may receive the same index (NR-39 rule 4).
  const Namespace* mOwner{nullptr};
  /// The owning namespace's flag that a Node of it may hold a version (NR-36 Cost): set when this Node is
  /// named 0:NodeVersion or 0:ViewVersion. Shared, so that a Node kept after its namespace sets nothing
  /// freed.
  shared_ptr<std::atomic<bool>> mMayHoldVersions;
  /// The link to the namespace that created this Node, set with @ref mOwner; null for a Node no namespace
  /// configured.
  shared_ptr<NamespaceLink> mNamespaceLink;
  // The Node's Attributes (NR-21 rule 5). Guarded by mMutex: a reader copies it, a write builds the new
  // description from it and stores that under the same hold, so two concurrent writes both land.
  NodeDescription mDescription;
  base_node_details::SharedReferences mReferences;

  // Live-node counter for leak diagnostics (RAII; zero-cost in release). Its
  // delta across a create/destroy loop reveals leaked address-space nodes.
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::DefaultBaseNodeTag>
    mInstanceTracker;

  // The held description's value of the Attribute in wire form, a VariableType's Value as a DataValue, or
  // an empty Variant when the node does not carry it. Checks neither the deleted flag nor the NodeClass.
  // The caller holds mMutex.
  Variant stored_attribute(AttributeId attributeId) const;
  // The held description with @p value written to @p attributeId (`NodeDescription::try_with_attribute`).
  // Throws the description's refusal. The caller holds mMutex for writing.
  NodeDescription written_description(AttributeId attributeId, const Variant& value) const;
  // A BrowseName that names a version Property (0:NodeVersion or 0:ViewVersion).
  static bool is_version_name(const QualifiedName& name) noexcept;
  /// Adds (@p add) or removes @p references on this Node through the namespace that created it, which
  /// checks that it still holds the Node and reports the change (NR-27). Refused with Bad_InvalidState when
  /// no namespace created the Node or that namespace is gone.
  VoidResult change_through_namespace(std::vector<Reference> references, bool add, bool reportMissing);
  base_node_details::MutationSnapshot mutation_snapshot() const;
  void commit_reference_snapshot(base_node_details::SharedReferences references);
  void mark_as_deleted();

  /// What @ref change_references did: its answer, and whether this Node's References changed.
  struct ReferencesOutcome
  {
    VoidResult result;
    bool changed{false};
  };

  /// Adds (@p add) or removes @p references among this Node's own References under its lock, so that each
  /// change is atomic for the Node (F14). An add of a Reference the Node holds, or one @p references repeats,
  /// is refused whole with Bad_DuplicateReferenceNotAllowed (OPC 10000-3 4.3.4); a removal removes every held
  /// Reference identified as the same, and answers Uncertain_ReferenceNotDeleted when @p reportMissing and
  /// none was held. A deleted Node answers Bad_NodeIdUnknown.
  ReferencesOutcome change_references(const std::vector<Reference>& references, bool add, bool reportMissing);

  /// Leaves out every Reference whose target is one of @p targets, under this Node's lock.
  /// @return Whether any was left out; false for a deleted Node.
  bool remove_references_to(const std::unordered_set<NodeId>& targets);
  /// Links @p helper and counts one more Reported registration on this Node.
  void raise_reported_registrations(std::weak_ptr<NamespaceMonitoringSupport> helper);
  /// Links @p helper without counting a registration: a Sampled registration on this Variable's Value, which
  /// a change of the Variable's DataType marks StructureChanged through the helper.
  void link_monitoring_helper(std::weak_ptr<NamespaceMonitoringSupport> helper);
  /// Counts one Reported registration fewer; never below 0.
  void lower_reported_registrations() noexcept;
};

}  // namespace ua::default_ns

#endif  // UA_BASE_NODE_DEFAULT_H
