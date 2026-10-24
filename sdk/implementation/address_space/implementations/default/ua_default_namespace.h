// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_DEFAULT_H
#define UA_NAMESPACE_DEFAULT_H

#include "ua_access_restriction_type.h"
#include "ua_address_space_change_events.h"
#include "ua_default_base_node.h"
#include "ua_namespace.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_default_variable_node.h"
#include "ua_role_permission_type.h"
#include "ua_string.h"
#include "ua_node_id.h"
#include "ua_node_class.h"
#include "ua_referencetype_id.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_to_string.h"
#include "ua_value_source.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua
{

class AddressSpaceImpl;

namespace default_ns
{

class VariableNode;
class ViewNode;

class Namespace : public ua::Namespace
{
public:
  Namespace() = delete;
  Namespace(const Namespace&) = delete;
  Namespace(Namespace&&) noexcept = delete;
  Namespace& operator=(const Namespace&) = delete;
  Namespace& operator=(Namespace&&) noexcept = delete;
  ~Namespace() override;

  String uri() const override;

  /// Stops this namespace's sampling: cancels the engine's bucket timers and drops every
  /// tracked monitoring registration. Until this runs, the sampling timers keep the executor
  /// alive and joining it never returns.
  ///
  /// @param callback Invoked once sampling has stopped. Completes inline - the stop is
  ///                 synchronous under the engine's own lock - and is safe to call twice.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override;

  /// Answers from the local store, one @ref resolve_here per NodeId, inline. maxAge is ignored: the store is
  /// the source.
  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override;

  /// Answers from the local store, always. The whole namespace is in memory, so there is nothing
  /// this could have to go away for and it never declines.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override;

  /// The typed lookup below declares the name `find_node` too, which would otherwise hide the
  /// interface's own.
  using ua::Namespace::find_node;

  /// The NodeIds of every Node this namespace holds, inline.
  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete) override;

  /// The typed local lookup: this namespace's own node object, downcast, or null.
  ///
  /// @note The template argument is REQUIRED - `find_node<Node>(id)`, not `find_node(id)`. It had a
  ///       default until the interface gained a `find_node` of its own, at which point `find_node(id)`
  ///       silently began to mean the other one: same spelling, same argument, a different type and
  ///       a different contract. Removing the default makes that impossible to write by accident and
  ///       turns every affected call site into a compile error rather than a changed meaning.
  template<typename NodeType>
  shared_ptr<NodeType> find_node(const NodeId& nodeId);

  shared_ptr<Node> create_node(const NodeId& nodeId, NodeClass nodeClass);

  template<typename NodeType = Node>
  shared_ptr<NodeType> create_node(const NodeId& nodeId);

  DeleteNodeResult delete_node(const NodeId& nodeId, bool deleteTargetRefs);

  static shared_ptr<Namespace> create(string_view uri, boost::asio::any_io_executor executor);

  // Monitoring overrides: through `context().monitoring()`, the registration's helper. Each item is
  // Reported - told of each change by this namespace's write paths - when it is on an attribute other
  // than the Value, or on the Value at interval 0 of a Node whose MinimumSamplingInterval is 0 or
  // absent; every other item is Sampled. A modify decides again by the same rule.
  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override;
  void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override;
  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override;

  // The batched members over this namespace's own Nodes (NR-70 C1). Each item's Node is checked before it is
  // used: one this namespace did not return for the item's NodeId fails that item with Bad_InvalidArgument
  // and the ErrorDetail ForeignNode, and a deleted one with Bad_NodeIdUnknown (NR-43 rule 2, NR-44 rule 3).

  /// Reads each Node's References under its lock. A ReferenceType hint is applied with
  /// `reference_type_may_match_hint` (NR-61), before the page is taken; the direction is not applied. The
  /// resume token is the offset of the next Reference in the hinted list, so it holds nothing.
  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override;

  /// Reads each Variable's Value from its source, the default store or the handlers, and narrows it to the
  /// item's IndexRange.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;

  /// Writes each item, starting them in item order. A ranged or ValidBits write of a Variable on the default
  /// store is merged and stored under the store's lock, so it is atomic (NR-11 rule 4); one of a Variable
  /// with handlers reads the current Value through them and writes the merged whole Value, as before C3. Any
  /// other Attribute, a VariableType's Value included, is written as the Write service decodes a client's
  /// write, or as given for the server's own. Nothing is reported as versioned until C2.
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  /// Takes an item when this namespace holds its Method and runs the Method's handler, or answers
  /// Bad_NotSupported for a Method with none; declines an item whose Method another namespace holds (NR-15
  /// rule 5). The item's Object is not used.
  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override;

  /// Answers from the View's explicit member set (NR-16 rule 4). A candidate of another server is not a
  /// member.
  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override;

  /// Adds each Node to the View's explicit member set and advances its ViewVersion, as the View's own add
  /// does.
  void add_to_view_async(const RequestInfo& request, const NodeId& view, std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  /// Creates each Node with its Attributes under the namespace's lock, so that no lookup finds a Node before
  /// its Attributes are applied; a Node an Attribute refuses is not created, and the item answers the
  /// refusal.
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override;

  /// Deletes each Node under the namespace's lock: it is marked deleted and leaves the Views that list it
  /// (each advancing its ViewVersion before the completion runs, F11). With @p halves `Both`, one pass over
  /// the Nodes left removes their References to the deleted Nodes, and a deleted Node's References to Nodes
  /// of other namespaces are reported; with `ThisHalfOnly` the Nodes left keep theirs and nothing is
  /// reported.
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override;

  /// Adds each half to its source Node under that Node's lock (F14): a half the Node holds, or one the call
  /// repeats, answers Bad_DuplicateReferenceNotAllowed; a source this namespace does not hold answers
  /// Bad_NodeIdUnknown.
  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  /// Removes each half from its source Node under that Node's lock: a half the Node does not hold answers
  /// Uncertain_ReferenceNotDeleted; a source this namespace does not hold answers Bad_NodeIdUnknown.
  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  /// Sets the answers returned by the namespace-wide access-control defaults.
  /// Configuration-only: a second call is refused with `BadInvalidState`.
  /// `nullopt` Role permissions explicitly selects a vendor-specific model;
  /// an engaged empty array is the standard Role model granting nothing.
  void set_namespace_defaults(std::optional<std::vector<RolePermissionType>> rolePermissions,
    std::optional<AccessRestrictionType> accessRestrictions);

  /// The namespace-wide `RolePermissions` fallback this namespace answers with.
  ///
  /// @return The three-state default; see `ua::Namespace::default_role_permissions`.
  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override;

  /// @return The channel condition, or `nullopt` for none.
  std::optional<AccessRestrictionType> default_access_restrictions() const override;

  /// The steps for a Value that a write made on one of this namespace's Variables directly, or a change its
  /// source reported, changed (NR-37, NR-38, NR-40), run for the namespace @p link names: the
  /// SemanticsChanged marks and the SemanticChangeEvent of @ref values_committed, then the
  /// ConfigurationVersion advance for a Constant Variable, after which @p answer receives @p result, or the
  /// advance's failure. When the namespace is gone, or the context refuses the advance, @p answer receives @p
  /// result. A null @p answer is allowed.
  static void own_value_committed(NamespaceLink& link, shared_ptr<VariableNode> variable, bool initial,
    VoidResult result, std::function<void(VoidResult)> answer) noexcept;

  /// Adds (@p add) or removes @p references on @p holder, a Node of the namespace @p link names, for a change
  /// made on the Node directly. The namespace checks that it still holds @p holder (Bad_NodeIdUnknown
  /// otherwise), changes the References as `BaseNode::change_references` does, and reports a change with
  /// `context().model_changed()`, which advances the model generation (NR-27 rule 2). Refused with
  /// Bad_InvalidState when the namespace is gone.
  static VoidResult change_own_references(NamespaceLink& link, const shared_ptr<BaseNode>& holder,
    std::vector<Reference> references, bool add, bool reportMissing);

  /// The logger of the namespace @p link names, for a step on one of its Nodes made outside its members that
  /// has a code to log: the address space's, once attached; one that logs nothing when the namespace is gone.
  static ua::Logger logger_of(NamespaceLink& link) noexcept;

protected:
  /// Resolves one id against the local store. **The extension point for what resolution MEANS.**
  ///
  /// Both @ref find_node and @ref find_nodes_async answer from here and from nowhere else, which is what
  /// keeps them from disagreeing. A subclass that wants resolution to mean something different -
  /// aliases, a redirect, a computed view - overrides THIS, once, and both routes obey it.
  ///
  /// Overriding @ref find_nodes_async instead changes only how a batch is delivered, never what resolves,
  /// and a subclass that put its resolution logic there would find the synchronous form answering
  /// straight past it. That is not hypothetical: it is what happened to an alias-resolving fixture
  /// here the first time the synchronous form existed, and the symptom was BadNodeIdInvalid from a
  /// namespace that had the node.
  ///
  /// Called on the caller's thread and possibly in a loop, so it takes the read lock, releases it,
  /// and builds its answer outside - never invoking a user callback.
  virtual NodeResult resolve_here(const NodeId& nodeId);

  mutable std::shared_mutex mMutex;

  Namespace(string_view uri, boost::asio::any_io_executor executor);

private:
  friend class ua::AddressSpaceImpl;

  const String mUri;

  std::unordered_map<NodeId::Identifier, shared_ptr<BaseNode>> mNodes;

  /// The namespace access-control defaults, as one immutable object.
  ///
  /// The two move together deliberately. Held as separate members, a reader that took the Role
  /// permissions from one configuration and the access restrictions from the next would evaluate a
  /// pairing that never existed.
  struct Defaults
  {
    std::optional<std::vector<RolePermissionType>> rolePermissions{std::vector<RolePermissionType>{}};
    std::optional<AccessRestrictionType> accessRestrictions;
  };

  /// The published snapshot, read WITHOUT the namespace mutex.
  ///
  /// Every Read authorises, and authorisation asks for these defaults once per operation. Reaching
  /// them through `mMutex` made that a shared-lock acquisition per operation on the one mutex the
  /// whole namespace shares - and a shared_mutex read-lock WRITES its reader counter, so every core
  /// wrote the same cache line on every operation. Measured on a 16-core host: a single cache line
  /// written by every core costs 51% of throughput at eight threads and 58% at sixteen, and caps
  /// scaling at +7.3% for a doubling of cores (`raw/read_concurrency/sweep-out.txt`).
  ///
  /// An acquire load of a pointer is a pure READ. The line stays Shared in every core's cache and
  /// generates no coherency traffic, because nothing writes it except a reconfiguration.
  ///
  /// Deliberately NOT `atomic<shared_ptr<const Defaults>>`, which would be simpler and would handle
  /// lifetime by itself: copying the handle is a refcount increment, which puts every core back to
  /// writing one line on every operation - the configuration measured at -58%.
  std::atomic<const Defaults*> mDefaults;

  /// Every snapshot ever published, kept until the namespace is destroyed.
  ///
  /// This is what makes the lock-free read sound, and the argument is short enough to check: a
  /// reader can only hold a snapshot that was published at or before its load, and no published
  /// snapshot is ever freed while the namespace lives, so no reader can hold a dangling pointer.
  /// No hazard pointers, no epochs, no grace period.
  ///
  /// The cost is retention - one small object per reconfiguration, never reclaimed. Defaults are
  /// configuration, so that is bounded by how often an integrator reconfigures, not by load. Guarded
  /// by @ref mMutex, which only the writer takes.
  std::vector<std::unique_ptr<const Defaults>> mPublishedDefaults;
  bool mNamespaceDefaultsConfigured{false};

  shared_ptr<BaseNode> find_node_internal(const NodeId& nodeId);

  /// The Node an item carries, as this namespace's own: Bad_InvalidArgument with the ErrorDetail ForeignNode
  /// when this namespace did not create it or does not return it for @p nodeId, and Bad_NodeIdUnknown when it
  /// has been deleted. A Node of another NodeId is the one returned for @p nodeId when this namespace's
  /// resolution (@ref resolve_here) answers it, as an alias does; that is asked only then.
  Result<shared_ptr<BaseNode>> own_node(const Node& node, const NodeId& nodeId);

  /// The one source every item's Variable has, when every item is a Variable of this namespace with that
  /// source and no item is screened out (NR-11 rule 3.2); null otherwise.
  std::shared_ptr<ValueSource> common_source(std::span<const ValueReadItem> items);

  /// Reads @p item from its Variable's default source through the source's synchronous member and answers
  /// @p complete at once: no source call, no grouping and no join (NR-13a rule 1, DL-115 (2)). Returns false,
  /// leaving @p complete untouched, when the item is not a Variable of this namespace without an application
  /// source; never throws.
  bool read_from_default_source(const ValueReadItem& item, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)>& complete) noexcept;

  /// A Value this namespace committed, for @ref values_committed.
  struct CommittedValue
  {
    shared_ptr<const VariableNode> variable;
    /// The write gave the Variable its first Value (NR-38 rule 1).
    bool initial{false};
    /// Set by @ref values_committed: the Variable has the Constant bit and the Value was not its first.
    bool constant{false};
    /// The item of the write_async call that committed it.
    std::size_t index{0};
  };

  /// NR-37 and NR-38 for Values this namespace committed: for each Variable that is a Property of a Node this
  /// namespace holds, found from the inverse HasProperty Reference the Property holds, the monitoring helper
  /// marks the owner's registrations (`property_value_changed`), and one SemanticChangeEvent lists the owners
  /// whose flagged Property changed. Sets `constant` on each Value that was not a first one of a Variable
  /// with the Constant bit (NR-40), and returns whether any was; the caller then reports them once through
  /// `context().constant_values_changed`. Takes the namespace's shared lock; never throws.
  bool values_committed(std::span<CommittedValue> committed) noexcept;

  /// Runs @ref values_committed for @p committed on the namespace @p link names, then answers the write_async
  /// call through @p answer, without the link's lock: at once, or once ConfigurationVersion is advanced when
  /// an item changed a Constant Value, a failed advance then being the answer of each Constant item that was
  /// Good.
  template<typename Answer>
  static void finish_value_writes(NamespaceLink& link, std::span<CommittedValue> committed, Answer answer,
    BatchResult<VoidResult> answers, std::vector<VersionedNode> versioned) noexcept;

  /// Writes @p items, which all have the one source @p source, in one call to it (NR-13a rules 1 and 2), with
  /// @p complete wrapped once to run the steps for the committed Values.
  void write_to_common_source(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items, std::shared_ptr<ValueSource> source,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) noexcept;

  /// The one source every item's Variable has, when every item is a Value write to a Variable of this
  /// namespace with that source, none writes an IndexRange or ValidBits, and none is screened out (NR-11
  /// rule 3.2); null otherwise.
  std::shared_ptr<ValueSource> common_write_source(std::span<const ValueWriteItem> items);

  /// Writes @p item to its Variable's default source through the source's synchronous member, installing it
  /// when the Variable has no source, then tells the Reported registrations, runs the steps for the committed
  /// Value (@ref finish_value_writes) and answers @p complete, with no completion wrapper (NR-13a rule 1,
  /// DL-115 (2)). Returns false, leaving @p complete untouched, when the item is not a Value write to a
  /// Variable of this namespace without an application source; never throws.
  bool write_to_default_source(const CallerInfo* caller, const ValueWriteItem& item,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>& complete) noexcept;

  /// The Value writes of one source that has several in a write_async call: the items at @p indices, and
  /// their answers once started.
  struct SourceWrites
  {
    std::shared_ptr<ValueSource> source;
    std::vector<std::size_t> indices;
    std::vector<VariableNode::ValueWritten> answers;
  };

  /// The sources that have more than one of @p items' Value writes, each with its items in order.
  std::vector<SourceWrites> source_write_groups(std::span<const ValueWriteItem> items);

  /// Calls @p group's source once with its items; once it answers, the Reported registrations on each
  /// committed item's Node are told and each item's answer is given. A failure of the call is every item's.
  static void write_group(const ValueSource::WriteContext& context, std::span<const ValueWriteItem> items,
    SourceWrites group) noexcept;

  /// Calls @p source once with the items at @p indices, then gives each of @p answers, in order, its item's
  /// answer; a failure of the call is every item's.
  static void read_group(const ValueSource::ReadContext& context, std::span<const ValueReadItem> items,
    std::shared_ptr<ValueSource> source, const std::vector<std::size_t>& indices,
    std::vector<std::function<void(DataValueResult)>> answers) noexcept;

  void configure_node(const shared_ptr<BaseNode>& node);
  /// The description a Node of @p nodeClass is created with: the Attributes this namespace gives every Node
  /// of the NodeClass, then @p given, a later one replacing an earlier one, built at once (NR-21 rule 5);
  /// AccessLevel and AccessLevelEx one value, as a write makes them. Throws the description's refusal.
  static NodeDescription creation_description(
    const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& given);
  /// Reports a change of this namespace's Nodes made outside the address space's routes, which advances the
  /// model generation (NR-27 rule 2). Callable under @ref mMutex.
  void advance_model_generation() const noexcept;
  /// The logger for a NodeVersion or ViewVersion that cannot advance: the address space's, once attached.
  ua::Logger version_logger() const;

  template<typename NodeType = Node>
  auto create_node_internal(
    const NodeId& nodeId, const InitialAttributes& initialAttributes = {}) -> shared_ptr<NodeType>;

  shared_ptr<Node> create_node_internal(
    const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& initialAttributes = {});

  /// Creates a Node with @p initialAttributes under the namespace's lock; a refused Attribute creates nothing
  /// and is the answer.
  NodeResult create_with_attributes(
    const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& initialAttributes) noexcept;

  /// Removes a Node from this namespace and marks it deleted; called under the namespace's lock. With
  /// @p removeReferencesToIt, its NodeId joins @p deleted, for @ref remove_references_to_locked, and its
  /// References to Nodes of other namespaces are the answer.
  DeleteNodeResult delete_node_internal(
    const NodeId& nodeId, bool removeReferencesToIt, std::unordered_set<NodeId>& deleted);

  /// Removes, from every Node of this namespace, the References whose target is one of @p deleted; called
  /// under the namespace's lock, once per delete call.
  /// @return The Nodes that lost a Reference.
  std::vector<shared_ptr<BaseNode>> remove_references_to_locked(const std::unordered_set<NodeId>& deleted);

  /// This namespace's half of each change, on its source Node (add_references_async,
  /// remove_references_async).
  void change_own_references(std::span<const ReferenceChange> changes, bool add,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>& complete) noexcept;

  /// Removes @p deleted from every View of this namespace that lists it, under the namespace's lock so
  /// a Node created again with the same NodeId cannot be removed in its place; expired entries and
  /// @p deleted itself leave the list of Views.
  /// @return The Views that listed @p deleted.
  std::vector<shared_ptr<ViewNode>> remove_from_views_locked(const NodeId& deleted);

  /// The ViewVersion Properties of Views whose content changed, found while the namespace is alive, so that
  /// they can be advanced after an asynchronous step that does not hold the namespace.
  struct ViewVersions
  {
    Logger logger;
    std::vector<std::pair<NodeId, shared_ptr<VariableNode>>> properties;
  };

  /// The ViewVersion Property of each of @p views that has one. Called without the namespace's lock.
  ViewVersions view_versions_of(const std::vector<shared_ptr<ViewNode>>& views);

  /// Advances each of @p views' ViewVersions, then invokes @p done; at once when there is none. A failure is
  /// logged: the View's content has changed. Uses nothing of the namespace.
  static void advance_view_versions(ViewVersions views, std::function<void()> done);

  /// The 0:NodeVersion (with @p view, 0:ViewVersion) Property of @p node: a HasProperty target of this
  /// namespace with that BrowseName and no ModellingRule (NR-36 rule 2, an InstanceDeclaration does not
  /// count); null when there is none, at once while no Node of this namespace was given such a name. Takes
  /// the namespace's shared lock unless @p locked says the caller holds its lock.
  shared_ptr<VariableNode> version_property(const BaseNode& node, bool view, bool locked = false);

  /// Gives @p property, a NodeVersion (a String) or with @p view a ViewVersion (a UInt32 that skips 0), a
  /// value it does not hold (NR-55), then @p done; Bad_TypeMismatch (`NodeVersionTypeMismatch`,
  /// `ViewVersionTypeMismatch`) when it holds another type. The Value is read and replaced under the default
  /// store's lock, so concurrent advances never give one value twice.
  /// Uses nothing of the namespace but @p counter, its NodeVersion counter, so that it may run after the
  /// namespace is gone.
  static void advance_version(shared_ptr<std::atomic<uint64_t>> counter, shared_ptr<VariableNode> property,
    bool view, std::function<void(VoidResult)> done);

  /// One Node a call changed whose NodeVersion it advances and reports.
  struct VersionedChange
  {
    shared_ptr<BaseNode> node;
    /// Created in this operation (`ReferenceChange::sourceCreated`): reported, its NodeVersion kept.
    bool created{false};
  };

  /// The outcome of @ref advance_versions: the Nodes to report, and the Nodes whose NodeVersion holds another
  /// type than String, with why.
  struct VersionsAdvanced
  {
    std::vector<VersionedNode> reported;
    std::unordered_map<NodeId, StatusCode> refused;
  };

  /// Advances the NodeVersion of each versioned Node of @p changes, then @p done. Called without the
  /// namespace's lock.
  void advance_versions(std::vector<VersionedChange> changes, std::function<void(VersionsAdvanced)> done);

  /// The Views this namespace created, for the deletes that must update their members. Guarded by
  /// mMutex.
  std::vector<std::weak_ptr<ViewNode>> mViews;

  /// Whether a Node of this namespace was named 0:NodeVersion or 0:ViewVersion: until then no Node is
  /// versioned and the members skip the version work (NR-36 Cost). Shared with the Nodes, which set it; never
  /// cleared.
  const shared_ptr<std::atomic<bool>> mMayHoldVersions{std::make_shared<std::atomic<bool>>(false)};
  /// The last NodeVersion this namespace gave; shared with an advance that completes after a handler answers.
  const shared_ptr<std::atomic<uint64_t>> mNodeVersionCounter{std::make_shared<std::atomic<uint64_t>>(0)};
  /// What this namespace's Nodes reach it through (@ref own_value_committed); cleared by the destructor.
  const shared_ptr<NamespaceLink> mLink{std::make_shared<NamespaceLink>()};
};

template<typename NodeType>
auto Namespace::create_node(const NodeId& nodeId) -> shared_ptr<NodeType>
{
  const WriteLock lock(mMutex);

  return create_node_internal<NodeType>(nodeId);
}

template<typename NodeType>
auto Namespace::create_node_internal(
  const NodeId& nodeId, const InitialAttributes& initialAttributes) -> shared_ptr<NodeType>
{
  if (find_node_internal(nodeId))
  {
    throw UaException{Status::BadNodeIdExists,
      ErrorDetail::build("NodeAlreadyExists", "Node already exists in namespace", "DefaultNamespace")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  }

  if (nodeId.namespace_index() != context().index())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("NamespaceIndexMismatch",
        "Node namespace index does not match this namespace index",
        "DefaultNamespace")
        .context(ua::ContextKeys::actual, std::to_string(nodeId.namespace_index()))
        .context(ua::ContextKeys::expected, std::to_string(context().index()))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  }

  auto node = NodeType::create(nodeId);
  BaseNode& created = *node;
  created.mDescription = creation_description(nodeId, created.get_node_class(), initialAttributes);
  configure_node(node);

  mNodes.emplace(std::make_pair(nodeId.identifier(), node));
  if constexpr (std::is_same_v<NodeType, ViewNode>)
  {
    mViews.push_back(node);
  }
  advance_model_generation();

  return node;
}

template<typename NodeType>
shared_ptr<NodeType> Namespace::find_node(const NodeId& nodeId)
{
  const ReadLock lock(mMutex);

  return find_node_internal(nodeId);
}

}  // namespace default_ns
}  // namespace ua

#endif  // UA_NAMESPACE_DEFAULT_H
