// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_H
#define UA_NAMESPACE_H

/// @file
/// @brief Abstract namespace contract for nodes, references and monitoring in the address space.
/// @ingroup address_space

#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_authorization.h"
#include "ua_namespace_items.h"
#include "ua_namespace_context.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_request_info.h"
#include "ua_node_class.h"
#include "ua_reference_halves.h"
#include "ua_access_restriction_type.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <optional>
#include <span>
#include <vector>

namespace ua
{

class NamespaceRegisterNodesDelegate;
class NamespaceHistoryDelegate;

class Node;
class AddNodesItem;
class AddNodesResult;
class AddReferencesItem;

/// A reference from a deleted node whose target lives in another namespace.
///
/// Returned for a deleted Node by Namespace::delete_nodes_async so the caller (the owning AddressSpace)
/// can remove the corresponding inverse reference from the target node, which a single namespace cannot
/// reach on its own.
/// @ingroup address_space
struct ExternalReference
{
  NodeId referenceType;  ///< Type of the dangling reference.
  ExpandedNodeId target;  ///< Cross-namespace endpoint that still holds the inverse reference.
  bool isForward;  ///< Direction of the reference as seen from the deleted node.
};

/// Outcome of deleting one Node (Namespace::delete_nodes_async).
///
/// On success the payload is the set of `ExternalReference` entries that require
/// cross-namespace inverse-reference cleanup by the AddressSpace (empty when the node
/// had no external references). On failure it carries the rich `StatusCode`,
/// including any attached `ErrorDetail` cause chain.
using DeleteNodeResult = Result<std::vector<ExternalReference>>;

/// One OPC UA namespace within the server address space.
///
/// A namespace owns a disjoint set of nodes addressed under a single namespace URI / index. The owning
/// AddressSpace routes every request to the namespace that owns the target node. Implementations decide
/// their own threading and serialization (typically a private strand); callers invoke from any thread and
/// a completion runs on an unspecified worker thread - do not block it.
///
/// @par One rule explains every member here
/// **Answer synchronously if you can. Go asynchronous only in batches. Decline a
/// capability you do not have.**
///
/// - A member that can answer from state you already hold returns its answer, and
///   returns `nullopt` to mean *ask me again through the asynchronous form* -
///   never to mean *denied*. The immediate @ref find_node and @ref effective_permissions
///   are this shape.
/// - Every asynchronous member is BATCHED. There is deliberately no asynchronous
///   single-node lookup: a namespace fronting a remote server collapses N cold
///   round trips into one, and that is only worth anything if it is the only way
///   in.
/// - Everything optional declines by default, so a namespace implements what it
///   can do and says nothing about what it cannot. Monitoring is the exception: once
///   the namespace is registered, the SDK's monitoring helper samples every item by
///   default (@ref create_monitoring_async).
///
/// Implementations override the pure-virtual core (@ref uri, @ref shutdown_async,
/// @ref find_nodes_async, @ref read_references_async and @ref read_values_async) and
/// may override the optional members; the base provides a decline default for each.
///
/// @par The batched members
/// The `*_async` members taking a @ref RequestInfo first (@ref find_nodes_async,
/// @ref read_references_async, @ref read_values_async, @ref write_async and the rest) are
/// the namespace API every service and every accessor reaches the namespace through.
/// Conventions that hold for every one of them:
///
/// - Each takes the request's @ref RequestInfo first. The members that act on behalf of a
///   Session (@ref read_values_async, @ref write_async, @ref call_async,
///   @ref create_monitoring_async) also take a `const CallerInfo*`, null for the server's own
///   call.
/// - Each completes EXACTLY ONCE, inline or later, on any thread, with one result per item in
///   item order. A bad batch status fails every item. The address space checks the count and
///   accepts one completion; an exception thrown by a member becomes `Bad_InternalError` for
///   that call's items. None is `noexcept`. No SDK lock is held while a member runs, and a
///   member must not block.
/// - **Lifetime.** Everything a member is given - the `RequestInfo`, the `CallerInfo` pointer,
///   the spans, and everything an item refers to - is valid until the member RETURNS. The two
///   exceptions are the Nodes items carry, which the caller holds by `shared_ptr` until the
///   call completes, and `CallItem::context`, which is shared and may be kept. A namespace that
///   answers later copies what it needs before returning: a `RequestInfo` or `CallerInfo` is
///   cheap to copy, and copying `CallerInfo::identity` keeps the identity alive.
/// - **Ownership.** The address space holds a registered namespace until the address space is
///   destroyed. The completion a member is given does not hold the namespace: a namespace that
///   answers after its member has returned keeps itself alive for that work, for example by
///   holding a `shared_ptr` to itself in what it posts, or checks through a `weak_ptr` that it
///   still exists. Its last reference may be released on any thread, including the thread on
///   which it completes a call, so its destructor must not join or wait for that thread.
/// - A member is called by the address space. Calling one directly from other code is allowed
///   (a forwarding namespace, a test), and skips the address space's work around it; each
///   member with such work says what is skipped.
///
/// @ingroup address_space
class Namespace
{
public:
  Namespace() = default;

  virtual ~Namespace()
  {}

  Namespace(const Namespace&) = delete;
  Namespace& operator=(const Namespace&) = delete;
  Namespace(Namespace&&) = delete;
  Namespace& operator=(Namespace&&) = delete;

  /// Returns the namespace URI that uniquely identifies this namespace.
  ///
  /// @return The namespace URI, the string form used to register and look this namespace up in
  ///         the server's namespace array.
  virtual String uri() const = 0;

  /// Gives this namespace the context of its registration, once.
  ///
  /// The address space calls it when registration starts, with the context it created for that registration,
  /// before lifecycle participants prepare the registration; a namespace that forwards to another calls it on
  /// that other namespace from its `on_attached`, with the context it was given. It stores @p context,
  /// which @ref context answers from then on, and then calls `on_attached`, whose answer it returns.
  ///
  /// A namespace object accepts one context: a second call is refused with `Bad_InvalidState` and changes
  /// nothing, and registering an object that is already attached - by an earlier registration, or by a
  /// namespace that forwards to it - is refused with that status. When a registration fails after the object
  /// was attached, the object keeps its context and cannot be registered again; the application registers a
  /// new namespace object. A registration refused before it attaches (an empty or duplicate URI, a full
  /// namespace table, shutdown) leaves the object unattached. The context @ref context answers before attach
  /// is refused with `Bad_InvalidArgument`.
  ///
  /// Lifecycle preparation may dispatch node operations through the private candidate route after
  /// this call; ordinary public routing does not expose the namespace until registration commits.
  ///
  /// @param context The registration's context; only the address space creates one.
  /// @return Good, `Bad_InvalidState` when this object was attached already, `Bad_InvalidArgument` for the
  ///         context a namespace answers before it is attached, or the answer of `on_attached` (an
  ///         exception it throws is answered as its status).
  VoidResult attach(NamespaceContext context);

  /// Stops the background work this namespace is running, without destroying it.
  ///
  /// A namespace that samples values, refreshes a cache or arms any other timer keeps the
  /// executor it was given ALIVE for as long as that work is armed. Joining an executor with
  /// work still on it never returns, and the symptom is a process that will not exit with
  /// nothing in the log to say why. So the server asks every namespace to stop, during
  /// shutdown, before it joins.
  ///
  /// PURE VIRTUAL ON PURPOSE. A default no-op would let a namespace that arms timers compile
  /// unchanged and hang the executor exactly as before, and nobody would find out until a
  /// process refused to terminate. If your namespace has nothing running, say so explicitly by
  /// completing the callback at once:
  ///
  /// @code
  /// void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  /// {
  ///   if (callback) { callback(VoidResult{}); }  // nothing armed
  /// }
  /// @endcode
  ///
  /// CONTRACT. Invoke @p callback EXACTLY ONCE, when nothing this namespace started is still
  /// running or can start again. Completing it early is worse than completing it late: the
  /// server takes the callback as permission to join the executor. Completing INLINE is
  /// allowed - the caller is written to tolerate it - as is completing much later from your own
  /// strand. Calling this twice must be safe: the second call completes immediately, because
  /// shutdown and destruction both reach it.
  ///
  /// Report a failure to stop through the @ref VoidResult rather than by never completing; the
  /// server bounds its wait, and a namespace that goes silent is reported by URI.
  ///
  /// Monitoring is not this member's to stop: the monitoring helper of the registration
  /// (`NamespaceContext::monitoring`) is the address space's, which shuts it down, and waits for it,
  /// before it calls this.
  ///
  /// @param callback Invoked exactly once when this namespace has no work left running. Runs on
  ///                 an unspecified worker thread. Never throws.
  virtual void shutdown_async(std::function<void(VoidResult)> callback) noexcept = 0;

  // --- Batched members (conventions: see the class documentation) ---

  /// Looks up nodes this namespace owns. **The lookup.** Required in its final form.
  ///
  /// Batched because a namespace fronting a remote server collapses N round trips into one. The
  /// namespace that hands out a Node keeps it: while anyone holds the Node for a NodeId, every lookup of
  /// that NodeId answers that same Node, and the namespace keeps it current (see `Node::attributes`).
  /// The SDK keeps no copy and no table of Nodes. A namespace without a Node class of its own answers
  /// with `DescribedNodes`.
  ///
  /// @param request The request served.
  /// @param nodeIds NodeIds of this namespace to look up.
  /// @param maxAge  The Read service's maxAge (OPC 10000-4 5.10.2.2), in milliseconds, for the
  ///                Attributes of the Nodes it reads a non-Value Attribute of; `nullopt` from every
  ///                other caller, and the namespace then uses its own default. A namespace whose store
  ///                is its source ignores it.
  /// @param complete One @ref NodeResult per NodeId: the Node, or `Bad_NodeIdUnknown` for a NodeId this
  ///                namespace does not hold, with any ErrorDetail.
  virtual void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) = 0;

  /// Looks up one node from state this namespace already holds. **The immediate form of
  /// @ref find_nodes_async.**
  ///
  /// `nullopt` means *ask me through `find_nodes_async`*, never *no such node*: a NodeId this
  /// namespace does not hold is an engaged result carrying `Bad_NodeIdUnknown`. Called on the caller's
  /// thread, possibly in a loop: never blocks, never waits on a lock it does not expect to get, never
  /// calls back into the SDK.
  ///
  /// @param nodeId The NodeId to look up.
  /// @param maxAge As @ref find_nodes_async. A caching namespace declines rather than answer from a
  ///               copy older than @p maxAge allows (`DescribedNodes::held` does this).
  /// @return The outcome, or `nullopt` to be asked in a batch. The default declines.
  virtual std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge);

  /// Enumerates the NodeIds of every node this namespace owns. Optional; used by tooling such as
  /// NodeSet export and the event-graph check, never on a service path.
  ///
  /// @param request  The request served (the server's own).
  /// @param complete The owned NodeIds, or `Bad_NotSupported` (the default) with an ErrorDetail.
  virtual void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete);

  /// Reads the References nodes hold. **The one route to References** for Browse, BrowseNext,
  /// TranslateBrowsePaths, the event climb and accessors. Required in its final form.
  ///
  /// Return the References a Node holds: type, target, direction. Do not fill in target Attributes;
  /// the services look targets up. `direction` and `referenceTypeHint` are hints: the service filters
  /// again, so ignoring them is correct. A namespace that applies the hint leaves a Reference out only
  /// when it knows the Reference's type is neither a hinted type nor a subtype of one; one that applies
  /// the direction leaves an inverse Reference out of a `Forward` query only when it knows the
  /// Reference's type is not symmetric, since the services take a symmetric Reference as forward
  /// (OPC 10000-4 5.8.2.2); when unsure it returns the Reference (see @ref ReferenceQuery).
  /// `maxReferences` and `resumeToken` page the answer; a resume token passed back is consumed by the
  /// call whatever it answers.
  ///
  /// @param request  The request served.
  /// @param queries  One query per Node; each carries the Node this namespace returned for it.
  /// @param complete One @ref NodeReferencesResult per query.
  virtual void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) = 0;

  /// Releases what a resume token from @ref read_references_async holds, when its caller abandons it
  /// (a Browse continuation point released or discarded, a TranslateBrowsePaths path answered before
  /// its References were read to the end). A token passed back to @ref read_references_async is
  /// consumed by that call whatever it answers and is never released here. The caller releases an
  /// abandoned token through the namespace that issued it, which an index reused after this namespace
  /// is removed cannot misdirect; an exception is caught and logged there. A namespace whose tokens
  /// hold nothing (offsets, for example) keeps the default.
  ///
  /// @param token The abandoned token.
  ///
  /// Default: does nothing.
  virtual void release_resume_token(ByteString token);

  /// Reads Variables' Values. **The only batched Attribute read**: every other Attribute is read from
  /// `Node::attributes()`. Required in its final form.
  ///
  /// The namespace returns each item's Value for its IndexRange (OPC 10000-4 7.27), fetching only that
  /// part from its source or narrowing the whole Value with `index_range_utils::apply_to_value`; a range
  /// that selects nothing is `Bad_IndexRangeNoData`. The service has already checked the range's syntax,
  /// keeps applying DataEncoding, and fails an item whose Value is larger than its range with
  /// `Bad_InternalError`, so a namespace never returns more than was asked for. A namespace answering
  /// from a copy may set the ServerTimestamp to when it obtained the copy; otherwise the service sets it.
  /// Values serve Variables only: a VariableType's Value is a description Attribute.
  ///
  /// @param request            The request served.
  /// @param caller             On whose behalf the Values are read; null for the server's own reads.
  /// @param items              One item per Value; each carries the Node this namespace returned.
  /// @param maxAge             The Read request's maxAge in milliseconds (OPC 10000-4 5.10.2.2); 0 from
  ///                           every other caller, which asks for the source to be read.
  /// @param setSourceTimestamp `true` when the caller wants the SourceTimestamp.
  /// @param complete           One `DataValueResult` per item.
  virtual void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) = 0;

  /// Writes Attributes: Variables' Values and every other writable Attribute. Optional.
  ///
  /// The Write service has already checked, the same for every namespace: access, WriteMask and
  /// AccessLevel, the DataType and ValueRank, the range's syntax, WriteFullArrayOnly, and an OptionSet's
  /// ValidBits. The namespace applies the write to its data: a ranged write per OPC 10000-4 7.27, against
  /// the current value, which decides whether the written value fits the range (`Bad_IndexRangeNoData`
  /// when the range lies outside the current value or the current value is empty, `Bad_TypeMismatch`
  /// when the written value's type or shape does not match it, or `Bad_WriteNotSupported` when the Node
  /// does not support ranged writes; `index_range_utils::apply_write` helps), and an OptionSet ValidBits
  /// write as `(value & validBits) | (current & ~validBits)`. A result may carry a Good subcode, such as
  /// Good_Clamped, which the service passes to the client.
  ///
  /// **Obligations.**
  /// - A successful write of a non-Value Attribute is applied to the Node this namespace hands out
  ///   before the completion runs (see `Node::attributes`; `DescribedNodes::record_write`).
  /// - A namespace whose Nodes carry NodeVersion Properties advances the NodeVersion of each versioned
  ///   Variable or VariableType whose DataType, ValueRank or ArrayDimensions it changed, and reports the
  ///   Node in the second completion argument (@ref VersionedNode). One that leaves it empty has
  ///   NodeVersions that never advance. The output lists only Nodes whose NodeVersion this call changed.
  /// - A namespace that lets clients write a VariableType's DataType, ValueRank or ArrayDimensions
  ///   (it sets those WriteMask bits) takes on OPC 10000-3 6.5: it keeps the type's subtypes and
  ///   instances consistent with the change, or refuses the write. The SDK checks neither. A namespace
  ///   that does not set those WriteMask bits has nothing to do.
  ///
  /// **Called by the address space.** A call by other code is this namespace changing its own data: the
  /// address space then does none of its work around it (the model generation and the ModelChangeEvent
  /// for the reported Nodes). Report such a change through the namespace's context, or make the change
  /// through the address space (an accessor or `AddressSpace`) to have that work done.
  ///
  /// @param request  The request served.
  /// @param caller   On whose behalf the write is made; null for the server's own writes.
  /// @param items    One item per write; each carries the Node this namespace returned.
  /// @param complete One `VoidResult` per item, and the versioned Nodes the call changed (usually empty).
  ///
  /// Default: `Bad_NotWritable` per item.
  virtual void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// Runs Method calls, or declines them. Optional.
  ///
  /// The Call service has already applied its rules to every item (the Method is a component of the
  /// Object or of its type, the arguments, Executable, AccessRestrictions). It asks the Object's
  /// namespace first, in one batch, and the Method's namespace for the items the first declines; an item
  /// both decline is answered `Bad_NotImplemented`. Decline with `nullopt`, never with a status: a
  /// handler that answers `Bad_NotImplemented` is a call result and is not re-run elsewhere. A namespace
  /// takes an item it can run, for example a call on one of its own Objects of a Method another
  /// namespace defines.
  ///
  /// @param request  The request served.
  /// @param caller   On whose behalf the calls are made; null for the server's own calls.
  /// @param items    One item per call; use only the Node of each item that is this namespace's own.
  /// @param complete One result per item: the call's result, or `nullopt` to decline.
  ///
  /// Default: every item declined.
  virtual void call_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete);

  /// Answers which Nodes are members of a View this namespace holds. Optional.
  ///
  /// Asked of the namespace that holds the View Node, once per page of Browse targets. The address
  /// space decides two cases itself and does not ask: the View Node is a member of its own View, and
  /// the Server Object (i=2253) is a member of no View (OPC 10000-3 5.4). Membership does not depend on
  /// the caller.
  ///
  /// @param request  The request served.
  /// @param view     The View Node, of this namespace.
  /// @param nodes    Candidate members: local Nodes by namespace index, remote ones as stored.
  /// @param complete One `BoolResult` per candidate.
  ///
  /// Default: true exactly for the targets of the View Node's own References in this namespace, read
  /// with @ref read_references_async; a remote candidate is not a member.
  virtual void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete);

  /// Adds Nodes to a View this namespace holds. Optional.
  ///
  /// A namespace whose View carries a ViewVersion Property advances it itself when the View's content
  /// changes (OPC 10000-3 5.4, Table 10), and does not report that: a content change leaves the View
  /// Node's NodeVersion unchanged, so no ModelChangeEvent is due for it.
  /// **The versioned-Node output** lists only Nodes whose NodeVersion this call changed, as
  /// @ref VersionedNode states (a View Node only when it gained or lost a Reference); never a View
  /// whose only change is its ViewVersion, which the namespace advances itself.
  ///
  /// **Called by the address space.** A call by other code is this namespace changing its own data: the
  /// address space then does none of its work around it (refusing the Server Object as a member, the
  /// model generation). Make the change through the address space to have that work done.
  ///
  /// @param request  The request served.
  /// @param view     The View Node, of this namespace.
  /// @param nodes    The Nodes to add; may be of other namespaces.
  /// @param complete One `VoidResult` per Node, and the versioned Nodes the call changed.
  ///
  /// Default: `Bad_NotSupported` per Node.
  virtual void add_to_view_async(const RequestInfo& request, const NodeId& view,
    std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// Creates Nodes, each with its Attributes, in one call. Optional.
  ///
  /// A new Node has no References yet: the creators add them afterwards with @ref add_references_async.
  /// So nothing is versioned and the completion has no versioned-Node output. A Node takes its initial
  /// NodeVersion from its creation; nothing advances while it is built.
  ///
  /// **Called by the address space.** A call by other code is this namespace changing its own data: the
  /// address space then does none of its work around it (the model generation and the ModelChangeEvent).
  /// Report such a change through the namespace's context, or create the Node through `AddressSpace` to
  /// have that work done.
  ///
  /// @param request  The request served (the server's own: creation is never a client's call).
  /// @param nodes    The Nodes to create.
  /// @param complete One @ref NodeResult per Node: the created Node, or why it was not created.
  ///
  /// Default: `Bad_NotSupported` per item.
  virtual void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete);

  /// Deletes Nodes. Optional.
  ///
  /// For each Node: removes it and the Reference halves it holds. With @p halves `Both`, it also removes
  /// the References of other Nodes of this namespace that target it, and reports in its result the
  /// References whose other half lives in another namespace, which the address space removes there. With
  /// `ThisHalfOnly`, the other Nodes of this namespace keep their halves of References to it, left
  /// unresolved (OPC 10000-4 5.7.4.1 and 5.7.4.2, `deleteTargetReferences` FALSE), and are neither
  /// changed nor reported; the address space removes nothing in other namespaces, whatever the result
  /// lists. The cascade over children is the address space's. Before the completion runs, each deleted Node's
  /// `deleted()` answers true (a `DescribedNodes` namespace calls `DescribedNodes::remove`), so that every
  /// holder of it, the monitoring included, sees `Bad_NodeIdUnknown`.
  ///
  /// A namespace whose Nodes carry NodeVersion Properties reports each deleted Node that was versioned
  /// and each surviving versioned Node that lost a Reference to a deleted Node (only with `Both`), after
  /// advancing the survivors' NodeVersions. A View that only loses a member advances its ViewVersion and is
  /// not reported.
  /// **The versioned-Node output** lists only Nodes whose NodeVersion this call changed, as
  /// @ref VersionedNode states (a View Node only when it gained or lost a Reference); never a View
  /// whose only change is its ViewVersion, which the namespace advances itself.
  ///
  /// **Called by the address space.** A call by other code is this namespace changing its own data: the
  /// address space then does none of its work around it (removing the other halves in other namespaces,
  /// the model generation and the ModelChangeEvent). Report such a change through the namespace's
  /// context, or delete through `AddressSpace` to have that work done.
  ///
  /// @param request  The request served (the server's own).
  /// @param nodes    The Nodes to delete.
  /// @param halves   `Both` to remove the halves other Nodes of this namespace hold of References to the
  ///                 deleted Nodes; `ThisHalfOnly` to leave them.
  /// @param complete One `DeleteNodeResult` per Node, and the versioned Nodes the call changed.
  ///
  /// Default: `Bad_NotSupported` per item.
  virtual void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes,
    ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete);

  /// Adds Reference halves held by Nodes of this namespace. Optional.
  ///
  /// Each change is one half; the inverse half is a separate change sent to the target's namespace. An
  /// add of a half the Node already holds stores nothing and answers `Bad_DuplicateReferenceNotAllowed`
  /// (References are identified as OPC 10000-3 4.3.4 says); the address space treats that answer as
  /// success where it adds a half itself. A Node that holds the Reference with a type that is neither the one
  /// asked for nor a subtype of it answers `Bad_DuplicateReferenceNotAllowed` with the ErrorDetail
  /// `DuplicateReferenceOfAnotherType`, which the address space passes on, since the half asked for is not
  /// held. A namespace whose Nodes carry NodeVersion Properties advances
  /// the NodeVersion of each versioned Node that gained a half and reports it. A source the change marks
  /// `sourceCreated` was created in this operation: its NodeVersion is not advanced, and it is still
  /// reported, so that the operation's event lists it as added (see @ref ReferenceChange::sourceCreated).
  /// **The versioned-Node output** lists only Nodes whose NodeVersion this call changed, as
  /// @ref VersionedNode states (a View Node only when it gained or lost a Reference); never a View
  /// whose only change is its ViewVersion, which the namespace advances itself.
  ///
  /// **Called by the address space.** A call by other code is this namespace changing its own data: the
  /// address space then does none of its work around it (the other half of a hierarchical, GeneratesEvent,
  /// HasSubtype or HasEncoding Reference, the OPC 10000-3 6.2.7 check of a HasSubtype between VariableTypes,
  /// the model generation and the ModelChangeEvent). Report such a change through the namespace's context, or
  /// make the change through the address space (an accessor or `AddressSpace`) to have that work done.
  ///
  /// @param request  The request served.
  /// @param changes  The halves to add.
  /// @param complete One `VoidResult` per change, and the versioned Nodes the call changed.
  ///
  /// Default: `Bad_NotSupported` per change.
  virtual void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// Removes Reference halves held by Nodes of this namespace. Optional.
  ///
  /// The removal of a half the Node does not hold answers `Uncertain_ReferenceNotDeleted`, and a change
  /// whose source this namespace does not hold answers `Bad_NodeIdUnknown`: the address space reads that
  /// answer, when it removes the halves of a deleted Node's References, as a Node that holds nothing.
  /// Versions and reports as @ref add_references_async.
  ///
  /// **Called by the address space.** As @ref add_references_async "add_references_async": a direct call
  /// skips the other half of a required pair, the model generation and the ModelChangeEvent.
  ///
  /// The versioned-Node output follows @ref add_references_async.
  ///
  /// @param request  The request served.
  /// @param changes  The halves to remove.
  /// @param complete One `VoidResult` per change, and the versioned Nodes the call changed.
  ///
  /// Default: `Bad_NotSupported` per change.
  virtual void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// Creates monitoring registrations. Optional.
  ///
  /// @param request  The request served: for CreateMonitoredItems, the deadline its timeoutHint sets from its
  ///                 arrival, and a cancellation flag set when the create has ended, after which no answer is
  ///                 read.
  /// @param caller   The subscription's current caller, `sink->caller()` at the time of the call; null
  ///                 for a sink with no Session.
  /// @param items    The items to register. An item from CreateMonitoredItems carries the Node this
  ///                 namespace's lookup returned for it for the same request (@ref
  ///                 MonitoringCreateItem::node) and the IndexRange to which the namespace narrows every
  ///                 sample it delivers (@ref MonitoringCreateItem::indexRange); a sample larger than the
  ///                 range fails its monitored item with `Bad_InternalError`.
  /// @param complete One result per item: a handle, or why the item was refused.
  ///
  /// Default: once the namespace is registered, every item goes to the registration's monitoring helper
  /// (`context().monitoring()`) as `NamespaceMonitoringSupport::Delivery::Sampled` with the Node it
  /// carries: the helper reads a Variable's Value through @ref read_values_async and any other attribute
  /// from the Node's description (`Node::attributes()`) at each tick of the item's sampling interval, and
  /// delivers a value that changed. An item that carries no Node is answered `Bad_NodeIdUnknown`
  /// (ErrorDetail `NodeIdUnknown`). Before registration, `Bad_NotSupported` (ErrorDetail
  /// `NamespaceNotRegistered`) per item. Override it, with @ref modify_monitoring_async and
  /// @ref delete_monitoring_async, to report changes as they happen rather than have them sampled, or to
  /// decline.
  virtual void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete);

  /// Modifies monitoring registrations. Optional.
  ///
  /// @param request  The request served.
  /// @param items    The modifications, by handle.
  /// @param complete One result per item.
  ///
  /// Default: the registration's monitoring helper (`context().monitoring()`) modifies what it issued,
  /// each registration keeping its delivery, and answers `Bad_MonitoredItemIdInvalid` for a handle it did
  /// not issue; before registration, `Bad_NotSupported` per item.
  virtual void modify_monitoring_async(const RequestInfo& request,
    std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete);

  /// Deletes monitoring registrations. Optional.
  ///
  /// @param request  The request served (the server's own: a release outlives its request).
  /// @param handles  The handles to release.
  /// @param complete One `VoidResult` per handle.
  ///
  /// Default: the registration's monitoring helper (`context().monitoring()`) releases what it issued and
  /// answers `Bad_MonitoredItemIdInvalid` for any other handle; before registration, `Bad_NotSupported`
  /// per handle.
  virtual void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete);

  // --- Service delegates ---
  // Override a delegate hook to provide custom service behavior for this namespace.
  // The base returns nullptr, meaning the SDK applies its default implementation.
  // A namespace that is itself the delegate may return shared_from_this().

  /// Returns the delegate that customizes RegisterNodes/UnregisterNodes handling for this namespace.
  ///
  /// @return The register-nodes delegate, or `nullptr` to use the SDK's default handling.
  virtual shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept
  {
    return nullptr;
  }

  /// Returns the delegate that provides historical-access for nodes in this namespace.
  ///
  /// The returned shared_ptr is retained by HistoryContinuationPoints so the delegate
  /// stays alive for as long as any continuation point references it.
  ///
  /// @return The history delegate, or `nullptr` if this namespace has no history support.
  virtual shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept
  {
    return nullptr;
  }

  // --- Access control ---------------------------------------------------------------------------
  //
  // The namespace that owns a node answers what an identity may do with it. Every member below has a
  // default, and a namespace on the standard Part 3 Role model overrides none of them: the defaults
  // *are* that model, evaluated against the node's own `RolePermissions` and this namespace's
  // `default_role_permissions()`.
  //
  // The namespace is never told which operation is in flight, never told which Session is asking, and
  // never asked to report a status - it reports what the identity holds, and the service that asked
  // decides what to do about it.

  /// What @p identity may do with @p node, or with this namespace when @p node is null. **The immediate
  /// form**, taking the Node a lookup returned.
  ///
  /// **Synchronous, and shall not block, hop a strand or perform I/O.** It runs on the calling thread of
  /// every service request, and a namespace that would have to wait says so instead: it returns
  /// `nullopt`, meaning *ask me through @ref effective_permissions_async* - never *denied*. The server
  /// then names every such subject of this namespace in one @ref effective_permissions_async call and
  /// uses the returned masks directly. An engaged but empty mask is a real answer and denies; returning
  /// an empty mask where the answer is unknown is how a gateway silently invents a denial.
  ///
  /// The default is the OPC 10000-3 4.8.3 evaluation of the Node's own RolePermissions (from
  /// `node->attributes()`), or this namespace's @ref default_role_permissions when it has none, against
  /// the Roles @p identity holds; it never answers `nullopt`, so a namespace that overrides nothing never
  /// needs the asynchronous form.
  ///
  /// @param identity The caller equivalence class; borrowed for the call only.
  /// @param node     A Node of this namespace, or null to ask about the namespace itself; borrowed for
  ///                 the call only. A Node whose `deleted()` is true is the caller's to refuse with
  ///                 `Bad_NodeIdUnknown` before asking.
  /// @return The effective permission bits, or `nullopt` when only the asynchronous member can answer.
  virtual std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const;

  /// Resolves effective permissions for nodes of this namespace, or for the namespace itself, in one
  /// call. **The asynchronous form**, with the request it serves.
  ///
  /// Called after the immediate form answered `nullopt`, naming every such subject of this namespace in
  /// one operation, so a request touching twenty of this namespace's nodes produces one call, not twenty.
  /// Complete exactly once, inline allowed; a whole-call failure in the batch status, a subject's failure
  /// in its item, every ErrorDetail kept; an engaged empty @p nodes is `Bad_InvalidArgument`; a disengaged
  /// one asks for the namespace subject. A callback that never runs is contained by the server's
  /// authorization deadline, which denies this namespace's subjects for that operation.
  ///
  /// @param request  The request served; its deadline bounds the wait.
  /// @param identity The caller equivalence class, owned so it may be kept across the call.
  /// @param nodes    Engaged and non-empty for node subjects; disengaged for the namespace subject.
  /// @param callback Completion carrying the effective masks; invoked exactly once.
  ///
  /// Default: each subject through the immediate form, a Node subject looked up with
  /// `find_node(nodeId, std::nullopt)`. A subject whose lookup or immediate answer is declined is
  /// `Bad_NotSupported` with an ErrorDetail naming which; a Node whose `deleted()` is true is
  /// `Bad_NodeIdUnknown`. A namespace that declines either immediate member overrides this one.
  virtual void effective_permissions_async(const RequestInfo& request,
    shared_ptr<const AccessIdentity> identity, std::optional<std::vector<NodeId>> nodes,
    EffectivePermissionsCallback callback);

  /// Refuses proposed RolePermissions changes that would leave the Server inoperable (OPC 10000-3 5.2.9:
  /// "Servers shall prevent Permissions from being changed in such a way as to render the Server
  /// inoperable"). Only the owning namespace knows what would make its Nodes unmanageable, so the check
  /// is this namespace's, and no server-wide administrator predicate exists.
  ///
  /// An operability check, not caller authorization: the Write service calls it after the WriteMask and
  /// WriteRolePermissions checks and before @ref write_async, with every RolePermissions item of the
  /// request for this namespace, and passes no caller identity. A refused item keeps its StatusCode and
  /// ErrorDetail, which the Write service returns for it unchanged, and its Attribute is not written. A
  /// namespace that exposes a writable RolePermissions Attribute under its own permission model
  /// overrides this with its own policy.
  ///
  /// @param request  The request served.
  /// @param updates  The proposed changes.
  /// @param complete One `VoidResult` per update: Good to accept, a bad status to refuse.
  ///
  /// Default (final): when @ref default_role_permissions is disengaged (a vendor-specific model that did
  /// not provide a validator), refuses every update with `Bad_NotSupported`, one naming a null NodeId
  /// included. Otherwise (the Role model) accepts every update except one naming a null NodeId, which it
  /// refuses with `Bad_InvalidArgument`.
  virtual void validate_role_permissions_updates_async(const RequestInfo& request,
    std::span<const RolePermissionsUpdate> updates, std::function<void(BatchResult<VoidResult>)> complete);

  /// This namespace's `DefaultRolePermissions` - the Part 3 5.2.9 fallback for a node carrying none.
  ///
  /// Three states, and the optional's engagement carries the first:
  ///
  /// - `nullopt` - this namespace does not use the Role model. Both Role Properties are absent from
  ///   its metadata Object. Only ever by an explicit override, and a namespace answering it **shall**
  ///   also override both effective-permission members, whose default implementation *is* the Role
  ///   model and would otherwise contradict it.
  /// - engaged and empty - the Role model, granting nothing by default. Both Properties are present
  ///   and empty; a node carrying no `RolePermissions` denies.
  /// - engaged with values - the Role model with a default.
  ///
  /// The default is **engaged and empty**. A namespace overriding nothing inherits the Role-model
  /// evaluation, so 5.2.9 makes the Property mandatory for it - but the SDK has no policy for nodes
  /// it knows nothing about, so it grants nothing and the namespace's nodes stay invisible until its
  /// owner decorates them. NS0 and NS1 do not rely on this: the server installs their values through
  /// `default_ns::Namespace::set_namespace_defaults`.
  ///
  /// @return The namespace-wide default; see the three states above.
  virtual std::optional<std::vector<RolePermissionType>> default_role_permissions() const;

  /// This namespace's `DefaultAccessRestrictions` - the channel condition for a node carrying none.
  ///
  /// Independent of the Role model: Part 3 5.2.11 turns on `AccessRestrictions` support, which this
  /// SDK always has, so `nullopt` here means only "no condition" and suppresses no publication.
  ///
  /// @return The namespace-wide channel condition, or `nullopt` for none. Default: `nullopt`.
  virtual std::optional<AccessRestrictionType> default_access_restrictions() const;

  /// No further call will name @p key.
  ///
  /// A signal, not an operation: it runs on the thread that released the last caller mapping to the
  /// identity, so drop the row and return. **Must not block** - tear down an upstream session on your
  /// own strand.
  ///
  /// @param key The key of the identity now dead. Never reissued.
  virtual void on_identity_released(const AccessIdentityKey& key) noexcept;

  /// The `NamespaceMetadataType` Object this namespace already serves for itself.
  ///
  /// Opt-in enrichment rather than an obligation: a namespace overriding nothing still gets a
  /// conformant Object unless its registration suppresses publication (`NamespaceMetadataOptions`).
  /// The SDK adopts an Object already under `Server.Namespaces` with the BrowseName `<index>:<uri>`,
  /// such as one an imported NodeSet brought, and otherwise creates one in namespace 1. It never
  /// creates the Object in this namespace. Override it where the namespace already *has* one, which
  /// is a proxy mirroring an upstream server's Object or a namespace that holds its metadata itself.
  ///
  /// Called during registration, after @ref attach and before the namespace becomes visible; the
  /// returned NodeId shall resolve through this namespace's own lookup by then, belong to this
  /// namespace, be an instance of `NamespaceMetadataType`, and carry a `NamespaceUri` equal to
  /// @ref uri - any of those failing refuses registration rather than publishing something wrong.
  ///
  /// @return The Object this namespace serves, or `nullopt` to let the SDK create one.
  virtual std::optional<NodeId> metadata_object() const;

protected:
  /// The context this namespace was attached with: its index, from any thread.
  ///
  /// Before @ref attach, it answers a context whose index is 0, which @ref attach refuses; a namespace has no
  /// index of its own until the address space registers it.
  ///
  /// @return The context given to @ref attach.
  const NamespaceContext& context() const noexcept;

  /// Answers a @ref find_nodes_async batch by looking up one id at a time, in request order.
  ///
  /// This is the whole of `find_nodes_async` for a namespace whose store is local: there is nothing to
  /// collapse, and the fan-out is fiddly enough - a resolver may answer inline or later, and the
  /// batch must not complete mid-loop when it answers inline - to be worth getting right once.
  ///
  /// A namespace fronting a remote server should NOT use this. Issuing one upstream call per id is
  /// exactly what @ref find_nodes_async exists to avoid.
  ///
  /// @param nodeIds   The batch, in request order.
  /// @param callback  Receives one result per id, in that order.
  /// @param resolveOne Invoked once per id; may complete inline or asynchronously.
  static void resolve_each(std::span<const NodeId> nodeIds,
    std::function<void(BatchResult<NodeResult>)> callback,
    const std::function<void(const NodeId&, std::function<void(NodeResult)>)>& resolveOne);

private:
  /// Called by @ref attach once the context is stored; its answer is @ref attach's.
  ///
  /// A namespace that forwards to another forwards this as it forwards every other member, by calling the
  /// other namespace's @ref attach with @p context, so that the namespace it forwards to reads the same
  /// index. A namespace that needs its index before its first request reads it here.
  /// The default does nothing.
  ///
  /// @param context The context just stored; @ref context answers it as well.
  /// @return Good to accept the registration; a Bad status refuses it, and registration answers that status.
  virtual VoidResult on_attached(const NamespaceContext& context);

  // Claimed by the first attach; a second finds it set and is refused.
  std::atomic<bool> mAttachClaimed{false};
  // Set, with release order, once mContext holds the context; context() reads mContext only after it.
  std::atomic<bool> mAttached{false};
  std::optional<NamespaceContext> mContext;
};

}  // namespace ua

#endif  // UA_NAMESPACE_H
