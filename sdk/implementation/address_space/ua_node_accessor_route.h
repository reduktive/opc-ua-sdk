// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_address_space.h"
#include "ua_call_method_request.h"
#include "ua_logger.h"
#include "ua_model_change_step.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_read_value_id.h"
#include "ua_reference_halves.h"
#include "ua_request_info.h"
#include "ua_service_operation_limits.h"
#include "ua_write_value.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace ua
{

class AddressSpaceImpl;

namespace detail
{

struct NamespaceRegistrationRoute;

/// One NodeId of a lookup, and the Read service's maxAge for its non-Value Attributes; `nullopt` from every
/// other caller.
struct LookupItem
{
  NodeId nodeId;
  std::optional<Duration> maxAge;
};

/// One Value of a Read: the Variable the lookup returned, and the item it is read for.
struct ValueRead
{
  NodeAccessor variable;
  ReadValueId value;
};

/// One Value write of @ref NodeAccessorRoute::write_values: the Variable, as the address space returned it,
/// and what is written to it.
struct ValueWrite
{
  NodeAccessor variable;
  WriteValue value;
};

/// A namespace that answers a Node's References with a resume token and no References this many times in a
/// row is not followed further: the read fails with `Bad_InternalError` (`NamespacePagingDidNotEnd`) and the
/// last token is released. An answer that holds a Reference starts the count again, so a list a namespace
/// answers in many pages is followed to its end (DL-67 (8)). Browse, BrowseNext, TranslateBrowsePaths and the
/// model access all follow tokens under this bound.
inline constexpr std::size_t maxEmptyReferencePages = 1024;

/// A resume token a namespace answered, with the namespace that issued it (NR-9 rule 3).
///
/// Move-only. A token not taken is released through its issuer, once, when the holder is destroyed or
/// assigned over, so every way an answer is dropped - its caller withdrawn, failed or done with it -
/// releases the token. A throw from the release is caught and logged. A token passed back to
/// `read_references_async` is taken (@ref take) only after query construction, immediately before that
/// call, since the call consumes it whatever it answers.
class ResumeToken
{
public:
  ResumeToken() = default;

  /// Holds @p token, issued by @p issuer; @p logger records a release that throws.
  ResumeToken(ByteString token, weak_ptr<Namespace> issuer, Logger logger) noexcept;

  ResumeToken(const ResumeToken&) = delete;
  ResumeToken& operator=(const ResumeToken&) = delete;
  ResumeToken(ResumeToken&& other) noexcept;

  /// Releases the token held, then takes @p other's.
  ResumeToken& operator=(ResumeToken&& other) noexcept;

  ~ResumeToken();

  /// Whether a token is held.
  [[nodiscard]] bool empty() const noexcept;

  /// The token, to pass back to a read; the holder no longer releases it.
  [[nodiscard]] ByteString take() noexcept;

  /// Releases the token now, through its issuer; nothing when none is held or the issuer is gone.
  void release() noexcept;

private:
  ByteString mToken;
  weak_ptr<Namespace> mIssuer;
  Logger mLogger;
};

/// One query of a References read: the Node whose References are read, and the hints and paging of
/// `ReferenceQuery`. Composed callers move the original issuer-bound holder into resumeToken; only the
/// raw accessor adapter supplies ByteString without issuer metadata. An unissued held token is released
/// through its original issuer before caller completion, even if a duplicate retains the route state.
struct ReferenceRead
{
  NodeAccessor node;
  BrowseDirection direction{BrowseDirection::Both};
  std::vector<NodeId> hint;
  uint32_t maxReferences{0};
  std::variant<ByteString, ResumeToken> resumeToken;
};

/// One answer of a References read: the namespace's answer, whose `resumeToken` is moved into
/// @ref resumeToken with the namespace that issued it.
struct ReferencePage
{
  NodeReferencesResult answer;
  ResumeToken resumeToken;
};

/// One item of a Method call: the Method and the Object its caller looked up, its request and the context its
/// handler receives.
struct MethodCallItem
{
  NodeAccessor method;
  NodeAccessor object;
  CallMethodRequest request;
  shared_ptr<const MethodCallContext> context;
};

/// The items one namespace's call answered, or the items answered before any namespace was called.
struct MethodCallAnswers
{
  /// The positions of the answered items among the items of the call, in item order.
  std::vector<std::size_t> positions;
  /// One result per position.
  std::vector<CallResult> results;
  /// The route's own copies of the items, valid for as long as this is held, so that an answer that arrives
  /// after its caller has gone can still be read with its request.
  shared_ptr<const std::vector<MethodCallItem>> items;
};

/// The accessor's route into the namespaces (NR-2).
///
/// Builds the accessors the address space hands out, bound to it, and runs an accessor's operations as
/// one-item calls of the batched member of the namespace that owns its Node, through @ref NamespaceRoute and
/// so with the guards of NR-23 rule 4: a throw is `Bad_InternalError` (`NamespaceCallThrew`), a completion is
/// accepted once, an answer of another size fails the call's items. The calls carry the server's own
/// `RequestInfo`. An accessor whose address space is gone, or that has none, answers `Bad_Shutdown`; one
/// whose Node's namespace the address space does not hold answers `Bad_NodeIdUnknown` (`NamespaceNotFound`).
/// Each operation's completion is called once, through `invoke_user_callback`.
class NodeAccessorRoute
{
public:
  /// An accessor over @p node, bound to @p addressSpace through @p registrationRoute.
  static NodeAccessor bound(shared_ptr<Node> node, weak_ptr<AddressSpaceImpl> addressSpace,
    shared_ptr<const NamespaceRegistrationRoute> registrationRoute);

  /// Looks up @p items for the request @p request serves, through the address space @p addressSpace names and
  /// the registration route it holds: the immediate lookup first, then the items it declines grouped by
  /// namespace and maxAge, one `find_nodes_async` per group split by `maxNodesPerRead`. The answers are
  /// accessors bound to the address space, one per item in item order; a Good answer without a Node is
  /// `Bad_InternalError`. An address space that is gone answers every item `Bad_Shutdown`. @p callback is
  /// called once. A supplied @p requiredAddressSpace is checked before each unissued chunk, refusing
  /// ownerless continuation with `AddressSpaceGone`; omitted, existing lifetime diagnostics apply.
  static void find_nodes(const WeakAddressSpace& addressSpace, const RequestInfo& request,
    std::span<const LookupItem> items, AddressSpace::FindNodesCompleteCallback callback,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept;

  /// Creates @p creations through the address space @p addressSpace names and the registration route it
  /// holds, for the request @p request serves: one `create_nodes_async` per namespace split by
  /// `maxNodesPerNodeManagement` (`AddressSpaceImpl::create_nodes_async`). @p callback receives one answer
  /// per creation, in creation order, once; every creation answers `Bad_Shutdown` (`AddressSpaceGone`) when
  /// the address space is gone.
  static void create_nodes(const WeakAddressSpace& addressSpace, const RequestInfo& request,
    shared_ptr<const std::vector<NodeCreation>> creations,
    std::function<void(std::vector<NodeAccessorResult>)> callback) noexcept;

  /// Adds @p changes through the address space @p addressSpace names, for the request @p request serves: each
  /// change sent to the namespace of its source, one `add_references_async` per namespace split by
  /// `maxNodesPerNodeManagement`. A source of a namespace the address space does not hold answers
  /// `Bad_NodeIdUnknown` (`NamespaceNotFound`) and is not sent. @p callback receives one answer per change,
  /// in change order, once; every change answers `Bad_Shutdown` (`AddressSpaceGone`) when the address space
  /// is gone.
  ///
  /// The other half of a change whose type is hierarchical, GeneratesEvent, HasSubtype or HasEncoding, or a
  /// subtype of one, is added too, in its target's namespace, once the change's own half is held (added, or
  /// answered `Bad_DuplicateReferenceNotAllowed`), unless @p changes holds it already or the target is in
  /// another Server (NR-30 rule 2, NR-50, NR-68 item 7, DL-115 (4) and (5)); a target given by namespace URI
  /// is resolved first. A type of another namespace is classified once per call, by its supertypes. A change
  /// whose own half is refused leaves no half behind. Nothing is undone. The other half already held, or a
  /// target Node that does not exist, is not a failure. A failure of the other half is logged; it answers the
  /// change with its StatusCode and an ErrorDetail (`OtherHalfNotAdded`) naming that half only where the type
  /// requires that half: HasEncoding's, and HasSubtype's inverse half. Since the address space adds those
  /// halves itself, a half of a paired type already held answers Good rather than
  /// `Bad_DuplicateReferenceNotAllowed`, so that a caller adding both halves itself does not fail (NR-30 rule
  /// 4).
  ///
  /// A HasSubtype change with a local target is added after the call's other changes are held, and when both
  /// its ends are VariableTypes it is first checked against OPC 10000-3 6.2.7 (NR-52): one that breaks the
  /// rule answers `Bad_ReferenceNotAllowed`, with an ErrorDetail naming the rule and both values, and no half
  /// of it is sent.
  ///
  /// With @p addRequiredPairs false only @p changes are sent: a NodeSet import sends both halves itself, as
  /// its caller's filter keeps them, and the route adds no half that filter dropped.
  ///
  /// The versioned Nodes the namespaces report are recorded in @p step, the step of the operation this call
  /// is part of (an import, an instantiation), which its driver closes; without one the call is an operation
  /// of its own, and its event is raised before @p callback runs (NR-36 rule 4, NR-46).
  static void add_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
    shared_ptr<const std::vector<ReferenceChange>> changes,
    std::function<void(std::vector<VoidResult>)> callback, bool addRequiredPairs = true,
    shared_ptr<ModelChangeStep> step = nullptr) noexcept;

  /// Removes @p changes as @ref add_references adds them, through `remove_references_async`: the other half
  /// of each change with a local target, whatever its type (OPC 10000-4 5.7.5.1, `deleteBidirectional` TRUE),
  /// is removed too once its own half is removed or found not held (`Uncertain_ReferenceNotDeleted`). An
  /// other half that is not held, or a target Node that does not exist, is not a failure; any other failure
  /// of it is logged, and answers the change (`OtherHalfNotRemoved`) only where the type requires that half.
  ///
  /// With @p removeOtherHalves false only @p changes are sent, as @ref add_references sends them with
  /// `addRequiredPairs` false.
  static void remove_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
    shared_ptr<const std::vector<ReferenceChange>> changes,
    std::function<void(std::vector<VoidResult>)> callback, bool removeOtherHalves = true,
    shared_ptr<ModelChangeStep> step = nullptr) noexcept;

  /// A step for one operation of @p addressSpace that is not one route call (a Write request, a delete, an
  /// import, an instantiation): its driver passes it to each call and closes it at the end (NR-36 rule 4).
  static shared_ptr<ModelChangeStep> model_change_step(const WeakAddressSpace& addressSpace);

  /// The completion for a `write_async` call of @p items that records its versioned Nodes in @p step:
  /// DataTypeChanged for a Node whose DataType was written; a Node reported for another Attribute makes the
  /// event a BaseModelChangeEvent.
  static std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> recording_writes(
    std::function<void(BatchResult<VoidResult>)> answer, ModelChangeStep& step,
    std::span<const ValueWriteItem> items);

  /// Advances the model generation of @p addressSpace when one of @p writes, written by a service through the
  /// namespaces itself, changed a BrowseName or a DataType: its answer in @p answers is not Bad (NR-68 item
  /// 1).
  static void model_written(const WeakAddressSpace& addressSpace, std::span<const WriteValue> writes,
    std::span<const VoidResult> answers) noexcept;

  /// The operation limits the address space @p addressSpace names was given; nullopt when it has none or is
  /// gone.
  static std::optional<ServiceOperationLimits> operation_limits(
    const WeakAddressSpace& addressSpace) noexcept;

  /// The executor of the accessor's address space, on whose threads its synchronous forms refuse (NR-7); an
  /// empty executor when the address space is gone or the accessor has none, whose operations answer
  /// `Bad_Shutdown`.
  static boost::asio::any_io_executor executor(const NodeAccessor& accessor) noexcept;

  /// A scalar snapshot of the configured browse-operation limit; nullopt for an unset limit or an
  /// empty/expired address space. Neither the call nor the returned value retains the owner. Like
  /// AddressSpace::set_operation_limits, configuration is set before serving requests and is not
  /// mutated concurrently. This observation does not replace an operation's required-owner check.
  static std::optional<uint32_t> browse_limit(const WeakAddressSpace& addressSpace) noexcept;

  /// The owning pointer to the accessor's Node, as the accessor holds it; null when it holds none. Unlike
  /// `shared_from_this()` on the Node it cannot throw: a Node held through an aliasing `shared_ptr` has no
  /// `weak_ptr` of its own to share.
  static shared_ptr<Node> node_of(const NodeAccessor& accessor) noexcept;

  /// The References of @p reads for the request @p request serves: grouped by the namespace that owns each
  /// read's Node, one `read_references_async` per namespace split by `maxNodesPerBrowse`, each query
  /// carrying its read's direction, hint, maxReferences and resume token. @p callback receives one page per
  /// read, in read order, once, after every namespace has answered, each token answered held by its page;
  /// an empty vector only when the pages could not be allocated, the tokens answered then released.
  /// A supplied requiredAddressSpace is checked before every unissued namespace chunk; omitted, the
  /// accessor's ordinary route diagnostics apply. Held input tokens are taken only immediately before
  /// namespace invocation; unissued tokens are released through their original issuer before callback.
  static void read_references(const RequestInfo& request, std::vector<ReferenceRead> reads,
    std::function<void(std::vector<ReferencePage>)> callback,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept;

  /// One page of the accessor's References: one read of @ref read_references, both directions, no hint.
  static void read_references(const NodeAccessor& accessor, uint32_t maxReferences, ByteString resumeToken,
    NodeAccessor::GetReferencesPageCallback callback) noexcept;

  /// Every Reference of the accessor's Node: pages of @ref read_references until no resume token is left.
  /// A supplied requiredAddressSpace is checked before each unissued page; tokens remain issuer-bound
  /// until invocation or explicit release before completion.
  static void read_all_references(const NodeAccessor& accessor, NodeAccessor::GetReferencesCallback callback,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept;

  /// Adds or removes @p references, held by the accessor's Node: one change per Reference in one call of
  /// `add_references_async` or `remove_references_async`, or through the batched entries when a change needs
  /// more than its own half sent. With @p halves `ReferenceHalves::Both` that is an add whose type may be
  /// paired (hierarchical, GeneratesEvent, HasSubtype, HasEncoding, or a subtype of one), any removal with a
  /// local target, or a target named by namespace URI: @ref add_references or @ref remove_references then
  /// adds or removes its other half too. With `ReferenceHalves::ThisHalfOnly` no other half is sent; a change
  /// with a local target whose type is, or may be, HasEncoding or HasSubtype, or a subtype of one, is first
  /// classified, and one that would leave a Node without a half OPC 10000-3 requires (either half of
  /// HasEncoding alone, 5.8.4; an add of a supertype's forward HasSubtype alone or a removal of a subtype's
  /// inverse HasSubtype alone, 5.3.3.3) is answered `Bad_NotSupported`
  /// (`RequiredOtherHalfLeftAlone`) and not sent. Answers Good when every change is Good, otherwise the first
  /// failure.
  static void change_references(const NodeAccessor& accessor, std::vector<Reference> references, bool add,
    ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept;

  /// The existing add-if-absent composition, with an optional weak owner required before new paging
  /// or mutation. Terminal received results are not replaced merely because that owner has expired. An absent
  /// Reference is added with @p halves, as @ref change_references adds it.
  static void add_reference_if_not_present(const NodeAccessor& accessor, NodeId type, NodeId target,
    bool isForward, NodeAccessor::ReferenceModifyCallback callback,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt,
    ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// The Values of @p reads for the request @p request serves, on behalf of @p caller (null for the server's
  /// own call). Per item, an IndexRange that does not parse answers `Bad_IndexRangeInvalid` and is not sent;
  /// the rest are grouped by the namespace that owns each Variable's Node, one `read_values_async` per
  /// namespace split by `maxNodesPerRead`, each item carrying the Node of its accessor. A Value answered
  /// larger than its IndexRange in any dimension is `Bad_InternalError` (`NamespaceValueExceedsRange`, NR-10
  /// rule 8). @p callback receives one answer per read, in read order, once, after every namespace has
  /// answered. A supplied @p requiredAddressSpace additionally checks the composed operation's weak owner
  /// before each unissued chunk, without replacing answers already received or changing default diagnostics.
  static void read_values(const RequestInfo& request, const CallerInfo* caller, std::vector<ValueRead> reads,
    Duration maxAge, bool setSourceTimestamp, std::function<void(std::vector<DataValueResult>)> callback,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept;

  /// The description of the accessor's Node, read once: every Attribute it holds and could read.
  static Result<NodeDescription> attributes(const NodeAccessor& accessor) noexcept;

  /// The Variable's Value for @p nodeToRead's IndexRange: one item of `read_values_async`, sent to the owning
  /// namespace directly with no batch state (NR-2 rule 4). The route's guards hold: one answer reaches
  /// @p callback, a count other than one or a throwing member answers `Bad_InternalError`, and a Value larger
  /// than the IndexRange is refused as @ref read_values refuses it.
  static void read_value(const NodeAccessor& accessor, Duration maxAge, bool setSourceTimestamp,
    const ReadValueId& nodeToRead, const CallerInfo* caller,
    NodeAccessor::ReadValueCompleteCallback callback) noexcept;

  /// One item of `write_async`, sent to the owning namespace directly with no batch state (NR-2 rule 4), with
  /// the guards @ref read_value keeps. A ModelChangeStep is created only when the write has a versioned Node
  /// to record or writes a NodeVersion.
  static void write(const NodeAccessor& accessor, const WriteValue& nodeToWrite, const CallerInfo* caller,
    std::function<void(VoidResult)> callback) noexcept;

  /// The Value writes of @p writes for the request @p request serves, on behalf of @p caller (null for the
  /// server's own write): grouped by the namespace that owns each Variable's Node, one `write_async` per
  /// namespace split by `maxNodesPerWrite`, each item carrying the Node of its accessor. @p callback receives
  /// one answer per write, in write order, once, after every namespace has answered.
  ///
  /// The versioned Nodes are recorded in @p step as @ref add_references states.
  static void write_values(const RequestInfo& request, const CallerInfo* caller,
    std::vector<ValueWrite> writes, std::function<void(std::vector<VoidResult>)> callback,
    shared_ptr<ModelChangeStep> step = nullptr) noexcept;

  /// The Method calls of @p items for the request @p request serves, on behalf of @p caller (null for the
  /// server's own call), NR-15 rules 2 to 4. The items are grouped by the namespace of the Object's NodeId,
  /// one `call_async` per namespace split by `maxNodesPerMethodCall`, each item in item order; the items a
  /// namespace declines go, as soon as that namespace has answered, to their Methods' namespaces, one call
  /// per Method namespace, unless it is the same namespace. An item both decline answers `Bad_NotImplemented`
  /// (`CallDeclined`). A Method or Object Node deleted since its lookup answers `Bad_NodeIdUnknown`
  /// (`NodeDeleted`), and an Object of a namespace the address space does not hold `Bad_NodeIdUnknown`,
  /// before any namespace is called.
  ///
  /// The route holds its own copies of the items, the request and the caller until the last namespace has
  /// answered. @p answered is called once per namespace call with the items it answered, and once with the
  /// items answered before any call, so one namespace's answers do not wait for another's; it may be called
  /// from several threads at once. Every item is answered exactly once.
  static void call_items(const RequestInfo& request, shared_ptr<const CallerInfo> caller,
    std::vector<MethodCallItem> items, std::function<void(MethodCallAnswers)> answered) noexcept;

  /// A Method accessor's call: the request's Object is looked up through the address space, then the item is
  /// called as one item of @ref call_items for the server's own request, with no caller; an Object not found
  /// answers the lookup's status.
  static void call(const NodeAccessor& method, const CallMethodRequest& request,
    shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback) noexcept;

  /// As @ref call, with the request's Object already looked up: @p object is the item's Object, and no second
  /// lookup is made.
  static void call(const NodeAccessor& method, const NodeAccessor& object, const CallMethodRequest& request,
    shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback) noexcept;

  /// Whether @p candidates belong to the View @p view, for the request @p request serves. The View's own
  /// Node is a member (NR-16 rule 6) and the Server Object (i=2253) is not (NR-41), each answered without
  /// asking; the other candidates, each once, in one `view_contains_async` to the View's namespace.
  /// Candidates are compared as given: a caller resolves a namespace URI form first. @p callback receives
  /// one answer per candidate, in candidate order, once; an empty vector only when the answers could not be
  /// allocated.
  static void view_contains(const RequestInfo& request, const NodeAccessor& view,
    std::vector<ExpandedNodeId> candidates, std::function<void(std::vector<BoolResult>)> callback) noexcept;

  /// Whether @p member belongs to the accessor's View: one candidate of @ref view_contains.
  static void view_contains(
    const NodeAccessor& view, NodeId member, NodeAccessor::IsNodeInViewCallback callback) noexcept;

  /// Adds @p member to the accessor's View: one Node of `add_to_view_async`. The Server Object (i=2253)
  /// is refused `Bad_ReferenceNotAllowed` (`ServerObjectInView`) without asking the namespace (NR-41).
  static void add_to_view(
    const NodeAccessor& view, NodeId member, NodeAccessor::ViewModifyCallback callback) noexcept;

private:
  // An accessor's Node, its address space, and the namespace that owns a NodeId; or why there is none.
  struct Bound;
  static Bound bound_of(const NodeAccessor& accessor, const NodeId& nodeId);

  // @ref add_references when @p add, otherwise @ref remove_references.
  static void change_references(const WeakAddressSpace& addressSpace, const RequestInfo& request,
    shared_ptr<const std::vector<ReferenceChange>> requested, bool add,
    std::function<void(std::vector<VoidResult>)> callback, shared_ptr<ModelChangeStep> step) noexcept;

  // One round of @p changes: each sent to the namespace of its source, one call per namespace split by
  // `maxNodesPerNodeManagement`; answered in change order.
  static void send_changes(const WeakAddressSpace& addressSpace, shared_ptr<const RequestInfo> request,
    shared_ptr<const std::vector<ReferenceChange>> changes, bool add,
    std::function<void(std::vector<VoidResult>)> callback, shared_ptr<ModelChangeStep> step) noexcept;
};

}  // namespace detail
}  // namespace ua
