// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace that records the batched calls the address space and the services make
///        into it, with the request each carries.

#ifndef UA_TEST_BATCH_RECORDING_NAMESPACE_H
#define UA_TEST_BATCH_RECORDING_NAMESPACE_H

#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_default_namespace.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_numeric_range.h"
#include "ua_permission_type.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_status_code.h"
#include "ua_write_value.h"
#include "ua_call_method_request.h"

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace ua::test
{

/// A namespace that keeps the default namespace's real Node store and records, under a mutex, every call the
/// SDK makes into the members below: which member, the NodeIds it names (in order), the request it serves and
/// the caller it acts for. Every recorded member forwards to the default namespace unless an option below
/// says otherwise.
///
/// **Counting once.** A default member this namespace forwards to may call another member of this namespace
/// (the asynchronous permission form asks `find_node` and the immediate form for each subject). Such a call,
/// made on the same thread while the recorded member runs, is not recorded: each call the SDK makes is
/// recorded once, as the member the SDK called. A completion runs outside that scope, so a call the SDK makes
/// from inside a completion is recorded.
///
/// **Options.**
/// - @ref decline_single_lookups: `find_node` answers `nullopt` for each NodeId without a scripted answer
///   (@ref answer_lookup_of), so every other lookup through the address space reaches the batched member.
/// - @ref decline_immediate_permissions: the immediate `effective_permissions` answers `nullopt`, and the
///   asynchronous form answers itself, with the mask @ref grant gave each NodeId (every permission bit by
///   default).
/// - @ref refuse_role_permissions_update: `validate_role_permissions_updates_async` answers the update naming
///   that NodeId with the status given; the others as the default does.
/// - @ref set_history_delegate: the history delegate this namespace returns.
/// - @ref answer_whole_values: `read_values_async` answers each item with the Variable's whole Value,
///   ignoring the item's IndexRange, as a namespace that does not apply the range would.
/// - @ref fail_value_reads_of: `read_values_async` answers the item naming that NodeId with the status
///   given, and the ErrorDetail it carries; the other items as it otherwise would.
/// - @ref hold_writes: `write_async` is recorded and held, neither applied nor completed, until
///   @ref release_held_writes.
/// - @ref fail_writes_of: `write_async` answers the item naming that NodeId with the status given, and the
///   ErrorDetail it carries, without applying it; the other items as it otherwise would.
/// - @ref fail_reference_changes_of: `add_references_async` and `remove_references_async` answer each change
///   held by that NodeId with the status given, without applying it; the other changes as they otherwise
///   would.
/// - @ref answer_view_membership: `view_contains_async` answers each candidate with the function given,
///   without asking the View Node.
/// - @ref accept_view_additions: `add_to_view_async` answers Good for every Node, without the in-memory
///   View's checks and without changing the View.
/// - @ref apply_reference_hints: `read_references_async` leaves a Reference out of a query's answer only
///   when `reference_type_may_match_hint` says its type cannot be one the query's hint wants (NR-61). The
///   direction is not applied.
/// - @ref page_references: `read_references_async` answers each query with at most that many References,
///   in the Node's stored order, and while more remain a resume token naming the call and the offset; a
///   query carrying such a token resumes at its offset. The hint, when applied, is applied before paging.
/// - @ref page_references_by_max_references: as @ref page_references, with each query's own maxReferences
///   as its page size (every remaining Reference for 0).
/// - @ref answer_every_reference: `read_references_async` answers each query with every Reference the Node
///   holds and no resume token, whatever its maxReferences asks.
/// - @ref answer_lookup_of: both lookups answer that NodeId with the status given and no Node, or with the
///   Node given, whatever the store holds when the lookup is made.
/// - @ref answer_reference_query_of: the n-th `read_references_async` query naming that NodeId is answered
///   with the status given and no References.
/// - @ref hold_reference_reads_of: a `read_references_async` call one of whose queries names one of those
///   NodeIds is recorded and held, unanswered, until @ref release_held_reference_reads.
/// - @ref page_without_end_of: each `read_references_async` query naming one of those NodeIds is answered
///   with no References and a fresh resume token, without end, on this namespace's executor.
/// - @ref hold_lookups_of: a batched lookup naming one of those NodeIds is recorded and held, unanswered,
///   until @ref release_held_lookups, or destroyed unanswered by @ref discard_held_lookups; a single lookup
///   of one of them that @ref answer_lookup_of has not scripted declines.
/// - @ref hold_value_reads_of: a `read_values_async` call naming one of those NodeIds is read when it is
///   made, and its answer held until @ref release_held_value_reads.
/// - @ref hold_modify_answers: each `modify_monitoring_async` call is applied when it is made, and its
///   answer held until @ref release_held_modify_answers.
/// - @ref observe_deliveries: the sink of each item given to `create_monitoring_async` is replaced by one
///   that records each sample and notice it is given (@ref deliveries) after passing it on to the sink.
/// - @ref on_value_read: a function run with each recorded `read_values_async` call before it is answered.
/// - @ref decline_calls: `call_async` declines every item.
/// - @ref hold_calls: `call_async` is recorded and held, unanswered, until @ref release_held_calls.
/// - @ref answer_calls: a script answers each recorded `call_async` not held or declined.
///
/// The monitoring members are recorded too, and otherwise forward to the default namespace; @ref
/// report_change reports a change through this namespace's monitoring helper, as the namespace does when a
/// Node's attribute changes, and @ref create_sampled registers items through the helper, every one Sampled.
class BatchRecordingNamespace : public default_ns::Namespace
{
public:
  /// The recorded members.
  enum class Member
  {
    BatchedLookup,  ///< `find_nodes_async`.
    SingleLookup,  ///< `find_node(id, maxAge)`.
    ImmediatePermissionsOfNode,  ///< The immediate `effective_permissions`, taking `const Node*`.
    PermissionsAsyncForRequest,  ///< `effective_permissions_async`, taking a `RequestInfo`.
    ReadValues,  ///< `read_values_async`.
    Write,  ///< `write_async`.
    ReadReferences,  ///< `read_references_async`.
    ValidateRolePermissionsUpdates,  ///< `validate_role_permissions_updates_async`.
    ViewContains,  ///< `view_contains_async`.
    AddToView,  ///< `add_to_view_async`.
    ReleaseResumeToken,  ///< `release_resume_token`.
    CreateMonitoring,  ///< `create_monitoring_async`.
    ModifyMonitoring,  ///< `modify_monitoring_async`.
    DeleteMonitoring,  ///< `delete_monitoring_async`.
    Call,  ///< `call_async`.
    CreateNodes,  ///< `create_nodes_async`.
    DeleteNodes,  ///< `delete_nodes_async`.
    RemoveReferences,  ///< `remove_references_async`.
    AddReferences,  ///< `add_references_async`.
  };

  /// One query of a `read_references_async` call, as the namespace received it.
  struct ReferenceQueryRecord
  {
    NodeId nodeId;
    BrowseDirection direction{BrowseDirection::Both};
    std::vector<NodeId> referenceTypeHint;
    uint32_t maxReferences{0};

    /// The resume token the query carried; empty on a first call.
    ByteString resumeToken;

    /// The resume token this namespace answered the query with, while @ref page_references pages the
    /// answers; empty when it answered the last page, when it does not page, and until it has answered.
    ByteString answeredToken;

    /// The status this namespace answered the query with in place of its References, when
    /// @ref answer_reference_query_of scripted one for it; `nullopt` otherwise, and until it has answered.
    std::optional<StatusCode> answeredStatus;
  };

  /// One recorded call.
  struct Call
  {
    Member member{Member::BatchedLookup};

    /// The call's place among every call this namespace recorded since construction, from 1. @ref reset
    /// does not restart it.
    std::size_t sequence{0};

    /// When the member was entered.
    std::chrono::steady_clock::time_point entered{};

    /// The NodeIds named, in order. Empty for a namespace subject (a disengaged node list, a null Node), and
    /// for a Node given to the immediate permission form whose Attributes cannot be read.
    /// For `read_references_async` each query's NodeId; for `add_to_view_async` the Nodes to add; for
    /// `call_async` each item's objectId.
    std::vector<NodeId> nodeIds;

    /// Whether the member took a `RequestInfo`; the three fields below are its fields.
    bool hasRequest{false};
    std::chrono::steady_clock::time_point deadline{std::chrono::steady_clock::time_point::max()};
    std::optional<std::chrono::steady_clock::time_point> answerBy;
    bool cancelled{false};

    /// The maxAge the member took, when it takes one.
    std::optional<Duration> maxAge;

    /// For the value members and `call_async`: whether a `CallerInfo` was given (null is the server's own
    /// call), and its fields.
    bool hasCaller{false};
    NodeId callerSessionId;

    /// For the value members and `call_async`: the `CallerInfo` given, null for the server's own call.
    /// Compared by address only; it is valid only until the member returns.
    const CallerInfo* caller{nullptr};

    /// The caller's identity for the value members and `call_async`; the identity asked about for the
    /// permission members.
    shared_ptr<const AccessIdentity> identity;

    /// The Node given to the immediate form taking a Node; null otherwise.
    const Node* node{nullptr};

    /// For `read_values_async` and `write_async`: each item's Node (`ValueReadItem::node`,
    /// `ValueWriteItem::node`), in item order. Compared by address only; the caller holds the Nodes only
    /// until the call completes.
    std::vector<const Node*> itemNodes;

    /// For `read_values_async`: whether each item's `ReadValueId` carried an IndexRange, in item order.
    std::vector<bool> itemRanged;

    /// For `read_values_async`: each item's IndexRange, in item order.
    std::vector<NumericRange> itemRanges;

    /// For `read_values_async`: whether the call was answered before the member returned. Set when the
    /// member returns, so it is false while the member runs, and for a call answered after it returned.
    bool answeredInline{false};

    /// For the monitoring create: each item's monitoredItemId, in item order (@ref nodeIds holds their
    /// NodeIds).
    std::vector<IntegerId> monitoredItemIds;

    /// For the monitoring create: each item as given, in item order, without its Node and its sink.
    std::vector<MonitoringCreateItem> monitoringItems;

    /// For the monitoring modify and delete: the handles named, in order.
    std::vector<MonitoringHandle> handles;

    /// For `validate_role_permissions_updates_async`: each update's proposed RolePermissions, in update
    /// order (`nullopt` for the empty-array clear).
    std::vector<std::optional<std::vector<RolePermissionType>>> proposals;

    /// For `read_references_async`: each query, in query order.
    std::vector<ReferenceQueryRecord> referenceQueries;

    /// For `view_contains_async` and `add_to_view_async`: the View Node named.
    NodeId view;

    /// For `view_contains_async`: the candidates, in order.
    std::vector<ExpandedNodeId> candidates;

    /// For `release_resume_token`: the token released.
    ByteString token;

    /// For `call_async`: each item's received request, copied in item order.
    std::vector<CallMethodRequest> methodRequests;

    /// For `create_nodes_async`: each creation, copied in item order (@ref nodeIds holds their NodeIds).
    std::vector<NodeCreation> creations;

    /// For `add_references_async` and `remove_references_async`: each change, copied in item order. Their
    /// sources are in @ref nodeIds.
    std::vector<ReferenceChange> referenceChanges;
  };

  BatchRecordingNamespace(string_view uri, boost::asio::any_io_executor executor);

  void decline_single_lookups(bool decline = true);
  void decline_immediate_permissions(bool decline = true);

  /// The mask the asynchronous form taking a `RequestInfo` answers for @p nodeId while immediate permissions
  /// are declined. A NodeId given none answers every permission bit.
  void grant(const NodeId& nodeId, PermissionType permissions);

  /// `validate_role_permissions_updates_async` answers the update naming @p nodeId with @p refusal.
  void refuse_role_permissions_update(const NodeId& nodeId, StatusCode refusal);

  void set_history_delegate(shared_ptr<NamespaceHistoryDelegate> delegate);

  /// `create_nodes_async` answers each item Good without a Node, and creates nothing.
  void answer_creations_without_node(bool answer = true);

  /// `read_values_async` answers each item with the Variable's whole Value, ignoring its IndexRange.
  void answer_whole_values(bool whole = true);

  /// `read_values_async` answers the item naming @p nodeId with @p failure, the ErrorDetail it carries
  /// included; every other item is answered as it otherwise would be.
  void fail_value_reads_of(const NodeId& nodeId, StatusCode failure);

  /// `write_async` records each call and holds it, unanswered, until @ref release_held_writes.
  void hold_writes(bool hold = true);

  /// `write_async` answers the item naming @p nodeId with @p failure, the ErrorDetail it carries included,
  /// and does not apply it; every other item is applied and answered as it otherwise would be. Applies to the
  /// calls that are not held.
  void fail_writes_of(const NodeId& nodeId, StatusCode failure);

  /// `add_references_async` and `remove_references_async` answer each change whose source is @p nodeId with
  /// @p failure and do not apply it; every other change is applied and answered as it otherwise would be.
  void fail_reference_changes_of(const NodeId& nodeId, StatusCode failure);

  /// `view_contains_async` answers each candidate `member(view, candidate)`, the candidate taken by its
  /// NodeId, without asking the View Node. An empty function restores the default.
  void answer_view_membership(std::function<bool(const NodeId& view, const NodeId& candidate)> member);

  /// `add_to_view_async` answers Good for every Node and versions nothing, without the in-memory View's
  /// checks and without adding the Node.
  void accept_view_additions(bool accept = true);

  /// `read_references_async` leaves out a Reference only when `reference_type_may_match_hint` says its
  /// type cannot be one the query's hint wants; the query's direction is not applied.
  void apply_reference_hints(bool apply = true);

  /// `read_references_async` answers each query with at most @p pageSize References in the Node's stored
  /// order and, while more remain, a resume token naming the call and the offset; a query carrying such a
  /// token resumes at its offset, and one carrying any other token is answered
  /// `Bad_ContinuationPointInvalid`. The query's own maxReferences is not applied. 0 stops paging.
  void page_references(std::size_t pageSize);

  /// As @ref page_references, with each query's own maxReferences as its page size: at most that many
  /// References and, while more remain, a resume token; every remaining Reference and no token for 0.
  void page_references_by_max_references(bool page = true);

  /// `read_references_async` answers each query with every Reference the Node holds and no resume token,
  /// whatever its maxReferences asks, as a namespace that does not page would.
  void answer_every_reference(bool every = true);

  /// Both lookups (`find_node`, `find_nodes_async`) answer @p nodeId with @p answer, the ErrorDetail it
  /// carries included, and no Node. @p answer is not Good. Optional @p batchStatus replaces the
  /// containing batched lookup's status; @p itemLimit truncates its returned items. Either option makes
  /// the immediate lookup decline so the call reaches the batched member. The options apply only to a
  /// batch naming this NodeId and are cleared when omitted on a later script for the same NodeId.
  void answer_lookup_of(const NodeId& nodeId, StatusCode answer,
    std::optional<StatusCode> batchStatus = std::nullopt,
    std::optional<std::size_t> itemLimit = std::nullopt);

  /// Both lookups answer @p nodeId with @p node, whatever the store holds when the lookup is made: a
  /// Node a test found and then deleted is answered as found, as a lookup that raced the deletion would be.
  /// Optional @p batchStatus and @p itemLimit have the same meaning as in the status overload.
  void answer_lookup_of(const NodeId& nodeId, shared_ptr<Node> node,
    std::optional<StatusCode> batchStatus = std::nullopt,
    std::optional<std::size_t> itemLimit = std::nullopt);

  /// The @p nth (from 1) `read_references_async` query naming @p nodeId, counted over every call the SDK
  /// makes, is answered with @p answer, the ErrorDetail it carries included, and no References; the other
  /// queries as they otherwise would be. @p answer is not Good: a `NodeReferencesResult` holds References
  /// only with a Good status.
  void answer_reference_query_of(const NodeId& nodeId, std::size_t nth, StatusCode answer);

  /// A `read_references_async` call one of whose queries names one of @p nodeIds is recorded and held,
  /// unanswered, until @ref release_held_reference_reads. An empty list holds nothing.
  void hold_reference_reads_of(std::vector<NodeId> nodeIds);

  /// Waits until @p count calls have been held since construction, or @p limit passes.
  /// @return Whether that many have been held.
  bool wait_for_held_reference_reads(std::size_t count, std::chrono::milliseconds limit);

  /// How many `read_references_async` calls have been held since construction, released or not.
  std::size_t held_reference_read_count() const;

  /// The request held call @p index (from 0, in arrival order, released or not) carried, its cancellation
  /// flag the one the call was given.
  RequestInfo held_reference_read_request(std::size_t index) const;

  /// Answers every held call not yet released, in the order they arrived, as it would have been answered
  /// had it not been held: each query is read from the Node this namespace's own lookup answers for its
  /// NodeId now, and shaped by the options in force now. Called from the test's thread, never from inside a
  /// member. Holding continues for calls that arrive later.
  /// @return How many calls it let go.
  std::size_t release_held_reference_reads();

  /// Every `read_references_async` query naming one of @p nodeIds is answered Good with no References and a
  /// fresh resume token, whatever token it carried, so that its paging never ends. The call's answer is
  /// delivered on this namespace's executor, never on the caller's stack. A scripted query keeps its scripted
  /// answer. An empty list stops it: later queries are answered as they otherwise would be.
  void page_without_end_of(std::vector<NodeId> nodeIds);

  /// A batched lookup (`find_nodes_async`) naming one of @p nodeIds is recorded and held, unanswered, until
  /// @ref release_held_lookups, and `find_node` declines those NodeIds that @ref answer_lookup_of has not
  /// scripted, so that a lookup reaches the batched member. An empty list holds nothing.
  void hold_lookups_of(std::vector<NodeId> nodeIds);

  /// Waits until @p count lookups have been held since construction, or @p limit passes.
  /// @return Whether that many have been held.
  bool wait_for_held_lookups(std::size_t count, std::chrono::milliseconds limit);

  /// Answers every held lookup not yet released, in the order they arrived, as it would have been answered
  /// had it not been held, with the scripted lookup answers in force when it arrived. Called from the test's
  /// thread, never from inside a member.
  /// @return How many lookups it let go.
  std::size_t release_held_lookups();

  /// Destroys every held lookup not yet released, in the order they arrived, without answering it: the
  /// completion each was given is destroyed uncalled, as a namespace that drops a call does. Called from the
  /// test's thread, never from inside a member; no lock of this namespace is held while they are destroyed.
  /// @return How many lookups it discarded.
  std::size_t discard_held_lookups();

  /// A `read_values_async` call one of whose items names one of @p nodeIds is recorded and read at once, as
  /// it otherwise would be, and its answer is held until @ref release_held_value_reads. An empty list holds
  /// nothing.
  void hold_value_reads_of(std::vector<NodeId> nodeIds);

  /// Waits until @p count `read_values_async` calls have been held since construction, or @p limit passes.
  /// @return Whether that many have been held.
  bool wait_for_held_value_reads(std::size_t count, std::chrono::milliseconds limit);

  /// The request held `read_values_async` call @p index (from 0, in arrival order, released or not) carried,
  /// its cancellation flag the one the call was given.
  RequestInfo held_value_read_request(std::size_t index) const;

  /// Delivers the answer of every held `read_values_async` call not yet released, in the order they arrived,
  /// as it was read when the call was made; a read still running delivers its answer when it completes.
  /// Called from the test's thread, never from inside a member. Holding continues for calls that arrive
  /// later.
  /// @return How many calls it let go.
  std::size_t release_held_value_reads();

  /// Each `modify_monitoring_async` call is recorded and applied at once, as it otherwise would be, and its
  /// answer held until @ref release_held_modify_answers. `false` stops holding later calls.
  void hold_modify_answers(bool hold = true);

  /// Waits until @p count `modify_monitoring_async` answers have been held since construction, or @p limit
  /// passes.
  /// @return Whether that many have been held.
  bool wait_for_held_modify_answers(std::size_t count, std::chrono::milliseconds limit);

  /// Delivers every held `modify_monitoring_async` answer not yet released, in the order the calls arrived.
  /// Called from the test's thread, never from inside a member.
  /// @return How many answers it let go.
  std::size_t release_held_modify_answers();

  /// Each `effective_permissions_async` call is recorded and answered at once, as it otherwise would be, and
  /// its answer held until @ref release_held_permission_answers. `false` stops holding later calls.
  void hold_permission_answers(bool hold = true);

  /// Waits until @p count `effective_permissions_async` answers have been held since construction, or @p
  /// limit passes.
  /// @return Whether that many have been held.
  bool wait_for_held_permission_answers(std::size_t count, std::chrono::milliseconds limit);

  /// Delivers every held `effective_permissions_async` answer not yet released, in the order the calls
  /// arrived. Called from the test's thread, never from inside a member.
  /// @return How many answers it let go.
  std::size_t release_held_permission_answers();

  /// `create_monitoring_async` answers each later call with the batch status @p failure and registers none of
  /// its items, as a namespace that refuses the whole call does. A Good @p failure stops it.
  void fail_create_monitoring(StatusCode failure);

  /// `create_monitoring_async` answers the item on @p nodeId with @p failure in its place, and registers and
  /// answers the call's other items as it otherwise would.
  void fail_create_monitoring_of(const NodeId& nodeId, StatusCode failure);

  /// One sample or notice an observed sink was given (@ref observe_deliveries).
  struct Delivery
  {
    IntegerId monitoredItemId{0};
    std::optional<DataValue> sample;  ///< The value pushed; disengaged for a notice.
    std::optional<StatusCode> notice;  ///< The reason of an `invalidate`; disengaged for a sample.
  };

  /// The sink of each item given to `create_monitoring_async` is replaced by one that passes every call on to
  /// it and then records each sample and notice. Every item of one sink is given the same replacement.
  void observe_deliveries(bool observe = true);

  /// Every sample and notice an observed sink was given, in the order they were passed on.
  std::vector<Delivery> deliveries() const;

  /// Waits until an observed sink has passed on a sample (@p notice false) or a notice (@p notice true) for
  /// @p monitoredItemId, or @p limit passes. A delivery is recorded after it was passed on, so the sink's own
  /// work on it has been started when this returns true.
  /// @return Whether one was passed on.
  bool wait_for_delivery(IntegerId monitoredItemId, bool notice, std::chrono::milliseconds limit) const;

  /// Reports through this namespace's monitoring helper (`context().monitoring().attribute_changed`) that
  /// @p attribute of @p nodeId now holds @p value. The Node is not changed.
  void report_change(const NodeId& nodeId, AttributeId attribute, const DataValue& value);

  /// Registers @p items through this namespace's monitoring helper (`context().monitoring()`), every one
  /// Sampled, as a namespace that samples all its items does. Each item is given the Node this namespace
  /// holds for its NodeId (null when it holds none) in place of the Node it carries. Not recorded.
  /// @return The helper's result for each item, in order.
  std::vector<default_ns::NamespaceMonitoringSupport::CreateResult> create_sampled(
    std::span<const MonitoringCreateItem> items);

  /// Runs @p hook with each recorded `read_values_async` call, on the thread that made the call, once it is
  /// recorded and before it is read or answered; no lock of this namespace is held. An empty function
  /// removes it.
  void on_value_read(std::function<void(const Call&)> hook);

  /// `call_async` answers every item of each later call `nullopt`, declining it, as a namespace that runs
  /// none of the calls it is offered does. `false` stops it.
  void decline_calls(bool decline = true);

  /// Answers each recorded `call_async` not held or declined from its copied request facts. The script
  /// is copied under the namespace's mutex and invoked without any namespace lock; an empty function
  /// restores the default answer.
  void answer_calls(std::function<BatchResult<std::optional<CallResult>>(const Call&)> answer);

  /// `call_async` records each later call and holds it, unanswered, until @ref release_held_calls. The
  /// items are not copied: they are read when the call is released, as a namespace that answers after its
  /// member has returned reads them. `false` stops holding later calls.
  void hold_calls(bool hold = true);

  /// Waits until @p count `call_async` calls have been held since construction, or @p limit passes.
  /// @return Whether that many have been held.
  bool wait_for_held_calls(std::size_t count, std::chrono::milliseconds limit);

  /// The request held call @p index (from 0, in arrival order, released or not) carried, its cancellation
  /// flag the one the call was given.
  RequestInfo held_call_request(std::size_t index) const;

  /// Stops holding calls and lets every held `call_async` call go, in the order they arrived: each is
  /// answered as the default answers it, from the items the call was given, read now. Called from the
  /// test's thread, never from inside a member.
  /// @return How many calls it let go.
  std::size_t release_held_calls();

  /// Stops holding writes and lets every held `write_async` call go, in the order they arrived: each is
  /// applied as the default applies it, to the Nodes this namespace's own lookup answers for its NodeIds,
  /// and completed. A call naming a NodeId the lookup does not answer completes with `Bad_NodeIdUnknown`
  /// for every item. Called from the test's thread, never from inside a member.
  /// @return How many calls it let go.
  std::size_t release_held_writes();

  /// The request held `write_async` call @p index (from 0, in arrival order, until @ref release_held_writes
  /// lets it go) carried, its cancellation flag the one the call was given.
  RequestInfo held_write_request(std::size_t index) const;

  /// Every call recorded since construction or the last @ref reset, in the order they were entered.
  std::vector<Call> calls() const;

  /// The recorded calls of @p member, in order.
  std::vector<Call> calls(Member member) const;

  /// Waits until @p count calls of @p member have been recorded since construction or the last
  /// @ref reset, or @p limit passes.
  /// @return Whether that many have been recorded.
  bool wait_for_calls(Member member, std::size_t count, std::chrono::milliseconds limit) const;

  /// How many calls of @p member were recorded.
  std::size_t count(Member member) const;

  /// Clears the record, so that what follows measures one operation rather than the fixture's setup.
  void reset();

  // --- Recorded members
  // --------------------------------------------------------------------------------------

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override;
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override;

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override;
  void effective_permissions_async(const RequestInfo& request, shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override;

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override;
  void release_resume_token(ByteString token) override;
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override;
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override;
  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void validate_role_permissions_updates_async(const RequestInfo& request,
    std::span<const RolePermissionsUpdate> updates,
    std::function<void(BatchResult<VoidResult>)> complete) override;
  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override;
  void add_to_view_async(const RequestInfo& request, const NodeId& view, std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;
  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override;

  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override;
  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override;
  void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override;

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override;

private:
  /// An answer held until it is released: stored when it arrives before the release, delivered when it
  /// arrives after.
  template<typename Answer>
  struct HeldAnswer
  {
    std::mutex mutex;
    std::optional<Answer> answer;
    bool released{false};
    std::function<void(Answer)> complete;
  };

  /// What the observed sinks were given, shared with them: a sink may outlive this namespace.
  struct DeliveryLog
  {
    mutable std::mutex mutex;
    mutable std::condition_variable arrived;
    std::vector<Delivery> deliveries;
  };

  /// The items to pass on: @p items, each sink replaced by its observing sink while deliveries are observed.
  std::vector<MonitoringCreateItem> observed_items(std::span<const MonitoringCreateItem> items);

  /// @p callback, or, while permission answers are held, a completion that holds its answer.
  EffectivePermissionsCallback held_permission_answer(EffectivePermissionsCallback callback);

  /// Records a monitoring create of @p items for @p request.
  void record_monitoring_create(
    std::span<const MonitoringCreateItem> items, const RequestInfo& request) const;

  /// A `write_async` call held until @ref release_held_writes: what the call is given that is valid only
  /// until it returns, copied.
  struct HeldWrite
  {
    RequestInfo request;
    std::optional<CallerInfo> caller;
    std::vector<WriteValue> values;
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete;
  };

  /// A `call_async` call held until @ref release_held_calls: the request and the caller copied, the items
  /// as given (emptied when released), and the completion.
  struct HeldCall
  {
    RequestInfo request;
    std::optional<CallerInfo> caller;
    std::vector<CallItem> items;
    std::function<void(BatchResult<std::optional<CallResult>>)> complete;
    bool released{false};
  };

  /// A `read_references_async` call held until @ref release_held_reference_reads: what the call is given
  /// that is valid only until it returns, copied.
  struct HeldReferenceRead
  {
    RequestInfo request;
    std::size_t sequence{0};
    std::vector<ReferenceQueryRecord> queries;
    std::vector<std::optional<StatusCode>> scripted;
    std::function<void(BatchResult<NodeReferencesResult>)> complete;
    bool released{false};
  };

  /// Whether a call entered now is made by a default member this namespace forwards to (and is not recorded).
  bool forwarding() const noexcept;

  // Sends @p changes to the default member, answering those of mFailedReferenceChanges' Nodes with their
  // status.
  void change_references_scripted(const RequestInfo& request, std::span<const ReferenceChange> changes,
    bool add, std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete);

  /// Whether a lookup the SDK makes now naming any of @p nodeIds is held.
  bool holds_lookup_of(std::span<const NodeId> nodeIds) const;

  /// Holds @p resume, which answers a held lookup, until @ref release_held_lookups.
  void hold_lookup(std::function<void()> resume);

  /// Answers @p queries of the call recorded as @p sequence (0 when not recorded) as the options say, each
  /// query whose @p scripted entry is engaged with that status.
  void answer_references(const RequestInfo& request, std::size_t sequence,
    std::span<const ReferenceQuery> queries, std::vector<std::optional<StatusCode>> scripted,
    std::function<void(BatchResult<NodeReferencesResult>)> complete);

  /// The scripted lookup answer for @p nodeId, when there is one.
  std::optional<NodeResult> scripted_lookup(const NodeId& nodeId) const;

  /// Records @p call and returns its @ref Call::sequence.
  std::size_t record(Call call) const;

  /// Sets the answered tokens of the recorded `read_references_async` call @p sequence, when it is still
  /// recorded.
  void note_answered_tokens(std::size_t sequence, const std::vector<ByteString>& tokens) const;

  /// Sets the scripted statuses the recorded `read_references_async` call @p sequence was answered with,
  /// when it is still recorded.
  void note_answered_statuses(
    std::size_t sequence, const std::vector<std::optional<StatusCode>>& statuses) const;

  mutable std::mutex mMutex;
  mutable std::vector<Call> mCalls;
  mutable std::size_t mSequence{0};
  bool mDeclineSingleLookups{false};
  bool mDeclineImmediatePermissions{false};
  std::map<NodeId, PermissionType> mGrants;
  std::map<NodeId, StatusCode> mRefusals;
  shared_ptr<NamespaceHistoryDelegate> mHistoryDelegate;
  bool mWholeValues{false};
  std::map<NodeId, StatusCode> mFailedReads;
  bool mHoldWrites{false};
  std::vector<HeldWrite> mHeldWrites;
  std::map<NodeId, StatusCode> mFailedWrites;
  std::map<NodeId, StatusCode> mFailedReferenceChanges;
  std::function<bool(const NodeId&, const NodeId&)> mViewMembership;
  bool mAcceptViewAdditions{false};
  bool mAnswerCreationsWithoutNode{false};
  bool mApplyReferenceHints{false};
  std::size_t mPageSize{0};
  bool mPageByMaxReferences{false};
  bool mEveryReference{false};
  std::map<NodeId, NodeResult> mLookupAnswers;
  std::map<NodeId, StatusCode> mLookupBatchStatuses;
  std::map<NodeId, std::size_t> mLookupItemLimits;
  std::map<NodeId, std::map<std::size_t, StatusCode>> mReferenceQueryAnswers;
  std::map<NodeId, std::size_t> mReferenceQueryCounts;
  std::vector<NodeId> mHoldReferenceReadsOf;
  std::vector<HeldReferenceRead> mHeldReferenceReads;
  std::condition_variable mHeldReferenceReadArrived;
  std::vector<NodeId> mPageWithoutEndOf;
  std::vector<NodeId> mHoldLookupsOf;
  std::vector<std::function<void()>> mHeldLookups;
  std::size_t mHeldLookupCount{0};
  std::condition_variable mHeldLookupArrived;
  std::size_t mEndlessTokens{0};
  mutable std::condition_variable mRecorded;
  std::vector<NodeId> mHoldValueReadsOf;
  std::vector<std::shared_ptr<HeldAnswer<BatchResult<DataValueResult>>>> mHeldValueReads;
  std::vector<RequestInfo> mHeldValueReadRequests;
  std::condition_variable mHeldValueReadArrived;
  bool mHoldModifyAnswers{false};
  std::vector<std::shared_ptr<HeldAnswer<BatchResult<MonitoringModifyItemResult>>>> mHeldModifyAnswers;
  std::condition_variable mHeldModifyAnswerArrived;
  bool mHoldPermissionAnswers{false};
  std::vector<std::shared_ptr<HeldAnswer<EffectivePermissionsResult>>> mHeldPermissionAnswers;
  std::condition_variable mHeldPermissionAnswerArrived;
  std::optional<StatusCode> mCreateMonitoringFailure;
  std::map<NodeId, StatusCode> mCreateMonitoringItemFailures;
  bool mObserveDeliveries{false};
  std::shared_ptr<DeliveryLog> mDeliveryLog{std::make_shared<DeliveryLog>()};
  std::map<const SampleSink*, std::shared_ptr<SampleSink>> mObservingSinks;
  std::function<void(const Call&)> mValueReadHook;
  bool mDeclineCalls{false};
  std::function<BatchResult<std::optional<CallResult>>(const Call&)> mCallAnswer;
  bool mHoldCalls{false};
  std::vector<HeldCall> mHeldCalls;
  std::condition_variable mHeldCallArrived;
  boost::asio::any_io_executor mExecutor;
};

}  // namespace ua::test

#endif  // UA_TEST_BATCH_RECORDING_NAMESPACE_H
