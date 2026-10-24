// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ATTRIBUTE_SERVICE_SET_H
#define UA_ATTRIBUTE_SERVICE_SET_H

#include <atomic>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "ua_access_control.h"
#include "ua_allow_nulls_batch.h"
#include "ua_write_type_facts.h"
#include "ua_request_info.h"
#include "ua_await_callback.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_data_access_projection.h"
#include "ua_diagnostic_collector.h"
#include "ua_locale_id.h"
#include "ua_node_accessor.h"
#include "ua_node_utilities.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_service_base.h"
#include "ua_state_machine_runtime.h"
#include "ua_data_access_utils.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

namespace ua
{

class Node;
class VariableAccessor;

namespace detail
{
class ModelChangeStep;
}  // namespace detail

namespace server
{

struct ReadOperation;
struct ValueGroup;

/// The two values the AllowNulls policy read reports, carried together.
///
/// An await resumes with ONE value and that read produces two. Naming the pair is the honest way to
/// bridge it; the alternative - a second await, or smuggling the status into the optional - would
/// hide a policy decision inside a mechanism.
struct WriteOperation;
struct WriteFactsCache;

class AttributeServiceSet : public ServiceBase<AttributeServiceSet>
{
public:
  AttributeServiceSet(const AttributeServiceSet&) = delete;
  AttributeServiceSet& operator=(const AttributeServiceSet&) = delete;
  AttributeServiceSet(AttributeServiceSet&&) = delete;
  AttributeServiceSet& operator=(AttributeServiceSet&&) = delete;

  void abort(StatusCode reason) override;

  /// This request's withdrawal flag, for the coroutines that belong to it.
  ///
  /// Read by @ref ua::async::detail::PromiseBase, which constructs every promise from the
  /// coroutine's own argument list - and for a member coroutine the first of those is `*this`. So
  /// every task this service starts adopts the token with nothing written at any call site: there is
  /// no parameter to pass, and so none to forget. Renaming or removing this silently unhooks
  /// cancellation from the whole service, which is why `tooling/ci/falsify_coro.py` mutates it.
  [[nodiscard]] std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return mCancelled;
  }

  ~AttributeServiceSet();

  using ServiceCallComplete = std::function<void(Response)>;

  // Read factory
  static shared_ptr<AttributeServiceSet> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, ReadRequest&& readRequest,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // Write factory
  static shared_ptr<AttributeServiceSet> create(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId,
    WriteRequest&& writeRequest, boost::asio::any_io_executor executor, ServiceCallComplete callback);

private:
  friend class ServiceBase<AttributeServiceSet>;

  std::vector<LocaleId> mSessionLocales;
  uint32_t mRequestId;
  optional<ReadRequest> mReadRequest;
  optional<WriteRequest> mWriteRequest;
  ServiceCallComplete mServiceCallCompleteCallback;

  shared_ptr<std::atomic_bool> mCancelled;
  /// The request the Read or the Write serves, as the namespaces are told it: its deadline from the
  /// timeoutHint, this service's cancellation flag and the Session's locales. Built once, when the request
  /// starts.
  RequestInfo mRequestInfo;

  // Read request state. This service is constructed PER REQUEST, so these members ARE the request's
  // state - there is nothing for a struct to group and nothing for a pointer to disengage. What an
  // operation uses on its own lives in its own coroutine frame; see ReadOperation.
  std::optional<AddressSpace> mReadAddressSpace;  // optional only because AddressSpace has no default
  shared_ptr<ReadResponse> mReadResponse;
  DiagnosticCollector mReadCollector{0};
  LocaleId mReadDefaultLocale;
  std::optional<SessionAccessControl> mReadAccessControl;
  /// On whose behalf the namespaces read the Values: the Session's CallerInfo with the identity the
  /// authorization used. Null without access control, which is the server's own read.
  std::shared_ptr<const CallerInfo> mReadCaller;
  /// Bound on the Read response body, in bytes: the Session's negotiated maxResponseMessageSize when
  /// non-zero, else the configured maximum message size; 0 means unbounded (OPC 10000-4 5.3, 5.6.2.2).
  uint64_t mReadResponseLimit{0};
  /// Running lower bound on the encoded size of the results read so far; see
  /// @ref note_read_result_size. Once it exceeds @ref mReadResponseLimit no further operation starts
  /// and the whole request is answered Bad_ResponseTooLarge.
  uint64_t mReadResponseEstimate{0};

  /// Each request's own coroutine - the batched head. Held here for the same reason the
  /// per-operation tasks are: it must outlive the frame that started it.
  ua::async::Task<> mReadRequestTask;
  ua::async::Task<> mWriteRequestTask;

  // Write request state. Plain members for the same reason the Read ones are: this service is
  // constructed per request, so its members ARE the request's state.
  std::optional<AddressSpace> mWriteAddressSpace;  // optional only because AddressSpace has no default
  shared_ptr<WriteResponse> mWriteResponse;
  DiagnosticCollector mWriteCollector{0};
  std::vector<std::string> mWriteSupportedLocales;
  std::optional<SessionAccessControl> mWriteAccessControl;

  // Read constructor
  AttributeServiceSet(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
    uint32_t requestId, ReadRequest&& readRequest, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  // Write constructor
  AttributeServiceSet(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId, WriteRequest&& writeRequest,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // Kick-off hook called by ServiceBase::start(). Dispatches to start_read_request
  // or start_write_request based on which constructor was used.
  void begin_processing();

  // --- Read path --------------------------------------------------------------
  void start_read_request();
  void complete_read_request();
  void fail_read_request(VoidResult error);

  /// The batched half of a Read, top to bottom.
  ///
  /// ONE `find_nodes` answers the whole request and ONE authorization call answers its nodes. That
  /// is not an optimisation to be traded away: resolving or authorizing per operation would turn a
  /// remote namespace's single round trip into one per item.
  ///
  /// @param operationIndices The items to run, BY VALUE so that they are moved into this task's own
  ///                         frame. A root task owns what it needs; only the body it calls borrows.
  ua::async::Task<> run_read_request(std::vector<size_t> operationIndices);

  /// Carries out the batched half. @see run_read_request
  ///
  /// Separate from @ref run_read_request only so that one has somewhere to catch: a coroutine has
  /// one body, and an exception escaping a root task is stored in its promise and read by nobody.
  ///
  /// @param operationIndices Borrowed from @ref run_read_request's frame, which outlives this one.
  ua::async::Task<> dispatch_read_request(std::span<const size_t> operationIndices);

  /// Answers one read operation: from its resolved, authorized node to the value the client gets.
  ///
  /// Takes the operation BY VALUE, so the whole of it is moved into this task's frame and nothing
  /// outside that frame can reach or invalidate it. Returns the answer rather than writing it into
  /// shared state, which is what lets exactly one place - @ref read_and_record - record it.
  ua::async::Task<DataValue> read_operation(ReadOperation operation);

  /// Runs one read operation and records its answer the moment it has one, so that a response sent
  /// at the timeoutHint carries every item that finished, whatever order the join reaches them in.
  ua::async::Task<> read_and_record(ReadOperation operation);

  /// One namespace's Value items: one read of their Values, then each item finished and recorded, so
  /// that they are answered when their namespace answers, whatever the other namespaces do.
  ua::async::Task<> read_group(ValueGroup group);

  /// Finishes one Value item and records its answer. @see read_and_record
  ua::async::Task<> finish_and_record(ReadOperation operation, DataValueResult read);

  /// Everything the service does to a Value after its namespace answered it: the projections keyed on
  /// the Variable's BrowseName, the state machine's activity, AllowNulls, and the post-processing.
  ua::async::Task<DataValue> finish_value(ReadOperation operation, DataValueResult read);

  /// The user's view of the attribute, the DataEncoding and, unless the namespace applied it, the
  /// IndexRange; a bad status's detail collected once and the result's size counted.
  DataValue projected_read_result(const ReadOperation& operation, DataValue value);

  /// Sets @p status on @p value, keeping the value read, and collects its detail.
  void fail_read_value(size_t opIndex, DataValue& value, const StatusCode& status);

  /// Runs the node-independent pre-checks for one read operation (access-identity availability,
  /// attribute-id mapping, dataEncoding validation) and builds the operation itself.
  ///
  /// @return The operation to run, or nothing when a pre-check already settled it - in which case it
  ///         must not enter the batch.
  std::optional<ReadOperation> prepare_read_operation(size_t opIndex);

  /// Awaits one collaborator call in an operation's flow.
  ///
  /// Every suspension in a read operation has the same shape - hand the collaborator a completion,
  /// resume with what it produced - and the lifetime rule is identical for all of them: the answer
  /// hops to this service's strand and the suspension's generation is re-checked before the frame is
  /// touched. Naming it once keeps that rule in one place rather than restated at each await, and
  /// keeps each step in the flow one line long.
  ///
  /// The awaiting task's liveness travels in its own promise, so no slot is threaded through and no
  /// accessor on this service is needed: a completion arriving after the task is gone finds an
  /// expired weak pointer and retires itself. This service owns the frames, directly or through the
  /// request task that holds them, so its weak handle is what pins them across a resumption.
  /// @see ua::async::await_callback
  ///
  /// @tparam T        The collaborator's result type.
  /// @param initiate  Invoked with the completion to hand the collaborator.
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand, mLogger, weak_from_this(), std::forward<Initiate>(initiate));
  }

  // --- the projections ---------------------------------------------------------------------
  //
  // Each is named for something the OPC UA specification talks about, takes what it needs BY VALUE,
  // and returns what it computed. None of them knows which operation it is serving - that stays the
  // dispatcher's business - so a projection cannot be wrong about it, and has nothing to re-acquire
  // after a suspension. The only thing they share with this service is @ref await_step.

  /// Part 19 section 7.1: the ValueAsDictionaryEntries snapshot of its owning
  /// MultiStateDictionaryEntryDiscrete Variable.
  ua::async::Task<data_access_projection::OptionalDictionarySnapshotResult> project_dictionary(
    AddressSpace addressSpace, NodeAccessor node);

  /// The LocalizedText a Variable publishes alongside its numeric Value.
  ua::async::Task<data_access_projection::OptionalLocalizedTextResult> project_value_as_text(
    AddressSpace addressSpace, NodeAccessor node);

  /// SVR-AUTHZ-011: the owner a Part-19 projection discloses is a different Node from the one the
  /// batch authorized, so before the projection runs it is authorized for Read in its own right and
  /// checked readable (CurrentRead). No owner means nothing is disclosed and nothing to authorize.
  /// Cost: one reference walk, one find and one authorization per projected read, on top of the
  /// projection's own walk (kept, so the projection's answer stays independent of the service).
  ua::async::Task<VoidResult> authorize_projection_owner(AddressSpace addressSpace, NodeAccessor node);

  /// Part 20 section 4.2.1: FileType.UserWritable is the static file-writability flag projected
  /// through the current user's rights on the owning File Object. Value handlers deliberately have
  /// no Session context, so this projection belongs at the authenticated Read service boundary.
  ///
  /// @return The projected flag, or the status of the hop that failed. A standard UserWritable
  ///         Property with no owning File yields `false` - failing closed, while leaving the Read
  ///         itself usable for diagnostics.
  ua::async::Task<Result<bool>> project_user_writable(
    AddressSpace addressSpace, NodeAccessor node, SessionAccessControl accessControl);

  /// Whether the state-machine Variable at @p target is in an active state.
  ua::async::Task<OptionalStateMachineActiveResult> state_machine_is_active(
    AddressSpace addressSpace, NodeId target);

  /// Whether the Method at @p target may be executed in the state the machine is in.
  ua::async::Task<OptionalMethodExecutableResult> method_is_executable(
    AddressSpace addressSpace, NodeId target);

  /// The Variable's AllowNulls policy, as its AllowNulls Property reports it.
  ua::async::Task<AllowNullsOutcome> null_value_is_allowed(AddressSpace addressSpace, NodeId target);

  /// The Variable's current value, asking the namespace to answer without deferring first.
  ///
  /// When it can - which an in-memory namespace can for nearly every operation - the completion is
  /// called on this stack, its resumption dispatches to the strand already running, and the await
  /// finds the answer waiting without ever suspending.
  /// @param identity The Session this Read serves, where the value may depend on it. Null for the
  ///                  Write path's before/after reads, which compare the stored value rather than
  ///                  any caller's view of it.
  ua::async::Task<DataValueResult> read_variable_value(VariableAccessor variable, double maxAge,
    bool sourceTimestamp, ReadValueId nodeToRead, std::optional<CallerInfo> caller);

  /// Writes one operation's answer onto the response.
  void record_read_result(size_t opIndex, DataValue result);

  /// Adds @p value's lower-bound encoded size to @ref mReadResponseEstimate.
  ///
  /// Called once per answered value, on the strand, from the operation's projection. Cost: O(1) for a
  /// scalar and O(elements) for an array of Strings/ByteStrings (each element's size is already held),
  /// with no encoding pass.
  void note_read_result_size(const DataValue& value);

  /// Whether the results read so far already exceed the response limit. O(1).
  bool read_response_too_large() const noexcept;

  /// Folds an awaited ValueAsDictionaryEntries snapshot into an operation's result.
  void apply_dictionary_snapshot(ReadOperation& operation, DataValue& value,
    data_access_projection::OptionalDictionarySnapshotResult result);

  void emit_read_audit_if_failed(SessionInfo& sessionInfo, ReadResponse& response);

  // --- Write path -------------------------------------------------------------
  void start_write_request();
  void complete_write_request();
  void fail_write_request(VoidResult error);

  /// The batched half of a Write, top to bottom.
  ///
  /// ONE `find_nodes` and ONE authorization call for the whole request, as on the Read path. The
  /// per-operation entry stays @ref on_write_node_resolved, because the dictionary-write
  /// translation re-enters it with a DIFFERENT node - the owning Variable - which has to be
  /// authorized in its own right. That is one extra item, not one per operation, so it does not
  /// undo the batching.
  /// @param operationIndices The items to run, BY VALUE so they are moved into this task's frame.
  ua::async::Task<> run_write_request(std::vector<size_t> operationIndices);

  /// Carries out the batched half. @see run_write_request
  ua::async::Task<> dispatch_write_request(std::span<const size_t> operationIndices);

  /// Writes one operation's status onto the response. The audit event is NOT emitted here.
  void record_write_result(size_t opIndex, StatusCode status);

  /// Folds one authorization verdict into an operation: denied finalizes it, permitted hands it to
  /// the per-operation chain.
  ///
  // Runs the node-independent pre-checks for one write op (session liveness, access-identity
  // availability, attribute-id mapping). Returns true when the op still needs node resolution;
  // returns false when it already finalized (early reject) and so must not enter the batch.
  std::optional<WriteOperation> prepare_write_operation(size_t opIndex);

  /// Writes one wave of the request (DL-62 (5)): the items of @p wave name each (NodeId, Attribute) once. The
  /// checks the Nodes' descriptions decide; the DataType facts (shared through @p facts by the waves), the
  /// AllowNulls Properties, the audit old values and the RolePermissions validations, read together with one
  /// namespace call per namespace each; the checks on what was read; the information-model pairs and the
  /// Data Access rules (NR-24 5e, 5f); the checks on the value they leave; one `write_async` per namespace.
  /// An item is recorded, with its audit event, before the wave next waits once it has its answer, and the
  /// items each namespace writes when that namespace answers, so a response sent at the timeoutHint carries
  /// every item that finished (DL-62 (2)).
  /// @p step records the versioned Nodes of the whole request, every wave included; null when there is
  /// nothing to write.
  ua::async::Task<> write_wave(std::vector<WriteOperation>& wave, WriteFactsCache& facts,
    std::shared_ptr<::ua::detail::ModelChangeStep> step);

  /// One namespace's open items of a wave, written in one `write_async` (split by MaxNodesPerWrite) and each
  /// recorded, with its audit event, when that namespace answers. @param group BY VALUE, owned by this task.
  ua::async::Task<> write_group(std::vector<WriteOperation> group, RequestInfo request,
    std::optional<CallerInfo> caller, std::optional<uint32_t> maxNodesPerWrite,
    std::shared_ptr<::ua::detail::ModelChangeStep> step);

  /// Records @p status as @p operation's result, with its detail, and emits its audit event when it is
  /// audited.
  void record_write_outcome(WriteOperation& operation, StatusCode status);

  /// Part 19 7.1: a Value write to ValueAsDictionaryEntries translated into a write to its owner, which is
  /// authorized in its own right. @return The refusal, or nothing when the item now names the owner.
  ua::async::Task<std::optional<StatusCode>> translate_dictionary_write(WriteOperation& operation);

  /// The checks of an item that its Node's description decides, in today's order; classifies the item and
  /// determines its audit interest. A refusal is the item's answer.
  void early_write_checks(WriteOperation& operation, bool auditInterest);

  /// The checks of a Value against its declared DataType's facts (@p facts null when it needs none or has
  /// none): enumeration member, lexical form, built-in base; notes a structured declared type for
  /// @ref structure_and_rank_checks.
  void typed_value_checks(WriteOperation& operation, const DataTypeFacts* facts);

  /// The written Structures against the declared structured DataType, then the ValueRank.
  void structure_and_rank_checks(WriteOperation& operation, const WriteFactsCache& facts);

  /// NR-24 step 5e (NR-34 rule 1): the whole-array Value writes to 0:Selections, 0:SelectionDescriptions and
  /// 0:EnumValues are checked against their pairs, together; any other item costs nothing. A refusal is the
  /// item's answer.
  ua::async::Task<> information_model_pairs(std::vector<WriteOperation>& wave);

  /// NR-24 step 5f (NR-58, NR-59): the Data Access rules for the Value writes to Variables of a Data Access
  /// type. Their TypeDefinitions are read in one call per namespace and decided from the namespace-0 table, a
  /// type of another namespace walked up to namespace 0; the bounding Properties are read in three calls. An
  /// analog value outside InstrumentRange, else EURange, is refused or clamped as @p policy says (a clamped
  /// item answers Good_Clamped when it is stored with plain Good); a MultiState value that is not defined is
  /// refused. A read the rules need that fails refuses the item with its status.
  ua::async::Task<> data_access_rules(std::vector<WriteOperation>& wave, DataAccessOutOfRangePolicy policy,
    std::optional<uint32_t> maxNodesPerBrowse, std::optional<uint32_t> maxNodesPerRead);

  /// The checks on the value steps 5e and 5f leave (DL-62 (4)): WriteFullArrayOnly and the range's syntax
  /// for a ranged write, the ValidBits of an OptionSet write.
  void late_write_checks(WriteOperation& operation, const WriteFactsCache& facts);

  void emit_write_audit_event(SessionInfo& sessionInfo, WriteOperation& operation, StatusCode result);

  // --- Common ----------------------------------------------------------------
  void set_timeout();
  void timeout();

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);
};

// Backwards-compatible alias
using ReadService = AttributeServiceSet;

}  // namespace server

}  // namespace ua

#endif  // !UA_ATTRIBUTE_SERVICE_SET_H
