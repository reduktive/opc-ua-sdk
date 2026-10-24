// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_method_service_set.h"
#include "ua_verdict_rules.h"
#include "ua_access_control.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_callback_safety.h"
#include "ua_audit_update_method_event_payload.h"
#include "ua_audit_update_state_event_payload.h"
#include "ua_date_time.h"
#include "ua_diagnostic_collector.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_log_exception.h"

#include "ua_namespace.h"
#include "ua_namespace_route.h"
#include "ua_instance_utils.h"
#include "ua_method_id.h"
#include "ua_method_result.h"
#include "ua_method_call_authorization_internal.h"
#include "ua_state_machine_method_hook.h"
#include "ua_state_machine_runtime.h"
#include "ua_namespace_zero_tables.h"
#include "ua_node.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_reference_type_model.h"
#include "ua_referencetype_id.h"
#include "ua_service_request_info.h"
#include "ua_on_strand.h"
#include "ua_object_id.h"
#include "ua_variant.h"
#include "ua_weak_address_space.h"
#include "ua_server.h"
#include "ua_server_encoding_limits.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include "fmt/format.h"

#include <algorithm>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace ua::server
{

/// What a call's `AuditUpdateMethodEventType` Event takes from its Session and server, captured when the Call
/// is received, so that every item is audited on behalf of the user who made the request, at the time it was
/// made, and a call answered after the Session has closed is audited all the same (OPC 10000-4 6.5.9,
/// COMP-SVR-NAMESPACE-CALLS-20).
struct CallAuditFacts
{
  /// Whether the server audits; nothing else is captured when it does not.
  bool auditing{false};
  /// The time the user initiated the action (OPC 10000-5 6.4.3): when the Call was received. The
  /// ActionTimeStamp of every audit Event the request raises, the state Event of a transition included.
  DateTime actionTime;
  /// The server's event bus, held weakly: nothing is raised through one that has been destroyed.
  std::weak_ptr<EventSink> eventSink;
  String serverId;
  String clientAuditEntryId;
  String clientUserId;
};

namespace
{

/// Logs, at Warning, that the Method @p methodId gave its statusCode the Good subcode @p given, which OPC
/// 10000-4 5.11.2.4 forbids, and that the Call service answered plain Good.
void log_method_status_qualified(const Logger& logger, const NodeId* methodId, const StatusCode& given)
{
  if (!logger.is_enabled(LogLevel::Warning))
  {
    return;
  }
  const std::string method = methodId ? ua::to_string(*methodId) : std::string{};
  const std::string code = ua::to_string(given);
  logger.warning({{"method_id", std::string_view{method}}, {"status", std::string_view{code}}},
    "A Method's statusCode was Good with a subcode, which OPC 10000-4 5.11.2.4 forbids; answered Good");
}

/// The statusCode the Call service answers for a Method whose namespace answered @p outer on its result and
/// @p inner as the CallMethodResult's statusCode: the code @ref server::detail::combined_item_status gives
/// for the two (OPC 10000-4 has room for one), and a Good subcode answered plain Good with the ErrorDetail
/// `MethodStatusQualified` whose cause is the given code (5.11.2.4 forbids a Good subcode as a Method's
/// statusCode). This is the only place a Method's Good subcode is answered Good: a namespace, a handler and
/// its `MethodResult` pass the code on as given. With a @p logger, a dropped outer code and a Good subcode
/// answered Good are logged, naming the Method.
StatusCode method_status_as_answered(
  const StatusCode& outer, const StatusCode& inner, const Logger* logger, const NodeId* methodId)
{
  const StatusCode combined = logger ? server::detail::combined_item_status(outer,
                                         inner,
                                         *logger,
                                         "CallService: a Method's answer code was not answered",
                                         methodId ? *methodId : NodeId{})
                                     : ua::detail::combined_status(outer, inner);
  if (ua::detail::is_good_with_subcode(combined))
  {
    if (logger)
    {
      log_method_status_qualified(*logger, methodId, combined);
    }
    return ua::detail::method_status_qualified(combined);
  }
  return combined;
}

void sanitize_method_status(CallMethodResult& result)
{
  const auto& status = result.status_code();

  // Part 4 5.11.2.2: InputArgumentResults and InputArgumentDiagnosticInfos are defined only for
  // Bad_InvalidArgument. A Method body may populate them defensively, but they must not escape for
  // any other operation status.
  if (status.as_status() != Status::BadInvalidArgument)
  {
    result.input_argument_results().payload().clear();
    result.input_argument_diagnostic_infos().payload().clear();
  }

  // OutputArguments describe a successfully completed Method invocation. Preserve the primary
  // rich failure while removing outputs that cannot be valid after a failed application operation.
  if (status.is_bad())
  {
    result.output_arguments().payload().clear();
  }
}

/// Puts @p answer, which holds a CallMethodResult, into the form the Call service answers it in: its code
/// combined onto the CallMethodResult's statusCode (@ref method_status_as_answered), the result itself Good,
/// and the input argument results and output arguments the statusCode does not allow cleared.
void sanitize_method_answer(CallResult& answer, const Logger& logger, const NodeId* methodId)
{
  const StatusCode outer = answer.status_code();
  CallMethodResult result = std::move(answer).value();
  result.status_code() = method_status_as_answered(outer, result.status_code(), &logger, methodId);
  answer = CallResult{std::move(result)};
  sanitize_method_status(answer.value());
}

/// The facts of a call's audit Event, from @p sessionInfo, for a request received at @p actionTime. Throws as
/// the Session's server accessors do once its server has been destroyed.
CallAuditFacts call_audit_facts(
  const SessionInfo& sessionInfo, const String& auditEntryId, DateTime actionTime)
{
  CallAuditFacts facts;
  facts.actionTime = actionTime;
  facts.auditing = sessionInfo.server_configuration().auditingEnabled;
  if (!facts.auditing)
  {
    return facts;
  }
  facts.eventSink = sessionInfo.event_sink();
  facts.serverId = sessionInfo.configuration().application_description_part().applicationUri;
  facts.clientAuditEntryId = auditEntryId;
  if (const auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto user = sec->user_identity())
      facts.clientUserId = user->userId;
  }
  return facts;
}

/// Raises the AuditUpdateMethodEvent of one Method call whose outcome is @p status, from @p facts, when the
/// server audits and something listens.
void emit_call_audit(const CallAuditFacts& facts, const Logger& logger, const CallMethodRequest& methodToCall,
  const StatusCode& status)
{
  if (!facts.auditing)
    return;
  const auto sink = facts.eventSink.lock();
  if (!sink || !static_cast<EventBus*>(sink.get())->has_event_interest())
    return;
  try
  {
    AuditUpdateMethodEventPayload auditEvent;
    // OPC 10000-5 section 6.4.x: SourceNode is the Object the Method resides on, and the SourceName for
    // this Event type is "Attribute/Call" -- the Attribute service set the Call Service belongs to,
    // not the "Method/..." the service set's own name suggests. A name invented from the service set
    // reads plausibly and matches nothing a compliant Client filters on.
    auditEvent.sourceNode = methodToCall.object_id();
    auditEvent.sourceName = "Attribute/Call";
    auditEvent.actionTimeStamp = Variant{facts.actionTime};
    auditEvent.status = status.is_good();
    auditEvent.serverId = facts.serverId;
    auditEvent.methodId = methodToCall.method_id();
    auditEvent.inputArguments = Variant{methodToCall.input_arguments()};
    auditEvent.message = LocalizedText{"", "Call"};
    auditEvent.severity = 1;
    auditEvent.clientAuditEntryId = facts.clientAuditEntryId;
    auditEvent.clientUserId = facts.clientUserId;
    sink->emit(auditEvent);
  }
  catch (const UaException&)
  {
    // This void post-response helper's throw would escape to std::terminate. Record the drop at debug via
    // the service's own logger so the swallow stays observable rather than silent.
    log_exception(
      logger, LogLevel::Debug, "EmitAuditEvent", ua::exception_to_status_code(std::current_exception()));
  }
}

/// @ref emit_call_audit on behalf of the Session @p session, with its facts as they are now: for a request
/// whose facts were never captured.
void emit_call_audit(const weak_ptr<SessionInfo>& session, const String& auditEntryId, const Logger& logger,
  const CallMethodRequest& methodToCall, const StatusCode& status)
{
  auto sessionInfo = session.lock();
  if (!sessionInfo)
    return;
  // Best-effort, post-response auditing. A shutdown/teardown race can destroy the ServerImpl behind the
  // still-live SessionInfo, so server_configuration()/configuration() throw ServerDestroyed (BadInvalidState)
  // and event_sink() answers null. Auditing a call on a server that is going away is meaningless, and this
  // void post-response helper's throw would escape to std::terminate. Contain the race and skip the audit.
  try
  {
    emit_call_audit(
      call_audit_facts(*sessionInfo, auditEntryId, DateTime::now()), logger, methodToCall, status);
  }
  catch (const UaException&)
  {
    // Server torn down mid-flight (BadInvalidState / ServerDestroyed) - nothing left to audit to.
    // Record the drop at debug via the service's own logger (sessionInfo may be the torn-down object)
    // so the swallow stays observable rather than silent.
    log_exception(
      logger, LogLevel::Debug, "EmitAuditEvent", ua::exception_to_status_code(std::current_exception()));
  }
}

}  // namespace

// =============================================================================================
// Per-request state. CallRequestState holds the request's inputs and response. The existing
// Call flow processes every item; its child tasks belong to the run_dispatch frame.
// =============================================================================================

/// What one Call request is working with, for as long as it is working.
///
/// This is state, not a flow: no step saying where the request has got to, and no `pendingUnits`
/// counting its units down. Where the request has got to is where its body has got to, and the count
/// is the join in @ref MethodServiceSet::run_dispatch. What remains is what the request was given
/// and what it is building - and something OTHER than the body reads it, because a timeout or a
/// cancellation has to answer a request whose body can no longer be asked.
struct CallRequestState
{
  AddressSpace addressSpace;
  shared_ptr<CallResponse> response;
  DiagnosticCollector collector;
  std::optional<SessionAccessControl> accessControl;
  /// What every item's audit Event is raised with, captured when the Call was received.
  CallAuditFacts audit;

  CallRequestState(AddressSpace initialAddressSpace, DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), collector(std::move(initialCollector))
  {}
};

shared_ptr<MethodServiceSet> MethodServiceSet::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, CallRequest&& callRequest,
  boost::asio::any_io_executor executor, CallServiceCallComplete callback,
  std::optional<MethodResponseCorrelation> responseCorrelation)
{
  struct Wrapper : public MethodServiceSet
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      CallRequest&& callRequest, boost::asio::any_io_executor executor, CallServiceCallComplete callback,
      std::optional<MethodResponseCorrelation> responseCorrelation)
      : MethodServiceSet(sessionInfo, std::move(sessionLocales), requestId, std::move(callRequest), executor,
          callback, responseCorrelation)
    {}
  };

  auto svc = make_shared<Wrapper>(sessionInfo,
    std::move(sessionLocales),
    requestId,
    std::move(callRequest),
    executor,
    callback,
    responseCorrelation);
  svc->start();
  return svc;
}

MethodServiceSet::MethodServiceSet(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
  uint32_t requestId, CallRequest&& callRequest, boost::asio::any_io_executor executor,
  CallServiceCallComplete callback, std::optional<MethodResponseCorrelation> responseCorrelation)
  : ServiceBase(callRequest.request_header().request_handle(), sessionInfo, executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId), mCallRequest(std::move(callRequest)),
    mServiceCallCompleteCallback(callback), mResponseCorrelation(responseCorrelation),
    mCancelled(std::make_shared<std::atomic_bool>(false))
{}

// Destructor - fires Status::BadShutdown when destroyed mid-flight.
MethodServiceSet::~MethodServiceSet()
{
  if (!mRequestState && !mCallTask)
  {
    return;
  }
  if (!try_finish())
  {
    return;
  }
  auto callback = std::move(mServiceCallCompleteCallback);
  mRequestState.reset();
  mCallTask = {};
  if (callback)
  {
    auto serviceFault =
      stack_utils::create_service_fault(&mCallRequest.request_header(), Status::BadShutdown);
    callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceFault)));
  }
}

void MethodServiceSet::begin_processing()
{
  start_call();
}

// =============================================================================================
// Top-level Call flow
// =============================================================================================

void MethodServiceSet::start_call()
{
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{mCallRequest.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    check(sessionInfo);
    // The time the Call was received, which every audit Event of its items reports as the time the user
    // initiated the action (OPC 10000-5 6.4.3).
    const auto received = DateTime::now();

    set_timeout();
    mRequestInfo = service_request_info(std::chrono::steady_clock::now(),
      mCallRequest.request_header().timeout_hint(),
      std::nullopt,
      mCancelled,
      mSessionLocales);

    auto addressSpace = sessionInfo->address_space();

    const size_t noOfOperations{mCallRequest.methods_to_call().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail("EmptyCallRequest", "Call request contains no methods to call", "MethodService")};
    }

    auto& maxNodesPerMethodCall =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerMethodCall;
    if (maxNodesPerMethodCall && (noOfOperations > maxNodesPerMethodCall.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyMethodsToCall",
          "Requested number of methods exceeds the MaxNodesPerMethodCall operation limit",
          "MethodService")
          .context(ua::ContextKeys::sizeActual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxNodesPerMethodCall.value()))};
    }

    auto callResponse = make_shared<CallResponse>();
    callResponse->results().resize(noOfOperations);
    // Every item starts as Bad_Timeout and is overwritten when it is answered, so a response sent at
    // the timeoutHint reports the unfinished items as such (see timeout()).
    for (auto& result : callResponse->results())
    {
      result.status_code() = StatusCode{Status::BadTimeout};
    }

    mRequestState = std::make_unique<CallRequestState>(std::move(addressSpace), std::move(collector));
    mRequestState->accessControl = SessionAccessControl::create(*sessionInfo);
    mRequestState->audit =
      call_audit_facts(*sessionInfo, mCallRequest.request_header().audit_entry_id(), received);
    mRequestState->response = callResponse;

    const auto limits = ua::server::make_server_encoding_limits(
      sessionInfo->configuration(), sessionInfo->server_configuration());

    std::vector<size_t> indices;
    indices.reserve(noOfOperations);
    for (size_t index = 0; index < noOfOperations; ++index)
    {
      indices.push_back(index);
    }

    start_dispatch(std::move(indices), limits);
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(sessionInfo->logger().with_category("service"), LogLevel::Error, "CallService", er);
    }
    collector.set_service_detail(er);
    send_service_fault(mCallRequest.request_header(), er, collector);
  }
}

void MethodServiceSet::start_dispatch(std::vector<size_t> indices, ua::EncodingLimits limits)
{
  // A per-request service handles exactly ONE call, so there is no next request to race the slot -
  // the generation guard the strand components need has nothing to guard here. The body may still
  // finish entirely before this returns, which is why the service is kept alive across this call by
  // the posted handler that reached it.
  mCallTask = run_dispatch(std::move(indices), std::move(limits));
}

void MethodServiceSet::answer_unstarted_rows(std::span<const size_t> rows, StatusCode failure)
{
  if (!mRequestState)
  {
    return;
  }
  auto& results = mRequestState->response->results();
  for (auto index : rows)
  {
    if (index >= results.size())
    {
      continue;
    }
    results[index].status_code() = failure;
    if (auto detail = failure.shared_detail())
    {
      mRequestState->collector.add_item_detail(index, std::move(detail));
    }
    // Audited like every other answered row: a method the server refused to even start is still a
    // method the client asked for and was answered about.
    emit_audit_event(mCallRequest.methods_to_call()[index], results[index]);
  }
}

ua::async::Task<> MethodServiceSet::run_dispatch(std::vector<size_t> indices, ua::EncodingLimits limits)
{
  // A ROOT task: nobody awaits `mCallTask`, so an exception that escaped this body would be stored
  // in a promise nobody can read, and the client's Call would never be answered at all - no
  // response, no fault, and with `timeoutHint == 0` not even a timeout. The chain this replaces did
  // not need to say so, because its spawn loop ran inside `start_call`'s own try; moving the loop
  // into a coroutine body moved it out of that try's reach, and this is what puts it back.
  try
  {
    // The unit bodies are LOCALS of this frame. Unwinding this body destroys them and retires their
    // continuations without anything being told, which is why there is no vector of them on the
    // service and nothing that can free a frame from inside one.
    std::vector<ua::async::Task<>> units;
    units.reserve(1);

    if (!mRequestState)
    {
      co_return;
    }
    if (!indices.empty())
    {
      // A frame allocation failure cannot be caught inside the flow whose frame was not created.
      // Preserve its rows here, with the same rich failure and audit handling as any other answer.
      try
      {
        units.push_back(run_call_flow(indices, limits));
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        answer_unstarted_rows(indices, ua::exception_to_status_code(std::current_exception()));
      }
    }

    // The join IS the barrier. Each unit has already written its own result slot, so there is
    // nothing to collect here - only to wait. A unit that contained a throw answered its own rows
    // before returning, so nothing it owed is lost.
    for (auto& unit : units)
    {
      try
      {
        // Moved because a Task's `operator co_await` is rvalue-qualified. The awaiter only BORROWS
        // the frame handle - the Task in this vector still owns the frame, and still destroys it
        // when this frame unwinds.
        co_await std::move(unit);
      }
      catch (const ua::async::Abandoned&)
      {
        // The whole request has been withdrawn and already answered; stop, and let the rest of the
        // units be destroyed with this frame.
        co_return;
      }
      catch (...)
      {
        // A unit body contains its own failures AND writes its answer through `guarded`, so this
        // path is defensive: reaching it means the containment itself threw. Two things are then
        // true and neither can be repaired from here - there is no way to know which rows that unit
        // owed, and a row nothing wrote still holds the Good its default construction gave it.
        // Recording why, and carrying on waiting for the units that can still answer, is the whole
        // of what this can do; knowing which rows to correct would need a record of which were
        // answered, and the request does not keep one.
        if (auto sessionInfo = mSessionInfo.lock())
        {
          log_exception(sessionInfo->logger().with_category("service"),
            LogLevel::Error,
            "CallService: a method operation's own containment threw",
            ua::exception_to_status_code(std::current_exception()));
        }
      }
    }

    if (mRequestState)
    {
      complete_call();
    }
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it answered the client.
    ::ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    // Everything above is contained, so reaching here means the containment itself threw, or
    // `complete_call` did. Answering with a fault is the best that can be done - and if the throw
    // came from `complete_call` AFTER it took the finish, `send_service_fault` will find the request
    // already finished and send nothing, which is the one case this cannot rescue.
    ua::async::guarded(
      mLogger, [this] { fail_call(ua::exception_to_status_code(std::current_exception())); })();
  }
}

void MethodServiceSet::fail_call(StatusCode error)
{
  if (!mRequestState)
  {
    return;
  }
  mRequestState->collector.set_service_detail(error);
  send_service_fault(mCallRequest.request_header(), error, mRequestState->collector);
  mRequestState.reset();
}

void MethodServiceSet::complete_call()
{
  if (!try_finish())
  {
    mRequestState.reset();
    return;
  }
  if (!mRequestState)
    return;
  auto& state = *mRequestState;
  const size_t noOfOperations = state.response->results().size();
  auto& results = state.response->results();
  state.collector.apply_to(
    state.response->response_header(),
    state.response->diagnostic_infos(),
    noOfOperations,
    [&results](size_t index) -> Array<DiagnosticInfo>*
    {
      if (index >= results.size())
      {
        return nullptr;
      }
      return &results[index].input_argument_diagnostic_infos();
    },
    [&results](size_t index)
    {
      if (index >= results.size())
      {
        return size_t{0};
      }
      return results[index].input_argument_results().size();
    });
  stack_utils::prepare_response_header(mCallRequest.request_header(), state.response->response_header());

  auto serviceResponse = std::move(state.response);
  mRequestState.reset();
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(
      std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceResponse)));
  }
}

// =============================================================================================
// The items this server resolves itself: one flow per request
// =============================================================================================

/// One item of the flow, and what the flow has learned of it.
struct CallFlowItem
{
  /// Where the item's pairing climb is (OPC 10000-4 5.11.2.2 Table 65).
  enum class Pairing
  {
    /// The level in @ref level is read next.
    Climbing,
    /// The Method is a component of the Object, of its type or of a supertype, or the shelving exception
    /// holds.
    Paired,
    /// The climb ended without finding the Method.
    NotFound
  };

  /// The item's position in the request.
  size_t index{0};
  /// The Method and the Object, once their lookups and verdicts have passed.
  std::optional<NodeAccessor> method;
  std::optional<NodeAccessor> object;
  /// Whether the objectId names an ObjectType rather than an Object.
  bool objectIsType{false};
  /// What the Object's Write permission decided, for the Method's handler.
  std::optional<StatusCode> objectWrite;
  /// The first of the Method's own checks to fail (NodeClass, AccessRestrictions, Executable), answered after
  /// the pairing.
  std::optional<StatusCode> methodCheck;
  Pairing pairing{Pairing::Climbing};
  /// The level the climb reads next, and its NodeId.
  std::optional<NodeAccessor> level;
  NodeId levelId;
  /// The next level, to be looked up, and whether it is the Object's TypeDefinition (which must be an
  /// ObjectType) rather than a supertype.
  std::optional<NodeId> next;
  bool nextIsTypeDefinition{false};
  /// The levels climbed, charged per level against the request's LoopLimit.
  std::optional<LoopLimit> levels;
  /// Whether a Good call of the item starts its Object's StateMachine transition (DL-75 (C3),
  /// COMP-SVR-NAMESPACE-CALLS-20).
  bool hook{false};
  /// Whether the item has been answered; an answered item takes no further part in the flow.
  bool answered{false};
};

/// One distinct Method's InputArguments, read once for the request (NR-29 rule 2).
struct MethodFacts
{
  explicit MethodFacts(NodeAccessor methodNode) : method(std::move(methodNode))
  {}

  NodeAccessor method;
  /// Why the InputArguments could not be read; every item calling the Method answers it.
  std::optional<StatusCode> failure;
  /// The targets of the Method's forward HasProperty References, in Reference order.
  std::vector<NodeId> properties;
  /// The targets of its forward HasOptionalInputArgumentDescription References, in Reference order.
  std::vector<NodeId> descriptions;
  /// The 0:InputArguments Property, when the Method has one, and its NodeId.
  std::optional<NodeAccessor> property;
  NodeId propertyId;
  /// The declared arguments, once the Property's Value has been read.
  std::optional<InputArgumentsMetadata> inputs;
};

/// What one request's flow works with: its items, and every answer the namespaces gave it, each asked once.
struct CallFlow
{
  CallFlow(AddressSpace space, ua::EncodingLimits flowLimits, std::optional<uint32_t> referencesLimit)
    : addressSpace(std::move(space)), limits(flowLimits), browseLimit(referencesLimit)
  {}

  AddressSpace addressSpace;
  ua::EncodingLimits limits;
  /// The operation limit of a `read_references_async` call (maxNodesPerBrowse).
  std::optional<uint32_t> browseLimit;
  MessageSecurityMode securityMode{MessageSecurityMode::None};
  std::vector<CallFlowItem> items;
  /// Every lookup of the request, by NodeId.
  std::unordered_map<NodeId, NodeAccessorResult> found;
  /// The References of each level of the climbs, read once for the request.
  std::unordered_map<NodeId, Result<std::vector<Reference>>> levels;
  /// Whether a ReferenceType the namespace-0 table does not hold is HasComponent or a subtype of it, as the
  /// request's supertype facts answered.
  std::unordered_map<NodeId, bool> componentTypes;
  /// The InputArguments of each distinct Method whose items may reach their call.
  std::unordered_map<NodeId, MethodFacts> methods;
};

/// What starting one item's StateMachine transition needs, taken while the Session is held, before the item's
/// Method is called (COMP-SVR-NAMESPACE-CALLS-20).
///
/// The transition starts where the Method's answer is taken, which may be after the Call's response and after
/// the service has gone, so this holds nothing of the request and nothing that keeps the server alive: the
/// address space and the event sink are held weakly.
struct TransitionStart
{
  NodeId machineId;
  NodeId methodId;
  WeakAddressSpace addressSpace;
  std::weak_ptr<EventSink> eventSink;
  /// The `AuditUpdateStateEventType` Event the transition raises, when the server audits.
  std::optional<AuditUpdateStateEventPayload> auditEvent;
  /// The executor the transition's runtime makes its strand on.
  boost::asio::any_io_executor executor;
};

/// Where the answers of the call route and of the state-machine transitions meet the bodies awaiting them
/// (DL-75 (C5), (C10)).
///
/// The route answers each namespace's part as it completes, from that namespace's thread, and each answer is
/// posted to the service's strand. There a Good answer of an item that starts a StateMachine transition
/// starts it, whether or not a body still awaits it, and the transition's answer is posted back in its place;
/// every other answer is given to its item's body. An answer that no body awaits any more - the request has
/// been answered at its timeoutHint, cancelled, or has gone with its service - audits the call instead, from
/// a copy of the item's request that the answer carries (OPC 10000-4 6.5.9).
struct CallInbox
{
  CallInbox(
    CallAuditFacts auditFacts, Logger auditLogger, shared_ptr<const std::atomic_bool> requestCancelled)
    : audit(std::move(auditFacts)), logger(std::move(auditLogger)), cancelled(std::move(requestCancelled))
  {}

  /// One per call, in the order the calls were given to the route: resumes the item's body with its answer -
  /// its transition's answer when its call started one, otherwise its call's. Read and written only on the
  /// strand while the service is held; emptied when delivered and when the body that owns the inbox ends.
  std::vector<std::function<void(CallResult)>> deliver;
  /// One per call: what starting the item's transition needs, while it has not been started. Read and written
  /// only on the strand; taken when the call's answer starts the transition.
  std::vector<std::optional<TransitionStart>> transitions;
  /// One per call: the outcome of the last answer given to the slot's body, which audits the call with it
  /// when it is withdrawn before it has answered its item. Read and written as @ref deliver is.
  std::vector<std::optional<StatusCode>> outcome;
  /// What an answer the bodies no longer await is audited with, taken from the Session at the request, so
  /// that it is audited after the Session has closed; and the service's logger.
  const CallAuditFacts audit;
  const Logger logger;
  /// The request's cancellation flag: once it is set, a body awaiting an answer is withdrawn rather than
  /// resumed, so the answer is audited here.
  const shared_ptr<const std::atomic_bool> cancelled;
};

namespace
{

/// True for the six shelving Methods OPC 10000-9 Table 73 declares on ShelvedStateMachineType: the
/// three Mandatory ones and their Optional `*2` siblings. The siblings belong here for the reason
/// 5.8.17.3/.5/.7 give for everything they do not restate - each "extends" its base Method and "for
/// other functionality see the [base] Method definition", and the ConditionId-as-ObjectId allowance
/// below is part of that base definition.
bool is_shelved_state_machine_method(const NodeId& methodId)
{
  return methodId == NodeId{MethodId::ShelvedStateMachineType_TimedShelve} ||
         methodId == NodeId{MethodId::ShelvedStateMachineType_OneShotShelve} ||
         methodId == NodeId{MethodId::ShelvedStateMachineType_Unshelve} ||
         methodId == NodeId{MethodId::ShelvedStateMachineType_TimedShelve2} ||
         methodId == NodeId{MethodId::ShelvedStateMachineType_OneShotShelve2} ||
         methodId == NodeId{MethodId::ShelvedStateMachineType_Unshelve2};
}

/// Whether the namespace-0 ReferenceType table holds @p referenceType. `reference_type_may_match_hint`
/// answers "may match" for a type the table does not hold, so only a held type is decided from the table
/// (DL-75 (C4)).
bool namespace_zero_table_holds(const NodeId& referenceType) noexcept
{
  if (referenceType.namespace_index() != 0 || !referenceType.is_numeric())
  {
    return false;
  }
  const auto rows = namespace_zero_tables::reference_types();
  const uint32_t id = referenceType.identifier().get_numeric();
  const auto row = std::ranges::lower_bound(rows,
    id,
    std::ranges::less{},
    [](const namespace_zero_tables::ReferenceTypeRow& entry) { return entry.id; });
  return row != rows.end() && row->id == id;
}

/// Whether a Reference of @p type is a HasComponent Reference or one of a subtype; `nullopt` when only the
/// request's supertype facts can tell.
std::optional<bool> is_component_type(const CallFlow& flow, const NodeId& type)
{
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  if (type == hasComponent)
  {
    return true;
  }
  if (namespace_zero_table_holds(type))
  {
    return reference_type_may_match_hint(type, std::span<const NodeId>{&hasComponent, 1});
  }
  if (const auto known = flow.componentTypes.find(type); known != flow.componentTypes.end())
  {
    return known->second;
  }
  return std::nullopt;
}

/// The lookup answer the flow holds for @p nodeId.
NodeAccessorResult lookup_of(const CallFlow& flow, const NodeId& nodeId)
{
  if (const auto found = flow.found.find(nodeId); found != flow.found.end())
  {
    return found->second;
  }
  return NodeAccessorResult{StatusCode{Status::BadInternalError,
    ErrorDetail::build("CallLookupMissing", "The flow did not look this Node up", "MethodService")
      .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))}};
}

/// The answer of an item whose lookup of @p nodeId was answered @p answer, not Good: a Bad answer is the
/// item's; an Uncertain one, with or without the Node, is refused, since the SDK does not act on an answer
/// the namespace is uncertain of (`LookupAnswerUncertain`, DL-75 (C7)).
StatusCode lookup_uncertain(const NodeId& nodeId, const StatusCode& answer)
{
  return ::ua::detail::lookup_failure(nodeId, answer, "MethodService");
}

/// The failure of an item whose read of @p nodeId's References was not Good: a Bad answer is the item's
/// status; an Uncertain one, with or without References, is not the Method's answer and the SDK does not act
/// on it, so it refuses the item `Bad_InternalError` (`ReferencesAnswerUncertain`) with the Uncertain answer
/// as cause.
StatusCode references_failure(const StatusCode& answer, const NodeId& nodeId)
{
  return server::detail::not_acted_on(
    server::detail::referencesAnswerUncertain, answer, "MethodService", nodeId);
}

/// The failure of an item whose read of @p nodeId's Value was not Good, as @ref references_failure for a
/// Value (`ReadAnswerUncertain`).
StatusCode value_failure(const StatusCode& answer, const NodeId& nodeId)
{
  return server::detail::not_acted_on(server::detail::readAnswerUncertain, answer, "MethodService", nodeId);
}

/// The rounds of pairing climbs run in one strand turn at most.
constexpr size_t roundsPerStrandTurn = 1024;

/// The read of one level of a pairing climb, one query per Node: its components, and its TypeDefinition for
/// an Object or its supertype for an ObjectType. Subtypes of HasComponent are kept (O-3).
namespace_calls::ReferenceRead level_read(const NodeAccessor& node, const NodeId& nodeId)
{
  return namespace_calls::ReferenceRead{node,
    nodeId,
    BrowseDirection::Both,
    NodeId{ReferenceTypeId::HasComponent},
    {node.is_object_type() ? NodeId{ReferenceTypeId::HasSubtype}
                           : NodeId{ReferenceTypeId::HasTypeDefinition}},
    true};
}

/// What one level of a climb decided for an item.
struct LevelOutcome
{
  enum class Kind
  {
    Paired,
    Climb,
    NoSupertype,
    NotFound,
    Failed
  } kind{Kind::NotFound};
  NodeId next;
  bool nextIsTypeDefinition{false};
  VoidResult failure;
};

/// Whether @p methodId is a component of the level @p item has reached, and where the climb goes from there,
/// as the per-item walk decided it: a failed read at an Object answers its status, and at a type ends the
/// climb with no supertype (DL-75 (C9)). Every ReferenceType on a Reference to the Method has been decided.
LevelOutcome decide_level(const CallFlow& flow, const CallFlowItem& item, const NodeId& methodId)
{
  using Kind = LevelOutcome::Kind;
  const bool isType = item.level->is_object_type();
  const auto read = flow.levels.find(item.levelId);
  if (read == flow.levels.end() || !read->second.is_good())
  {
    if (!isType)
    {
      const StatusCode failure = read == flow.levels.end()
                                   ? StatusCode{Status::BadInternalError}
                                   : references_failure(read->second.status_code(), item.levelId);
      return LevelOutcome{Kind::Failed, {}, false, VoidResult{failure}};
    }
    return LevelOutcome{Kind::NoSupertype, {}, false, {}};
  }
  const auto& references = read->second.value();
  for (const auto& reference : references)
  {
    if (reference.is_forward() && reference.target_id().is_index_based() &&
        reference.target_id().node_id() == methodId &&
        is_component_type(flow, reference.type_id()).value_or(false))
    {
      return LevelOutcome{Kind::Paired, {}, false, {}};
    }
  }
  if (!isType)
  {
    // An Object climbs to its TypeDefinition: the first forward HasTypeDefinition Reference.
    const auto typeDefinition = std::ranges::find_if(references,
      [](const Reference& reference) {
        return reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition};
      });
    if (typeDefinition == references.end() || typeDefinition->target_id().is_null() ||
        !typeDefinition->target_id().is_local())
    {
      return LevelOutcome{Kind::NotFound, {}, false, {}};
    }
    return LevelOutcome{Kind::Climb, typeDefinition->target_id().node_id(), true, {}};
  }
  // A type climbs to its supertype: the first inverse HasSubtype Reference. A remote supertype cannot be
  // looked up, which ends the climb as a type without one.
  const auto supertype = std::ranges::find_if(references,
    [](const Reference& reference)
    { return !reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasSubtype}; });
  if (supertype == references.end() || supertype->target_id().is_remote())
  {
    return LevelOutcome{Kind::NoSupertype, {}, false, {}};
  }
  return LevelOutcome{Kind::Climb, supertype->target_id().node_id(), false, {}};
}

/// The first of @p objectId's children named @p browseName whose lookup is Good: the forward HasComponent
/// Reference targets of this server, in Reference order, as `find_child_id_by_browse_name_async` takes them.
std::optional<NodeAccessor> child_named(
  const CallFlow& flow, const NodeId& objectId, const QualifiedName& browseName)
{
  const auto read = flow.levels.find(objectId);
  if (read == flow.levels.end() || !read->second.is_good())
  {
    return std::nullopt;
  }
  for (const auto& reference : read->second.value())
  {
    if (!reference.is_forward() || reference.is_remote() ||
        reference.type_id() != NodeId{ReferenceTypeId::HasComponent} || !reference.target_id().is_local())
    {
      continue;
    }
    const auto child = lookup_of(flow, reference.target_id().node_id());
    if (child.is_good() && child.value().get_browse_name() == browseName)
    {
      return child.value();
    }
  }
  return std::nullopt;
}

/// The forward HasComponent Reference targets of this server of @p objectId, in Reference order: the children
/// @ref child_named compares.
std::vector<NodeId> component_children(const CallFlow& flow, const NodeId& objectId)
{
  std::vector<NodeId> children;
  const auto read = flow.levels.find(objectId);
  if (read == flow.levels.end() || !read->second.is_good())
  {
    return children;
  }
  for (const auto& reference : read->second.value())
  {
    if (reference.is_forward() && !reference.is_remote() &&
        reference.type_id() == NodeId{ReferenceTypeId::HasComponent} && reference.target_id().is_local())
    {
      children.push_back(reference.target_id().node_id());
    }
  }
  return children;
}

/// The first of the Method's own checks to fail (OPC 10000-4 5.11.2): it is a Method, the channel meets its
/// AccessRestrictions, and it is Executable.
std::optional<StatusCode> method_check(const NodeAccessor& method, MessageSecurityMode securityMode)
{
  const auto methodAccessor = method.as<MethodAccessor>();
  if (!methodAccessor)
  {
    return StatusCode{Status::BadNodeClassInvalid};
  }
  if (const auto accessRestrictions = method.get_access_restrictions())
  {
    if (accessRestrictions->test(AccessRestrictionType::Bit::EncryptionRequired) &&
        securityMode != MessageSecurityMode::SignAndEncrypt)
    {
      return StatusCode{Status::BadSecurityModeInsufficient};
    }
    if (accessRestrictions->test(AccessRestrictionType::Bit::SigningRequired) &&
        securityMode != MessageSecurityMode::Sign && securityMode != MessageSecurityMode::SignAndEncrypt)
    {
      return StatusCode{Status::BadSecurityModeInsufficient};
    }
  }
  if (!methodAccessor->get_executable())
  {
    return StatusCode{Status::BadNotExecutable};
  }
  return std::nullopt;
}

/// The status of an item whose Method lookup failed: a methodId that does not resolve to a Node is not a
/// Method of the Object (OPC 10000-4 Table 67, Bad_MethodInvalid); any other failure keeps its own status.
VoidResult method_lookup_failure(const NodeId& methodId, const NodeAccessorResult& found)
{
  if (!found.is_bad())
  {
    return VoidResult{lookup_uncertain(methodId, found.status_code())};
  }
  if (found.status_code() == Status::BadNodeIdUnknown)
  {
    return VoidResult{Status::BadMethodInvalid,
      ErrorDetail::build("BadMethodInvalid",
        "methodId does not refer to an existing method node",
        "MethodService::on_method_node_resolved")
        .context(ua::ContextKeys::nodeId, ua::to_string(methodId))};
  }
  return VoidResult{found.status_code(), found.shared_detail()};
}

/// Empties the inbox's deliveries when the body that awaits them ends, so that an answer arriving later is
/// audited rather than handed to a body that no longer exists. The entries are emptied, never erased: a
/// delivery in progress may be iterating over them.
struct CallInboxClosing
{
  explicit CallInboxClosing(shared_ptr<CallInbox> closed) : inbox(std::move(closed))
  {}

  shared_ptr<CallInbox> inbox;

  CallInboxClosing(const CallInboxClosing&) = delete;
  CallInboxClosing& operator=(const CallInboxClosing&) = delete;
  CallInboxClosing(CallInboxClosing&&) = delete;
  CallInboxClosing& operator=(CallInboxClosing&&) = delete;

  ~CallInboxClosing()
  {
    for (auto& deliver : inbox->deliver)
    {
      deliver = nullptr;
    }
  }
};

/// The outcome a call's audit Event reports for @p answer: for an answer holding a CallMethodResult, the
/// Method's statusCode as the Call service answers it (@ref method_status_as_answered), the code the client
/// was answered; any other answer's own status.
StatusCode answered_status(const CallResult& answer)
{
  if (!answer.has_value())
  {
    return answer.status_code();
  }
  return method_status_as_answered(answer.status_code(), answer.value().status_code(), nullptr, nullptr);
}

/// Gives @p answer, on the service's strand, to the body awaiting it at @p slot while the service is @p held
/// and the request has not been cancelled. False, leaving @p answer, when no body awaits it.
bool deliver_answer(bool held, CallInbox& inbox, size_t slot, CallResult& answer)
{
  if (!held || inbox.cancelled->load() || slot >= inbox.deliver.size() || !inbox.deliver[slot])
  {
    return false;
  }
  // Kept for the body: a cancel set from another thread after the read above withdraws the body as it
  // resumes, and the body then audits the call with this outcome (DL-75 (C10)).
  inbox.outcome[slot] = answered_status(answer);
  // Taken out first: delivering resumes the body inline, and the body may end the request.
  auto deliver = std::exchange(inbox.deliver[slot], nullptr);
  deliver(std::move(answer));
  return true;
}

/// Takes the state-machine transition's answer for the item at @p slot on the service's strand: to the body
/// awaiting it, otherwise audited from @p request with the outcome the body would have answered.
void take_hook_answer(
  bool held, CallInbox& inbox, size_t slot, CallResult hooked, const CallMethodRequest& request)
{
  if (deliver_answer(held, inbox, slot, hooked))
  {
    return;
  }
  const StatusCode outcome = answered_status(hooked);
  if (outcome.is_bad())
  {
    // The audit Event says only that the action was not performed; the reason is kept here.
    log_exception(inbox.logger,
      LogLevel::Warning,
      "CallService: a StateMachine transition answered after its Call's response failed",
      outcome);
  }
  emit_call_audit(inbox.audit, inbox.logger, request, outcome);
}

/// Whether @p answer, as the namespace gave it, starts its item's StateMachine transition: the namespace
/// answered Good and the Method's status is not Bad (COMP-SVR-NAMESPACE-CALLS-20 rule 1). An Uncertain answer
/// does not, whether or not it holds a CallMethodResult (DL-75 (C7)): the SDK does not act on an answer the
/// namespace is uncertain of.
bool starts_transition(const CallResult& answer)
{
  return answer.is_good() && !answer.value().status_code().is_bad();
}

/// Starts the StateMachine transition @p start describes for the item at @p slot, whose Method has answered
/// @p methodResult, and posts the transition's answer to the service's strand, where @ref take_hook_answer
/// gives it to the item's body or audits the call with it.
///
/// Started whether or not a body still awaits the item: the Method has run (COMP-SVR-NAMESPACE-CALLS-20). The
/// runtime is owned by its own outstanding work, so nothing here holds it. A transition that cannot be
/// started answers the status of the failure, so that the Method that ran is answered and audited all the
/// same.
void start_transition(bool held, const shared_ptr<CallInbox>& inbox, size_t slot,
  const weak_ptr<MethodServiceSet>& owner, const boost::asio::strand<boost::asio::any_io_executor>& strand,
  TransitionStart start, CallMethodResult methodResult, const CallMethodRequest& request) noexcept
{
  StateMachineMethodHookCompletion answered;
  try
  {
    answered = [inbox, slot, request = std::make_shared<const CallMethodRequest>(request), owner, strand](
                 CallResult answer)
    {
      ua::async::post_self_owning(strand,
        inbox->logger,
        [inbox, slot, request, owner, answer = std::move(answer)]() mutable
        {
          // Held for the whole delivery: the body it resumes belongs to the service.
          const auto service = owner.lock();
          take_hook_answer(service != nullptr, *inbox, slot, std::move(answer), *request);
        });
    };
  }
  catch (...)
  {
    // Not even the way back could be made, so the failure is taken here, on the strand, as the call's own
    // answer would have been.
    ua::async::guarded(inbox->logger,
      [held, &inbox, slot, &request]
      {
        take_hook_answer(
          held, *inbox, slot, CallResult{ua::exception_to_status_code(std::current_exception())}, request);
      })();
    return;
  }

  try
  {
    auto addressSpace = start.addressSpace.lock();
    if (!addressSpace)
    {
      ua::detail::invoke_user_callback(inbox->logger,
        answered,
        CallResult{StatusCode{Status::BadShutdown,
          ErrorDetail::build("StateMachineTransitionNotStarted",
            "The address space was destroyed before the Method's StateMachine transition could start",
            "MethodService")
            .context(ua::ContextKeys::nodeId, ua::to_string(start.machineId))}});
      return;
    }
    auto runtime = StateMachineRuntime::create(std::move(start.executor),
      make_address_space_state_machine_model(std::move(*addressSpace)),
      std::move(start.eventSink),
      inbox->logger,
      std::move(start.auditEvent));
    // `answered` is copied, not moved: a throw before the hook has taken it leaves this one to answer with,
    // and once the hook has been called it answers through its own copy and throws nothing.
    apply_state_machine_method_hook_async(
      CallResult{std::move(methodResult)},
      [runtime = std::move(runtime),
        machineId = std::move(start.machineId),
        methodId = std::move(start.methodId)](std::function<void(VoidResult)> callback) mutable {
        runtime->transition_after_method_async(
          std::move(machineId), std::move(methodId), std::move(callback));
      },
      answered,
      inbox->logger);
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      inbox->logger, answered, CallResult{ua::exception_to_status_code(std::current_exception())});
  }
}

/// Replaces a Good @p answer that carries no CallMethodResult - a Result built from a Good status, which only
/// a build without assertions lets through - with `Bad_InternalError` (`CallAnswerWithoutValue`), so that it
/// is answered and audited as the item's failure rather than throwing where its value is read.
void require_call_value(CallResult& answer, const CallMethodRequest* request)
{
  if (!answer.is_good() || answer.has_value())
  {
    return;
  }
  auto detail = ErrorDetail::build(
    "CallAnswerWithoutValue", "The namespace answered a Method call Good with no result", "MethodService");
  if (request)
  {
    answer = CallResult{StatusCode{Status::BadInternalError,
      std::move(detail).context(ua::ContextKeys::nodeId, ua::to_string(request->method_id()))}};
    return;
  }
  answer = CallResult{StatusCode{Status::BadInternalError, std::move(detail)}};
}

/// Takes one namespace's answers on the service's strand (DL-75 (C10)). A Good answer of an item whose call
/// starts a StateMachine transition starts it, whether or not the request has been answered; every other
/// answer goes to the body awaiting it, otherwise it is audited from the route's copy of its request.
void take_call_answers(bool held, const shared_ptr<CallInbox>& inbox, const weak_ptr<MethodServiceSet>& owner,
  const boost::asio::strand<boost::asio::any_io_executor>& strand, ua::detail::MethodCallAnswers answers)
{
  for (size_t k = 0; k < answers.positions.size() && k < answers.results.size(); ++k)
  {
    // Guarded per answer, so that one answer whose audit throws does not keep the others from their items.
    ua::async::guarded(inbox->logger,
      [held, &inbox, &owner, &strand, &answers, k]
      {
        const size_t slot = answers.positions[k];
        const CallMethodRequest* request =
          answers.items && slot < answers.items->size() ? &(*answers.items)[slot].request : nullptr;
        auto& answer = answers.results[k];
        try
        {
          require_call_value(answer, request);
          // Decided on the namespace's own answer: the answer is given on below with its code on the
          // CallMethodResult, where an Uncertain code no longer shows as the result's.
          const bool startsTransition = starts_transition(answer);
          if (answer.has_value())
          {
            // Here rather than in the item's body, so that a transition is started with, and the body is
            // given, the answer as the Call service answers it: Good, an Uncertain one included, with the
            // code on the CallMethodResult.
            sanitize_method_answer(answer, inbox->logger, request ? &request->method_id() : nullptr);
          }
          if (request && slot < inbox->transitions.size() && inbox->transitions[slot] && startsTransition)
          {
            auto start = std::move(*inbox->transitions[slot]);
            inbox->transitions[slot].reset();
            start_transition(
              held, inbox, slot, owner, strand, std::move(start), std::move(answer).value(), *request);
            return;
          }
        }
        catch (...)
        {
          // Whatever failed before the answer was given on is the item's answer, delivered or audited below
          // like any other, so that a Method that ran is not left unanswered.
          answer = CallResult{ua::exception_to_status_code(std::current_exception())};
        }
        if (!deliver_answer(held, *inbox, slot, answer) && request)
        {
          emit_call_audit(inbox->audit, inbox->logger, *request, answered_status(answer));
        }
      })();
  }
}

/// What starting the StateMachine transition of a call of @p methodToCall needs, taken while @p sessionInfo
/// is held: the Method and its Object, the address space and the event sink held weakly, and the
/// `AuditUpdateStateEventType` Event to raise when the server audits, with @p actionTime as its
/// ActionTimeStamp.
TransitionStart transition_start(SessionInfo& sessionInfo, const CallFlow& flow,
  const CallMethodRequest& methodToCall, const String& auditEntryId, const DateTime& actionTime,
  boost::asio::any_io_executor executor)
{
  TransitionStart start{.machineId = methodToCall.object_id(),
    .methodId = methodToCall.method_id(),
    .addressSpace = WeakAddressSpace{flow.addressSpace},
    .eventSink = sessionInfo.event_sink(),
    .auditEvent = std::nullopt,
    .executor = std::move(executor)};
  if (sessionInfo.server_configuration().auditingEnabled)
  {
    auto& auditEvent = start.auditEvent.emplace();
    auditEvent.sourceName = "Attribute/Call";
    auditEvent.actionTimeStamp = Variant{actionTime};
    auditEvent.status = true;
    auditEvent.serverId = sessionInfo.configuration().application_description_part().applicationUri;
    auditEvent.methodId = methodToCall.method_id();
    auditEvent.inputArguments = Variant{methodToCall.input_arguments()};
    auditEvent.message = LocalizedText{"", "StateMachine transition"};
    auditEvent.severity = 1;
    auditEvent.clientAuditEntryId = auditEntryId;
    if (const auto* securityContext = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
    {
      if (auto user = securityContext->user_identity())
        auditEvent.clientUserId = user->userId;
    }
  }
  return start;
}

/// The context one item's handler receives: the Session's facts and whether it may write the Object.
shared_ptr<MethodCallContext> call_context(const SessionInfo& sessionInfo,
  const std::optional<MethodResponseCorrelation>& responseCorrelation, const std::vector<LocaleId>& locales,
  const CallFlowItem& item, const NodeId& objectId)
{
  // Built with shared ownership so a handler that completes asynchronously can retain the context
  // past the synchronous portion of the call (the call_async hop) without it dangling.
  auto callContext = std::make_shared<MethodCallContext>();
  if (responseCorrelation)
  {
    ua::detail::MethodCallContextInternalAccess::set_response_correlation(*callContext, *responseCorrelation);
  }
  callContext->sessionLocales = locales;
  if (const auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    callContext->sessionId = sec->session_id();
    if (auto user = sec->user_identity())
      callContext->clientUserId = user->userId;
    if (auto ep = sec->endpoint_security())
      callContext->channelSecurityMode = ep->messageSecurityMode;
  }
  // Named by the request's objectId, not by a getter of the Object, which may have been deleted since its
  // lookup.
  const StatusCode authorization =
    item.objectWrite ? *item.objectWrite
                     : StatusCode{Status::BadUserAccessDenied,
                         ErrorDetail::build("AuthorizationUnavailable",
                           "Object Write authorization was unavailable before Method invocation",
                           "MethodService")
                           .context(ua::ContextKeys::nodeId, objectId)};
  ua::detail::MethodCallAuthorizationInternalAccess::set_object_write_authorizer(*callContext,
    [authorization]
    {
      if (authorization.is_good())
        return VoidResult{};
      return VoidResult{authorization};
    });
  return callContext;
}

/// The arguments an InputArguments Value declares.
Array<Argument> declared_arguments(const DataValue& value)
{
  Array<Argument> arguments;
  const auto& variant = value.value();
  if (!variant.empty() && variant.is_array_of_structure())
  {
    const auto& structures = variant.as<Array<RefStructure<Structure>>>();
    arguments.payload().reserve(structures.size());
    for (size_t i = 0; i < structures.size(); ++i)
    {
      if (const auto* argumentDefinition = dynamic_cast<const Argument*>(structures[i].get()))
      {
        arguments.payload().push_back(*argumentDefinition);
      }
    }
  }
  return arguments;
}

/// The status and ErrorDetail of a request whose supplied arguments do not match the declared ones.
VoidResult argument_failure(StatusCode status, const NodeId& methodId)
{
  std::shared_ptr<const ErrorDetail> detail;
  if (status == Status::BadArgumentsMissing)
  {
    detail = ErrorDetail::build("BadArgumentsMissing",
      "Required Method input arguments are missing",
      "MethodService::validate_input_arguments")
               .context(ua::ContextKeys::nodeId, ua::to_string(methodId));
  }
  else if (status == Status::BadTooManyArguments)
  {
    detail = ErrorDetail::build("BadTooManyArguments",
      "Too many Method input arguments were supplied",
      "MethodService::validate_input_arguments")
               .context(ua::ContextKeys::nodeId, ua::to_string(methodId));
  }
  else
  {
    detail = ErrorDetail::build("BadInvalidArgument",
      "Method input argument type or rank does not match the model",
      "MethodService::validate_input_arguments")
               .context(ua::ContextKeys::nodeId, ua::to_string(methodId));
  }
  return VoidResult{status, std::move(detail)};
}

}  // namespace

ua::async::Task<> MethodServiceSet::run_call_flow(std::vector<size_t> indices, ua::EncodingLimits limits)
{
  // A ROOT task, as every unit is: an exception that escaped would be stored in a promise nobody reads. A
  // failure answers the flow's unanswered items with its status; the items already answered keep theirs.
  std::optional<CallFlow> flow;
  try
  {
    if (!mRequestState)
    {
      co_return;
    }
    std::optional<uint32_t> browseLimit;
    {
      // Scoped: a lock on the session must not span a suspension (R7).
      if (auto sessionInfo = mSessionInfo.lock())
      {
        browseLimit =
          sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerBrowse;
      }
    }
    flow.emplace(mRequestState->addressSpace, limits, browseLimit);
    flow->items.reserve(indices.size());
    for (const size_t index : indices)
    {
      CallFlowItem item;
      item.index = index;
      flow->items.push_back(std::move(item));
    }
    co_await resolve_call_flow(*flow);
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was cancelled and has already been answered; it owes these rows nothing.
    co_return;
  }
  catch (...)
  {
    const StatusCode failure = ua::exception_to_status_code(std::current_exception());
    if (flow && flow->items.size() == indices.size())
    {
      for (auto& item : flow->items)
      {
        answer_item(item, VoidResult{failure});
      }
    }
    else
    {
      answer_unstarted_rows(indices, failure);
    }
    co_return;
  }

  // ----- 5. the calls: the items that passed every check together, each answered as its namespace answers
  // -----
  try
  {
    co_await call_flow_items(*flow);
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    // Reached only before any item was given to the route, so no item has been called.
    const StatusCode failure = ua::exception_to_status_code(std::current_exception());
    for (auto& item : flow->items)
    {
      answer_item(item, VoidResult{failure});
    }
  }
}

ua::async::Task<> MethodServiceSet::resolve_call_flow(CallFlow& flow)
{
  // ----- 1. per item: the Session, its access control and the objectId's syntax -----
  {
    // Scoped: a lock on the session must not span a suspension (R7).
    auto sessionInfo = mSessionInfo.lock();
    if (!sessionInfo)
    {
      for (auto& item : flow.items)
      {
        answer_item(item, VoidResult{Status::BadShutdown});
      }
      co_return;
    }
    if (const auto* sec = dynamic_cast<SessionSecurityContext*>(sessionInfo.get()))
    {
      if (const auto endpoint = sec->endpoint_security())
      {
        flow.securityMode = endpoint->messageSecurityMode;
      }
    }
  }

  std::optional<SessionAccessControl> accessControl;
  if (mRequestState)
  {
    accessControl = mRequestState->accessControl;
  }
  std::vector<NodeId> lookups;
  lookups.reserve(2 * flow.items.size());
  for (auto& item : flow.items)
  {
    const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
    if (!accessControl)
    {
      answer_item(item,
        VoidResult{Status::BadUserAccessDenied,
          ErrorDetail::build("AuthorizationUnavailable",
            "No committed access identity for session - failed closed",
            "MethodService")
            .context(ua::ContextKeys::operationIndex, std::to_string(item.index))});
      continue;
    }
    // A null or malformed objectId is invalid by its syntax alone, so answering Bad_NodeIdInvalid reveals
    // nothing about the address space or the caller's permissions. It is answered before the Method is
    // looked up and authorized, which would otherwise report a denial for a request that names no Object.
    if (const auto& objectId = methodToCall.object_id();
        objectId.is_null() || !objectId.is_structurally_valid())
    {
      answer_item(item,
        VoidResult{Status::BadNodeIdInvalid,
          ErrorDetail::build(
            "MethodObjectIdInvalid", "Method Call objectId is null or structurally invalid", "MethodService")
            .context(ua::ContextKeys::nodeId, ua::to_string(objectId))});
      continue;
    }
    lookups.push_back(methodToCall.method_id());
    lookups.push_back(methodToCall.object_id());
  }
  if (lookups.empty())
  {
    co_return;
  }

  // ----- 2. one lookup of the distinct Methods and Objects, and one authorization of those found -----
  co_await look_up(flow, std::move(lookups));

  std::vector<AccessControl::Item> authorizationItems;
  std::unordered_map<NodeId, size_t> authorizationOf;
  const auto authorize = [&authorizationItems, &authorizationOf](
                           const NodeAccessor& node, const NodeId& nodeId)
  {
    if (authorizationOf.try_emplace(nodeId, authorizationItems.size()).second)
    {
      authorizationItems.push_back(AccessControl::Item{node, AccessOperation::Call});
    }
  };
  for (const auto& item : flow.items)
  {
    if (item.answered)
    {
      continue;
    }
    const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
    if (const auto method = lookup_of(flow, methodToCall.method_id()); method.is_good())
    {
      authorize(method.value(), methodToCall.method_id());
    }
    if (const auto object = lookup_of(flow, methodToCall.object_id());
        object.is_good() && (object.value().is_object() || object.value().is_object_type()))
    {
      authorize(object.value(), methodToCall.object_id());
    }
  }
  std::vector<AccessControl::Verdict> verdicts;
  if (!authorizationItems.empty())
  {
    verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
      [this, &accessControl, &authorizationItems](auto completion)
      { accessControl->authorize_async(mRequestInfo, authorizationItems, std::move(completion)); });
  }
  // SVR-AUTHZ-015: a verdict list of another size authorizes nothing.
  std::optional<StatusCode> countDenial;
  if (verdicts.size() != authorizationItems.size())
  {
    countDenial = detail::first_denial(verdicts, authorizationItems.size());
  }
  const auto verdictOf = [&verdicts, &authorizationOf, &countDenial](const NodeId& nodeId)
  {
    const auto position = authorizationOf.find(nodeId);
    if (countDenial || position == authorizationOf.end())
    {
      return AccessControl::Verdict{.cause = countDenial.value_or(StatusCode{Status::BadUserAccessDenied})};
    }
    return verdicts[position->second];
  };

  // ----- per item, in today's order: the Method's lookup and verdict, the Object's lookup, NodeClass and
  // verdict
  std::vector<NodeId> argumentMethods;
  for (auto& item : flow.items)
  {
    if (item.answered)
    {
      continue;
    }
    const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
    const NodeId& methodId = methodToCall.method_id();
    const NodeId& objectId = methodToCall.object_id();

    const auto method = lookup_of(flow, methodId);
    if (!method.is_good())
    {
      answer_item(item, method_lookup_failure(methodId, method));
      continue;
    }
    if (auto verdict = verdictOf(methodId); !verdict.permitted)
    {
      answer_item(item, VoidResult{std::move(verdict.cause)});
      continue;
    }

    const auto object = lookup_of(flow, objectId);
    if (object.is_bad())
    {
      answer_item(item, VoidResult{object.status_code(), object.shared_detail()});
      continue;
    }
    if (!object.is_good())
    {
      answer_item(item, VoidResult{lookup_uncertain(objectId, object.status_code())});
      continue;
    }
    const NodeAccessor& objectNode = object.value();
    if (!objectNode.is_object() && !objectNode.is_object_type())
    {
      answer_item(item,
        VoidResult{Status::BadNodeIdInvalid,
          ErrorDetail::build(
            "BadNodeIdInvalid", "Node is not an Object or ObjectType", "MethodService::validate_object_id")
            .context(ua::ContextKeys::nodeId, ua::to_string(objectId))});
      continue;
    }
    auto verdict = verdictOf(objectId);
    if (!verdict.permitted)
    {
      answer_item(item, VoidResult{std::move(verdict.cause)});
      continue;
    }
    item.objectWrite = verdict.mask.test(PermissionType::Bit::Write)
                         ? StatusCode{Status::Good}
                         : StatusCode{Status::BadUserAccessDenied,
                             ErrorDetail::build("MethodObjectWriteDenied",
                               "The current Session identity may not write the called Object",
                               "MethodService")
                               .context(ua::ContextKeys::nodeId, objectId)};

    item.method = method.value();
    item.object = objectNode;
    // Calling a Method on an ObjectType is valid per Part 4 5.11.2 only when the type (or a supertype) is the
    // source of the Method's HasComponent, as ConditionType is of ConditionRefresh; otherwise the Object is
    // not valid for the operation, which OPC 10000-9 5.5.6/5.7.3/5.7.4 require as Bad_NodeIdInvalid.
    item.objectIsType = objectNode.is_object_type();
    item.level = objectNode;
    item.levelId = objectId;
    item.levels.emplace(flow.limits.execution.loopLimit);
    item.methodCheck = method_check(*item.method, flow.securityMode);
    if (!item.methodCheck && flow.methods.try_emplace(methodId, *item.method).second)
    {
      argumentMethods.push_back(methodId);
    }
  }

  // ----- 3. the pairings and the InputArguments, each level and each Method read once for the request -----
  co_await pair_and_read_arguments(flow, std::move(argumentMethods));

  // ----- 4. per item: the Method's own checks, its InputArguments and the arguments supplied -----
  {
    // The last chance to notice the Session has gone before the checks that precede a call.
    auto sessionInfo = mSessionInfo.lock();
    if (!sessionInfo)
    {
      for (auto& item : flow.items)
      {
        answer_item(item, VoidResult{Status::BadShutdown});
      }
      co_return;
    }
  }
  const QualifiedName currentState{0, "CurrentState"};
  for (auto& item : flow.items)
  {
    if (item.answered)
    {
      continue;
    }
    const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
    if (item.methodCheck)
    {
      answer_item(item, VoidResult{*item.methodCheck});
      continue;
    }
    const auto facts = flow.methods.find(methodToCall.method_id());
    if (facts == flow.methods.end())
    {
      answer_item(item, VoidResult{StatusCode{Status::BadInternalError}});
      continue;
    }
    if (facts->second.failure)
    {
      answer_item(item, VoidResult{*facts->second.failure});
      continue;
    }
    // A Method with no InputArguments Property is not validated here: there is nothing in the model to
    // validate against, and the handler owns it instead.
    if (const auto& inputMetadata = facts->second.inputs)
    {
      CallMethodResult validationResult;
      const StatusCode status = validate_input_arguments(
        inputMetadata->arguments, inputMetadata->requiredArgumentCount, methodToCall, validationResult);
      // Not fatal to the batch: the item is answered with the argument failure, and the others go on.
      if (status.is_bad())
      {
        answer_item(item, argument_failure(status, methodToCall.method_id()), std::move(validationResult));
        continue;
      }
    }
    // The hook follows the call only when the Object has a CurrentState Variable, which is when today's
    // resolve finds a transition to make; for any other Object it answers "no transition" (DL-75 (C3)).
    const auto child = child_named(flow, methodToCall.object_id(), currentState);
    item.hook = child && child->as<VariableAccessor>().has_value();
  }
}

ua::async::Task<> MethodServiceSet::look_up(CallFlow& flow, std::vector<NodeId> nodeIds)
{
  std::vector<NodeId> asked;
  std::unordered_set<NodeId> asking;
  asked.reserve(nodeIds.size());
  for (auto& nodeId : nodeIds)
  {
    if (!flow.found.contains(nodeId) && asking.insert(nodeId).second)
    {
      asked.push_back(std::move(nodeId));
    }
  }
  if (asked.empty())
  {
    co_return;
  }
  auto answers = co_await await_step<std::vector<NodeAccessorResult>>([this, &flow, &asked](auto completion)
    { namespace_calls::find_nodes(flow.addressSpace, mRequestInfo, asked, std::move(completion)); });
  for (size_t k = 0; k < asked.size(); ++k)
  {
    flow.found.insert_or_assign(asked[k],
      k < answers.size() ? std::move(answers[k])
                         : NodeAccessorResult{StatusCode{Status::BadInternalError,
                             ErrorDetail::build("LookupItemCountMismatch",
                               "The lookup answered another number of items than it was asked for",
                               "MethodService")
                               .context(ua::ContextKeys::sizeExpected, std::to_string(asked.size()))
                               .context(ua::ContextKeys::sizeActual, std::to_string(answers.size()))}});
  }
}

ua::async::Task<std::vector<Result<std::vector<Reference>>>> MethodServiceSet::read_flow_references(
  CallFlow& flow, std::vector<namespace_calls::ReferenceRead> reads)
{
  const size_t count = reads.size();
  if (count == 0)
  {
    co_return std::vector<Result<std::vector<Reference>>>{};
  }
  auto answers = co_await await_step<std::vector<Result<std::vector<Reference>>>>(
    [this, &flow, &reads](auto completion)
    {
      namespace_calls::read_references(
        flow.addressSpace, mRequestInfo, std::move(reads), flow.browseLimit, std::move(completion));
    });
  while (answers.size() < count)
  {
    answers.emplace_back(StatusCode{Status::BadInternalError});
  }
  co_return answers;
}

ua::async::Task<> MethodServiceSet::pair_and_read_arguments(CallFlow& flow, std::vector<NodeId> methods)
{
  using Pairing = CallFlowItem::Pairing;
  using Kind = LevelOutcome::Kind;
  const auto climbing = [](const CallFlowItem& item)
  {
    return !item.answered && item.pairing == Pairing::Climbing;
  };
  const auto methodOf = [this](const CallFlowItem& item) -> const NodeId&
  {
    return mCallRequest.methods_to_call()[item.index].method_id();
  };
  // A type without a supertype ends the climb: for an ObjectType objectId the Object is not valid for the
  // call (OPC 10000-9 5.5.6/5.7.3/5.7.4), and for an Object the Method was not found.
  const auto noSupertype = [this](CallFlowItem& item)
  {
    if (!item.objectIsType)
    {
      item.pairing = Pairing::NotFound;
      return;
    }
    answer_item(item,
      VoidResult{Status::BadNodeIdInvalid,
        ErrorDetail::build("BadNodeIdInvalid",
          "Method cannot be invoked on an ObjectType node",
          "MethodService::validate_object_id")
          .context(
            ua::ContextKeys::nodeId, ua::to_string(mCallRequest.methods_to_call()[item.index].object_id()))});
  };

  // Each round reads one level of every climb still going. LoopLimit bounds the levels of each item, and an
  // item whose limit is reached is answered, so the rounds end.
  size_t rounds = 0;
  for (bool first = true; first || std::ranges::any_of(flow.items, climbing); first = false)
  {
    // A round whose levels and lookups the flow already holds makes no namespace call, so nothing ends its
    // strand turn: a HasSubtype cycle would run every round up to LoopLimit in one turn. The strand is given
    // back every `roundsPerStrandTurn` rounds; the completion `await_step` passes is posted, never run
    // inline.
    if (++rounds % roundsPerStrandTurn == 0)
    {
      co_await await_step<std::monostate>([](auto completion) { completion(std::monostate{}); });
    }
    // ----- a. the levels' References, each Node read once, and in the first round the Methods' -----
    std::vector<namespace_calls::ReferenceRead> reads;
    std::vector<NodeId> levelsRead;
    std::unordered_set<NodeId> reading;
    for (auto& item : flow.items)
    {
      if (!climbing(item))
      {
        continue;
      }
      try
      {
        item.levels->consume_iteration();
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        answer_item(item, VoidResult{ua::exception_to_status_code(std::current_exception())});
        continue;
      }
      if (!flow.levels.contains(item.levelId) && reading.insert(item.levelId).second)
      {
        reads.push_back(level_read(*item.level, item.levelId));
        levelsRead.push_back(item.levelId);
      }
    }
    if (first)
    {
      for (const auto& methodId : methods)
      {
        reads.push_back(namespace_calls::ReferenceRead{flow.methods.at(methodId).method,
          methodId,
          BrowseDirection::Forward,
          NodeId{ReferenceTypeId::HasProperty},
          {NodeId{ReferenceTypeId::HasOptionalInputArgumentDescription}},
          false});
      }
    }
    auto answers = co_await read_flow_references(flow, std::move(reads));
    for (size_t k = 0; k < levelsRead.size(); ++k)
    {
      flow.levels.insert_or_assign(levelsRead[k], std::move(answers[k]));
    }
    if (first)
    {
      for (size_t m = 0; m < methods.size(); ++m)
      {
        auto& facts = flow.methods.at(methods[m]);
        auto& answer = answers[levelsRead.size() + m];
        if (!answer.is_good())
        {
          facts.failure = references_failure(answer.status_code(), methods[m]);
          continue;
        }
        for (const auto& reference : answer.value())
        {
          if (!reference.is_forward() || !reference.target_id().is_index_based())
          {
            continue;
          }
          if (reference.type_id() == NodeId{ReferenceTypeId::HasProperty})
          {
            facts.properties.push_back(reference.target_id().node_id());
          }
          else if (reference.type_id() == NodeId{ReferenceTypeId::HasOptionalInputArgumentDescription})
          {
            facts.descriptions.push_back(reference.target_id().node_id());
          }
        }
      }
    }

    // ----- b. the ReferenceTypes the namespace-0 table cannot place, from the request's supertype facts
    // -----
    std::vector<std::pair<NodeId, NodeId>> questions;
    for (const auto& item : flow.items)
    {
      if (!climbing(item))
      {
        continue;
      }
      const auto read = flow.levels.find(item.levelId);
      if (read == flow.levels.end() || !read->second.is_good())
      {
        continue;
      }
      for (const auto& reference : read->second.value())
      {
        if (!reference.is_forward() || !reference.target_id().is_index_based() ||
            reference.target_id().node_id() != methodOf(item) ||
            is_component_type(flow, reference.type_id()).has_value())
        {
          continue;
        }
        auto question = std::make_pair(reference.type_id(), NodeId{ReferenceTypeId::HasComponent});
        if (std::ranges::find(questions, question) == questions.end())
        {
          questions.push_back(std::move(question));
        }
      }
    }
    if (!questions.empty())
    {
      std::vector<bool> facts;
      try
      {
        facts = co_await await_step<std::vector<bool>>(
          [this, &flow, &questions](auto completion)
          {
            SubtypeFacts::resolve_async(flow.addressSpace,
              mRequestInfo,
              questions,
              SubtypeFacts::Bounds{flow.limits.execution.loopLimit,
                [](const NodeId& type)
                {
                  return type == NodeId{ReferenceTypeId::References};
                }},
              std::move(completion));
          });
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        // What cannot be decided is not a match, as a failed walk was not one.
        facts.clear();
      }
      for (size_t q = 0; q < questions.size(); ++q)
      {
        flow.componentTypes.insert_or_assign(questions[q].first, q < facts.size() && facts[q]);
      }
    }

    // ----- c. per item: paired at this level, or the next level to look up -----
    std::vector<NodeId> lookups;
    for (auto& item : flow.items)
    {
      if (!climbing(item))
      {
        continue;
      }
      auto outcome = decide_level(flow, item, methodOf(item));
      switch (outcome.kind)
      {
      case Kind::Paired:
        item.pairing = Pairing::Paired;
        break;
      case Kind::Failed:
        answer_item(item, std::move(outcome.failure));
        break;
      case Kind::NotFound:
        item.pairing = Pairing::NotFound;
        break;
      case Kind::NoSupertype:
        noSupertype(item);
        break;
      case Kind::Climb:
        item.next = outcome.next;
        item.nextIsTypeDefinition = outcome.nextIsTypeDefinition;
        lookups.push_back(std::move(outcome.next));
        break;
      }
    }
    if (first)
    {
      // The Objects' children, for the shelving exception and the StateMachine hook, and the Methods'
      // Properties.
      for (const auto& item : flow.items)
      {
        if (item.answered)
        {
          continue;
        }
        auto children = component_children(flow, mCallRequest.methods_to_call()[item.index].object_id());
        lookups.insert(lookups.end(), children.begin(), children.end());
      }
      for (const auto& methodId : methods)
      {
        const auto& facts = flow.methods.at(methodId);
        if (!facts.failure)
        {
          lookups.insert(lookups.end(), facts.properties.begin(), facts.properties.end());
        }
      }
    }
    co_await look_up(flow, std::move(lookups));

    // ----- d. per item: the next level, or the end of the climb -----
    for (auto& item : flow.items)
    {
      if (!climbing(item) || !item.next)
      {
        continue;
      }
      const NodeId next = *std::exchange(item.next, std::nullopt);
      const auto found = lookup_of(flow, next);
      if (item.nextIsTypeDefinition)
      {
        // A TypeDefinition that cannot be looked up, or is not an ObjectType, is not fatal: it ends the
        // climb, and step e answers the item as a Method its Object does not have. An Uncertain answer, with
        // or without the Node, is refused: the climb decides the pairing, and the SDK does not act on an
        // answer the namespace is uncertain of.
        if (found.is_bad() || (found.is_good() && !found.value().is_object_type()))
        {
          item.pairing = Pairing::NotFound;
          continue;
        }
        if (!found.is_good())
        {
          answer_item(item, VoidResult{lookup_uncertain(next, found.status_code())});
          continue;
        }
      }
      else if (!found.is_good())
      {
        noSupertype(item);
        continue;
      }
      item.level = found.value();
      item.levelId = next;
    }

    if (first)
    {
      // The InputArguments Property: the first 0:InputArguments Variable among the Method's Properties, in
      // Reference order. A Property before it that cannot be looked up fails the items, one after it does not
      // (DL-75 (C8)).
      const QualifiedName inputArguments{0, "InputArguments"};
      for (const auto& methodId : methods)
      {
        auto& facts = flow.methods.at(methodId);
        if (facts.failure)
        {
          continue;
        }
        for (const auto& propertyId : facts.properties)
        {
          const auto property = lookup_of(flow, propertyId);
          if (property.is_bad())
          {
            facts.failure = property.status_code();
            break;
          }
          if (!property.is_good())
          {
            facts.failure = lookup_uncertain(propertyId, property.status_code());
            break;
          }
          if (property.value().get_browse_name() == inputArguments && property.value().as<VariableAccessor>())
          {
            facts.property = property.value();
            facts.propertyId = propertyId;
            break;
          }
        }
      }
    }
  }

  // ----- e. the ends of the climbs: the shelving exception, or the Method is not a component -----
  const QualifiedName shelvingState{0, "ShelvingState"};
  for (auto& item : flow.items)
  {
    if (item.answered || item.pairing != Pairing::NotFound)
    {
      continue;
    }
    const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
    // OPC 10000-9 5.8.17.2/.4/.6: the shelving Methods may be called with the ConditionId as the ObjectId,
    // where the Condition has the Shelving child. They are components of that child, never of the Condition
    // or its type, so no climb reaches them; an ObjectType objectId has no such child and still fails.
    if (!item.objectIsType && is_shelved_state_machine_method(methodToCall.method_id()))
    {
      if (child_named(flow, methodToCall.object_id(), shelvingState))
      {
        item.pairing = Pairing::Paired;
        continue;
      }
      answer_item(item,
        VoidResult{Status::BadMethodInvalid,
          ErrorDetail::build("BadMethodInvalid",
            "Method not found in object's type hierarchy, and the object has no ShelvingState child",
            "MethodService::validate_object_id")
            .context(ua::ContextKeys::nodeId, ua::to_string(methodToCall.method_id()))});
      continue;
    }
    answer_item(item,
      VoidResult{Status::BadMethodInvalid,
        ErrorDetail::build("BadMethodInvalid",
          "Method not found in object's type hierarchy",
          "MethodService::validate_object_id")
          .context(ua::ContextKeys::nodeId, ua::to_string(methodToCall.method_id()))});
  }

  // ----- f. the InputArguments Values of the Methods still called, then their optional arguments -----
  std::unordered_set<NodeId> called;
  for (const auto& item : flow.items)
  {
    if (!item.answered && !item.methodCheck)
    {
      called.insert(mCallRequest.methods_to_call()[item.index].method_id());
    }
  }
  std::vector<ua::detail::ValueRead> valueReads;
  std::vector<NodeId> valueOf;
  for (const auto& methodId : methods)
  {
    const auto& facts = flow.methods.at(methodId);
    if (facts.failure || !facts.property || !called.contains(methodId))
    {
      continue;
    }
    ReadValueId readValueId;
    readValueId.node_id() = facts.propertyId;
    readValueId.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    valueReads.push_back(ua::detail::ValueRead{*facts.property, std::move(readValueId)});
    valueOf.push_back(methodId);
  }
  if (valueReads.empty())
  {
    co_return;
  }
  // Read with maxAge 0 and no caller: the declared arguments are the Method's, not the caller's (DL-75 (C8)).
  auto values = co_await await_step<std::vector<DataValueResult>>(
    [this, &valueReads](auto completion)
    {
      ua::detail::NodeAccessorRoute::read_values(
        mRequestInfo, nullptr, std::move(valueReads), Duration{0}, false, std::move(completion));
    });
  std::vector<NodeId> descriptionLookups;
  for (size_t v = 0; v < valueOf.size(); ++v)
  {
    auto& facts = flow.methods.at(valueOf[v]);
    if (v >= values.size() || !values[v].is_good())
    {
      facts.failure = v < values.size() ? value_failure(values[v].status_code(), facts.propertyId)
                                        : StatusCode{Status::BadInternalError};
      continue;
    }
    facts.inputs =
      InputArgumentsMetadata{.arguments = declared_arguments(values[v].value()), .requiredArgumentCount = 0};
    descriptionLookups.insert(descriptionLookups.end(), facts.descriptions.begin(), facts.descriptions.end());
  }
  co_await look_up(flow, std::move(descriptionLookups));
  for (const auto& methodId : valueOf)
  {
    auto& facts = flow.methods.at(methodId);
    if (facts.failure || !facts.inputs)
    {
      continue;
    }
    // The trailing arguments named by a HasOptionalInputArgumentDescription target are optional (OPC 10000-3
    // 5.7.1); each target is looked up in Reference order, and the first that fails fails the items.
    std::vector<String> optionalNames;
    for (const auto& descriptionId : facts.descriptions)
    {
      const auto nodeDescription = lookup_of(flow, descriptionId);
      if (nodeDescription.is_bad())
      {
        facts.failure = nodeDescription.status_code();
        break;
      }
      if (!nodeDescription.is_good())
      {
        facts.failure = lookup_uncertain(descriptionId, nodeDescription.status_code());
        break;
      }
      const auto variable = nodeDescription.value().as<VariableAccessor>();
      if (!variable)
      {
        facts.failure = StatusCode{Status::BadNodeClassInvalid,
          ErrorDetail::build("OptionalInputDescriptionNodeClassInvalid",
            "HasOptionalInputArgumentDescription target is not a Variable",
            "MethodService")
            .context(ua::ContextKeys::nodeId, ua::to_string(descriptionId))};
        break;
      }
      optionalNames.push_back(variable->get_browse_name().name());
    }
    if (facts.failure)
    {
      continue;
    }
    auto& inputMetadata = *facts.inputs;
    size_t requiredArgumentCount = inputMetadata.arguments.size();
    while (requiredArgumentCount > 0 &&
           std::ranges::find(optionalNames, inputMetadata.arguments[requiredArgumentCount - 1].name()) !=
             optionalNames.end())
    {
      --requiredArgumentCount;
    }
    inputMetadata.requiredArgumentCount = requiredArgumentCount;
  }
}

ua::async::Task<> MethodServiceSet::call_flow_items(CallFlow& flow)
{
  // The Session's facts every call carries: on whose behalf it is made, and each handler's context; and what
  // each item whose call may start a StateMachine transition needs to start it.
  shared_ptr<const CallerInfo> caller;
  std::vector<shared_ptr<MethodCallContext>> contexts(flow.items.size());
  std::vector<std::optional<TransitionStart>> transitions(flow.items.size());
  // What an answer the bodies no longer await is audited with: the request's, so that it does not depend on
  // the Session at the answer (OPC 10000-4 6.5.9).
  CallAuditFacts audit;
  {
    // Scoped: a lock on the session must not span a suspension (R7). The last chance to notice the Session
    // has gone before a Method is called.
    auto sessionInfo = mSessionInfo.lock();
    if (!sessionInfo)
    {
      for (auto& item : flow.items)
      {
        answer_item(item, VoidResult{Status::BadShutdown});
      }
      co_return;
    }
    if (mRequestState)
    {
      caller = session_caller(*sessionInfo, mRequestState->accessControl);
    }
    audit = mRequestState ? mRequestState->audit
                          : call_audit_facts(
                              *sessionInfo, mCallRequest.request_header().audit_entry_id(), DateTime::now());
    // The time the user initiated the action of each transition's audit Event (OPC 10000-5 6.4.3): the
    // request's, not the time a transition completes, which may be after the response.
    const auto actionTime = audit.actionTime;
    for (size_t position = 0; position < flow.items.size(); ++position)
    {
      const auto& item = flow.items[position];
      if (!item.answered)
      {
        const auto& methodToCall = mCallRequest.methods_to_call()[item.index];
        contexts[position] =
          call_context(*sessionInfo, mResponseCorrelation, mSessionLocales, item, methodToCall.object_id());
        if (item.hook)
        {
          transitions[position] = transition_start(*sessionInfo,
            flow,
            methodToCall,
            mCallRequest.request_header().audit_entry_id(),
            actionTime,
            mStrand);
        }
      }
    }
  }

  auto inbox = std::make_shared<CallInbox>(std::move(audit), mLogger, mCancelled);
  inbox->deliver.resize(flow.items.size());
  inbox->outcome.resize(flow.items.size());
  inbox->transitions.resize(flow.items.size());
  // Built before any body awaits it, so that nothing that can throw lies between the bodies and the route.
  std::function<void(ua::detail::MethodCallAnswers)> answered =
    [inbox, owner = weak_from_this(), strand = mStrand, logger = mLogger](
      ua::detail::MethodCallAnswers answers)
  {
    ua::async::post_self_owning(strand,
      logger,
      [inbox, owner, strand, answers = std::move(answers)]() mutable
      {
        // Held for the whole delivery: the bodies it resumes belong to the service.
        const auto held = owner.lock();
        take_call_answers(held != nullptr, inbox, owner, strand, std::move(answers));
      });
  };
  std::vector<ua::detail::MethodCallItem> calls;
  calls.reserve(flow.items.size());
  // One body per call, awaiting its answer; LOCALS of this frame, so destroying the request destroys them.
  // The inbox is closed when they are gone.
  const CallInboxClosing closing{inbox};
  std::vector<ua::async::Task<>> waits;
  waits.reserve(flow.items.size());
  for (size_t position = 0; position < flow.items.size(); ++position)
  {
    auto& item = flow.items[position];
    if (item.answered)
    {
      continue;
    }
    // Contained per item: an item that could not be given to the route answers its own failure and is not
    // called.
    try
    {
      const size_t slot = calls.size();
      calls.push_back(ua::detail::MethodCallItem{*item.method,
        *item.object,
        mCallRequest.methods_to_call()[item.index],
        std::move(contexts[position])});
      try
      {
        waits.push_back(run_call(flow, position, inbox, slot));
      }
      catch (...)
      {
        calls.pop_back();
        throw;
      }
      // Set for every slot given to the route, empty or not, so that no slot keeps the start of an item that
      // could not be given to it.
      inbox->transitions[slot] = std::move(transitions[position]);
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      answer_item(item, VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }
  if (calls.empty())
  {
    co_return;
  }
  ua::detail::NodeAccessorRoute::call_items(
    mRequestInfo, std::move(caller), std::move(calls), std::move(answered));

  for (auto& wait : waits)
  {
    try
    {
      co_await std::move(wait);
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      // A call body contains its own failures, so reaching here means its containment threw.
      log_exception(mLogger,
        LogLevel::Error,
        "CallService: a method call's own containment threw",
        ua::exception_to_status_code(std::current_exception()));
    }
  }
}

ua::async::Task<> MethodServiceSet::run_call(
  CallFlow& flow, size_t position, shared_ptr<CallInbox> inbox, size_t slot)
{
  // A unit of the flow's join: whatever the call throws answers its own item, so one Method's failure cannot
  // take down the request.
  auto& item = flow.items[position];
  VoidResult terminalStatus{};
  optional<CallMethodResult> callResult;
  try
  {
    terminalStatus = co_await call_item(inbox, slot, callResult);
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was cancelled and has already been answered; it owes this row nothing, but a Method that
    // has run is audited with the last outcome given to this body (OPC 10000-4 6.5.9, DL-75 (C10)).
    if (const auto& outcome = inbox->outcome[slot])
    {
      emit_call_audit(inbox->audit, mLogger, mCallRequest.methods_to_call()[item.index], *outcome);
    }
    co_return;
  }
  catch (...)
  {
    terminalStatus = VoidResult{ua::exception_to_status_code(std::current_exception())};
    callResult.reset();
  }
  answer_item(item, std::move(terminalStatus), std::move(callResult));
}

ua::async::Task<VoidResult> MethodServiceSet::call_item(
  const shared_ptr<CallInbox>& inbox, size_t slot, optional<CallMethodResult>& callResult)
{
  // ----- The item's answer: its transition's when its call started one, otherwise its call's -----
  // Awaited without a post of its own: the answer reaches the strand through the inbox's post, and resuming
  // in that turn means a request answered at its timeoutHint cannot come between the answer and its item, so
  // an answer is either the item's result or audited as late. A transition is started where the call's
  // answer is taken (`take_call_answers`), not here, so that it runs whether or not this body is still
  // waiting (COMP-SVR-NAMESPACE-CALLS-20); its answer keeps the Method's output arguments with the
  // transition's status when it fails (COMP-SVR-STATE-MACHINE-RUNTIME-04).
  auto called = co_await ua::async::await_callback<CallResult>(mStrand,
    mLogger,
    weak_from_this(),
    [&inbox, slot](auto done) { inbox->deliver[slot] = std::move(done); });

  // A result holding no CallMethodResult is the item's status, with its ErrorDetail; an Uncertain one
  // included (DL-75 (C7)).
  if (!called.has_value())
  {
    co_return VoidResult{called.status_code(), called.shared_detail()};
  }

  // Sanitized where it was taken (`take_call_answers`): sanitizing a transition's failed answer here would
  // clear the output arguments it keeps. A code the answer still carries on its result is put on the
  // CallMethodResult, which has room for one.
  const StatusCode answeredCode = called.status_code();
  auto methodResult = std::move(called).value();
  methodResult.status_code() =
    method_status_as_answered(answeredCode, methodResult.status_code(), nullptr, nullptr);

  // Resolve any aggregate LocalizedText in output arguments.
  for (auto& arg : methodResult.output_arguments())
  {
    resolve_in_variant(arg, mSessionLocales);
  }

  // The Method's statusCode, with its ErrorDetail: the detail joins the operation's diagnostics, a Good
  // status's `MethodStatusQualified` included.
  const VoidResult terminal{methodResult.status_code()};
  callResult = std::move(methodResult);
  co_return terminal;
}

void MethodServiceSet::answer_item(
  CallFlowItem& item, VoidResult terminalStatus, optional<CallMethodResult> callResult)
{
  if (item.answered)
  {
    return;
  }
  item.answered = true;
  ua::async::guarded(mLogger,
    [this, &item, &terminalStatus, &callResult]
    {
      finalize_operation(item.index,
        mCallRequest.methods_to_call()[item.index],
        std::move(terminalStatus),
        std::move(callResult));
    })();
}

void MethodServiceSet::finalize_operation(size_t opIndex, const CallMethodRequest& methodToCall,
  VoidResult terminalStatus, optional<CallMethodResult> callResult)
{
  if (mRequestState && opIndex < mRequestState->response->results().size())
  {
    auto& result = mRequestState->response->results()[opIndex];
    if (callResult)
    {
      result = std::move(*callResult);
    }
    else
    {
      result.status_code() = terminalStatus.status_code();
    }
    if (terminalStatus.shared_detail())
    {
      mRequestState->collector.add_item_detail(opIndex, terminalStatus.shared_detail());
    }
    // A Method body states why an input argument was rejected as an ErrorDetail on the inner StatusCode of
    // that argument's DiagnosticInfo, which does not travel. The collector turns it into the wire form
    // under the response's string table, and only when the client asked for operation diagnostics on a
    // secured, authenticated channel (OPC 10000-4 5.11.2.2: the list is empty otherwise).
    auto& argumentDiagnostics = result.input_argument_diagnostic_infos().payload();
    for (size_t argumentIndex = 0; argumentIndex < argumentDiagnostics.size(); ++argumentIndex)
    {
      const auto& inner = argumentDiagnostics[argumentIndex].inner_status_code();
      if (inner.has_value() && inner->shared_detail())
      {
        mRequestState->collector.add_operation_detail(opIndex, argumentIndex, inner->shared_detail());
      }
    }
    argumentDiagnostics.clear();
    emit_audit_event(methodToCall, result);
  }
}

// =============================================================================================
// Audit + lifecycle
// =============================================================================================

void MethodServiceSet::emit_audit_event(const CallMethodRequest& methodToCall, const CallMethodResult& result)
{
  if (mRequestState)
  {
    emit_call_audit(mRequestState->audit, mLogger, methodToCall, result.status_code());
    return;
  }
  emit_call_audit(mSessionInfo,
    mCallRequest.request_header().audit_entry_id(),
    mLogger,
    methodToCall,
    result.status_code());
}

void MethodServiceSet::abort(StatusCode reason)
{
  if (mCancelled)
    mCancelled->store(true);

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](MethodServiceSet& self)
    {
      DiagnosticCollector collector{0};
      self.send_service_fault(self.mCallRequest.request_header(), reason, collector);
      self.mRequestState.reset();
      // Destroying the request's body destroys every unit body with it, in order, because they are
      // its frame's own locals.
      self.mCallTask = {};
    })();
}

void MethodServiceSet::timeout()
{
  // Call runs to the full timeoutHint (OPC 10000-4 section 7.33) and then answers per item rather than
  // failing the whole request: a finished call keeps its result and an unfinished one keeps the
  // Bad_Timeout it was created with - its outcome is unknown, since the Method may still complete. The
  // token is set first so every unit still running unwinds instead of writing into the sent response.
  if (mCancelled)
    mCancelled->store(true);

  if (mRequestState && mRequestState->response)
  {
    complete_call();
  }
  else
  {
    DiagnosticCollector collector{0};
    send_service_fault(mCallRequest.request_header(), Status::BadTimeout, collector);
    mRequestState.reset();
  }
  mCallTask = {};
}

void MethodServiceSet::set_timeout()
{
  ServiceBase::set_timeout(mCallRequest.request_header().timeout_hint());
}

void MethodServiceSet::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
  }
}

}  // namespace ua::server
