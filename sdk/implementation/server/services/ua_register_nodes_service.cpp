// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_register_nodes_service.h"

#include <algorithm>
#include "ua_on_strand.h"
#include "ua_address_space.h"
#include "ua_callback_safety.h"
#include "ua_diagnostic_collector.h"
#include "ua_error_detail.h"
#include "ua_log_exception.h"
#include "ua_node_id_validation.h"
#include "ua_namespace.h"
#include "ua_namespace_service_delegates.h"
#include "ua_server.h"
#include "ua_server_session_info.h"
#include "ua_session_registered_nodes.h"
#include "ua_stack_utilities.h"
#include "ua_to_result.h"

#include <cassert>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua
{

namespace server
{

// --- Per-flow state (private to this translation unit). Each flow is single-instance per
// service; the unique_ptr on the class is the flow root and reset() at completion / cancel /
// timeout drops the flow's locals deterministically. -----------------------------------------

struct RegisterRequestState
{
  AddressSpace addressSpace;
  RegisterNodesResponse response;
  DiagnosticCollector collector;
  std::unordered_map<uint16_t, std::vector<size_t>> operationGroups;
  // What the namespaces registered for this request: kept when the response is sent, unregistered when
  // the flow ends any other way (this state is reset by failure, timeout and cancel alike).
  shared_ptr<RegisterRequestAnswers> answers;

  RegisterRequestState(AddressSpace addressSpaceArg, size_t noOfOperations,
    DiagnosticCollector initialCollector, shared_ptr<SessionRegisteredNodes> registeredNodes)
    : addressSpace(std::move(addressSpaceArg)), collector(std::move(initialCollector)),
      answers(std::make_shared<RegisterRequestAnswers>(std::move(registeredNodes), addressSpace.weak()))
  {
    response.registered_node_ids().resize(noOfOperations);
  }

  RegisterRequestState(const RegisterRequestState&) = delete;
  RegisterRequestState& operator=(const RegisterRequestState&) = delete;
  RegisterRequestState(RegisterRequestState&&) = delete;
  RegisterRequestState& operator=(RegisterRequestState&&) = delete;

  ~RegisterRequestState()
  {
    answers->discard();
  }
};

struct UnregisterRequestState
{
  AddressSpace addressSpace;
  DiagnosticCollector collector;
  // Per namespace, the request's operation indices this Session registered: the only ones forwarded.
  std::unordered_map<uint16_t, std::vector<size_t>> operationGroups;

  UnregisterRequestState(AddressSpace addressSpaceArg, DiagnosticCollector initialCollector)
    : addressSpace(std::move(addressSpaceArg)), collector(std::move(initialCollector))
  {}
};

namespace
{

ServiceFault build_service_fault(
  StatusCode status, const DiagnosticCollector& collector, const RequestHeader& requestHeader)
{
  ServiceFault serviceFault;
  // Echo the request handle + timestamp before stamping the fault status (every
  // response, fault included, round-trips RequestHandle - Part 4 7.30).
  stack_utils::prepare_response_header(requestHeader, serviceFault.response_header());
  serviceFault.response_header().service_result() = status;
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault.response_header(), unused, 0);
  return serviceFault;
}

}  // namespace

// --- create() overloads ---

shared_ptr<RegisterNodesServiceSet> RegisterNodesServiceSet::create(weak_ptr<SessionInfo> sessionInfo,
  RegisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public RegisterNodesServiceSet
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, RegisterNodesRequest&& request,
      boost::asio::any_io_executor executor, ServiceCallComplete callback)
      : RegisterNodesServiceSet(sessionInfo, std::move(request), executor, callback)
    {}
  };

  auto service = make_shared<Wrapper>(sessionInfo, std::move(request), executor, callback);
  service->start();
  return service;
}

shared_ptr<RegisterNodesServiceSet> RegisterNodesServiceSet::create(weak_ptr<SessionInfo> sessionInfo,
  UnregisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public RegisterNodesServiceSet
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, UnregisterNodesRequest&& request,
      boost::asio::any_io_executor executor, ServiceCallComplete callback)
      : RegisterNodesServiceSet(sessionInfo, std::move(request), executor, callback)
    {}
  };

  auto service = make_shared<Wrapper>(sessionInfo, std::move(request), executor, callback);
  service->start();
  return service;
}

// --- Constructors / destructor ---

RegisterNodesServiceSet::RegisterNodesServiceSet(weak_ptr<SessionInfo> sessionInfo,
  RegisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), sessionInfo, executor),
    mRegisterRequest(std::move(request)), mServiceCallCompleteCallback(callback)
{}

RegisterNodesServiceSet::RegisterNodesServiceSet(weak_ptr<SessionInfo> sessionInfo,
  UnregisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), sessionInfo, executor),
    mUnregisterRequest(std::move(request)), mServiceCallCompleteCallback(callback)
{}

RegisterNodesServiceSet::~RegisterNodesServiceSet() = default;

// --- Dispatch ---
void RegisterNodesServiceSet::begin_processing()
{
  if (mRegisterRequest.has_value())
  {
    start_register();
  }
  else
  {
    start_unregister();
  }
}

// =============================================================================================
// RegisterNodes flow
// =============================================================================================
//
// ASCII flow:
//   start_register                                   (entry from begin_processing, on mStrand)
//     [synchronous validation: Empty / TooMany / NullId] -> fail_register(...) inline if rejects
//     -> run_register spawns register_namespace(nsIndex) for each namespace and joins them
//          [no-delegate fast-path: echo originals into response, --barrier]
//          [delegate-path: register_nodes_async(...) -> on_register_namespace_complete]
//     -> on_register_namespace_complete(nsIndex, BatchResult<NodeId>)
//          [batch.batchStatus.is_bad()]  echo originals + log_batch_failure (best-effort skip)
//          [success]                     write batch.items into response slots
//          complete_register runs once, after the join
//     -> complete_register | fail_register

void RegisterNodesServiceSet::start_register()
{
  // begin_processing dispatches here only when mRegisterRequest is engaged; bind it once so the
  // engagement is provable at every deref below (the two sibling request optionals are mutually
  // exclusive and exactly one is set by the constructor for the lifetime of the flow).
  assert(mRegisterRequest.has_value());
  auto& registerRequest = *mRegisterRequest;

  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{registerRequest.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    check(sessionInfo);

    set_timeout();

    auto addressSpace = sessionInfo->address_space();

    const size_t noOfOperations{registerRequest.nodes_to_register().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail("EmptyRegisterNodesRequest",
          "RegisterNodes request contains no nodes to register",
          "RegisterNodesService")};
    }

    auto& maxNodesPerRegisterNodes =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerRegisterNodes;
    if (maxNodesPerRegisterNodes && (noOfOperations > maxNodesPerRegisterNodes.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyNodesToRegister",
          "RegisterNodes request exceeds the server operation limit",
          "RegisterNodesService")
          .context(ua::ContextKeys::actual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::limit, std::to_string(maxNodesPerRegisterNodes.value()))};
    }

    // Part 4 5.8.5.3 Table 44: one structurally invalid NodeId rejects the complete service.
    // Unknown and null NodeIds remain structurally valid and continue to the echo/delegate path.
    for (size_t operationIndex = 0; operationIndex < noOfOperations; ++operationIndex)
    {
      const auto& nodeId = registerRequest.nodes_to_register()[operationIndex];
      const auto validation = ua::detail::validate_node_id_structure(nodeId);
      if (validation.isValid)
      {
        continue;
      }

      const std::string identifierType = nodeId.identifier().is_string() ? "String" : "Opaque";
      if (!validation.encodingIsValid)
      {
        throw UaException{Status::BadNodeIdInvalid,
          ErrorDetail::build("MalformedNodeIdStringIdentifier",
            "NodeId String identifier is not valid UTF-8",
            "RegisterNodesService")
            .context(ua::ContextKeys::operationIndex, operationIndex)
            .context(ua::ContextKeys::typeName, identifierType)
            .context(ua::ContextKeys::encoding, "UTF-8")};
      }

      throw UaException{Status::BadNodeIdInvalid,
        ErrorDetail::build("StructurallyInvalidNodeId",
          "NodeId identifier exceeds its structural size bound",
          "RegisterNodesService")
          .context(ua::ContextKeys::operationIndex, operationIndex)
          .context(ua::ContextKeys::typeName, identifierType)
          .context(ua::ContextKeys::sizeActual, validation.identifierLength)
          .context(ua::ContextKeys::sizeMax, validation.maximumIdentifierLength)};
    }

    mRegisterFlow = std::make_unique<RegisterRequestState>(
      std::move(addressSpace), noOfOperations, std::move(collector), sessionInfo->registered_nodes());

    // Group operations by namespace index.
    mRegisterFlow->operationGroups.reserve(noOfOperations);
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      const auto& nodeToRegister = registerRequest.nodes_to_register()[i];
      mRegisterFlow->operationGroups[nodeToRegister.namespace_index()].push_back(i);
    }

    // Visited in ASCENDING namespace order. `operationGroups` is an unordered map, so the chain
    // visited in hash order; no client can observe it, because every id is written back into its own
    // response slot - but a delegate sees when it is called.
    std::vector<uint16_t> namespaceIndices;
    namespaceIndices.reserve(mRegisterFlow->operationGroups.size());
    for (const auto& [namespaceIndex, _] : mRegisterFlow->operationGroups)
    {
      namespaceIndices.push_back(namespaceIndex);
    }
    std::sort(namespaceIndices.begin(), namespaceIndices.end());

    // An empty request is not a special case any more: the body spawns nothing, joins nothing, and
    // falls through to the answer.
    mRequestTask = run_register(std::move(namespaceIndices));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "RegisterNodesService", er);
    }
    if (mRegisterFlow)
    {
      fail_register(VoidResult{er, er.shared_detail()});
    }
    else
    {
      // Pre-flow failure (validation rejected before we built the flow). Use the local collector.
      collector.set_service_detail(er);
      if (!try_finish())
        return;
      mServiceCallCompleteCallback(build_service_fault(er, collector, registerRequest.request_header()));
    }
  }
}

ua::async::Task<> RegisterNodesServiceSet::run_register(std::vector<uint16_t> namespaceIndices)
{
  // A ROOT task: nobody awaits `mRequestTask`, so an exception that escaped this body would be
  // stored in a promise nobody can read and the client's request would go unanswered.
  try
  {
    // The per-namespace bodies are LOCALS of this frame, started EAGERLY, so the request's wall time
    // is its slowest namespace rather than the sum of all of them.
    std::vector<ua::async::Task<>> units;
    units.reserve(namespaceIndices.size());
    // The namespace of each unit, in step with `units`.
    std::vector<uint16_t> unitNamespaces;
    unitNamespaces.reserve(namespaceIndices.size());

    for (auto namespaceIndex : namespaceIndices)
    {
      if (!mRegisterFlow)
      {
        co_return;
      }
      // Contained per SPAWN: a frame that could not be allocated has no `try` of its own.
      try
      {
        units.push_back(register_namespace(namespaceIndex));
        unitNamespaces.push_back(namespaceIndex);
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        // Echo the originals back, which is what this service does whenever a namespace cannot
        // answer: the client can still address them by NodeId.
        assert(mRegisterRequest.has_value());
        for (auto idx : mRegisterFlow->operationGroups.at(namespaceIndex))
        {
          mRegisterFlow->response.registered_node_ids()[idx] = mRegisterRequest->nodes_to_register()[idx];
        }
      }
    }

    // The join IS the barrier.
    for (std::size_t unitIndex = 0; unitIndex < units.size(); ++unitIndex)
    {
      try
      {
        co_await std::move(units[unitIndex]);
      }
      catch (const ua::async::Abandoned&)
      {
        co_return;
      }
      catch (...)
      {
        log_exception(mLogger,
          LogLevel::Error,
          "RegisterNodesService: a namespace body's own containment threw",
          ua::exception_to_status_code(std::current_exception()));
        // As a namespace that cannot answer: the originals are echoed, and an answer it gave before it
        // threw is not the Session's, as the response does not carry it.
        const uint16_t namespaceIndex = unitNamespaces[unitIndex];
        if (mRegisterFlow)
        {
          mRegisterFlow->answers->release(namespaceIndex);
          assert(mRegisterRequest.has_value());
          for (auto idx : mRegisterFlow->operationGroups.at(namespaceIndex))
          {
            mRegisterFlow->response.registered_node_ids()[idx] = mRegisterRequest->nodes_to_register()[idx];
          }
        }
      }
    }

    if (mRegisterFlow)
    {
      complete_register();
    }
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mRegisterFlow)
        {
          fail_register(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

ua::async::Task<> RegisterNodesServiceSet::register_namespace(uint16_t namespaceIndex)
{
  // Reached only inside the register flow, where the constructor engaged mRegisterRequest; bind it
  // once so the engagement is provable at every deref below.
  assert(mRegisterRequest.has_value());
  auto& registerRequest = *mRegisterRequest;

  auto& flow = *mRegisterFlow;
  auto& indices = flow.operationGroups.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  auto delegate = ns ? ns->register_nodes_delegate() : nullptr;

  if (!delegate)
  {
    // No-delegate fast path: echo the original NodeIds back into the matching response slots.
    for (auto idx : indices)
    {
      flow.response.registered_node_ids()[idx] = registerRequest.nodes_to_register()[idx];
    }
    co_return;
  }

  // Delegate path. Build per-namespace items.
  std::vector<NamespaceRegisterNodesDelegate::Item> items;
  items.reserve(indices.size());
  for (auto idx : indices)
  {
    items.push_back(NamespaceRegisterNodesDelegate::Item{idx, registerRequest.nodes_to_register()[idx]});
  }

  const NamespaceRegisterNodesDelegate::Context ctx;
  auto answers = flow.answers;

  // Re-enter the strand before mutating flow state; the delegate may fire inline on its own thread
  // or callback context. The answer is recorded where it arrives, before it is posted, so it is
  // unregistered again however this request ends without its response.
  auto batch = co_await await_step<BatchResult<NodeId>>(
    [&](auto completion)
    {
      delegate->register_nodes_async(ctx,
        std::move(items),
        [answers, namespaceIndex, completion = std::move(completion)](BatchResult<NodeId> answer) mutable
        {
          // Only the first answer is the request's; a later one is unregistered and not delivered.
          bool first = true;
          try
          {
            first = answers->take_answer(namespaceIndex, !answer.batchStatus.is_bad(), answer.items);
          }
          catch (...)
          {
            // Not recorded: the request still resumes with the answer.
            ua::detail::ignore_expected_exception();
          }
          if (first)
          {
            completion(std::move(answer));
          }
        });
    });

  if (!mRegisterFlow)
  {
    co_return;
  }
  on_register_namespace_complete(namespaceIndex, std::move(batch));
}

void RegisterNodesServiceSet::on_register_namespace_complete(
  uint16_t namespaceIndex, BatchResult<NodeId> batch)
{
  if (!mRegisterFlow)
  {
    // Flow already drained by cancel/timeout; the user callback has already fired and the
    // delegate callback arrived afterwards. Silent no-op.
    return;
  }
  // The register flow owns mRegisterRequest for its entire lifetime; bind it once so the engagement
  // is provable at the deref below.
  assert(mRegisterRequest.has_value());
  auto& registerRequest = *mRegisterRequest;

  auto& flow = *mRegisterFlow;
  auto& indices = flow.operationGroups.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    // Best-effort skip: the service contract on per-batch delegate failure is
    // to echo the originals back so the client can still address them by NodeId; service-level
    // status stays Good. Pin RegisterNodesBatchFailureFallsBackToOriginalIdsWithStatusGood locks
    // this. Server-side log is the only venue where the batch ErrorDetail surfaces, since
    // RegisterNodesResponse has no per-id DiagnosticInfo array.
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "RegisterNodesService: delegate batch failure",
        batch.batchStatus);
    }
    for (auto idx : indices)
    {
      flow.response.registered_node_ids()[idx] = registerRequest.nodes_to_register()[idx];
    }
  }
  else
  {
    // The delegate contract guarantees batch.items.size() matches the input items vector size.
    if (batch.items.size() != indices.size())
    {
      // The request fails, which discards every answer recorded for it.
      fail_register(VoidResult{Status::BadInternalError,
        ErrorDetail::build("DelegateContractViolation",
          "RegisterNodes delegate returned an item count that does not match the request",
          "RegisterNodesService")
          .context(ua::ContextKeys::actual, std::to_string(batch.items.size()))
          .context(ua::ContextKeys::expected, std::to_string(indices.size()))
          .context(ua::ContextKeys::namespaceIndex, std::to_string(namespaceIndex))});
      return;
    }
    for (size_t r = 0; r < indices.size(); ++r)
    {
      flow.response.registered_node_ids()[indices[r]] = std::move(batch.items[r]);
    }
  }
}

void RegisterNodesServiceSet::complete_register()
{
  if (!try_finish())
  {
    mRegisterFlow.reset();
    return;
  }
  // Move-out the response, drop flow state, then fire - matches the 5.4.5 move-out-then-reset-
  // then-fire completion point pattern.
  auto response = std::move(mRegisterFlow->response);
  // The response is sent: the Session owns what the namespaces registered for it.
  mRegisterFlow->answers->keep();
  // Echo the request handle + stamp the timestamp into the ResponseHeader (every
  // response must round-trip RequestHandle - Part 4 7.30). mRegisterRequest is engaged for the
  // whole register flow; bind it so the deref is provable.
  assert(mRegisterRequest.has_value());
  stack_utils::prepare_response_header(mRegisterRequest->request_header(), response.response_header());
  mRegisterFlow.reset();
  mServiceCallCompleteCallback(std::move(response));
}

void RegisterNodesServiceSet::fail_register(VoidResult error)
{
  if (!try_finish())
  {
    mRegisterFlow.reset();
    return;
  }
  // mRegisterRequest is engaged for the whole register flow; bind it so the deref is provable.
  assert(mRegisterRequest.has_value());
  auto& flow = *mRegisterFlow;
  flow.collector.set_service_detail(error.status_code());
  auto fault = build_service_fault(error.status_code(), flow.collector, mRegisterRequest->request_header());
  mRegisterFlow.reset();
  mServiceCallCompleteCallback(std::move(fault));
}

// =============================================================================================
// UnregisterNodes flow
// =============================================================================================
//
// ASCII flow:
//   start_unregister                                 (entry from begin_processing, on mStrand)
//     [synchronous validation: Empty / TooMany]      -> fail_unregister(...) inline if rejects
//     -> run_unregister spawns unregister_namespace(nsIndex) for each namespace and joins them
//          [no-delegate: silent no-op; --barrier]
//          [delegate-path: unregister_nodes_async -> on_unregister_namespace_complete]
//     -> on_unregister_namespace_complete(nsIndex, VoidResult)
//          [is_bad()]  fail_unregister(VoidResult{result.status_code(), result.shared_detail()})
//          [is_good()] --barrier; if 0 -> complete_unregister
//     -> complete_unregister | fail_unregister

void RegisterNodesServiceSet::start_unregister()
{
  // begin_processing dispatches here only when mUnregisterRequest is engaged (mRegisterRequest is
  // not); bind it once so the engagement is provable at every deref below.
  assert(mUnregisterRequest.has_value());
  auto& unregisterRequest = *mUnregisterRequest;

  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{unregisterRequest.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    check(sessionInfo);

    set_timeout();

    auto addressSpace = sessionInfo->address_space();

    const size_t noOfOperations{unregisterRequest.nodes_to_unregister().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail("EmptyUnregisterNodesRequest",
          "UnregisterNodes request contains no nodes to unregister",
          "UnregisterNodesService")};
    }

    auto& maxNodesPerRegisterNodes =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerRegisterNodes;
    if (maxNodesPerRegisterNodes && (noOfOperations > maxNodesPerRegisterNodes.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyNodesToUnregister",
          "UnregisterNodes request exceeds the server operation limit",
          "UnregisterNodesService")
          .context(ua::ContextKeys::actual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::limit, std::to_string(maxNodesPerRegisterNodes.value()))};
    }

    mUnregisterFlow = std::make_unique<UnregisterRequestState>(std::move(addressSpace), std::move(collector));

    // Only NodeIds this Session registered are forwarded, each to the namespace that registered it (a
    // delegate may answer with a NodeId in another namespace): a namespace sees balanced register and
    // unregister calls. A NodeId the Session did not register is ignored; a namespace that no longer has a
    // delegate is not called.
    auto registeredNodes = sessionInfo->registered_nodes();
    const std::vector<NodeId> nodeIds(
      unregisterRequest.nodes_to_unregister().begin(), unregisterRequest.nodes_to_unregister().end());
    const auto registeredBy = registeredNodes->take(nodeIds);
    mUnregisterFlow->operationGroups.reserve(noOfOperations);
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      const auto& registeredNamespace = registeredBy[i];
      if (registeredNamespace)
      {
        mUnregisterFlow->operationGroups[registeredNamespace.value()].push_back(i);
      }
    }
    std::vector<uint16_t> activeNamespaceIndices;
    activeNamespaceIndices.reserve(mUnregisterFlow->operationGroups.size());
    for (const auto& [namespaceIndex, indices] : mUnregisterFlow->operationGroups)
    {
      auto ns = mUnregisterFlow->addressSpace.namespace_array().get_namespace(namespaceIndex);
      if (ns && ns->register_nodes_delegate())
      {
        activeNamespaceIndices.push_back(namespaceIndex);
      }
    }

    std::sort(activeNamespaceIndices.begin(), activeNamespaceIndices.end());
    mRequestTask = run_unregister(std::move(activeNamespaceIndices));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "UnregisterNodesService", er);
    }
    if (mUnregisterFlow)
    {
      fail_unregister(VoidResult{er, er.shared_detail()});
    }
    else
    {
      collector.set_service_detail(er);
      if (!try_finish())
        return;
      mServiceCallCompleteCallback(build_service_fault(er, collector, unregisterRequest.request_header()));
    }
  }
}

ua::async::Task<> RegisterNodesServiceSet::run_unregister(std::vector<uint16_t> namespaceIndices)
{
  // A ROOT task: nobody awaits `mRequestTask`, so an exception that escaped this body would be
  // stored in a promise nobody can read and the client's request would go unanswered.
  try
  {
    // The per-namespace bodies are LOCALS of this frame, started EAGERLY, so the request's wall time
    // is its slowest namespace rather than the sum of all of them.
    std::vector<ua::async::Task<>> units;
    units.reserve(namespaceIndices.size());

    for (auto namespaceIndex : namespaceIndices)
    {
      if (!mUnregisterFlow)
      {
        co_return;
      }
      // Contained per SPAWN: a frame that could not be allocated has no `try` of its own.
      try
      {
        units.push_back(unregister_namespace(namespaceIndex));
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        // An unregister that cannot be started fails the request, which is what a bad
        // per-namespace result does.
        fail_unregister(VoidResult{ua::exception_to_status_code(std::current_exception())});
        co_return;
      }
    }

    // The join IS the barrier.
    for (auto& unit : units)
    {
      try
      {
        co_await std::move(unit);
      }
      catch (const ua::async::Abandoned&)
      {
        co_return;
      }
      catch (...)
      {
        log_exception(mLogger,
          LogLevel::Error,
          "UnregisterNodesService: a namespace body's own containment threw",
          ua::exception_to_status_code(std::current_exception()));
      }
    }

    if (mUnregisterFlow)
    {
      complete_unregister();
    }
  }
  catch (const ua::async::Abandoned&)
  {
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mUnregisterFlow)
        {
          fail_unregister(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

ua::async::Task<> RegisterNodesServiceSet::unregister_namespace(uint16_t namespaceIndex)
{
  // Reached only inside the unregister flow, where the constructor engaged mUnregisterRequest; bind
  // it once so the engagement is provable at the deref below.
  assert(mUnregisterRequest.has_value());
  auto& unregisterRequest = *mUnregisterRequest;

  auto& flow = *mUnregisterFlow;
  auto& indices = flow.operationGroups.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  auto delegate = ns->register_nodes_delegate();  // pre-filtered to be non-null in start_unregister

  std::vector<NamespaceRegisterNodesDelegate::Item> items;
  items.reserve(indices.size());
  for (auto idx : indices)
  {
    items.push_back(NamespaceRegisterNodesDelegate::Item{idx, unregisterRequest.nodes_to_unregister()[idx]});
  }

  const NamespaceRegisterNodesDelegate::Context ctx;
  // Taken from the Session's registrations before forwarding. A namespace that refuses still holds them,
  // so they go back, where the answer arrives, and are released at the Session's end or forwarded again.
  std::vector<NodeId> forwarded;
  forwarded.reserve(items.size());
  for (const auto& item : items)
  {
    forwarded.push_back(item.nodeId);
  }
  const auto sessionInfo = mSessionInfo.lock();
  auto registeredNodes = sessionInfo ? sessionInfo->registered_nodes() : nullptr;
  const auto weakAddressSpace = flow.addressSpace.weak();

  auto result = co_await await_step<VoidResult>(
    [&](auto completion)
    {
      delegate->unregister_nodes_async(ctx,
        std::move(items),
        [registeredNodes,
          weakAddressSpace,
          namespaceIndex,
          forwarded = std::move(forwarded),
          completion = std::move(completion)](VoidResult answer) mutable
        {
          if (answer.is_bad() && registeredNodes)
          {
            try
            {
              registeredNodes->add(weakAddressSpace, namespaceIndex, forwarded);
            }
            catch (...)
            {
              // Not put back: the namespace keeps them until it is told again; the request still completes.
              ua::detail::ignore_expected_exception();
            }
          }
          completion(std::move(answer));
        });
    });

  if (!mUnregisterFlow)
  {
    co_return;
  }
  on_unregister_namespace_complete(namespaceIndex, std::move(result));
}

void RegisterNodesServiceSet::on_unregister_namespace_complete(uint16_t /*namespaceIndex*/, VoidResult result)
{
  if (!mUnregisterFlow)
  {
    // Flow already drained by cancel/timeout. Silent no-op.
    return;
  }
  if (result.is_bad())
  {
    // Per-namespace fail-fast - preserves the pre-flip `result.value()` throw -> catch-all
    // ServiceFault behaviour. Forward status + shared_detail() losslessly.
    fail_unregister(VoidResult{result.status_code(), result.shared_detail()});
    return;
  }
}

void RegisterNodesServiceSet::complete_unregister()
{
  if (!try_finish())
  {
    mUnregisterFlow.reset();
    return;
  }
  // mUnregisterRequest is engaged for the whole unregister flow; bind it so the deref is provable.
  assert(mUnregisterRequest.has_value());
  mUnregisterFlow.reset();
  UnregisterNodesResponse response;
  // Echo the request handle + stamp the timestamp (Part 4 7.30).
  stack_utils::prepare_response_header(mUnregisterRequest->request_header(), response.response_header());
  mServiceCallCompleteCallback(std::move(response));
}

void RegisterNodesServiceSet::fail_unregister(VoidResult error)
{
  if (!try_finish())
  {
    mUnregisterFlow.reset();
    return;
  }
  // mUnregisterRequest is engaged for the whole unregister flow; bind it so the deref is provable.
  assert(mUnregisterRequest.has_value());
  auto& flow = *mUnregisterFlow;
  flow.collector.set_service_detail(error.status_code());
  auto fault = build_service_fault(error.status_code(), flow.collector, mUnregisterRequest->request_header());
  mUnregisterFlow.reset();
  mServiceCallCompleteCallback(std::move(fault));
}

// --- cancel / timeout / set_timeout ---

void RegisterNodesServiceSet::abort(StatusCode reason)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](RegisterNodesServiceSet& self)
    {
      if (!self.try_finish())
        return;
      self.mRegisterFlow.reset();
      self.mUnregisterFlow.reset();
      // Destroying the request's body destroys every namespace body with it, in order.
      self.mRequestTask = {};
      ServiceFault serviceFault;
      serviceFault.response_header().service_result() = reason;
      self.mServiceCallCompleteCallback(std::move(serviceFault));
    })();
}

void RegisterNodesServiceSet::timeout()
{
  if (!try_finish())
    return;

  mRegisterFlow.reset();
  mUnregisterFlow.reset();
  mRequestTask = {};

  ServiceFault serviceFault;
  serviceFault.response_header().service_result() = Status::BadTimeout;
  mServiceCallCompleteCallback(std::move(serviceFault));
}

void RegisterNodesServiceSet::set_timeout()
{
  if (mRegisterRequest.has_value())
  {
    ServiceBase::set_timeout(mRegisterRequest->request_header().timeout_hint());
  }
  else
  {
    // Exactly one request optional is engaged by the constructor; mRegisterRequest is empty here so
    // mUnregisterRequest must hold the value.
    assert(mUnregisterRequest.has_value());
    ServiceBase::set_timeout(mUnregisterRequest->request_header().timeout_hint());
  }
}

}  // namespace server

}  // namespace ua
