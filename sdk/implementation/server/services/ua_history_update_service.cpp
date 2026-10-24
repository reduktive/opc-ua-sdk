// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_update_service.h"
#include "ua_verdict_rules.h"

#include <algorithm>
#include "ua_on_strand.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_audit_history_at_time_delete_event_payload.h"
#include "ua_audit_history_annotation_update_event_payload.h"
#include "ua_audit_history_event_delete_event_payload.h"
#include "ua_audit_history_event_update_event_payload.h"
#include "ua_audit_history_raw_modify_delete_event_payload.h"
#include "ua_audit_history_update_event_payload.h"
#include "ua_audit_history_value_update_event_payload.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_event_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_diagnostic_collector.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_bus.h"
#include "ua_event_notifier_type.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_update_details.h"
#include "ua_log_exception.h"
#include "ua_namespace.h"
#include "ua_namespace_route.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_update_data_details.h"
#include "ua_update_event_details.h"
#include "ua_update_structure_data_details.h"

#include "security/ua_access_control.h"
#include "ua_node_accessor_route.h"
#include "ua_node_description.h"
#include "ua_service_request_info.h"

#include "fmt/format.h"

#include <array>
#include <unordered_map>
#include <vector>

namespace ua::server
{

// =============================================================================================
// Per-flow state (private to this translation unit). Single-instance per service; the unique_ptr
// on the class is the flow root, dropped at completion / cancel / timeout.
// =============================================================================================

enum class UpdateKind
{
  UpdateData,
  UpdateEvent,
  UpdateStructureData,
  DeleteRaw,
  DeleteAtTime,
  DeleteEvent,
};

// Maps a Part-11 PerformUpdateType to the Part-3 8.55 history-write permission
// it exercises: Insert -> InsertHistory, Replace/Update -> ModifyHistory,
// Remove -> DeleteHistory. Used to gate each update detail at the granularity the
// permission model distinguishes (a node may grant insert but not delete).
static AccessOperation history_write_op(PerformUpdateType type) noexcept
{
  switch (type)
  {
  case PerformUpdateType::Insert:
    return AccessOperation::InsertHistory;
  case PerformUpdateType::Replace:
  case PerformUpdateType::Update:
    return AccessOperation::ModifyHistory;  // Update ALSO needs InsertHistory: see second_history_write_op
  case PerformUpdateType::Remove:
    return AccessOperation::DeleteHistory;
  }
  return AccessOperation::ModifyHistory;
}

/// The second permission an update detail needs, when it needs one: Update inserts what is absent.
static std::optional<AccessOperation> second_history_write_op(PerformUpdateType type) noexcept
{
  return type == PerformUpdateType::Update ? std::optional{AccessOperation::InsertHistory} : std::nullopt;
}

struct HistoryUpdateState
{
  // One classified entry per request slot (after sync filtering of nulls / unsupported types).
  // entries[i].originalIndex is the slot in mRequest.history_update_details(); response slot too.
  struct ClassifiedEntry
  {
    size_t originalIndex{};
    UpdateKind kind{UpdateKind::UpdateData};
    NodeId nodeId;
    Structure* details{};  // borrowed pointer into mRequest; lifetime guaranteed.
    AccessOperation authzOp{
      AccessOperation::ModifyHistory};  // per-node authz op for this detail (Part 3 8.55).
    /// Update inserts what is absent and modifies what is present (Part 11 6.8.2), so it needs
    /// InsertHistory as well as ModifyHistory (SVC-11); the second op, when the detail needs one.
    std::optional<AccessOperation> secondAuthzOp;
    bool targetsHistoricalNode{false};
    bool auditEmitted{false};

    // UpdateEvent only: the OPC 10000-11 6.8.4.2 verdict on each eventData row, and the subset of
    // rows that survived it. `rowStatus` is the response's operationResults once the historian's
    // own answers have been spliced into the dispatched positions; `dispatchRows` maps a position
    // in the batch handed to the delegate back to its row, so the splice can be positional.
    std::vector<StatusCode> rowStatus;
    std::vector<size_t> dispatchRows;

    // Set by this entry's own body when it has decided the entry may be written. Recorded rather
    // than acted on immediately, so the grouping happens once, after the join, in `classified`
    // order - which is what keeps the positional splice in `dispatchRows` meaning what it says.
    bool accepted{false};
  };

  struct GroupKey
  {
    uint16_t nsIndex;
    UpdateKind kind;

    bool operator==(const GroupKey&) const = default;
  };

  struct GroupKeyHash
  {
    size_t operator()(const GroupKey& k) const
    {
      return std::hash<uint16_t>{}(k.nsIndex) ^ (std::hash<int>{}(utils::to_underlying(k.kind)) << 16);
    }
  };

  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<HistoryUpdateResponse> response;
  DiagnosticCollector collector;

  std::vector<ClassifiedEntry> classified;  // ordered list; pointer-stable - never resized after build

  // Indices into `classified` of the accepted UpdateEvent entries awaiting Part-11 6.8.4.2
  // validation. Built in `classified` order after the resolution join.
  std::vector<size_t> eventValidations;

  // Built after node resolution. Each value is a list of indices into `classified`.
  std::unordered_map<GroupKey, std::vector<size_t>, GroupKeyHash> groups;

  HistoryUpdateState(AddressSpace initialAddressSpace, shared_ptr<HistoryUpdateResponse> initialResponse,
    DiagnosticCollector initialCollector)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      collector(std::move(initialCollector))
  {}
};

namespace
{

void fill_history_audit_base(AuditHistoryUpdateEventPayload& event, const SessionInfo& sessionInfo,
  const NodeId& parameterDataTypeId, const StatusCode& outcome, const HistoryUpdateRequest& request)
{
  event.sourceName = "Attribute/HistoryUpdate";
  event.actionTimeStamp = Variant{DateTime::now()};
  event.status = outcome.is_good();
  event.serverId = sessionInfo.configuration().application_description_part().applicationUri;
  event.message = LocalizedText{"", "HistoryUpdate"};
  event.severity = 1;
  event.clientAuditEntryId = request.request_header().audit_entry_id();
  event.parameterDataTypeId = parameterDataTypeId;

  if (auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto user = sec->user_identity())
      event.clientUserId = user->userId;
  }
}

void emit_history_audit(const shared_ptr<SessionInfo>& sessionInfo, BaseEvent& event)
{
  if (!sessionInfo->server_configuration().auditingEnabled)
    return;

  const auto sink = sessionInfo->event_sink();
  if (!sink || !static_cast<EventBus*>(sink.get())->has_event_interest())
    return;

  sink->emit(event);
}

NodeId parameter_data_type_id(UpdateKind kind)
{
  switch (kind)
  {
  case UpdateKind::UpdateData:
    return NodeId{uint16_t{0}, UpdateDataDetails::typeId};
  case UpdateKind::UpdateEvent:
    return NodeId{uint16_t{0}, UpdateEventDetails::typeId};
  case UpdateKind::UpdateStructureData:
    return NodeId{uint16_t{0}, UpdateStructureDataDetails::typeId};
  case UpdateKind::DeleteRaw:
    return NodeId{uint16_t{0}, DeleteRawModifiedDetails::typeId};
  case UpdateKind::DeleteAtTime:
    return NodeId{uint16_t{0}, DeleteAtTimeDetails::typeId};
  case UpdateKind::DeleteEvent:
    return NodeId{uint16_t{0}, DeleteEventDetails::typeId};
  }
  return NodeId{};
}

void emit_generic_history_audit(const shared_ptr<SessionInfo>& sessionInfo,
  const HistoryUpdateState::ClassifiedEntry& entry, const StatusCode& outcome,
  const HistoryUpdateRequest& request)
{
  AuditHistoryUpdateEventPayload auditEvent;
  auditEvent.sourceNode = entry.nodeId;
  fill_history_audit_base(auditEvent, *sessionInfo, parameter_data_type_id(entry.kind), outcome, request);
  emit_history_audit(sessionInfo, auditEvent);
}

}  // namespace

shared_ptr<HistoryUpdateService> HistoryUpdateService::create(weak_ptr<SessionInfo> sessionInfo,
  uint32_t requestId, HistoryUpdateRequest&& request, boost::asio::any_io_executor executor,
  CompleteCallback callback)
{
  struct Wrapper : public HistoryUpdateService
  {
    Wrapper(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId, HistoryUpdateRequest&& request,
      boost::asio::any_io_executor executor, CompleteCallback callback)
      : HistoryUpdateService(
          std::move(sessionInfo), requestId, std::move(request), executor, std::move(callback))
    {}
  };

  auto service =
    make_shared<Wrapper>(sessionInfo, requestId, std::move(request), executor, std::move(callback));
  service->start();
  return service;
}

HistoryUpdateService::HistoryUpdateService(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId,
  HistoryUpdateRequest&& request, boost::asio::any_io_executor executor, CompleteCallback callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mRequestId(requestId), mRequest(std::move(request)), mCallback(std::move(callback)),
    mCancelled(make_shared<std::atomic_bool>(false))
{}

HistoryUpdateService::~HistoryUpdateService() = default;

void HistoryUpdateService::begin_processing()
{
  start_history_update();
}

// =============================================================================================
// HistoryUpdate flow
// =============================================================================================
//
// ASCII flow:
//   start_history_update                          (entry from begin_processing, on mStrand)
//     [validate session / Empty / TooMany]        rejects -> finish_with_service_error inline
//     [classify + null/unsupported per-item]      bad items pre-marked in response, dropped from
//                                                  classified
//     -> start_request -> run_history_update, which is the whole request in one body:
//          co_await run_resolution      one lookup, the classification of each entry, one authorization
//          group the accepted entries   in `classified` order; UpdateEvent defers to validation
//          co_await run_event_validations   spawns walk_event_validation(i) and joins, then groups
//                                       the surviving rows, still in `classified` order
//          co_await run_groups          spawns run_group(key) per group, ascending, and joins
//          complete_history_update      once, after the last join
//     -> run_group(nsIndex, kind)
//          [no-delegate]   mark all in-group BadHistoryOperationUnsupported and return
//          [delegate-path] co_await update_data_async / delete_raw_async / delete_at_time_async /
//                          delete_events_async per kind, then on_<kind>_complete
//     -> on_<kind>_complete(nsIndex, BatchResult<...>)
//          [batchStatus.is_bad()] per-item bad status
//          [success]              per-item map status + emit audit events + apply_to results
//          --barrier; if 0 -> complete_history_update

void HistoryUpdateService::start_history_update()
{
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{mRequest.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw UaException{Status::BadSessionClosed,
        make_error_detail(
          "SessionClosed", "Session expired during HistoryUpdate processing", "HistoryUpdateService")};
    }

    const auto arrival = std::chrono::steady_clock::now();
    set_timeout(mRequest.request_header().timeout_hint());
    mRequestInfo =
      service_request_info(arrival, mRequest.request_header().timeout_hint(), std::nullopt, mCancelled, {});

    auto addressSpace = sessionInfo->address_space();

    auto response = make_shared<HistoryUpdateResponse>();

    // A whole-request validation failure is a SERVICE-level error: per OPC 10000-4 5.3 / 7.35 it must
    // be delivered as a ServiceFault (which carries only a ResponseHeader), NOT as a
    // HistoryUpdateResponse carrying a Bad serviceResult in its header. Mirrors
    // HistoryReadService::finishWithServiceError (which cites the same clauses and the CTT checks).
    auto finishWithServiceError = [&](StatusCode status)
    {
      collector.set_service_detail(status);
      send_service_fault(mRequest.request_header(), status, collector);
    };

    const size_t noOfOperations = mRequest.history_update_details().size();
    if (noOfOperations == 0)
    {
      finishWithServiceError(Status::BadNothingToDo);
      return;
    }

    // Part 4 5.10.5 gives HistoryUpdate two operation ceilings, one per detail class, and OPC 10000-5
    // advertises them as separate OperationLimits nodes. A HistoryUpdate batch is heterogeneous, so the
    // ceilings are applied to the COUNTS OF EACH CLASS rather than to the batch as a whole: a request is
    // refused when its event items exceed the event ceiling or its data items exceed the data ceiling.
    // Counting the whole batch against one ceiling (the previous behaviour) both over-refused mixed
    // batches and left the event ceiling advertised-but-unenforced (D6).
    const auto& opLimits = sessionInfo->server_configuration().server_capabilities().operationLimits;
    size_t eventOperations = 0;
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      auto* details = mRequest.history_update_details()[i].get();
      if (dynamic_cast<UpdateEventDetails*>(details) != nullptr ||
          dynamic_cast<DeleteEventDetails*>(details) != nullptr)
      {
        ++eventOperations;
      }
    }
    const size_t dataOperations = noOfOperations - eventOperations;

    const auto exceeds = [](const std::optional<std::uint32_t>& ceiling, size_t count)
    {
      return ceiling.has_value() && *ceiling > 0 && count > *ceiling;
    };

    if (exceeds(opLimits.maxNodesPerHistoryUpdateData, dataOperations) ||
        exceeds(opLimits.maxNodesPerHistoryUpdateEvents, eventOperations))
    {
      finishWithServiceError(Status::BadTooManyOperations);
      return;
    }

    response->results().resize(noOfOperations);

    mFlow = std::make_unique<HistoryUpdateState>(std::move(addressSpace), response, std::move(collector));
    mFlow->accessControl = SessionAccessControl::create(*sessionInfo);

    // Sync classification: validate per-item details + classify + drop bad items into response.
    mFlow->classified.reserve(noOfOperations);
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      auto* baseStructure = mRequest.history_update_details()[i].get();
      if (!baseStructure)
      {
        mFlow->response->results()[i].status_code() = Status::BadHistoryOperationInvalid;
        continue;
      }

      const auto* histDetails = dynamic_cast<const HistoryUpdateDetails*>(baseStructure);
      if (!histDetails)
      {
        mFlow->response->results()[i].status_code() = Status::BadHistoryOperationInvalid;
        continue;
      }

      HistoryUpdateState::ClassifiedEntry entry;
      entry.originalIndex = i;
      entry.details = baseStructure;

      // The abstract HistoryUpdateDetails base carries no fields (Part 11): the
      // target NodeId lives on each concrete subtype, so classify by concrete
      // type and read node_id() from that.
      if (auto* updateData = dynamic_cast<UpdateDataDetails*>(baseStructure))
      {
        if (updateData->update_values().empty())
        {
          mFlow->response->results()[i].status_code() = Status::BadHistoryOperationInvalid;
          continue;
        }
        entry.nodeId = updateData->node_id();
        entry.kind = UpdateKind::UpdateData;
        entry.authzOp = history_write_op(updateData->perform_insert_replace());
        entry.secondAuthzOp = second_history_write_op(updateData->perform_insert_replace());
      }
      else if (auto* updateEvent = dynamic_cast<UpdateEventDetails*>(baseStructure))
      {
        if (updateEvent->event_data().empty())
        {
          mFlow->response->results()[i].status_code() = Status::BadHistoryOperationInvalid;
          continue;
        }
        entry.nodeId = updateEvent->node_id();
        entry.kind = UpdateKind::UpdateEvent;
        entry.authzOp = history_write_op(updateEvent->perform_insert_replace());
        entry.secondAuthzOp = second_history_write_op(updateEvent->perform_insert_replace());
      }
      else if (auto* updateStructure = dynamic_cast<UpdateStructureDataDetails*>(baseStructure))
      {
        if (updateStructure->update_values().empty())
        {
          mFlow->response->results()[i].status_code() = Status::BadHistoryOperationInvalid;
          continue;
        }
        entry.nodeId = updateStructure->node_id();
        entry.kind = UpdateKind::UpdateStructureData;
        entry.authzOp = history_write_op(updateStructure->perform_insert_replace());
        entry.secondAuthzOp = second_history_write_op(updateStructure->perform_insert_replace());
      }
      else if (auto* deleteRaw = dynamic_cast<DeleteRawModifiedDetails*>(baseStructure))
      {
        if (deleteRaw->start_time().is_null() || deleteRaw->end_time().is_null())
        {
          shared_ptr<const ErrorDetail> detail =
            ErrorDetail::build("DeleteRangeBoundsUndefined",
              "DeleteRawModified requires both startTime and endTime",
              "HistoryUpdateService")
              .context(ua::ContextKeys::nodeId, deleteRaw->node_id())
              .context(ua::ContextKeys::expected, "both startTime and endTime")
              .context(ua::ContextKeys::actual, "one or both bounds are null");
          mFlow->response->results()[i].status_code() = StatusCode{Status::BadInvalidArgument, detail};
          mFlow->collector.add_item_detail(i, detail);
          continue;
        }
        if (deleteRaw->start_time() > deleteRaw->end_time())
        {
          shared_ptr<const ErrorDetail> detail = ErrorDetail::build("DeleteRangeReversed",
            "DeleteRawModified startTime must not follow endTime",
            "HistoryUpdateService")
                                                   .context(ua::ContextKeys::nodeId, deleteRaw->node_id())
                                                   .context(ua::ContextKeys::expected, "startTime <= endTime")
                                                   .context(ua::ContextKeys::actual, "startTime > endTime");
          mFlow->response->results()[i].status_code() = StatusCode{Status::BadInvalidArgument, detail};
          mFlow->collector.add_item_detail(i, detail);
          continue;
        }
        entry.nodeId = deleteRaw->node_id();
        entry.kind = UpdateKind::DeleteRaw;
        entry.authzOp = AccessOperation::DeleteHistory;
      }
      else if (auto* deleteAtTime = dynamic_cast<DeleteAtTimeDetails*>(baseStructure))
      {
        entry.nodeId = deleteAtTime->node_id();
        entry.kind = UpdateKind::DeleteAtTime;
        entry.authzOp = AccessOperation::DeleteHistory;
      }
      else if (auto* deleteEvent = dynamic_cast<DeleteEventDetails*>(baseStructure))
      {
        entry.nodeId = deleteEvent->node_id();
        entry.kind = UpdateKind::DeleteEvent;
        entry.authzOp = AccessOperation::DeleteHistory;
      }
      else
      {
        mFlow->response->results()[i].status_code() = Status::BadHistoryOperationUnsupported;
        continue;
      }

      mFlow->classified.push_back(std::move(entry));
    }

    // An empty classification is not a special case any more: the body spawns nothing, joins
    // nothing, and falls through to the answer.
    start_request();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "HistoryUpdateService", er);
    }
    if (mFlow)
    {
      fail_history_update(VoidResult{er, er.shared_detail()});
    }
    else
    {
      collector.set_service_detail(er);
      send_service_fault(mRequest.request_header(), er, collector);
    }
  }
}

void HistoryUpdateService::start_request()
{
  // A per-request service handles exactly ONE HistoryUpdate, so there is no next request to race
  // the slot. The body may still finish entirely before this returns, which is why the service is
  // kept alive across this call by the posted handler that reached it.
  mRequestTask = run_history_update();
}

ua::async::Task<> HistoryUpdateService::run_history_update()
{
  // A ROOT task: nobody awaits `mRequestTask`, so an exception that escaped this body would be
  // stored in a promise nobody can read, and the client's HistoryUpdate would never be answered at
  // all - no response and no fault.
  try
  {
    co_await run_resolution();

    if (!mFlow)
    {
      co_return;
    }

    // Grouped AFTER the join, walking `classified` in order. The chain grouped from inside each
    // entry's last handler, so a group's membership order was the order the resolutions completed -
    // and for an UpdateEvent group that order is load-bearing, because `dispatchRows` splices the
    // historian's answers back POSITIONALLY. Building the group in `classified` order is what keeps
    // that splice meaning what it says whatever the collaborators do with their timing.
    for (size_t classifiedIndex = 0; classifiedIndex < mFlow->classified.size(); ++classifiedIndex)
    {
      const auto& entry = mFlow->classified[classifiedIndex];
      if (!entry.accepted)
      {
        continue;
      }
      if (entry.kind == UpdateKind::UpdateEvent)
      {
        // An Event insert has one more gate to pass before any historian sees it: the OPC 10000-11
        // 6.8.4.2 parameter rules, which are answered against the address space and so cannot be
        // settled here. Grouping is deferred until that verdict is in.
        mFlow->eventValidations.push_back(classifiedIndex);
      }
      else
      {
        const HistoryUpdateState::GroupKey key{entry.nodeId.namespace_index(), entry.kind};
        mFlow->groups[key].push_back(classifiedIndex);
      }
    }

    co_await run_event_validations();

    if (!mFlow)
    {
      co_return;
    }
    co_await run_groups();
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the request and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mFlow)
        {
          fail_history_update(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

ua::async::Task<> HistoryUpdateService::run_resolution()
{
  if (!mFlow || mFlow->classified.empty())
  {
    co_return;
  }

  const size_t count = mFlow->classified.size();
  std::vector<ua::detail::LookupItem> lookups;
  lookups.reserve(count);
  for (const auto& entry : mFlow->classified)
  {
    lookups.push_back(ua::detail::LookupItem{entry.nodeId, std::nullopt});
  }
  // One lookup for every entry.
  auto found = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        mFlow->addressSpace.weak(), mRequestInfo, lookups, std::move(completion));
    });
  if (!mFlow || mFlow->classified.size() != count)
  {
    co_return;
  }

  const auto refuse = [this](size_t originalIndex, const StatusCode& status)
  {
    mFlow->response->results()[originalIndex].status_code() = status;
    if (auto detail = status.shared_detail())
    {
      mFlow->collector.add_item_detail(originalIndex, std::move(detail));
    }
  };

  // Per entry, in request order: the lookup's answer, then whether the Node can carry history and be
  // written, from its description. A Variable is gated by its AccessLevel, an Object by its EventNotifier,
  // and anything else cannot carry history. Each writable entry adds one Item per permission its detail needs
  // (two for Update).
  std::vector<AccessControl::Item> authorizationItems;
  // Per candidate entry: its index in `classified` and where its Items begin.
  std::vector<std::pair<size_t, size_t>> candidates;
  for (size_t classifiedIndex = 0; classifiedIndex < count; ++classifiedIndex)
  {
    auto& entry = mFlow->classified[classifiedIndex];
    const size_t originalIndex = entry.originalIndex;
    NodeAccessorResult result{StatusCode{Status::BadInternalError}};
    if (found.batchStatus.is_bad())
    {
      result = NodeAccessorResult{found.batchStatus.status_code()};
    }
    else if (found.items.size() != count)
    {
      result = NodeAccessorResult{StatusCode{Status::BadInternalError,
        ErrorDetail::build("LookupCountMismatch",
          "The lookup answered another number of items than it was asked for",
          "HistoryUpdateService")
          .context(ContextKeys::sizeExpected, std::to_string(count))
          .context(ContextKeys::sizeActual, std::to_string(found.items.size()))}};
    }
    else
    {
      result = found.items[classifiedIndex];
    }
    if (!result.is_good())
    {
      // A Bad answer is the operation's; an Uncertain one, with or without the Node, is refused, and only
      // this operation is.
      refuse(originalIndex,
        ::ua::detail::lookup_failure(entry.nodeId, result.status_code(), "HistoryUpdateService"));
      continue;
    }
    const NodeAccessor node = result.value();
    if (node->deleted())
    {
      refuse(originalIndex,
        StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("NodeDeleted", "The node has been deleted", "HistoryUpdateService")
            .context(ContextKeys::nodeId, to_string(entry.nodeId))});
      continue;
    }
    std::optional<NodeDescription> nodeDescription;
    try
    {
      nodeDescription = node->attributes();
    }
    catch (...)
    {
      refuse(originalIndex, ua::exception_to_status_code(std::current_exception()));
      continue;
    }

    bool writable = false;
    if (nodeDescription->node_class() == NodeClass::Variable)
    {
      const auto accessLevel = nodeDescription->access_level().value_or(AccessLevelType{});
      entry.targetsHistoricalNode = accessLevel.test(AccessLevelType::Bit::HistoryRead) ||
                                    accessLevel.test(AccessLevelType::Bit::HistoryWrite);
      writable = accessLevel.test(AccessLevelType::Bit::HistoryWrite);
    }
    else if (nodeDescription->node_class() == NodeClass::Object)
    {
      const auto eventNotifier = nodeDescription->event_notifier().value_or(EventNotifierType{});
      entry.targetsHistoricalNode = eventNotifier.test(EventNotifierType::Bit::HistoryRead) ||
                                    eventNotifier.test(EventNotifierType::Bit::HistoryWrite);
      writable = eventNotifier.test(EventNotifierType::Bit::HistoryWrite);
    }
    else
    {
      refuse(originalIndex, StatusCode{Status::BadHistoryOperationInvalid});
      continue;
    }
    if (!writable)
    {
      refuse(originalIndex, StatusCode{Status::BadNotWritable});
      continue;
    }

    candidates.emplace_back(classifiedIndex, authorizationItems.size());
    authorizationItems.push_back(
      AccessControl::Item{.node = node, .operation = entry.authzOp, .description = nodeDescription});
    if (const auto second = entry.secondAuthzOp)
    {
      authorizationItems.push_back(
        AccessControl::Item{.node = node, .operation = *second, .description = std::move(nodeDescription)});
    }
  }
  if (candidates.empty())
  {
    co_return;
  }

  // Failed closed: a request with no committed access identity is refused, never allowed through.
  if (!mFlow->accessControl)
  {
    for (const auto& candidate : candidates)
    {
      refuse(mFlow->classified[candidate.first].originalIndex, StatusCode{Status::BadUserAccessDenied});
    }
    co_return;
  }

  // One authorization for every writable entry.
  auto verdicts =
    co_await await_step<std::vector<AccessControl::Verdict>>([this, &authorizationItems](auto completion)
      { mFlow->accessControl->authorize_async(mRequestInfo, authorizationItems, std::move(completion)); });
  if (!mFlow || mFlow->classified.size() != count)
  {
    co_return;
  }
  if (verdicts.size() != authorizationItems.size())
  {
    const StatusCode mismatch{Status::BadInternalError,
      ErrorDetail::build("VerdictCountMismatch",
        "Access control answered another number of verdicts than the items it was asked about",
        "HistoryUpdateService")
        .context(ContextKeys::sizeExpected, std::to_string(authorizationItems.size()))
        .context(ContextKeys::sizeActual, std::to_string(verdicts.size()))};
    for (const auto& candidate : candidates)
    {
      refuse(mFlow->classified[candidate.first].originalIndex, mismatch);
    }
    co_return;
  }
  // Each entry's one or two verdicts; every one must permit (SVR-AUTHZ-015).
  for (size_t k = 0; k < candidates.size(); ++k)
  {
    const auto [classifiedIndex, first] = candidates[k];
    const size_t end = k + 1 < candidates.size() ? candidates[k + 1].second : authorizationItems.size();
    auto& entry = mFlow->classified[classifiedIndex];
    if (auto denial = detail::first_denial(
          std::span<const AccessControl::Verdict>{verdicts.data() + first, end - first}, end - first))
    {
      refuse(entry.originalIndex, *denial);
      continue;
    }
    entry.accepted = true;
  }
}

ua::async::Task<> HistoryUpdateService::run_event_validations()
{
  // The validation bodies are LOCALS of this frame, started eagerly and joined below.
  std::vector<ua::async::Task<>> validations;
  const auto pending = mFlow ? mFlow->eventValidations : std::vector<size_t>{};
  validations.reserve(pending.size());

  for (const size_t classifiedIndex : pending)
  {
    if (!mFlow)
    {
      co_return;
    }
    try
    {
      validations.push_back(walk_event_validation(classifiedIndex));
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      const auto originalIndex = mFlow->classified[classifiedIndex].originalIndex;
      mFlow->response->results()[originalIndex].status_code() = failure;
    }
  }

  for (auto& validation : validations)
  {
    try
    {
      co_await std::move(validation);
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      log_exception(mLogger,
        LogLevel::Error,
        "HistoryUpdateService: an event validation's own containment threw",
        ua::exception_to_status_code(std::current_exception()));
    }
  }

  if (!mFlow)
  {
    co_return;
  }

  // Grouped AFTER the join, walking `eventValidations` in order - which is `classified` order,
  // because that is how the resolution join built it. The historian's answers are spliced back
  // POSITIONALLY through `dispatchRows`, so the order a group is built in is part of its meaning.
  for (const size_t classifiedIndex : mFlow->eventValidations)
  {
    const auto& entry = mFlow->classified[classifiedIndex];
    if (entry.dispatchRows.empty())
    {
      continue;
    }
    const HistoryUpdateState::GroupKey key{entry.nodeId.namespace_index(), entry.kind};
    mFlow->groups[key].push_back(classifiedIndex);
  }
}

ua::async::Task<> HistoryUpdateService::walk_event_validation(size_t classifiedIndex)
{
  if (!mFlow || classifiedIndex >= mFlow->classified.size())
  {
    co_return;
  }

  auto* details = static_cast<UpdateEventDetails*>(mFlow->classified[classifiedIndex].details);
  auto outcome = co_await await_step<history_event_validation::Outcome>([this, details](auto completion)
    { history_event_validation::validate_async(mFlow->addressSpace, *details, std::move(completion)); });

  if (!mFlow || classifiedIndex >= mFlow->classified.size())
  {
    co_return;
  }

  auto& entry = mFlow->classified[classifiedIndex];
  auto& slot = mFlow->response->results()[entry.originalIndex];

  if (outcome.detailStatus.is_bad())
  {
    // A malformed filter describes the whole operation, so it is reported once and no row is
    // dispatched. Part 11 6.8.4.2 states these rules against "the statusCode" for exactly that
    // reason: there is no row for them to belong to.
    slot.status_code() = outcome.detailStatus;
  }
  else
  {
    entry.rowStatus = std::move(outcome.rowStatus);
    for (size_t row = 0; row < entry.rowStatus.size(); ++row)
    {
      if (!entry.rowStatus[row].is_bad())
        entry.dispatchRows.push_back(row);

      for (const auto& ignored : outcome.ignoredFields[row])
      {
        // Good_DataIgnored says a field was dropped; the Client cannot act on that without being
        // told which, so the name goes into the row's own DiagnosticInformation.
        mFlow->collector.add_operation_detail(entry.originalIndex,
          row,
          ErrorDetail::build("DataIgnored",
            "Event field is not defined by the EventType and was not stored",
            "HistoryUpdateService")
            .context(ua::ContextKeys::nodeId, ua::to_string(entry.nodeId))
            .context(ua::ContextKeys::fieldName, ignored));
      }
      for (const auto& invalid : outcome.invalidFields[row])
      {
        mFlow->collector.add_operation_detail(entry.originalIndex,
          row,
          ErrorDetail::build("InvalidEventField",
            "Event field value cannot be processed as its declared type",
            "HistoryUpdateService")
            .context(ua::ContextKeys::nodeId, ua::to_string(entry.nodeId))
            .context(ua::ContextKeys::fieldName, invalid));
      }
    }

    if (entry.dispatchRows.empty())
    {
      // Every row was refused, so there is nothing to hand the historian - but the per-row
      // verdicts are still the answer the Client asked for. The grouping of the rows that DID
      // survive happens after the join, in `run_event_validations`.
      slot.operation_results().payload().assign(entry.rowStatus.begin(), entry.rowStatus.end());
    }
  }
  co_return;
}

ua::async::Task<> HistoryUpdateService::run_groups()
{
  if (!mFlow)
  {
    co_return;
  }

  // Visited in a DEFINED order - by namespace index, then by update kind. `groups` is an unordered
  // map, so the chain visited its groups in hash order; no client can observe it, because every row
  // is keyed by `originalIndex`, but a delegate sees when it is called and hash order is not
  // something to hand it on purpose.
  std::vector<HistoryUpdateState::GroupKey> keys;
  keys.reserve(mFlow->groups.size());
  for (const auto& [key, _] : mFlow->groups)
  {
    keys.push_back(key);
  }
  std::sort(keys.begin(),
    keys.end(),
    [](const HistoryUpdateState::GroupKey& lhs, const HistoryUpdateState::GroupKey& rhs)
    {
      return lhs.nsIndex != rhs.nsIndex ? lhs.nsIndex < rhs.nsIndex
                                        : utils::to_underlying(lhs.kind) < utils::to_underlying(rhs.kind);
    });

  // The group bodies are LOCALS of this frame, started eagerly, so the request's wall time is its
  // slowest group rather than the sum of all of them.
  std::vector<ua::async::Task<>> dispatched;
  dispatched.reserve(keys.size());

  for (auto key : keys)
  {
    if (!mFlow)
    {
      co_return;
    }
    try
    {
      dispatched.push_back(run_group(key.nsIndex, utils::to_underlying(key.kind)));
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      for (const auto classifiedIndex : mFlow->groups.at(key))
      {
        const auto originalIndex = mFlow->classified[classifiedIndex].originalIndex;
        mFlow->response->results()[originalIndex].status_code() = failure;
      }
    }
  }

  // The join IS the barrier. An empty request joins nothing and falls straight through to the
  // answer, which is what the chain needed a separate early-complete branch for.
  for (auto& group : dispatched)
  {
    try
    {
      co_await std::move(group);
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      log_exception(mLogger,
        LogLevel::Error,
        "HistoryUpdateService: a group dispatch's own containment threw",
        ua::exception_to_status_code(std::current_exception()));
    }
  }

  if (mFlow)
  {
    complete_history_update();
  }
  co_return;
}

ua::async::Task<> HistoryUpdateService::run_group(uint16_t namespaceIndex, int kindRaw)
{
  auto kind = static_cast<UpdateKind>(kindRaw);
  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, kind};
  auto& classifiedIndices = flow.groups.at(key);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  shared_ptr<NamespaceHistoryDelegate> delegate;
  if (ns)
  {
    delegate = ns->history_delegate();
  }

  if (!delegate)
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      flow.response->results()[entry.originalIndex].status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  NamespaceHistoryDelegate::UpdateContext context;
  context.cancelled = mCancelled;
  // Pass the session user through so the delegate can record it in each ModificationInfo.userName.
  if (auto sessionInfo = mSessionInfo.lock())
  {
    if (auto* sec = dynamic_cast<const SessionSecurityContext*>(sessionInfo.get()))
    {
      if (auto user = sec->user_identity())
        context.userName = user->userId;
    }
  }

  switch (kind)
  {
  case UpdateKind::UpdateData:
  {
    std::vector<NamespaceHistoryDelegate::UpdateDataItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<UpdateDataDetails*>(entry.details);
      NamespaceHistoryDelegate::UpdateDataItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.performInsertReplace = details->perform_insert_replace();
      item.values.assign(details->update_values().begin(), details->update_values().end());
      items.push_back(std::move(item));
    }
    auto batch =
      co_await await_step<BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult>>([&](auto completion)
        { delegate->update_data_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_update_data_complete(namespaceIndex, std::move(batch));
    break;
  }
  case UpdateKind::UpdateEvent:
  {
    std::vector<NamespaceHistoryDelegate::UpdateEventsItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<UpdateEventDetails*>(entry.details);
      NamespaceHistoryDelegate::UpdateEventsItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.performInsertReplace = details->perform_insert_replace();
      item.filter = details->filter();
      // Only the rows that passed OPC 10000-11 6.8.4.2 are handed over: a row the Server has
      // already refused must not reach the historian, and its siblings must not be held back
      // because of it. `dispatchRows` records the mapping so the historian's answers can be put
      // back in the right places.
      item.events.reserve(entry.dispatchRows.size());
      for (const size_t row : entry.dispatchRows)
      {
        if (row < details->event_data().size())
          item.events.push_back(details->event_data()[row]);
      }
      items.push_back(std::move(item));
    }
    auto batch =
      co_await await_step<BatchResult<NamespaceHistoryDelegate::UpdateEventsItemResult>>([&](auto completion)
        { delegate->update_events_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_update_events_complete(namespaceIndex, std::move(batch));
    break;
  }
  case UpdateKind::UpdateStructureData:
  {
    std::vector<NamespaceHistoryDelegate::UpdateStructureDataItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<UpdateStructureDataDetails*>(entry.details);
      NamespaceHistoryDelegate::UpdateStructureDataItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.performInsertReplace = details->perform_insert_replace();
      item.values.assign(details->update_values().begin(), details->update_values().end());
      items.push_back(std::move(item));
    }
    auto batch = co_await await_step<BatchResult<NamespaceHistoryDelegate::UpdateStructureDataItemResult>>(
      [&](auto completion)
      { delegate->update_structure_data_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_update_structure_data_complete(namespaceIndex, std::move(batch));
    break;
  }
  case UpdateKind::DeleteRaw:
  {
    std::vector<NamespaceHistoryDelegate::DeleteRawItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<DeleteRawModifiedDetails*>(entry.details);
      NamespaceHistoryDelegate::DeleteRawItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.isDeleteModified = details->is_delete_modified();
      item.startTime = details->start_time();
      item.endTime = details->end_time();
      items.push_back(std::move(item));
    }
    auto batch = co_await await_step<BatchResult<NamespaceHistoryDelegate::DeleteItemResult>>(
      [&](auto completion) { delegate->delete_raw_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_delete_raw_complete(namespaceIndex, std::move(batch));
    break;
  }
  case UpdateKind::DeleteAtTime:
  {
    std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<DeleteAtTimeDetails*>(entry.details);
      NamespaceHistoryDelegate::DeleteAtTimeItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.timestamps.assign(details->req_times().begin(), details->req_times().end());
      items.push_back(std::move(item));
    }
    auto batch =
      co_await await_step<BatchResult<NamespaceHistoryDelegate::DeleteItemResult>>([&](auto completion)
        { delegate->delete_at_time_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_delete_at_time_complete(namespaceIndex, std::move(batch));
    break;
  }
  case UpdateKind::DeleteEvent:
  {
    std::vector<NamespaceHistoryDelegate::DeleteEventsItem> items;
    items.reserve(classifiedIndices.size());
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      auto* details = static_cast<DeleteEventDetails*>(entry.details);
      NamespaceHistoryDelegate::DeleteEventsItem item;
      item.index = entry.originalIndex;
      item.nodeId = entry.nodeId;
      item.eventIds.assign(details->event_ids().begin(), details->event_ids().end());
      items.push_back(std::move(item));
    }
    auto batch =
      co_await await_step<BatchResult<NamespaceHistoryDelegate::DeleteItemResult>>([&](auto completion)
        { delegate->delete_events_async(context, std::move(items), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_delete_events_complete(namespaceIndex, std::move(batch));
    break;
  }
  }
  co_return;
}

namespace
{

/// @tparam Results The batch's own item container, taken as a template parameter rather than as
///                 `std::vector`: @ref ua::BatchResult stores small batches inline, and a caller
///                 should not have to know which side of that boundary its batch fell on.
template<typename Results>
void apply_per_item_results(
  HistoryUpdateState& flow, std::vector<size_t>& classifiedIndices, StatusCode batchStatus, Results& results)
{
  if (batchStatus.is_bad())
  {
    for (auto ci : classifiedIndices)
    {
      const auto& entry = flow.classified[ci];
      flow.response->results()[entry.originalIndex].status_code() = batchStatus;
    }
    return;
  }
  for (size_t ri = 0; ri < classifiedIndices.size(); ++ri)
  {
    auto& entry = flow.classified[classifiedIndices[ri]];
    auto& slot = flow.response->results()[entry.originalIndex];
    if (ri >= results.size())
    {
      // A delegate that returns fewer results than items handed to it leaves the surviving
      // items unreported. Surface the contract violation as Bad_InternalError rather than
      // letting the slot keep its default Good - matching the Read / Write / Call delegate
      // services (which raise the same arity-mismatch error).
      slot.status_code() = Status::BadInternalError;
      flow.collector.add_item_detail(entry.originalIndex,
        ErrorDetail::build("DelegateArityMismatch",
          "History delegate returned fewer results than items",
          "HistoryUpdateService")
          .context(ua::ContextKeys::nodeId, ua::to_string(entry.nodeId))
          .context(ua::ContextKeys::expected, std::to_string(classifiedIndices.size()))
          .context(ua::ContextKeys::actual, std::to_string(results.size())));
      continue;
    }
    // The historian's code is the operation's, and its per-row results come with it whatever the code,
    // an Uncertain answer's included.
    slot.status_code() = results[ri].status_code();
    if (results[ri].has_value())
    {
      auto operationResults = std::move(results[ri]).value().operationResults;
      if (entry.rowStatus.empty())
      {
        slot.operation_results().payload() = std::move(operationResults);
      }
      else
      {
        // An Event update dispatched a subset of its rows. The historian answered for those only,
        // in `dispatchRows` order; every other position keeps the verdict validation already
        // reached. A dispatched row that validation passed as Good_DataIgnored keeps that code
        // when the historian is content, because the field it dropped is still dropped.
        for (size_t di = 0; di < entry.dispatchRows.size() && di < operationResults.size(); ++di)
        {
          const size_t row = entry.dispatchRows[di];
          if (row >= entry.rowStatus.size())
            continue;
          const StatusCode fromHistorian = operationResults[di];
          const bool historianIsPlainlyContent =
            fromHistorian.as_uint32() == StatusCode{Status::Good}.as_uint32();
          entry.rowStatus[row] = historianIsPlainlyContent ? entry.rowStatus[row] : fromHistorian;
        }
        slot.operation_results().payload().assign(entry.rowStatus.begin(), entry.rowStatus.end());
      }
    }
  }
}

}  // namespace

void HistoryUpdateService::on_update_data_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::UpdateData};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryValueUpdateEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, UpdateDataDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      auditEvent.updatedNode = entry.nodeId;
      auto* details = static_cast<UpdateDataDetails*>(entry.details);
      auditEvent.performInsertReplace = Variant{utils::as_int32(details->perform_insert_replace())};
      auditEvent.newValues = Variant{details->update_values()};
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::on_update_events_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateEventsItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::UpdateEvent};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryEventUpdateEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, UpdateEventDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      auditEvent.updatedNode = entry.nodeId;
      auto* details = static_cast<UpdateEventDetails*>(entry.details);
      auditEvent.performInsertReplace = Variant{utils::as_int32(details->perform_insert_replace())};
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::on_update_structure_data_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateStructureDataItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::UpdateStructureData};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryAnnotationUpdateEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, UpdateStructureDataDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      // AuditHistoryAnnotationUpdateEventType has no UpdatedNode field (only PerformInsertReplace /
      // NewValues / OldValues); the affected node is reported via SourceNode.
      auto* details = static_cast<UpdateStructureDataDetails*>(entry.details);
      auditEvent.performInsertReplace = Variant{utils::as_int32(details->perform_insert_replace())};
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::on_delete_raw_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::DeleteRaw};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryRawModifyDeleteEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, DeleteRawModifiedDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      auditEvent.updatedNode = entry.nodeId;
      auto* details = static_cast<DeleteRawModifiedDetails*>(entry.details);
      auditEvent.isDeleteModified = details->is_delete_modified();
      auditEvent.startTime = Variant{details->start_time()};
      auditEvent.endTime = Variant{details->end_time()};
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::on_delete_at_time_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::DeleteAtTime};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryAtTimeDeleteEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, DeleteAtTimeDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      auditEvent.updatedNode = entry.nodeId;
      auto* details = static_cast<DeleteAtTimeDetails*>(entry.details);
      auditEvent.reqTimes = Variant{details->req_times()};
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::on_delete_events_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch)
{
  if (!mFlow)
    return;

  auto& flow = *mFlow;
  const HistoryUpdateState::GroupKey key{namespaceIndex, UpdateKind::DeleteEvent};
  auto& classifiedIndices = flow.groups.at(key);

  apply_per_item_results(flow, classifiedIndices, batch.batchStatus.status_code(), batch.items);

  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (auto ci : classifiedIndices)
    {
      auto& entry = flow.classified[ci];
      AuditHistoryEventDeleteEventPayload auditEvent;
      auditEvent.sourceNode = entry.nodeId;
      fill_history_audit_base(auditEvent,
        *sessionInfo,
        NodeId{uint16_t{0}, DeleteEventDetails::typeId},
        flow.response->results()[entry.originalIndex].status_code(),
        mRequest);
      auditEvent.updatedNode = entry.nodeId;
      auto* details = static_cast<DeleteEventDetails*>(entry.details);
      auditEvent.eventIds = details->event_ids();
      emit_history_audit(sessionInfo, auditEvent);
      entry.auditEmitted = true;
    }
  }
}

void HistoryUpdateService::complete_history_update()
{
  if (!try_finish())
  {
    mFlow.reset();
    return;
  }
  auto& flow = *mFlow;
  if (auto sessionInfo = mSessionInfo.lock())
  {
    for (const auto& entry : flow.classified)
    {
      if (!entry.targetsHistoricalNode || entry.auditEmitted)
        continue;

      const auto& outcome = flow.response->results()[entry.originalIndex].status_code();
      emit_generic_history_audit(sessionInfo, entry, outcome, mRequest);
    }
  }
  const size_t noOfOperations = mRequest.history_update_details().size();
  auto& results = flow.response->results();
  flow.collector.apply_to(
    flow.response->response_header(),
    flow.response->diagnostic_infos(),
    noOfOperations,
    [&results](size_t index) -> Array<DiagnosticInfo>*
    { return index < results.size() ? &results[index].diagnostic_infos() : nullptr; },
    [&results](size_t index)
    { return index < results.size() ? results[index].operation_results().size() : size_t{0}; });
  prepare_response_header(flow.response->response_header());
  auto response = flow.response;
  mFlow.reset();
  mCallback(std::pair(mRequestId, response));
}

void HistoryUpdateService::fail_history_update(VoidResult error)
{
  if (!try_finish())
  {
    mFlow.reset();
    return;
  }
  auto& flow = *mFlow;
  flow.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&mRequest.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  flow.collector.apply_to(serviceFault->response_header(), unused, 0);
  mFlow.reset();
  mCallback(std::pair(mRequestId, serviceFault));
}

void HistoryUpdateService::abort(StatusCode reason)
{
  mCancelled->store(true, std::memory_order_relaxed);

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](HistoryUpdateService& self)
    {
      self.mFlow.reset();
      // Destroying the request's body destroys every body it spawned with it, in order, because
      // they are its frame's own locals.
      self.mRequestTask = {};
      DiagnosticCollector collector{0};
      self.send_service_fault(self.mRequest.request_header(), reason, collector);
    })();
}

void HistoryUpdateService::timeout()
{
  mFlow.reset();
  mRequestTask = {};
  DiagnosticCollector collector{0};
  send_service_fault(mRequest.request_header(), Status::BadTimeout, collector);
}

void HistoryUpdateService::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  mCallback(std::pair(mRequestId, serviceFault));
}

void HistoryUpdateService::prepare_response_header(ResponseHeader& responseHeader)
{
  stack_utils::prepare_response_header(mRequest.request_header(), responseHeader);
}

}  // namespace ua::server
