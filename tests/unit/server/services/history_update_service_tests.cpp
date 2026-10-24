// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_history_at_time_delete_event_payload.h"
#include "ua_audit_history_update_event_payload.h"
#include "ua_audit_history_event_delete_event_payload.h"
#include "ua_audit_history_event_update_event_payload.h"
#include "ua_audit_history_raw_modify_delete_event_payload.h"
#include "ua_audit_history_value_update_event_payload.h"
#include "ua_default_namespace.h"
#include "ua_event_bus.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_event_notifier_type.h"
#include "ua_sinks.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_event_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_history_update_service.h"
#include "ua_node_accessor.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_event_filter.h"
#include "ua_history_event_field_list.h"
#include "ua_history_event_validation.h"
#include "ua_qualified_name.h"
#include "ua_simple_attribute_operand.h"
#include "ua_annotation.h"
#include "ua_update_data_details.h"
#include "ua_update_event_details.h"
#include "ua_update_structure_data_details.h"

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Fake history delegate with configurable update/delete callbacks
// ---------------------------------------------------------------------------
class FakeHistoryUpdateDelegate : public NamespaceHistoryDelegate
{
public:
  using UpdateDataHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::UpdateDataItem>, UpdateDataCallback)>;
  using DeleteRawHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::DeleteRawItem>, DeleteRawCallback)>;
  using DeleteAtTimeHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem>, DeleteAtTimeCallback)>;
  using DeleteEventsHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::DeleteEventsItem>, DeleteEventsCallback)>;
  using UpdateEventsHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::UpdateEventsItem>, UpdateEventsCallback)>;
  using UpdateStructureDataHandler = std::function<void(const NamespaceHistoryDelegate::UpdateContext&,
    std::vector<NamespaceHistoryDelegate::UpdateStructureDataItem>, UpdateStructureDataCallback)>;

  void set_on_update_data(UpdateDataHandler handler)
  {
    mOnUpdateData = std::move(handler);
  }

  void set_on_delete_raw(DeleteRawHandler handler)
  {
    mOnDeleteRaw = std::move(handler);
  }

  void set_on_delete_at_time(DeleteAtTimeHandler handler)
  {
    mOnDeleteAtTime = std::move(handler);
  }

  void set_on_delete_events(DeleteEventsHandler handler)
  {
    mOnDeleteEvents = std::move(handler);
  }

  void set_on_update_events(UpdateEventsHandler handler)
  {
    mOnUpdateEvents = std::move(handler);
  }

  void set_on_update_structure_data(UpdateStructureDataHandler handler)
  {
    mOnUpdateStructureData = std::move(handler);
  }

  void update_data_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override
  {
    if (mOnUpdateData)
    {
      mOnUpdateData(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::update_data_async(context, items, std::move(callback));
  }

  void update_events_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::UpdateEventsItem> items,
    UpdateEventsCallback callback) noexcept override
  {
    if (mOnUpdateEvents)
    {
      mOnUpdateEvents(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::update_events_async(context, items, std::move(callback));
  }

  void update_structure_data_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::UpdateStructureDataItem> items,
    UpdateStructureDataCallback callback) noexcept override
  {
    if (mOnUpdateStructureData)
    {
      mOnUpdateStructureData(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::update_structure_data_async(context, items, std::move(callback));
  }

  void delete_raw_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::DeleteRawItem> items, DeleteRawCallback callback) noexcept override
  {
    if (mOnDeleteRaw)
    {
      mOnDeleteRaw(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::delete_raw_async(context, items, std::move(callback));
  }

  void delete_at_time_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem> items,
    DeleteAtTimeCallback callback) noexcept override
  {
    if (mOnDeleteAtTime)
    {
      mOnDeleteAtTime(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::delete_at_time_async(context, items, std::move(callback));
  }

  void delete_events_async(const NamespaceHistoryDelegate::UpdateContext& context,
    std::vector<NamespaceHistoryDelegate::DeleteEventsItem> items,
    DeleteEventsCallback callback) noexcept override
  {
    if (mOnDeleteEvents)
    {
      mOnDeleteEvents(context, items, std::move(callback));
      return;
    }
    NamespaceHistoryDelegate::delete_events_async(context, items, std::move(callback));
  }

private:
  UpdateDataHandler mOnUpdateData;
  UpdateEventsHandler mOnUpdateEvents;
  UpdateStructureDataHandler mOnUpdateStructureData;
  DeleteRawHandler mOnDeleteRaw;
  DeleteAtTimeHandler mOnDeleteAtTime;
  DeleteEventsHandler mOnDeleteEvents;
};

// ---------------------------------------------------------------------------
// Test namespace that provides a history delegate
// ---------------------------------------------------------------------------
class HistoryUpdateTestNamespace : public default_ns::Namespace,
                                   public std::enable_shared_from_this<HistoryUpdateTestNamespace>
{
public:
  HistoryUpdateTestNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void set_delegate(shared_ptr<FakeHistoryUpdateDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<FakeHistoryUpdateDelegate> mDelegate;
};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------
struct UpdateTestHarness
{
  ~UpdateTestHarness()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  optional<Server> server;
  shared_ptr<HistoryUpdateTestNamespace> ns;
  shared_ptr<FakeHistoryUpdateDelegate> delegate;
  shared_ptr<SessionInfoStub> sessionInfo;
  uint16_t nsIndex{0};

  void setup(bool withDelegate = true, ServerConfig serverConfig = ServerConfig{})
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};

    server.emplace(Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

    ns = make_shared<HistoryUpdateTestNamespace>("uri://history-update-test-ns", threadPool.get_executor());
    if (withDelegate)
    {
      delegate = make_shared<FakeHistoryUpdateDelegate>();
      ns->set_delegate(delegate);
    }
    server->address_space().add_namespace_sync(ns);
    nsIndex = server->address_space().namespace_array().get_namespace_index("uri://history-update-test-ns");

    sessionInfo = make_shared<SessionInfoStub>(std::move(*server), threadPool.get_executor());
    server.reset();
  }

  NodeId create_variable_with_history_write(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      al.set(AccessLevelType::Bit::HistoryRead);
      al.set(AccessLevelType::Bit::HistoryWrite);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  NodeId create_variable_without_history_write(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      al.set(AccessLevelType::Bit::HistoryRead);
      // No HistoryWrite bit
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  Response run_service(HistoryUpdateRequest request)
  {
    // Promise/future handoff instead of a hand-rolled mutex+condition_variable:
    // the shared state is heap-allocated and reference-counted, so there is no
    // stack-local condition_variable for the waiter to destroy while a pool thread
    // is still inside notify_* (the pthread_cond_destroy data race TSan flagged).
    // The promise lives in a shared_ptr because the callback is stored in a
    // copyable std::function and std::promise is move-only.
    auto resultPromise = std::make_shared<std::promise<Response>>();
    auto resultFuture = resultPromise->get_future();

    auto service = HistoryUpdateService::create(sessionInfo,
      0,
      std::move(request),
      threadPool.get_executor(),
      [resultPromise](Response response) { resultPromise->set_value(std::move(response)); });

    if (resultFuture.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Service did not complete within timeout";
      return {};
    }
    return resultFuture.get();
  }
};

bool is_service_fault(const Response& response, StatusCode expected)
{
  auto* fault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response).get());
  return fault && fault->response_header().service_result() == expected;
}

bool has_service_result(const Response& response, StatusCode expected)
{
  auto* structure = std::get<shared_ptr<Structure>>(response).get();
  auto* histResp = dynamic_cast<HistoryUpdateResponse*>(structure);
  if (histResp)
    return histResp->response_header().service_result() == expected;
  auto* fault = dynamic_cast<ServiceFault*>(structure);
  return fault && fault->response_header().service_result() == expected;
}

HistoryUpdateResponse* get_update_response(const Response& response)
{
  return dynamic_cast<HistoryUpdateResponse*>(std::get<shared_ptr<Structure>>(response).get());
}

// A well-formed Event insert for `nodeId`, as OPC 10000-11 6.9.4.2 defines well-formed: the
// selectClause names every field BaseEventType makes Mandatory, no whereClause, no IndexRange, and
// the row carries a value of each field's declared type. Tests whose subject is what the service
// does with an insert - dispatch, auditing, batching - need one that reaches the delegate, so the
// conforming shape is built once here rather than approximated per test.
std::unique_ptr<UpdateEventDetails> conforming_event_insert(
  const NodeId& nodeId, PerformUpdateType mode = PerformUpdateType::Insert)
{
  static constexpr std::array<std::string_view, 8> mandatoryFields{
    "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"};

  auto details = std::make_unique<UpdateEventDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = mode;
  for (const auto& name : mandatoryFields)
  {
    SimpleAttributeOperand operand;
    operand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(QualifiedName{uint16_t{0}, std::string{name}});
    operand.attribute_id() = utils::to_underlying(AttributeId::Value);
    details->filter().select_clauses().push_back(operand);
  }

  const auto when = DateTime::now();
  HistoryEventFieldList record;
  record.event_fields().push_back(Variant{});  // EventId: null asks the Server to generate one
  record.event_fields().push_back(Variant{NodeId{ObjectTypeId::BaseEventType}});
  record.event_fields().push_back(Variant{nodeId});
  record.event_fields().push_back(Variant{String{"history update service tests"}});
  record.event_fields().push_back(Variant{when});
  record.event_fields().push_back(Variant{when});
  record.event_fields().push_back(Variant{LocalizedText{"", "history update service tests"}});
  record.event_fields().push_back(Variant{uint16_t{500}});
  details->event_data().push_back(std::move(record));
  return details;
}

std::unique_ptr<UpdateEventDetails> focused_event_validation_details(NodeId sourceNode)
{
  static constexpr std::array<std::string_view, 3> fields{"EventType", "Time", "SourceNode"};

  auto details = std::make_unique<UpdateEventDetails>();
  details->node_id() = NodeId{uint16_t{1}, uint32_t{9000}};
  details->perform_insert_replace() = PerformUpdateType::Insert;
  for (const auto& name : fields)
  {
    SimpleAttributeOperand operand;
    operand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(QualifiedName{uint16_t{0}, std::string{name}});
    operand.attribute_id() = utils::to_underlying(AttributeId::Value);
    details->filter().select_clauses().push_back(std::move(operand));
  }

  HistoryEventFieldList record;
  record.event_fields().push_back(Variant{NodeId{ObjectTypeId::BaseEventType}});
  record.event_fields().push_back(Variant{DateTime::now()});
  record.event_fields().push_back(Variant{std::move(sourceNode)});
  details->event_data().push_back(std::move(record));
  return details;
}

event_type_model::Declarations focused_event_declarations()
{
  event_type_model::Declarations declarations;
  for (const auto& name :
    {std::string_view{"EventType"}, std::string_view{"Time"}, std::string_view{"SourceNode"}})
  {
    event_type_model::Declaration declaration;
    declaration.browsePath.push_back(QualifiedName{uint16_t{0}, std::string{name}});
    declarations.push_back(std::move(declaration));
  }
  return declarations;
}

}  // namespace

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-01-RICH-RESOLUTION-FAILURES, scope=function)
TEST(HistoryEventValidationTest, EventTypeDeclarationFailurePreservesExactRichResult)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{uint16_t{2}, uint32_t{9001}});

  std::shared_ptr<const ErrorDetail> upstreamDetail = ErrorDetail::build("InjectedEventTypeResolutionFailure",
    "Injected EventType declaration resolution failure",
    "HistoryEventValidationTest");
  const StatusCode sentinel{Status::BadResourceUnavailable, upstreamDetail};
  size_t collectCalls{0};
  size_t findCalls{0};
  size_t completionCalls{0};
  history_event_validation::Outcome outcome;

  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome result)
    {
      ++completionCalls;
      outcome = std::move(result);
    },
    [&](AddressSpace, NodeId, event_type_model::CollectCallback callback)
    {
      ++collectCalls;
      callback(event_type_model::DeclarationsResult{sentinel});
    },
    [&](AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback callback)
    {
      ++findCalls;
      callback(NodeAccessorResult{Status::BadInternalError});
    });

  EXPECT_EQ(collectCalls, 1u);
  EXPECT_EQ(findCalls, 0u);
  EXPECT_EQ(completionCalls, 1u);
  ASSERT_EQ(outcome.rowStatus.size(), 1u);
  EXPECT_EQ(outcome.rowStatus[0].value(), sentinel.value());
  EXPECT_EQ(outcome.rowStatus[0].shared_detail(), upstreamDetail);
}

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-01-RICH-RESOLUTION-FAILURES, scope=function)
TEST(HistoryEventValidationTest, SourceNodeFailureWrapsExactRichCause)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{uint16_t{2}, uint32_t{9002}});

  std::shared_ptr<const ErrorDetail> upstreamDetail = ErrorDetail::build(
    "InjectedSourceNodeFailure", "Injected SourceNode lookup failure", "HistoryEventValidationTest");
  const StatusCode sentinel{Status::BadCommunicationError, upstreamDetail};
  size_t completionCalls{0};
  size_t findCalls{0};
  history_event_validation::Outcome outcome;

  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome result)
    {
      ++completionCalls;
      outcome = std::move(result);
    },
    [](AddressSpace, NodeId, event_type_model::CollectCallback callback)
    { callback(event_type_model::DeclarationsResult{focused_event_declarations()}); },
    [&](AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback callback)
    {
      ++findCalls;
      callback(NodeAccessorResult{sentinel});
    });

  EXPECT_EQ(findCalls, 1u);
  EXPECT_EQ(completionCalls, 1u);
  ASSERT_EQ(outcome.rowStatus.size(), 1u);
  const StatusCode& rowStatus = outcome.rowStatus[0];
  EXPECT_EQ(rowStatus.as_status(), Status::BadSourceNodeIdInvalid);
  ASSERT_NE(rowStatus.shared_detail(), nullptr);
  EXPECT_EQ(rowStatus.shared_detail()->code, "HistoryEventSourceNodeInvalid");
  EXPECT_EQ(rowStatus.shared_detail()->summary, "History Event SourceNode does not refer to a valid node");
  EXPECT_EQ(rowStatus.shared_detail()->source, "HistoryEventValidation");
  EXPECT_EQ(rowStatus.shared_detail()->innerStatus, sentinel.value());
  EXPECT_EQ(rowStatus.shared_detail()->cause, upstreamDetail);
}

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-01-RICH-RESOLUTION-FAILURES, scope=function)
TEST(HistoryEventValidationTest, NullSourceNodeRemainsSuccessfulWithoutLookup)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{});

  size_t completionCalls{0};
  size_t findCalls{0};
  history_event_validation::Outcome outcome;

  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome result)
    {
      ++completionCalls;
      outcome = std::move(result);
    },
    [](AddressSpace, NodeId, event_type_model::CollectCallback callback)
    { callback(event_type_model::DeclarationsResult{focused_event_declarations()}); },
    [&](AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback callback)
    {
      ++findCalls;
      callback(NodeAccessorResult{Status::BadInternalError});
    });

  EXPECT_EQ(findCalls, 0u);
  EXPECT_EQ(completionCalls, 1u);
  EXPECT_TRUE(outcome.detailStatus.is_good());
  ASSERT_EQ(outcome.rowStatus.size(), 1u);
  EXPECT_TRUE(outcome.rowStatus[0].is_good());
}

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-02-THROWING-DEPENDENCIES, scope=function)
TEST(HistoryEventValidationTest, ThrowingEventTypeHookCompletesOnceWithRichFailure)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{uint16_t{2}, uint32_t{9003}});

  std::shared_ptr<const ErrorDetail> upstreamDetail =
    ErrorDetail::build("ThrowingEventTypeHook", "EventType hook threw", "HistoryEventValidationTest");
  const StatusCode sentinel{Status::BadResourceUnavailable, upstreamDetail};
  size_t completionCalls{0};
  history_event_validation::Outcome outcome;

  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome result)
    {
      ++completionCalls;
      outcome = std::move(result);
    },
    [sentinel](AddressSpace, NodeId, event_type_model::CollectCallback) { throw UaException{sentinel}; },
    {});

  EXPECT_EQ(completionCalls, 1u);
  ASSERT_EQ(outcome.rowStatus.size(), 1u);
  EXPECT_EQ(outcome.rowStatus[0].value(), sentinel.value());
  EXPECT_EQ(outcome.rowStatus[0].shared_detail(), upstreamDetail);
}

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-02-THROWING-DEPENDENCIES, scope=function)
TEST(HistoryEventValidationTest, ThrowingSourceNodeHookWrapsExactRichCause)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{uint16_t{2}, uint32_t{9004}});

  std::shared_ptr<const ErrorDetail> upstreamDetail =
    ErrorDetail::build("ThrowingSourceNodeHook", "SourceNode hook threw", "HistoryEventValidationTest");
  const StatusCode sentinel{Status::BadCommunicationError, upstreamDetail};
  size_t completionCalls{0};
  history_event_validation::Outcome outcome;

  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome result)
    {
      ++completionCalls;
      outcome = std::move(result);
    },
    [](AddressSpace, NodeId, event_type_model::CollectCallback callback)
    { callback(event_type_model::DeclarationsResult{focused_event_declarations()}); },
    [sentinel](AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback)
    { throw UaException{sentinel}; });

  EXPECT_EQ(completionCalls, 1u);
  ASSERT_EQ(outcome.rowStatus.size(), 1u);
  const StatusCode& rowStatus = outcome.rowStatus[0];
  EXPECT_EQ(rowStatus.as_status(), Status::BadSourceNodeIdInvalid);
  ASSERT_NE(rowStatus.shared_detail(), nullptr);
  EXPECT_EQ(rowStatus.shared_detail()->innerStatus, sentinel.value());
  EXPECT_EQ(rowStatus.shared_detail()->cause, upstreamDetail);
}

// @relation(AC-COMP-SVR-HISTORY-EVENT-VALIDATION-02-CALLBACK-CONTAINMENT, scope=function)
TEST(HistoryEventValidationTest, ThrowingCompletionIsContainedAndNotRetried)
{
  UpdateTestHarness harness;
  harness.setup(false);
  auto details = focused_event_validation_details(NodeId{});

  size_t completionCalls{0};
  size_t findCalls{0};
  history_event_validation::validate_async(
    harness.sessionInfo->address_space(),
    *details,
    [&](history_event_validation::Outcome)
    {
      ++completionCalls;
      throw std::runtime_error{"injected completion failure"};
    },
    [](AddressSpace, NodeId, event_type_model::CollectCallback callback)
    { callback(event_type_model::DeclarationsResult{focused_event_declarations()}); },
    [&](AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback callback)
    {
      ++findCalls;
      callback(NodeAccessorResult{Status::BadInternalError});
    });

  EXPECT_EQ(findCalls, 0u);
  EXPECT_EQ(completionCalls, 1u);
}

// ---------------------------------------------------------------------------
// Test 1: Empty request returns BadNothingToDo
// ---------------------------------------------------------------------------
// @relation(AC-SVR-ATTR-HUPD-001-NOTHINGTODO, scope=function)
TEST(HistoryUpdateServiceTests, EmptyRequestReturnsBadNothingToDo)
{
  UpdateTestHarness h;
  h.setup();

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  // history_update_details is empty

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result, Status::BadNothingToDo));
}

// ---------------------------------------------------------------------------
// Test 2: UpdateData dispatches to delegate and returns results
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, UpdateDataDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(100);

  // Capture the items received by the delegate.
  struct CapturedItem
  {
    NodeId nodeId;
    PerformUpdateType performInsertReplace;
    std::vector<DataValue> values;
  };

  std::mutex captureMtx;
  std::vector<CapturedItem> capturedItems;

  h.delegate->set_on_update_data(
    [&captureMtx, &capturedItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
        {
          CapturedItem ci;
          ci.nodeId = item.nodeId;
          ci.performInsertReplace = item.performInsertReplace;
          ci.values = item.values;
          capturedItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        // One operation result per value
        for (size_t vi = 0; vi < item.values.size(); ++vi)
        {
          success.operationResults.push_back(Status::Good);
        }
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  DataValue dv;
  dv.value() = 42;
  updateDetails->update_values().resize(1);
  updateDetails->update_values()[0] = std::move(dv);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  ASSERT_EQ(response->results()[0].operation_results().size(), 1u);
  EXPECT_TRUE(response->results()[0].operation_results()[0].is_good());

  // Verify delegate received correct parameters.
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(capturedItems.size(), 1u);
    EXPECT_EQ(capturedItems[0].nodeId, nodeId);
    EXPECT_EQ(capturedItems[0].performInsertReplace, PerformUpdateType::Insert);
    ASSERT_EQ(capturedItems[0].values.size(), 1u);
    EXPECT_EQ(capturedItems[0].values[0].value().as<int32_t>(), 42);
  }
}

// An Uncertain answer holding the per-value results is the operation's code, with those results.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-HISTORY-UPDATE-PASSES-AN-UNCERTAIN-ANSWER-WITH-ITS-RESULTS, scope=function)
TEST(HistoryUpdateServiceTests, AnUncertainAnswerIsAnsweredWithItsOperationResults)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(100);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
        {
          success.operationResults.push_back(Status::GoodEntryReplaced);
        }
        batch.items.emplace_back(std::move(success), StatusCode{Status::UncertainDataSubNormal});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Replace;
  DataValue dv;
  dv.value() = 42;
  updateDetails->update_values().resize(1);
  updateDetails->update_values()[0] = std::move(dv);
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code().as_status(), Status::UncertainDataSubNormal);
  ASSERT_EQ(response->results()[0].operation_results().size(), 1u)
    << "the historian's per-value results were dropped";
  EXPECT_EQ(response->results()[0].operation_results()[0].as_status(), Status::GoodEntryReplaced);
}

// UpdateEventDetails is classified and dispatched to the delegate's update_events_async.
TEST(HistoryUpdateServiceTests, UpdateEventDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(101);

  struct CapturedEventItem
  {
    NodeId nodeId;
    PerformUpdateType performInsertReplace;
    size_t eventCount;
  };

  std::mutex captureMtx;
  std::vector<CapturedEventItem> captured;

  h.delegate->set_on_update_events(
    [&captureMtx, &captured](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateEventsItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
          captured.push_back(CapturedEventItem{item.nodeId, item.performInsertReplace, item.events.size()});
      }

      BatchResult<NamespaceHistoryDelegate::UpdateEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t ei = 0; ei < item.events.size(); ++ei)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = conforming_event_insert(nodeId);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  ASSERT_EQ(response->results()[0].operation_results().size(), 1u);
  EXPECT_TRUE(response->results()[0].operation_results()[0].is_good());

  std::lock_guard lock(captureMtx);
  ASSERT_EQ(captured.size(), 1u);
  EXPECT_EQ(captured[0].nodeId, nodeId);
  EXPECT_EQ(captured[0].performInsertReplace, PerformUpdateType::Insert);
  EXPECT_EQ(captured[0].eventCount, 1u);
}

// UpdateStructureDataDetails (Annotations) is classified and dispatched to update_structure_data_async.
TEST(HistoryUpdateServiceTests, UpdateStructureDataDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(102);

  struct CapturedStructItem
  {
    NodeId nodeId;
    PerformUpdateType performInsertReplace;
    size_t valueCount;
  };

  std::mutex captureMtx;
  std::vector<CapturedStructItem> captured;

  h.delegate->set_on_update_structure_data(
    [&captureMtx, &captured](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateStructureDataItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
          captured.push_back(CapturedStructItem{item.nodeId, item.performInsertReplace, item.values.size()});
      }

      BatchResult<NamespaceHistoryDelegate::UpdateStructureDataItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::GoodEntryInserted);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateStructureDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  Annotation annotation;
  annotation.message() = String{"note"};
  DataValue dv{Variant{std::move(annotation)}};
  dv.source_timestamp() = DateTime::now();
  updateDetails->update_values().push_back(std::move(dv));

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  ASSERT_EQ(response->results()[0].operation_results().size(), 1u);
  EXPECT_TRUE(response->results()[0].operation_results()[0].is_good());

  std::lock_guard lock(captureMtx);
  ASSERT_EQ(captured.size(), 1u);
  EXPECT_EQ(captured[0].nodeId, nodeId);
  EXPECT_EQ(captured[0].performInsertReplace, PerformUpdateType::Insert);
  EXPECT_EQ(captured[0].valueCount, 1u);
}

// ---------------------------------------------------------------------------
// Test 3: DeleteRaw dispatches to delegate
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, DeleteRawDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(101);

  // Capture the items received by the delegate.
  struct CapturedDeleteItem
  {
    NodeId nodeId;
    DateTime startTime;
    DateTime endTime;
    bool isDeleteModified;
  };

  std::mutex captureMtx;
  std::vector<CapturedDeleteItem> capturedItems;

  h.delegate->set_on_delete_raw(
    [&captureMtx, &capturedItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
        {
          CapturedDeleteItem ci;
          ci.nodeId = item.nodeId;
          ci.startTime = item.startTime;
          ci.endTime = item.endTime;
          ci.isDeleteModified = item.isDeleteModified;
          capturedItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteRawModifiedDetails>();
  deleteDetails->node_id() = nodeId;
  deleteDetails->is_delete_modified() = false;
  DateTime expectedEndTime = DateTime::now();
  DateTime expectedStartTime{expectedEndTime.value() - std::chrono::hours{1}};
  deleteDetails->start_time() = expectedStartTime;
  deleteDetails->end_time() = expectedEndTime;

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  // Verify delegate received correct parameters.
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(capturedItems.size(), 1u);
    EXPECT_EQ(capturedItems[0].nodeId, nodeId);
    EXPECT_EQ(capturedItems[0].startTime, expectedStartTime);
    EXPECT_EQ(capturedItems[0].endTime, expectedEndTime);
    EXPECT_EQ(capturedItems[0].isDeleteModified, false);
  }
}

// ---------------------------------------------------------------------------
// Test 5: Variable without HistoryWrite access level returns BadNotWritable
// ---------------------------------------------------------------------------
// @relation(AC-SVR-ATTR-HUPD-003-HISTORY-NOTWRITABLE, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST(HistoryUpdateServiceTests, AccessLevelWithoutHistoryWriteReturnsBadNotWritable)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_without_history_write(103);

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadNotWritable});
}

// ---------------------------------------------------------------------------
// Fake event sink for audit event tests
// ---------------------------------------------------------------------------
struct CapturedAuditEvent
{
  // BaseEvent fields
  NodeId eventType;
  NodeId sourceNode;
  String sourceName;
  uint16_t severity{0};

  // AuditEventPayload fields
  bool status{false};
  String serverId;
  String clientAuditEntryId;
  String clientUserId;

  // AuditHistoryUpdateEventPayload fields
  NodeId parameterDataTypeId;

  // AuditHistoryValueUpdateEventPayload fields (optional -- only set for value updates)
  std::optional<NodeId> updatedNode;
  std::optional<int32_t> performInsertReplace;

  // AuditHistoryRawModifyDeleteEventPayload fields (optional)
  std::optional<bool> isDeleteModified;
  std::optional<DateTime> startTime;
  std::optional<DateTime> endTime;
};

class FakeEventBus : public EventBus
{
public:
  explicit FakeEventBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    std::lock_guard lock(mMutex);
    CapturedAuditEvent captured;
    captured.eventType = event.eventType;
    captured.sourceNode = event.sourceNode;
    captured.sourceName = event.sourceName;
    captured.severity = event.severity;

    if (auto* audit = dynamic_cast<AuditEventPayload*>(&event))
    {
      captured.status = audit->status;
      captured.serverId = audit->serverId;
      captured.clientAuditEntryId = audit->clientAuditEntryId;
      captured.clientUserId = audit->clientUserId;
    }

    if (auto* histUpdate = dynamic_cast<AuditHistoryUpdateEventPayload*>(&event))
    {
      captured.parameterDataTypeId = histUpdate->parameterDataTypeId;
    }

    if (auto* valueUpdate = dynamic_cast<AuditHistoryValueUpdateEventPayload*>(&event))
    {
      captured.updatedNode = valueUpdate->updatedNode;
      if (!valueUpdate->performInsertReplace.empty())
        captured.performInsertReplace = valueUpdate->performInsertReplace.as<int32_t>();
    }

    if (auto* rawDelete = dynamic_cast<AuditHistoryRawModifyDeleteEventPayload*>(&event))
    {
      captured.updatedNode = rawDelete->updatedNode;
      captured.isDeleteModified = rawDelete->isDeleteModified;
      if (!rawDelete->startTime.empty())
        captured.startTime = rawDelete->startTime.as<DateTime>();
      if (!rawDelete->endTime.empty())
        captured.endTime = rawDelete->endTime.as<DateTime>();
    }

    if (auto* atTimeDelete = dynamic_cast<AuditHistoryAtTimeDeleteEventPayload*>(&event))
    {
      captured.updatedNode = atTimeDelete->updatedNode;
    }

    if (auto* eventDelete = dynamic_cast<AuditHistoryEventDeleteEventPayload*>(&event))
    {
      captured.updatedNode = eventDelete->updatedNode;
    }

    mEvents.push_back(std::move(captured));
  }

  std::vector<CapturedAuditEvent> events()
  {
    std::lock_guard lock(mMutex);
    return mEvents;
  }

private:
  std::mutex mMutex;
  std::vector<CapturedAuditEvent> mEvents;
};

// A resolved HistoricalNode still constitutes a failed HistoryUpdate invocation when its namespace
// has no historian. The operation-level Bad_HistoryOperationUnsupported and the audit Status false
// must come from the same final response StatusCode; no parallel failure argument is involved.
// @relation(AC-SVR-ATTR-HUPD-005-UNSUPPORTED, AC-SVR-EVT-AUD-015-WRITE-AUDIT-BOTH, scope=function)
TEST(HistoryUpdateServiceTests, NoDelegateFailureRaisesAudit)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(false, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(102);

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});

  const auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "the refused HistoryUpdate invocation raised no audit Event";
  EXPECT_FALSE(events[0].status);
  EXPECT_EQ(events[0].sourceNode, nodeId);
  EXPECT_EQ(events[0].parameterDataTypeId, NodeId(uint16_t{0}, UpdateDataDetails::typeId));
}

// ---------------------------------------------------------------------------
// Test 6: Audit event emitted for UpdateData
// ---------------------------------------------------------------------------
// Covers SVR-ATTR-HUPD-007, SVR-ATTR-HUPD-013, SVR-EVT-AUD-017, SVR-HIST-AUDIT-001 (coverage-audit retag).
// @verifies AC-SVR-ATTR-HUPD-007-AUDIT-EVENT
TEST(HistoryUpdateServiceTests, AuditEventEmittedForUpdateData)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  // Register a dummy listener so has_event_interest() returns true.
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(200);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().audit_entry_id() = "test-audit-entry-123";

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  DataValue dv;
  dv.value() = 42;
  updateDetails->update_values().resize(1);
  updateDetails->update_values()[0] = std::move(dv);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u);

  // Verify correct event type
  AuditHistoryValueUpdateEventPayload expectedType;
  EXPECT_EQ(events[0].eventType, expectedType.eventType);
  // Verify source_name per spec Part 5 section 6.4.24
  EXPECT_EQ(events[0].sourceName, "Attribute/HistoryUpdate");
  // Verify source_node
  EXPECT_EQ(events[0].sourceNode, nodeId);
  // Verify severity
  EXPECT_EQ(events[0].severity, 1);
  // Verify status
  EXPECT_TRUE(events[0].status);
  // Verify parameter_data_type_id
  EXPECT_EQ(events[0].parameterDataTypeId, NodeId(uint16_t{0}, UpdateDataDetails::typeId));
  // Verify updated_node
  ASSERT_TRUE(events[0].updatedNode.has_value());
  EXPECT_EQ(*events[0].updatedNode, nodeId);
  // Verify perform_insert_replace
  ASSERT_TRUE(events[0].performInsertReplace.has_value());
  EXPECT_EQ(*events[0].performInsertReplace, static_cast<int32_t>(PerformUpdateType::Insert));
  // Verify server_id is populated
  EXPECT_FALSE(events[0].serverId.empty());
  // Verify client_user_id from session
  EXPECT_EQ(events[0].clientUserId, "test");
  // Verify client_audit_entry_id propagated from request
  EXPECT_EQ(events[0].clientAuditEntryId, "test-audit-entry-123");
}

// ---------------------------------------------------------------------------
// Test 7: No audit event when auditing is disabled
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, NoAuditEventWhenAuditingDisabled)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = false;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(201);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  h.run_service(std::move(request));

  EXPECT_EQ(eventBus.events().size(), 0u);
}

// ---------------------------------------------------------------------------
// Test 8: Audit event emitted for DeleteRaw
// ---------------------------------------------------------------------------
// Covers SVR-ATTR-HUPD-010, SVR-HIST-AUDIT-003, SVR-HIST-AUDIT-004 (coverage-audit retag).
TEST(HistoryUpdateServiceTests, AuditEventEmittedForDeleteRaw)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(202);

  h.delegate->set_on_delete_raw(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteRawModifiedDetails>();
  deleteDetails->node_id() = nodeId;
  deleteDetails->is_delete_modified() = false;
  const DateTime endTime = DateTime::now();
  deleteDetails->start_time() = DateTime{endTime.value() - std::chrono::hours{1}};
  deleteDetails->end_time() = endTime;

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u);

  // Verify correct event type
  AuditHistoryRawModifyDeleteEventPayload expectedType;
  EXPECT_EQ(events[0].eventType, expectedType.eventType);
  // Verify source_name per spec Part 5 section 6.4.24
  EXPECT_EQ(events[0].sourceName, "Attribute/HistoryUpdate");
  // Verify source_node
  EXPECT_EQ(events[0].sourceNode, nodeId);
  // Verify severity
  EXPECT_EQ(events[0].severity, 1);
  // Verify status
  EXPECT_TRUE(events[0].status);
  // Verify parameter_data_type_id
  EXPECT_EQ(events[0].parameterDataTypeId, NodeId(uint16_t{0}, DeleteRawModifiedDetails::typeId));
  // Verify updated_node
  ASSERT_TRUE(events[0].updatedNode.has_value());
  EXPECT_EQ(*events[0].updatedNode, nodeId);
  // Verify is_delete_modified
  ASSERT_TRUE(events[0].isDeleteModified.has_value());
  EXPECT_FALSE(*events[0].isDeleteModified);
  // Verify start_time and end_time are set
  ASSERT_TRUE(events[0].startTime.has_value());
  ASSERT_TRUE(events[0].endTime.has_value());
  // Verify server_id is populated
  EXPECT_FALSE(events[0].serverId.empty());
  // Verify client_user_id from session
  EXPECT_EQ(events[0].clientUserId, "test");
}

// ---------------------------------------------------------------------------
// Test 9: Audit event emitted for DeleteAtTime
// ---------------------------------------------------------------------------
// Covers SVR-ATTR-HUPD-011, SVR-HIST-AUDIT-005 (coverage-audit retag).
// @verifies AC-SVR-ATTR-HUPD-011-ATTIME-DELETE-AUDIT
TEST(HistoryUpdateServiceTests, AuditEventEmittedForDeleteAtTime)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(203);

  h.delegate->set_on_delete_at_time(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteAtTimeDetails>();
  deleteDetails->node_id() = nodeId;
  deleteDetails->req_times().push_back(DateTime::now());

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u);

  // Verify correct event type
  AuditHistoryAtTimeDeleteEventPayload expectedType;
  EXPECT_EQ(events[0].eventType, expectedType.eventType);
  // Verify source_name per spec Part 5 section 6.4.24
  EXPECT_EQ(events[0].sourceName, "Attribute/HistoryUpdate");
  // Verify source_node
  EXPECT_EQ(events[0].sourceNode, nodeId);
  // Verify severity
  EXPECT_EQ(events[0].severity, 1);
  // Verify status
  EXPECT_TRUE(events[0].status);
  // Verify parameter_data_type_id
  EXPECT_EQ(events[0].parameterDataTypeId, NodeId(uint16_t{0}, DeleteAtTimeDetails::typeId));
  // Verify updated_node
  ASSERT_TRUE(events[0].updatedNode.has_value());
  EXPECT_EQ(*events[0].updatedNode, nodeId);
  // Verify server_id is populated
  EXPECT_FALSE(events[0].serverId.empty());
  // Verify client_user_id from session
  EXPECT_EQ(events[0].clientUserId, "test");
}

// ---------------------------------------------------------------------------
// Test 10: Audit event emitted for DeleteEvent
// ---------------------------------------------------------------------------
// Covers SVR-ATTR-HUPD-012, SVR-HIST-AUDIT-006 (coverage-audit retag).
// @verifies AC-SVR-ATTR-HUPD-012-EVENT-DELETE-AUDIT
TEST(HistoryUpdateServiceTests, AuditEventEmittedForDeleteEvent)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  // DeleteEvent targets Object nodes with EventNotifier HistoryWrite bit set.
  NodeId nodeId{h.nsIndex, uint32_t{204}};
  {
    auto as = h.sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    ASSERT_TRUE(objResult.is_good()) << "Failed to create object node";
    EventNotifierType en;
    en.set(EventNotifierType::Bit::HistoryWrite);
    objResult.value().set_event_notifier(en);
  }

  h.delegate->set_on_delete_events(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteEventsItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteEventDetails>();
  deleteDetails->node_id() = nodeId;
  deleteDetails->event_ids().push_back(ByteString{});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u);

  // Verify correct event type
  AuditHistoryEventDeleteEventPayload expectedType;
  EXPECT_EQ(events[0].eventType, expectedType.eventType);
  // Verify source_name per spec Part 5 section 6.4.24
  EXPECT_EQ(events[0].sourceName, "Attribute/HistoryUpdate");
  // Verify source_node
  EXPECT_EQ(events[0].sourceNode, nodeId);
  // Verify severity
  EXPECT_EQ(events[0].severity, 1);
  // Verify status
  EXPECT_TRUE(events[0].status);
  // Verify parameter_data_type_id
  EXPECT_EQ(events[0].parameterDataTypeId, NodeId(uint16_t{0}, DeleteEventDetails::typeId));
  // Verify updated_node
  ASSERT_TRUE(events[0].updatedNode.has_value());
  EXPECT_EQ(*events[0].updatedNode, nodeId);
  // Verify server_id is populated
  EXPECT_FALSE(events[0].serverId.empty());
  // Verify client_user_id from session
  EXPECT_EQ(events[0].clientUserId, "test");
}

// ---------------------------------------------------------------------------
// Test 11: Audit event emitted on failure
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, AuditEventEmittedOnFailure)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(210);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        // Delegate reports failure
        batch.items.emplace_back(StatusCode{Status::BadTypeMismatch});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_bad());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "Audit event must be emitted on failure";
  EXPECT_FALSE(events[0].status) << "Audit Status must be false on failure";
  EXPECT_EQ(events[0].sourceNode, nodeId);
  EXPECT_EQ(events[0].sourceName, "Attribute/HistoryUpdate");
  EXPECT_EQ(events[0].severity, 1);
  EXPECT_FALSE(events[0].serverId.empty());
  EXPECT_EQ(events[0].clientUserId, "test");
}

// ---------------------------------------------------------------------------
// Test 12: Audit event per item (multi-item produces multi-event)
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, AuditEventPerItem)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FakeEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId1 = h.create_variable_with_history_write(220);
  auto nodeId2 = h.create_variable_with_history_write(221);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);

  size_t idx = 0;
  for (const auto& nid : {nodeId1, nodeId2})
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = nid;
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
    request.history_update_details()[idx++] = std::move(details);
  }

  h.run_service(std::move(request));

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 2u) << "One audit event per item";
  // Both nodes should appear as source_node in the audit events (order may vary).
  bool foundNode1 = false;
  bool foundNode2 = false;
  for (const auto& ev : events)
  {
    if (ev.sourceNode == nodeId1)
      foundNode1 = true;
    if (ev.sourceNode == nodeId2)
      foundNode2 = true;
    // All events should have correct source_name
    EXPECT_EQ(ev.sourceName, "Attribute/HistoryUpdate");
  }
  EXPECT_TRUE(foundNode1) << "Audit event for nodeId1 not found";
  EXPECT_TRUE(foundNode2) << "Audit event for nodeId2 not found";
}

// ---------------------------------------------------------------------------
// Test 13: DeleteAtTime dispatches to delegate
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, DeleteAtTimeDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(300);

  struct CapturedDeleteAtTimeItem
  {
    NodeId nodeId;
    std::vector<DateTime> timestamps;
  };

  std::mutex captureMtx;
  std::vector<CapturedDeleteAtTimeItem> capturedItems;

  h.delegate->set_on_delete_at_time(
    [&captureMtx, &capturedItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
        {
          CapturedDeleteAtTimeItem ci;
          ci.nodeId = item.nodeId;
          ci.timestamps = item.timestamps;
          capturedItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteAtTimeDetails>();
  deleteDetails->node_id() = nodeId;
  DateTime ts1 = DateTime::now();
  DateTime ts2 = DateTime::now();
  deleteDetails->req_times().push_back(ts1);
  deleteDetails->req_times().push_back(ts2);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  // Verify delegate received correct parameters.
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(capturedItems.size(), 1u);
    EXPECT_EQ(capturedItems[0].nodeId, nodeId);
    ASSERT_EQ(capturedItems[0].timestamps.size(), 2u);
    EXPECT_EQ(capturedItems[0].timestamps[0], ts1);
    EXPECT_EQ(capturedItems[0].timestamps[1], ts2);
  }
}

// ---------------------------------------------------------------------------
// Test 14: DeleteEvent dispatches to delegate
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, DeleteEventDispatchesToDelegate)
{
  UpdateTestHarness h;
  h.setup();

  // DeleteEvent targets Object nodes with EventNotifier HistoryWrite bit set.
  NodeId nodeId{h.nsIndex, uint32_t{301}};
  {
    auto as = h.sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    ASSERT_TRUE(objResult.is_good()) << "Failed to create object node";
    EventNotifierType en;
    en.set(EventNotifierType::Bit::HistoryWrite);
    objResult.value().set_event_notifier(en);
  }

  struct CapturedDeleteEventsItem
  {
    NodeId nodeId;
    std::vector<ByteString> eventIds;
  };

  std::mutex captureMtx;
  std::vector<CapturedDeleteEventsItem> capturedItems;

  h.delegate->set_on_delete_events(
    [&captureMtx, &capturedItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteEventsItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
        {
          CapturedDeleteEventsItem ci;
          ci.nodeId = item.nodeId;
          ci.eventIds = item.eventIds;
          capturedItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto deleteDetails = std::make_unique<DeleteEventDetails>();
  deleteDetails->node_id() = nodeId;
  ByteString evId1{0x01, 0x02, 0x03};
  ByteString evId2{0x04, 0x05, 0x06};
  deleteDetails->event_ids().push_back(evId1);
  deleteDetails->event_ids().push_back(evId2);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  // Verify delegate received correct parameters.
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(capturedItems.size(), 1u);
    EXPECT_EQ(capturedItems[0].nodeId, nodeId);
    ASSERT_EQ(capturedItems[0].eventIds.size(), 2u);
    EXPECT_EQ(capturedItems[0].eventIds[0], evId1);
    EXPECT_EQ(capturedItems[0].eventIds[1], evId2);
  }
}

// ---------------------------------------------------------------------------
// Test 15: BadNodeIdUnknown for non-existent node
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, BadNodeIdUnknown)
{
  UpdateTestHarness h;
  h.setup();

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = NodeId{h.nsIndex, uint32_t{99999}};
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadNodeIdUnknown});
}

// ---------------------------------------------------------------------------
// Test 16: TooManyOperations returns BadTooManyOperations
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HUPD-002, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST(HistoryUpdateServiceTests, TooManyOperationsReturnsBadTooManyOperations)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.server_capabilities().operationLimits.maxNodesPerHistoryUpdateData = 2;
  h.setup(true, std::move(serverConfig));

  auto nodeId1 = h.create_variable_with_history_write(400);
  auto nodeId2 = h.create_variable_with_history_write(401);
  auto nodeId3 = h.create_variable_with_history_write(402);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(3);

  uint32_t idx = 0;
  for (const auto& nid : {nodeId1, nodeId2, nodeId3})
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = nid;
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
    request.history_update_details()[idx++] = std::move(details);
  }

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result, Status::BadTooManyOperations));
}

// ---------------------------------------------------------------------------
// Test 17: Null details entry returns BadHistoryOperationInvalid
// ---------------------------------------------------------------------------
// @relation(AC-SVR-ATTR-HUPD-004-DETAILS-INVALID, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST(HistoryUpdateServiceTests, NullDetailsEntryReturnsBadHistoryOperationInvalid)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(500);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);

  // First entry: valid UpdateDataDetails
  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
  request.history_update_details()[0] = std::move(updateDetails);

  // Second entry: left as null/empty (default-constructed RefStructure)

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  // First entry should succeed
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  // Second entry (null) should return BadHistoryOperationInvalid
  EXPECT_EQ(response->results()[1].status_code(), StatusCode{Status::BadHistoryOperationInvalid});
}

// ---------------------------------------------------------------------------
// Test 18: Mixed operation types in a single request
// ---------------------------------------------------------------------------
TEST(HistoryUpdateServiceTests, MixedOperationTypes)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeIdUpdate = h.create_variable_with_history_write(600);
  auto nodeIdDelete = h.create_variable_with_history_write(601);

  // Capture UpdateData items
  struct CapturedUpdateItem
  {
    NodeId nodeId;
    PerformUpdateType performInsertReplace;
    std::vector<DataValue> values;
  };

  std::mutex updateCaptureMtx;
  std::vector<CapturedUpdateItem> capturedUpdateItems;

  h.delegate->set_on_update_data(
    [&updateCaptureMtx, &capturedUpdateItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(updateCaptureMtx);
        for (const auto& item : items)
        {
          CapturedUpdateItem ci;
          ci.nodeId = item.nodeId;
          ci.performInsertReplace = item.performInsertReplace;
          ci.values = item.values;
          capturedUpdateItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // Capture DeleteRaw items
  struct CapturedDeleteItem
  {
    NodeId nodeId;
    DateTime startTime;
    DateTime endTime;
    bool isDeleteModified;
  };

  std::mutex deleteCaptureMtx;
  std::vector<CapturedDeleteItem> capturedDeleteItems;

  h.delegate->set_on_delete_raw(
    [&deleteCaptureMtx, &capturedDeleteItems](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(deleteCaptureMtx);
        for (const auto& item : items)
        {
          CapturedDeleteItem ci;
          ci.nodeId = item.nodeId;
          ci.startTime = item.startTime;
          ci.endTime = item.endTime;
          ci.isDeleteModified = item.isDeleteModified;
          capturedDeleteItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);

  // First entry: UpdateDataDetails
  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeIdUpdate;
  updateDetails->perform_insert_replace() = PerformUpdateType::Replace;
  DataValue dv;
  dv.value() = 99;
  updateDetails->update_values().resize(1);
  updateDetails->update_values()[0] = std::move(dv);
  request.history_update_details()[0] = std::move(updateDetails);

  // Second entry: DeleteRawModifiedDetails
  auto deleteDetails = std::make_unique<DeleteRawModifiedDetails>();
  deleteDetails->node_id() = nodeIdDelete;
  deleteDetails->is_delete_modified() = true;
  DateTime expectedEndTime = DateTime::now();
  DateTime expectedStartTime{expectedEndTime.value() - std::chrono::hours{1}};
  deleteDetails->start_time() = expectedStartTime;
  deleteDetails->end_time() = expectedEndTime;
  request.history_update_details()[1] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_TRUE(response->results()[1].status_code().is_good());

  // Verify UpdateData delegate received correct parameters.
  {
    std::lock_guard lock(updateCaptureMtx);
    ASSERT_EQ(capturedUpdateItems.size(), 1u);
    EXPECT_EQ(capturedUpdateItems[0].nodeId, nodeIdUpdate);
    EXPECT_EQ(capturedUpdateItems[0].performInsertReplace, PerformUpdateType::Replace);
    ASSERT_EQ(capturedUpdateItems[0].values.size(), 1u);
    EXPECT_EQ(capturedUpdateItems[0].values[0].value().as<int32_t>(), 99);
  }

  // Verify DeleteRaw delegate received correct parameters.
  {
    std::lock_guard lock(deleteCaptureMtx);
    ASSERT_EQ(capturedDeleteItems.size(), 1u);
    EXPECT_EQ(capturedDeleteItems[0].nodeId, nodeIdDelete);
    EXPECT_EQ(capturedDeleteItems[0].startTime, expectedStartTime);
    EXPECT_EQ(capturedDeleteItems[0].endTime, expectedEndTime);
    EXPECT_EQ(capturedDeleteItems[0].isDeleteModified, true);
  }
}

// ---------------------------------------------------------------------------
// Authorization: per-detail HistoryUpdate authz granularity (Part 4 section 6.2.1,
// Part 3 section 8.55). The authz operation is derived from the detail itself:
//   UpdateData/Event/StructureData -> InsertHistory (Insert) / ModifyHistory
//                                     (Replace|Update) / DeleteHistory (Remove)
//   Delete*Details                  -> DeleteHistory.
// These tests prove the gate runs at the granularity the permission model
// distinguishes - an Insert is denied when InsertHistory is denied, but is
// still allowed when only the unrelated DeleteHistory permission is denied.
// ---------------------------------------------------------------------------

// Helper: build a single-item UpdateDataDetails(Insert) request for a node.
HistoryUpdateRequest make_insert_update_request(NodeId nodeId)
{
  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Insert;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);
  return request;
}

HistoryUpdateRequest make_update_update_request(NodeId nodeId)
{
  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = std::make_unique<UpdateDataDetails>();
  updateDetails->node_id() = nodeId;
  updateDetails->perform_insert_replace() = PerformUpdateType::Update;
  updateDetails->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);
  return request;
}

// An Insert detail maps to InsertHistory; denying InsertHistory denies the item
// (BadUserAccessDenied) and the delegate's update_data path is never reached.
TEST(HistoryUpdateServiceTests, UpdateDataInsertDeniedWhenInsertHistoryDenied)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(100);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::InsertHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_update_data(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_insert_update_request(nodeId));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "denied InsertHistory must not reach the history delegate";
}

// @verifies AC-SVR-AUTHZ-006-HISTORYUPDATE-UPDATE-NEEDS-INSERT-AND-MODIFY
// Update inserts what is absent and modifies what is present (Part 11 6.8.2): it needs BOTH InsertHistory and
// ModifyHistory. Denying either denies the item before the delegate.
TEST(HistoryUpdateServiceTests, UpdateDeniedWhenInsertHistoryDenied)
{
  UpdateTestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history_write(101);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::InsertHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_update_data(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      callback(BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult>{});
    });

  auto result = h.run_service(make_update_update_request(nodeId));

  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "Update without InsertHistory must not reach the delegate";
}

// @verifies AC-SVR-AUTHZ-006-HISTORYUPDATE-UPDATE-NEEDS-INSERT-AND-MODIFY
TEST(HistoryUpdateServiceTests, UpdateDeniedWhenModifyHistoryDenied)
{
  UpdateTestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history_write(102);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::ModifyHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_update_data(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      callback(BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult>{});
    });

  auto result = h.run_service(make_update_update_request(nodeId));

  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "Update without ModifyHistory must not reach the delegate";
}

// @verifies AC-SVR-AUTHZ-006-HISTORYUPDATE-UPDATE-NEEDS-INSERT-AND-MODIFY
// The control: with both permissions the Update reaches the delegate.
TEST(HistoryUpdateServiceTests, UpdateReachesTheDelegateWithInsertAndModifyHistory)
{
  UpdateTestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history_write(103);
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_update_data(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_update_update_request(nodeId));

  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(delegateCalls.load(), 1);
}

// The same Insert detail is ALLOWED when RolePermissions omit only the unrelated
// DeleteHistory permission - proving the op is derived from the detail (Insert ->
// InsertHistory), not a blanket history-write check.
TEST(HistoryUpdateServiceTests, UpdateDataInsertAllowedWhenOnlyDeleteHistoryDenied)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(101);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::DeleteHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_update_data(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_insert_update_request(nodeId));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good())
    << "Insert must not be gated by an unrelated DeleteHistory denial";
  EXPECT_EQ(delegateCalls.load(), 1) << "an allowed Insert must reach the history delegate";
}

// A delete detail (DeleteRawModifiedDetails) maps to DeleteHistory; denying
// DeleteHistory denies the item (BadUserAccessDenied) and the delete delegate path
// is never reached.
TEST(HistoryUpdateServiceTests, DeleteRawDeniedWhenDeleteHistoryDenied)
{
  UpdateTestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history_write(102);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::DeleteHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_delete_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  auto deleteDetails = std::make_unique<DeleteRawModifiedDetails>();
  deleteDetails->node_id() = nodeId;
  deleteDetails->is_delete_modified() = false;
  const DateTime endTime = DateTime::now();
  deleteDetails->start_time() = DateTime{endTime.value() - std::chrono::hours{1}};
  deleteDetails->end_time() = endTime;
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(deleteDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "denied DeleteHistory must not reach the history delegate";
}

// ---------------------------------------------------------------------------
// Audit sub-type selection and audit field content
//
// The bus below records, in addition to the plain event fields, which payload
// families the emitted object belongs to. The generated payload hierarchy is a
// one-for-one mirror of the NS0 EventType hierarchy
// (AuditHistoryRawModifyDelete/AtTimeDelete/EventDelete -> AuditHistoryDelete ->
// AuditHistoryUpdate), so a successful dynamic_cast is precisely the spec's
// "that type or a sub-type of it" test, taken from the object the service really
// emitted rather than from a name the test supplies.
// ---------------------------------------------------------------------------
struct CapturedAuditFields
{
  NodeId eventType;
  NodeId sourceNode;
  bool status{false};

  bool isHistoryUpdateFamily{false};
  bool isEventUpdateFamily{false};
  bool isDeleteFamily{false};
  bool isRawModifyDeleteFamily{false};

  std::optional<NodeId> updatedNode;
  std::optional<int32_t> performInsertReplace;
  bool newValuesPresent{false};

  std::optional<bool> isDeleteModified;
  bool startTimePresent{false};
  bool endTimePresent{false};
};

class FieldCapturingEventBus : public EventBus
{
public:
  explicit FieldCapturingEventBus(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    std::lock_guard lock(mMutex);
    CapturedAuditFields captured;
    captured.eventType = event.eventType;
    captured.sourceNode = event.sourceNode;

    if (auto* audit = dynamic_cast<AuditEventPayload*>(&event))
      captured.status = audit->status;

    captured.isHistoryUpdateFamily = dynamic_cast<AuditHistoryUpdateEventPayload*>(&event) != nullptr;
    captured.isEventUpdateFamily = dynamic_cast<AuditHistoryEventUpdateEventPayload*>(&event) != nullptr;
    captured.isDeleteFamily = dynamic_cast<AuditHistoryDeleteEventPayload*>(&event) != nullptr;
    captured.isRawModifyDeleteFamily =
      dynamic_cast<AuditHistoryRawModifyDeleteEventPayload*>(&event) != nullptr;

    if (auto* valueUpdate = dynamic_cast<AuditHistoryValueUpdateEventPayload*>(&event))
    {
      captured.updatedNode = valueUpdate->updatedNode;
      if (!valueUpdate->performInsertReplace.empty())
        captured.performInsertReplace = valueUpdate->performInsertReplace.as<int32_t>();
      captured.newValuesPresent = !valueUpdate->newValues.empty();
    }

    if (auto* eventUpdate = dynamic_cast<AuditHistoryEventUpdateEventPayload*>(&event))
    {
      captured.updatedNode = eventUpdate->updatedNode;
      if (!eventUpdate->performInsertReplace.empty())
        captured.performInsertReplace = eventUpdate->performInsertReplace.as<int32_t>();
      captured.newValuesPresent = !eventUpdate->newValues.empty();
    }

    if (auto* rawDelete = dynamic_cast<AuditHistoryRawModifyDeleteEventPayload*>(&event))
    {
      captured.updatedNode = rawDelete->updatedNode;
      captured.isDeleteModified = rawDelete->isDeleteModified;
      captured.startTimePresent = !rawDelete->startTime.empty();
      captured.endTimePresent = !rawDelete->endTime.empty();
    }
    else if (auto* anyDelete = dynamic_cast<AuditHistoryDeleteEventPayload*>(&event))
    {
      captured.updatedNode = anyDelete->updatedNode;
    }

    mEvents.push_back(std::move(captured));
  }

  std::vector<CapturedAuditFields> events()
  {
    std::lock_guard lock(mMutex);
    return mEvents;
  }

private:
  std::mutex mMutex;
  std::vector<CapturedAuditFields> mEvents;
};

// Part 4 section 5.10.5 / Part 11 section 5.6.1: inserting historical Events must raise
// AuditHistoryEventUpdateEventType (or a sub-type). A plausible implementation
// routes every HistoryUpdate detail through one generic emitter, or reuses the
// value-update emitter for all update-family details; either raises a type an
// audit query filtering on event-history changes will never select.
// @verifies AC-SVR-ATTR-HUPD-008-EVENT-INSERT-SUBTYPE
TEST(HistoryUpdateServiceTests, InsertingHistoricalEventsRaisesEventUpdateAuditSubType)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FieldCapturingEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto nodeId = h.create_variable_with_history_write(710);

  h.delegate->set_on_update_events(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateEventsItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateEventsItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t ei = 0; ei < item.events.size(); ++ei)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;

  auto updateDetails = conforming_event_insert(nodeId);

  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(updateDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "inserting historical Events must raise an audit Event";

  AuditHistoryEventUpdateEventPayload eventUpdateType;
  AuditHistoryUpdateEventPayload genericUpdateType;
  AuditHistoryValueUpdateEventPayload valueUpdateType;

  EXPECT_TRUE(events[0].isEventUpdateFamily)
    << "the emitted payload must be AuditHistoryEventUpdateEventType or a sub-type";
  EXPECT_EQ(events[0].eventType, eventUpdateType.eventType);
  EXPECT_NE(events[0].eventType, genericUpdateType.eventType)
    << "the generic AuditHistoryUpdateEventType is not sufficient for an event insert";
  EXPECT_NE(events[0].eventType, valueUpdateType.eventType)
    << "an Event insert must not be reported as a value update";
  EXPECT_EQ(events[0].sourceNode, nodeId);
  EXPECT_TRUE(events[0].status);
}

// Part 4 section 5.10.5 / Part 11 section 5.6.1: every delete-family detail
// (DeleteRawModifiedDetails, DeleteAtTimeDetails, DeleteEventDetails) must raise
// AuditHistoryDeleteEventType or one of its sub-types. Deletion destroys the
// evidence, so an implementation that falls back to the generic history-update
// audit for any one of the three variants leaves an auditor unable to tell a
// correction from an erasure.
// @verifies AC-SVR-ATTR-HUPD-009-DELETE-SUBTYPE
TEST(HistoryUpdateServiceTests, DeletingHistoryRaisesDeleteAuditSubTypeForEveryDeleteDetail)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FieldCapturingEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto rawNodeId = h.create_variable_with_history_write(720);
  auto atTimeNodeId = h.create_variable_with_history_write(721);

  // DeleteEvent targets Object nodes with EventNotifier HistoryWrite bit set.
  NodeId eventNodeId{h.nsIndex, uint32_t{722}};
  {
    auto as = h.sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(eventNodeId, NodeClass::Object);
    ASSERT_TRUE(objResult.is_good()) << "Failed to create object node";
    EventNotifierType en;
    en.set(EventNotifierType::Bit::HistoryWrite);
    objResult.value().set_event_notifier(en);
  }

  h.delegate->set_on_delete_raw(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      callback(std::move(batch));
    });
  h.delegate->set_on_delete_at_time(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteAtTimeItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      callback(std::move(batch));
    });
  h.delegate->set_on_delete_events(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteEventsItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(3);

  auto rawDetails = std::make_unique<DeleteRawModifiedDetails>();
  rawDetails->node_id() = rawNodeId;
  rawDetails->is_delete_modified() = false;
  const DateTime rawEndTime = DateTime::now();
  rawDetails->start_time() = DateTime{rawEndTime.value() - std::chrono::hours{1}};
  rawDetails->end_time() = rawEndTime;
  request.history_update_details()[0] = std::move(rawDetails);

  auto atTimeDetails = std::make_unique<DeleteAtTimeDetails>();
  atTimeDetails->node_id() = atTimeNodeId;
  atTimeDetails->req_times().push_back(DateTime::now());
  request.history_update_details()[1] = std::move(atTimeDetails);

  auto eventDetails = std::make_unique<DeleteEventDetails>();
  eventDetails->node_id() = eventNodeId;
  eventDetails->event_ids().push_back(ByteString{});
  request.history_update_details()[2] = std::move(eventDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_TRUE(response->results()[1].status_code().is_good());
  EXPECT_TRUE(response->results()[2].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 3u) << "every delete detail must raise its own audit Event";

  AuditHistoryUpdateEventPayload genericUpdateType;

  for (const auto& nid : {rawNodeId, atTimeNodeId, eventNodeId})
  {
    const CapturedAuditFields* match = nullptr;
    for (const auto& ev : events)
    {
      if (ev.sourceNode == nid)
        match = &ev;
    }
    ASSERT_NE(match, nullptr) << "no audit Event raised for a deleted node";
    EXPECT_TRUE(match->isDeleteFamily)
      << "a delete must raise AuditHistoryDeleteEventType or a sub-type of it";
    EXPECT_NE(match->eventType, genericUpdateType.eventType)
      << "the generic AuditHistoryUpdateEventType does not record that history was erased";
    ASSERT_TRUE(match->updatedNode.has_value());
    EXPECT_EQ(*match->updatedNode, nid);
    EXPECT_TRUE(match->status);
  }
}

// Part 11 section 5.6.1: BOTH the delete-raw and the delete-modified form of
// DeleteRawModifiedDetails must raise AuditHistoryRawModifyDeleteEventType (or a
// sub-type) carrying the startTime / endTime / IsDeleteModified actually used.
// An implementation that treats IsDeleteModified=true as a different operation
// - or that copies the flag from a default rather than from the request - leaves
// the two erasures indistinguishable in the audit trail.
// @verifies AC-SVR-ATTR-HUPD-010-RAWMODIFY-DELETE-AUDIT
TEST(HistoryUpdateServiceTests, DeletingRawAndModifiedHistoryBothRaiseRawModifyDeleteAudit)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FieldCapturingEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto rawNodeId = h.create_variable_with_history_write(730);
  auto modifiedNodeId = h.create_variable_with_history_write(731);

  h.delegate->set_on_delete_raw(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::DeleteRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryUpdateSuccess{});
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(2);

  DateTime endTime = DateTime::now();
  DateTime startTime{endTime.value() - std::chrono::hours{1}};

  auto rawDetails = std::make_unique<DeleteRawModifiedDetails>();
  rawDetails->node_id() = rawNodeId;
  rawDetails->is_delete_modified() = false;
  rawDetails->start_time() = startTime;
  rawDetails->end_time() = endTime;
  request.history_update_details()[0] = std::move(rawDetails);

  auto modifiedDetails = std::make_unique<DeleteRawModifiedDetails>();
  modifiedDetails->node_id() = modifiedNodeId;
  modifiedDetails->is_delete_modified() = true;
  modifiedDetails->start_time() = startTime;
  modifiedDetails->end_time() = endTime;
  request.history_update_details()[1] = std::move(modifiedDetails);

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_TRUE(response->results()[1].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 2u) << "delete-raw and delete-modified must each raise an audit Event";

  AuditHistoryRawModifyDeleteEventPayload rawModifyDeleteType;

  const CapturedAuditFields* rawEvent = nullptr;
  const CapturedAuditFields* modifiedEvent = nullptr;
  for (const auto& ev : events)
  {
    if (ev.sourceNode == rawNodeId)
      rawEvent = &ev;
    if (ev.sourceNode == modifiedNodeId)
      modifiedEvent = &ev;
  }

  ASSERT_NE(rawEvent, nullptr) << "no audit Event raised for the delete-raw operation";
  EXPECT_TRUE(rawEvent->isRawModifyDeleteFamily)
    << "delete-raw must raise AuditHistoryRawModifyDeleteEventType or a sub-type";
  EXPECT_EQ(rawEvent->eventType, rawModifyDeleteType.eventType);
  ASSERT_TRUE(rawEvent->isDeleteModified.has_value());
  EXPECT_FALSE(*rawEvent->isDeleteModified);
  EXPECT_TRUE(rawEvent->startTimePresent);
  EXPECT_TRUE(rawEvent->endTimePresent);

  ASSERT_NE(modifiedEvent, nullptr) << "no audit Event raised for the delete-modified operation";
  EXPECT_TRUE(modifiedEvent->isRawModifyDeleteFamily)
    << "delete-modified must raise AuditHistoryRawModifyDeleteEventType or a sub-type";
  EXPECT_EQ(modifiedEvent->eventType, rawModifyDeleteType.eventType);
  ASSERT_TRUE(modifiedEvent->isDeleteModified.has_value());
  EXPECT_TRUE(*modifiedEvent->isDeleteModified)
    << "the audit Event must carry the IsDeleteModified the request used";
  EXPECT_TRUE(modifiedEvent->startTimePresent);
  EXPECT_TRUE(modifiedEvent->endTimePresent);
}

// Part 11 section 5.6.1 / Part 5 AuditHistoryValueUpdateEventType: every remaining
// history update - insert, replace and update - must follow the
// AuditHistoryUpdateEventType model, meaning the Event carries the affected node,
// the update mode and the values written. Raising the right type with empty
// fields passes a type check while recording nothing, so NewValues is asserted
// alongside UpdatedNode and PerformInsertReplace.
// @verifies AC-SVR-ATTR-HUPD-013-OTHER-UPDATES-AUDIT
TEST(HistoryUpdateServiceTests, InsertReplaceAndUpdateAuditEventsCarryNodeModeAndValues)
{
  UpdateTestHarness h;
  ServerConfig serverConfig;
  serverConfig.auditingEnabled = true;
  h.setup(true, std::move(serverConfig));

  auto addressSpace = h.sessionInfo->address_space();
  FieldCapturingEventBus eventBus(addressSpace);
  eventBus.set_event_listener([](const BaseEvent&) {});
  h.sessionInfo->eventSink = &eventBus;

  auto insertNodeId = h.create_variable_with_history_write(740);
  auto replaceNodeId = h.create_variable_with_history_write(741);
  auto updateNodeId = h.create_variable_with_history_write(742);

  h.delegate->set_on_update_data(
    [](const NamespaceHistoryDelegate::UpdateContext&,
      std::vector<NamespaceHistoryDelegate::UpdateDataItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryUpdateSuccess success;
        for (size_t vi = 0; vi < item.values.size(); ++vi)
          success.operationResults.push_back(Status::Good);
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(3);

  struct ModeCase
  {
    NodeId nodeId;
    PerformUpdateType mode;
  };

  const std::vector<ModeCase> modes = {{insertNodeId, PerformUpdateType::Insert},
    {replaceNodeId, PerformUpdateType::Replace},
    {updateNodeId, PerformUpdateType::Update}};

  size_t idx = 0;
  for (const auto& mode : modes)
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = mode.nodeId;
    details->perform_insert_replace() = mode.mode;
    details->update_values().push_back(DataValue{Variant{int32_t{7}}, DateTime::now()});
    request.history_update_details()[idx++] = std::move(details);
  }

  auto result = h.run_service(std::move(request));
  auto* response = get_update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_TRUE(response->results()[1].status_code().is_good());
  EXPECT_TRUE(response->results()[2].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 3u) << "insert, replace and update must each raise an audit Event";

  for (const auto& mode : modes)
  {
    const CapturedAuditFields* match = nullptr;
    for (const auto& ev : events)
    {
      if (ev.sourceNode == mode.nodeId)
        match = &ev;
    }
    ASSERT_NE(match, nullptr) << "no audit Event raised for a history update";
    EXPECT_TRUE(match->isHistoryUpdateFamily)
      << "the Event must follow the AuditHistoryUpdateEventType model";
    // The affected node.
    ASSERT_TRUE(match->updatedNode.has_value()) << "UpdatedNode must name the affected node";
    EXPECT_EQ(*match->updatedNode, mode.nodeId);
    // The mode.
    ASSERT_TRUE(match->performInsertReplace.has_value()) << "PerformInsertReplace must be populated";
    EXPECT_EQ(*match->performInsertReplace, static_cast<int32_t>(mode.mode));
    // The values.
    EXPECT_TRUE(match->newValuesPresent)
      << "NewValues must carry the values written; an empty field records nothing";
  }
}
