// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 ua::client::detail::EventSubscriberImpl (client design section 8.13): the
// collapsing event backbone. Drives the strand-bearing Impl against a FakeEventBackboneOps (no
// ConnectionImpl, Session, or wire stack - the mockable backbone interface is the whole point) and asserts
// its OWN logic:
//   - N consumers on the same notifier COALESCE onto ONE backbone MonitoredItem (one CreateMonitoredItems);
//   - the composite EventFilter is the UNION of the consumers' WhereClauses (a second distinct type widens
//     the filter via one ModifyMonitoredItems; a duplicate type does NOT);
//   - a published event is DEMULTIPLEXED client-side to the consumer(s) whose filter matches (CL-EVT-002);
//   - deleting one event consumer DROPS THAT CONSUMER and recomputes the filter but does NOT delete the
//     shared backbone (the S9 event MonitoredItemOwner path - Bad_NotSupported deferral now resolved); the
//     backbone is torn down only when the LAST consumer of a dedicated backbone goes;
//   - empty SelectClauses are rejected at entry (CL-MI-016);
//   - a self-acting event MonitoredItem holds only a WEAK owner ref (no strong cycle) - its self-action
//     fails Bad_ConnectionClosed once the subscriber is gone.
//
// @verifies CL-EVT-002
// @relation(CL-EVT-002, scope=file)
// @verifies CL-MI-013
// @relation(CL-MI-013, scope=file)
// @verifies CL-MI-016
// @relation(CL-MI-016, scope=file)
// @verifies CL-MI-023
// @relation(CL-MI-023, scope=file)

#include "ua_element_operand.h"
#include "ua_event_subscriber_impl.h"

#include "ua_client_observers.h"
#include "ua_connection.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_content_filter_element.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_event_subscriber_test_access.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_objecttype_id.h"
#include "ua_observer_sink.h"
#include "ua_status.h"

#include "fake_session_ops.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::ConnectionObserver;
using ua::client::EventNotification;
using ua::client::EventSubscription;
using ua::client::MonitoredItem;
using ua::client::MonitoredItemKind;
using ua::client::Session;
using ua::client::SubscribeResult;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::EventBackboneCreated;
using ua::client::detail::EventBackboneOps;
using ua::client::detail::EventFilterDiagnostic;
using ua::client::detail::EventFilterDiagnosticKind;
using ua::client::detail::EventFilterDiagnostics;
using ua::client::detail::EventSubscriberImpl;
using ua::client::detail::EventSubscriberTestAccess;
using ua::client::detail::ObserverSink;
using ua::client::detail::ObserverSlots;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

// The mockable backbone interface: records every create/modify/delete and replies with configurable status
// (a Bad status fails the call; another status answers with it).
class FakeEventBackboneOps : public EventBackboneOps
{
public:
  struct CreateCall
  {
    ua::NodeId notifier;
    ua::EventFilter filter;
    std::uint32_t clientHandle = 0;
    std::uint32_t queueSize = 0;
  };

  struct ModifyCall
  {
    std::uint32_t subscriptionId = 0;
    std::uint32_t monitoredItemId = 0;
    ua::EventFilter filter;
  };

  struct DeleteCall
  {
    std::uint32_t subscriptionId = 0;
    std::uint32_t monitoredItemId = 0;
  };

  std::vector<CreateCall> creates;
  std::vector<ModifyCall> modifies;
  std::vector<DeleteCall> deletes;

  ua::Status createStatus = ua::Status::Good;
  ua::Status modifyStatus = ua::Status::Good;
  EventFilterDiagnostics createDiagnostics;
  EventFilterDiagnostics modifyDiagnostics;
  std::uint32_t nextSubscriptionId = 100;
  std::uint32_t nextMonitoredItemId = 500;

  void create_backbone_async(ua::NodeId notifier, ua::EventFilter filter, std::uint32_t clientHandle,
    std::uint32_t queueSize, std::function<void(Result<EventBackboneCreated>)> callback) noexcept override
  {
    creates.push_back(CreateCall{notifier, filter, clientHandle, queueSize});
    if (StatusCode{createStatus}.is_bad())
    {
      callback(Result<EventBackboneCreated>{StatusCode{createStatus}});
      return;
    }
    EventBackboneCreated created;
    created.subscriptionId = nextSubscriptionId++;
    created.monitoredItemId = nextMonitoredItemId++;
    created.filterDiagnostics = createDiagnostics;
    callback(Result<EventBackboneCreated>{created, StatusCode{createStatus}});
  }

  void modify_backbone_filter_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::uint32_t /*clientHandle*/, ua::EventFilter filter,
    std::function<void(Result<EventFilterDiagnostics>)> callback) noexcept override
  {
    modifies.push_back(ModifyCall{subscriptionId, monitoredItemId, filter});
    if (StatusCode{modifyStatus}.is_bad())
    {
      callback(Result<EventFilterDiagnostics>{StatusCode{modifyStatus}});
      return;
    }
    callback(Result<EventFilterDiagnostics>{modifyDiagnostics, StatusCode{modifyStatus}});
  }

  void delete_backbone_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::function<void(VoidResult)> callback) noexcept override
  {
    deletes.push_back(DeleteCall{subscriptionId, monitoredItemId});
    callback(VoidResult{});
  }

  // A scriptable HasSubtype hierarchy: `subtypeChildren[T]` is the list of T's IMMEDIATE subtypes, and the
  // walk below is transitive, exactly as the real Browse-driven walk is. Deliberately NOT an identity
  // ("every type has no subtypes") default that would let the demux tests pass against the exact-match bug
  // they exist to catch - a test that declares no subtypes cannot observe subtype delivery at all.
  std::unordered_map<ua::NodeId, std::vector<ua::NodeId>> subtypeChildren;
  ua::Status subtypeStatus = ua::Status::Good;  ///< force the resolution to fail (fallback path)
  std::vector<std::vector<ua::NodeId>> subtypeResolveCalls;  ///< one entry per resolve (cache assertions)

  void resolve_event_subtypes_async(std::vector<ua::NodeId> roots,
    std::function<void(Result<std::vector<ua::NodeId>>)> callback) noexcept override
  {
    subtypeResolveCalls.push_back(roots);
    if (subtypeStatus != ua::Status::Good)
    {
      callback(Result<std::vector<ua::NodeId>>{StatusCode{subtypeStatus}});
      return;
    }
    std::vector<ua::NodeId> closure = roots;
    for (std::size_t i = 0; i < closure.size(); ++i)
    {
      const auto entry = subtypeChildren.find(closure[i]);
      if (entry == subtypeChildren.end())
      {
        continue;
      }
      for (const auto& child : entry->second)
      {
        if (std::find(closure.begin(), closure.end(), child) == closure.end())
        {
          closure.push_back(child);
        }
      }
    }
    callback(Result<std::vector<ua::NodeId>>{std::move(closure)});
  }
};

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeEventBackboneOps> ops = std::make_shared<FakeEventBackboneOps>();

  std::shared_ptr<EventSubscriberImpl> make()
  {
    return EventSubscriberImpl::create(ctx.get_executor(), ops, ua::Logger{});
  }

  void drain()
  {
    ctx.run();
    ctx.restart();
  }
};

// One EventFieldList carrying the 8 BaseEventType mandatories in composite order, with a chosen EventType.
ua::EventFieldList make_event(std::uint32_t backboneHandle, const ua::NodeId& eventType)
{
  ua::EventFieldList list;
  list.client_handle() = backboneHandle;
  list.event_fields().push_back(ua::Variant{ua::ByteString{}});  // EventId
  list.event_fields().push_back(ua::Variant{eventType});  // EventType
  list.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectId::Server}});  // SourceNode
  list.event_fields().push_back(ua::Variant{ua::String{"src"}});  // SourceName (a String, per Part 5)
  list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // Time
  list.event_fields().push_back(ua::Variant{ua::DateTime{}});  // ReceiveTime
  list.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "msg"}});  // Message
  list.event_fields().push_back(ua::Variant{std::uint16_t{5}});  // Severity
  return list;
}

ua::EventFieldList make_audit_event(std::uint32_t backboneHandle, const ua::EventFilter& filter,
  ua::NodeId eventType = ua::NodeId{ua::ObjectTypeId::AuditEventType})
{
  ua::EventFieldList event;
  event.client_handle() = backboneHandle;
  for (const auto& clause : filter.select_clauses())
  {
    const std::string_view name = clause.browse_path().size() == 1
                                    ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                    : std::string_view{};
    if (name == "EventId")
      event.event_fields().push_back(ua::Variant{ua::ByteString{1, 2}});
    else if (name == "EventType")
      event.event_fields().push_back(ua::Variant{eventType});
    else if (name == "SourceNode")
      event.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectId::Server}});
    else if (name == "SourceName")
      event.event_fields().push_back(ua::Variant{ua::String{"server"}});
    else if (name == "Time" || name == "ReceiveTime" || name == "ActionTimeStamp")
      event.event_fields().push_back(ua::Variant{ua::DateTime{2026, 7, 24, 12, 0, 0.0}});
    else if (name == "Message")
      event.event_fields().push_back(ua::Variant{ua::LocalizedText{"", "audit"}});
    else if (name == "Severity")
      event.event_fields().push_back(ua::Variant{std::uint16_t{1}});
    else if (name == "Status")
      event.event_fields().push_back(ua::Variant{true});
    else if (name == "ServerId")
      event.event_fields().push_back(ua::Variant{ua::String{"server-1"}});
    else if (name == "ClientAuditEntryId")
      event.event_fields().push_back(ua::Variant{ua::String{"audit-42"}});
    else if (name == "ClientUserId")
      event.event_fields().push_back(ua::Variant{ua::String{"operator"}});
    else if (name == "StatusCodeId")
      event.event_fields().push_back(ua::Variant{ua::StatusCode{ua::Status::BadUserAccessDenied}});
    else if (name == "SecureChannelId")
      event.event_fields().push_back(ua::Variant{ua::String{"channel-7"}});
    else if (name == "SessionId")
      event.event_fields().push_back(ua::Variant{ua::NodeId{2, 700U}});
    else if (name == "MethodId")
      event.event_fields().push_back(ua::Variant{ua::NodeId{2, 701U}});
    else if (name == "InputArguments")
      event.event_fields().push_back(ua::Variant{ua::Array<std::int32_t>{1, 2}});
    else
      event.event_fields().push_back(ua::Variant{});
  }
  return event;
}

const ua::NodeId typeA{ua::ObjectTypeId::SystemStatusChangeEventType};
const ua::NodeId typeB{ua::ObjectTypeId::BaseModelChangeEventType};
const ua::NodeId typeC{ua::ObjectTypeId::DeviceFailureEventType};

ua::ContentFilterElement make_operator_element(ua::FilterOperator filterOperator)
{
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{ua::NodeId{ua::ObjectId::Server}};
  ua::ContentFilterElement element;
  element.filter_operator() = filterOperator;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  return element;
}

// A thread-safe ConnectionObserver that records the on_advisory_diagnostic fan-out the ObserverSink delivers
// (CL-EVT-001/002 drop-advisory). The sink delivers on its own delivery strand - here, the single-threaded
// io_context drained on the test thread.
class RecordingConnectionObserver : public ConnectionObserver
{
public:
  std::atomic<int> advisoryCount{0};
  std::shared_ptr<const ua::ErrorDetail> lastDetail;

  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    lastDetail = std::move(detail);
    advisoryCount.fetch_add(1, std::memory_order_release);
  }
};

ua::client::ReconnectPolicy fast_reconnect_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// Builds a live ConnectionImpl + a real per-Connection ObserverSink over it with @p observer installed in the
// connection slot, sharing @p executor so one io_context drives both the subscriber strand and the sink's
// delivery strand. The advisory fan-out only delivers while the ConnectionImpl is alive, so the harness keeps
// it (and the sink) alive for the test's duration.
struct SinkHarness
{
  std::shared_ptr<FakeSessionOps> session = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> reopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ua::client::detail::ConnectionImpl> connection;
  std::shared_ptr<ObserverSink> sink;

  void build(boost::asio::any_io_executor executor, std::shared_ptr<RecordingConnectionObserver> observer)
  {
    connection = ConnectionImplTestAccess::create_with_ops(executor,
      session,
      ConnectionConfig{},
      ua::Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_reconnect_policy(),
      {});
    sink = ObserverSink::create(executor, connection);
    ObserverSlots slots;
    slots.connection = std::move(observer);
    sink->set_slots(std::move(slots));
  }
};

// A fixture wiring the subscriber to a real ObserverSink so a drop-path advisory (CL-EVT-001/002) reaches a
// recording ConnectionObserver. Otherwise identical to the plain Fixture.
struct SinkFixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeEventBackboneOps> ops = std::make_shared<FakeEventBackboneOps>();
  std::shared_ptr<RecordingConnectionObserver> observer = std::make_shared<RecordingConnectionObserver>();
  SinkHarness harness;

  std::shared_ptr<EventSubscriberImpl> make()
  {
    harness.build(ctx.get_executor(), observer);
    return EventSubscriberImpl::create(ctx.get_executor(), ops, ua::Logger{}, {}, harness.sink);
  }

  void drain()
  {
    ctx.run();
    ctx.restart();
  }
};

// --- Coalescing (CL-AC-001 / section 8.13.4) ---

// @verifies CL-AC-001
// @relation(CL-AC-001, scope=function)
TEST(EventSubscriberCoalescing, TwoConsumersSameTypeShareOneBackboneNoModify)
{
  Fixture f;
  auto subscriber = f.make();

  std::optional<SubscribeResult> firstResult;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult result) { firstResult = std::move(result); });
  f.drain();
  ASSERT_TRUE(firstResult && firstResult->is_good());
  EXPECT_EQ(firstResult->value().kind(), MonitoredItemKind::Event);

  std::optional<SubscribeResult> secondResult;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult result) { secondResult = std::move(result); });
  f.drain();
  ASSERT_TRUE(secondResult && secondResult->is_good());

  // ONE CreateMonitoredItems for both consumers; the second (same type) does not change the composite.
  EXPECT_EQ(f.ops->creates.size(), 1u);
  EXPECT_EQ(f.ops->modifies.size(), 0u);
  EXPECT_EQ(EventSubscriberTestAccess::created_backbone_count(*subscriber), 1u);
  EXPECT_EQ(EventSubscriberTestAccess::consumer_count(*subscriber), 2u);
}

TEST(EventSubscriberCoalescing, SecondConsumerDistinctTypeWidensCompositeFilter)
{
  Fixture f;
  auto subscriber = f.make();

  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  // Still ONE backbone, but the distinct second type triggers exactly one ModifyMonitoredItems whose
  // composite WhereClause is the UNION: an Or root over the two OfType leaves (3 elements). The tree
  // SHAPE is pinned in TwoTypesCoalesceIntoAnOrTreeNotSiblingElements; this row pins the coalescing.
  EXPECT_EQ(f.ops->creates.size(), 1u);
  ASSERT_EQ(f.ops->modifies.size(), 1u);
  const auto filter = EventSubscriberTestAccess::last_sent_filter(*subscriber);
  ASSERT_TRUE(filter.has_value());
  ASSERT_EQ(filter->where_clause().elements().size(), 3u);
  EXPECT_EQ(filter->where_clause().elements()[0].filter_operator(), ua::FilterOperator::Or);
}

// A Good subcode on the backbone's creation reaches the subscriber with the event item.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(EventSubscriberStatusRouting, TheBackbonesCreationCodeReachesTheSubscriber)
{
  Fixture f;
  f.ops->createStatus = Status::GoodOverload;
  auto subscriber = f.make();

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult answer) { result = std::move(answer); });
  f.drain();

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::GoodOverload}.value());
  EXPECT_EQ(result->value().kind(), MonitoredItemKind::Event);
}

// An Uncertain code on the filter modification that adds a consumer reaches that consumer's subscriber with
// its event item.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(EventSubscriberStatusRouting, TheFilterModificationsCodeReachesTheSubscriber)
{
  Fixture f;
  auto subscriber = f.make();
  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  f.ops->modifyStatus = Status::UncertainInitialValue;

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeB, [](EventNotification) {}, [&](SubscribeResult answer) { result = std::move(answer); });
  f.drain();

  ASSERT_EQ(f.ops->modifies.size(), 1u) << "the second type widens the shared backbone's filter";
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_uncertain());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
  EXPECT_EQ(EventSubscriberTestAccess::consumer_count(*subscriber), 2u) << "the consumer is attached";
  EXPECT_NO_THROW({ EXPECT_EQ(result->value().kind(), MonitoredItemKind::Event); })
    << "the event item is held with the Uncertain code";
}

// @verifies CL-MI-018
// @relation(CL-MI-018, scope=function)
TEST(EventSubscriberFilterDiagnostics, CreateBadSelectClauseSurfacesIndexedAdvisoryAndStillSubscribes)
{
  SinkFixture fixture;
  fixture.ops->createDiagnostics.push_back(EventFilterDiagnostic{
    EventFilterDiagnosticKind::SelectClause, 3, 0, StatusCode{Status::BadTypeDefinitionInvalid}});
  auto subscriber = fixture.make();

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult subscribed) { result = std::move(subscribed); });
  fixture.drain();

  ASSERT_TRUE(result.has_value() && result->is_good())
    << "a filter diagnostic is advisory and must not replace the successful item result";
  ASSERT_EQ(fixture.observer->advisoryCount.load(), 1);
  ASSERT_NE(fixture.observer->lastDetail, nullptr);
  EXPECT_EQ(fixture.observer->lastDetail->code, "EventFilterResultRejected");
  EXPECT_EQ(fixture.observer->lastDetail->source, "client.tier2.event_subscriber.event_filter_result");
  EXPECT_EQ(fixture.observer->lastDetail->innerStatus, StatusCode{Status::BadTypeDefinitionInvalid}.value());
  ASSERT_EQ(fixture.observer->lastDetail->context.size(), 2u);
  EXPECT_EQ(fixture.observer->lastDetail->context[0].key, ua::ContextKeys::fieldName.value());
  EXPECT_EQ(fixture.observer->lastDetail->context[0].value, "selectClauseResults");
  EXPECT_EQ(fixture.observer->lastDetail->context[1].key, ua::ContextKeys::operationIndex.value());
  EXPECT_EQ(fixture.observer->lastDetail->context[1].value, "3");
}

// @verifies CL-MI-018
// @relation(CL-MI-018, scope=function)
TEST(EventSubscriberFilterDiagnostics, ModifyBadWhereOperandSurfacesElementAndOperandIndices)
{
  SinkFixture fixture;
  auto subscriber = fixture.make();
  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  fixture.drain();

  fixture.ops->modifyDiagnostics.push_back(EventFilterDiagnostic{
    EventFilterDiagnosticKind::WhereClauseOperand, 2, 4, StatusCode{Status::BadFilterOperandInvalid}});
  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeB, [](EventNotification) {}, [&](SubscribeResult subscribed) { result = std::move(subscribed); });
  fixture.drain();

  ASSERT_TRUE(result.has_value() && result->is_good());
  ASSERT_EQ(fixture.observer->advisoryCount.load(), 1);
  ASSERT_NE(fixture.observer->lastDetail, nullptr);
  EXPECT_EQ(fixture.observer->lastDetail->innerStatus, StatusCode{Status::BadFilterOperandInvalid}.value());
  ASSERT_EQ(fixture.observer->lastDetail->context.size(), 3u);
  EXPECT_EQ(
    fixture.observer->lastDetail->context[0].value, "whereClauseResult.elementResults.operandStatusCodes");
  EXPECT_EQ(fixture.observer->lastDetail->context[1].key, ua::ContextKeys::index.value());
  EXPECT_EQ(fixture.observer->lastDetail->context[1].value, "2");
  EXPECT_EQ(fixture.observer->lastDetail->context[2].key, ua::ContextKeys::operationIndex.value());
  EXPECT_EQ(fixture.observer->lastDetail->context[2].value, "4");
}

// @verifies CL-MI-018
// @relation(CL-MI-018, scope=function)
TEST(EventFilterDiagnostics, ExtractsOnlyBadSelectElementAndOperandStatuses)
{
  ua::EventFilterResult result;
  result.select_clause_results().push_back(StatusCode{Status::Good});
  result.select_clause_results().push_back(StatusCode{Status::BadTypeDefinitionInvalid});
  ua::ContentFilterElementResult element;
  element.status_code() = StatusCode{Status::BadFilterElementInvalid};
  element.operand_status_codes().push_back(StatusCode{Status::Good});
  element.operand_status_codes().push_back(StatusCode{Status::BadFilterOperandInvalid});
  result.where_clause_result().element_results().push_back(std::move(element));

  const auto diagnostics = ua::client::detail::bad_event_filter_diagnostics(result);

  ASSERT_EQ(diagnostics.size(), 3u);
  EXPECT_EQ(diagnostics[0].kind, EventFilterDiagnosticKind::SelectClause);
  EXPECT_EQ(diagnostics[0].index, 1u);
  EXPECT_EQ(diagnostics[1].kind, EventFilterDiagnosticKind::WhereClauseElement);
  EXPECT_EQ(diagnostics[1].index, 0u);
  EXPECT_EQ(diagnostics[2].kind, EventFilterDiagnosticKind::WhereClauseOperand);
  EXPECT_EQ(diagnostics[2].index, 0u);
  EXPECT_EQ(diagnostics[2].operandIndex, 1u);
}

// A ContentFilter is a TREE: OPC 10000-4 7.4.1 evaluates elements[0] as the root and reaches the rest only
// through ElementOperands that name them by index. Two consumers on one backbone therefore need an Or over
// their OfType elements - as sibling elements, everything after the first is unreachable and the server
// silently applies only one consumer's type.
TEST(EventSubscriberCoalescing, TwoTypesCoalesceIntoAnOrTreeNotSiblingElements)
{
  Fixture f;
  auto subscriber = f.make();

  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const auto filter = EventSubscriberTestAccess::last_sent_filter(*subscriber);
  ASSERT_TRUE(filter.has_value());
  const auto& elements = filter->where_clause().elements();
  ASSERT_EQ(elements.size(), 3u) << "an Or plus the two OfType leaves";

  // elements[0] is the root and must be the Or, naming the two leaves by index.
  EXPECT_EQ(elements[0].filter_operator(), ua::FilterOperator::Or);
  ASSERT_EQ(elements[0].filter_operands().size(), 2u);
  const auto* left = dynamic_cast<const ua::ElementOperand*>(elements[0].filter_operands()[0].get());
  const auto* right = dynamic_cast<const ua::ElementOperand*>(elements[0].filter_operands()[1].get());
  ASSERT_NE(left, nullptr) << "an Or operand must reference another element, not a literal";
  ASSERT_NE(right, nullptr);
  EXPECT_EQ(left->index(), 1u);
  EXPECT_EQ(right->index(), 2u);
  EXPECT_EQ(elements[1].filter_operator(), ua::FilterOperator::OfType);
  EXPECT_EQ(elements[2].filter_operator(), ua::FilterOperator::OfType);
}

// One type needs no Or at all - the single OfType is itself the root.
TEST(EventSubscriberCoalescing, OneTypeEmitsABareOfTypeRoot)
{
  Fixture f;
  auto subscriber = f.make();

  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const auto filter = EventSubscriberTestAccess::last_sent_filter(*subscriber);
  ASSERT_TRUE(filter.has_value());
  ASSERT_EQ(filter->where_clause().elements().size(), 1u);
  EXPECT_EQ(filter->where_clause().elements()[0].filter_operator(), ua::FilterOperator::OfType);
}

// Three types chain right: every Or is reachable from the root, and every OfType is reachable from an Or.
// A chain that mis-numbers one index silently drops the branch below it, which is the defect in miniature.
TEST(EventSubscriberCoalescing, ThreeTypesChainIntoAFullyReachableOrTree)
{
  Fixture f;
  auto subscriber = f.make();

  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeC, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const auto filter = EventSubscriberTestAccess::last_sent_filter(*subscriber);
  ASSERT_TRUE(filter.has_value());
  const auto& elements = filter->where_clause().elements();
  ASSERT_EQ(elements.size(), 5u) << "two Ors and three OfType leaves";

  // Walk the tree from the root and collect every element the server would actually evaluate.
  std::vector<bool> reached(elements.size(), false);
  std::vector<std::size_t> pending{0};
  std::size_t ofTypesReached = 0;
  while (!pending.empty())
  {
    const std::size_t index = pending.back();
    pending.pop_back();
    ASSERT_LT(index, elements.size()) << "an ElementOperand names a slot that does not exist";
    ASSERT_FALSE(reached[index]) << "the tree must not contain a cycle";
    reached[index] = true;
    if (elements[index].filter_operator() == ua::FilterOperator::OfType)
    {
      ++ofTypesReached;
      continue;
    }
    for (std::size_t operand = 0; operand < elements[index].filter_operands().size(); ++operand)
    {
      const auto* reference =
        dynamic_cast<const ua::ElementOperand*>(elements[index].filter_operands()[operand].get());
      ASSERT_NE(reference, nullptr);
      pending.push_back(reference->index());
    }
  }
  EXPECT_EQ(ofTypesReached, 3u) << "every requested type must be reachable from the root";
  EXPECT_TRUE(std::all_of(reached.begin(), reached.end(), [](bool seen) { return seen; }))
    << "an element no operand names is dead weight the server never evaluates";
}

// A match-all consumer (nullopt filter == OfType(BaseEventType)) sharing a backbone with a type-specific
// consumer must NOT have the composite WhereClause narrowed to the specific type - that would silently
// starve it of every other event (the client-side demux still treats it as match-all -> silent loss).
TEST(EventSubscriberCoalescing, MatchAllConsumerKeepsCompositeFilterMatchAll)
{
  Fixture f;
  auto subscriber = f.make();

  EventSubscription matchAll;  // no filter set == match-all on the default Server notifier
  subscriber->subscribe_async(matchAll, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const auto filter = EventSubscriberTestAccess::last_sent_filter(*subscriber);
  ASSERT_TRUE(filter.has_value());
  // With a match-all consumer present the composite WhereClause stays EMPTY (match-all backbone), NOT
  // OfType(B). (Today it wrongly emits OfType(B) because the match-all consumer contributes nothing to the
  // union.)
  EXPECT_EQ(filter->where_clause().elements().size(), 0u);
}

TEST(EventSubscriberFilterValidation, EveryBasicOperatorIsPreservedOnDedicatedBackbone)
{
  constexpr std::array allowedOperators{ua::FilterOperator::Equals,
    ua::FilterOperator::IsNull,
    ua::FilterOperator::GreaterThan,
    ua::FilterOperator::LessThan,
    ua::FilterOperator::GreaterThanOrEqual,
    ua::FilterOperator::LessThanOrEqual,
    ua::FilterOperator::Like,
    ua::FilterOperator::Not,
    ua::FilterOperator::Between,
    ua::FilterOperator::InList,
    ua::FilterOperator::And,
    ua::FilterOperator::Or,
    ua::FilterOperator::Cast,
    ua::FilterOperator::BitwiseAnd,
    ua::FilterOperator::BitwiseOr};

  for (const auto filterOperator : allowedOperators)
  {
    Fixture fixture;
    auto subscriber = fixture.make();
    EventSubscription subscription;
    ua::EventFilter filter;
    filter.select_clauses().push_back(ua::SimpleAttributeOperand{});
    filter.where_clause().elements().push_back(make_operator_element(filterOperator));
    subscription.filter = std::move(filter);

    std::optional<SubscribeResult> result;
    subscriber->subscribe_async(
      std::move(subscription),
      [](EventNotification) {},
      [&](SubscribeResult subscribed) { result = std::move(subscribed); });
    fixture.drain();

    ASSERT_TRUE(result.has_value() && result->is_good());
    ASSERT_EQ(fixture.ops->creates.size(), 1u);
    const auto& wireElements = fixture.ops->creates.front().filter.where_clause().elements();
    ASSERT_EQ(wireElements.size(), 1u);
    EXPECT_EQ(wireElements[0].filter_operator(), filterOperator);
    EXPECT_EQ(EventSubscriberTestAccess::created_backbone_count(*subscriber), 1u);
  }
}

TEST(EventSubscriberFilterValidation, InViewAndRelatedToAreRejectedWithDetailBeforeBackboneIo)
{
  for (const auto filterOperator :
    {ua::FilterOperator::InView, ua::FilterOperator::RelatedTo, static_cast<ua::FilterOperator>(999)})
  {
    Fixture fixture;
    auto subscriber = fixture.make();
    EventSubscription subscription;
    ua::EventFilter filter;
    filter.select_clauses().push_back(ua::SimpleAttributeOperand{});
    filter.where_clause().elements().push_back(make_operator_element(filterOperator));
    subscription.filter = std::move(filter);

    std::optional<SubscribeResult> result;
    subscriber->subscribe_async(
      std::move(subscription),
      [](EventNotification) {},
      [&](SubscribeResult subscribed) { result = std::move(subscribed); });

    EXPECT_FALSE(result.has_value()) << "async completion must run on the configured executor";
    fixture.drain();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status_code(), StatusCode{Status::BadFilterOperatorInvalid});
    ASSERT_TRUE(result->shared_detail());
    EXPECT_EQ(result->shared_detail()->source, "client.tier2.event_subscriber.invalid_where_operator");
    EXPECT_TRUE(fixture.ops->creates.empty());
    EXPECT_TRUE(fixture.ops->modifies.empty());
  }
}

// --- Demux (CL-EVT-002) ---

TEST(EventSubscriberDemux, PublishedEventReachesOnlyTheMatchingConsumer)
{
  Fixture f;
  auto subscriber = f.make();

  std::vector<ua::NodeId> aDelivered;
  std::vector<ua::NodeId> bDelivered;

  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification event) { aDelivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(
    typeB, [&](EventNotification event) { bDelivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();

  ASSERT_EQ(f.ops->creates.size(), 1u);
  // on_publish keys on the backbone's CLIENT handle (what the server echoes in EventFieldList.client_handle).
  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;

  subscriber->on_publish_events_async(backboneHandle, {make_event(0, typeA)}, [] {});
  f.drain();
  subscriber->on_publish_events_async(backboneHandle, {make_event(0, typeB)}, [] {});
  f.drain();

  ASSERT_EQ(aDelivered.size(), 1u);
  EXPECT_EQ(aDelivered.front(), typeA);
  ASSERT_EQ(bDelivered.size(), 1u);
  EXPECT_EQ(bDelivered.front(), typeB);
}

// `OfType` is subtype-inclusive (OPC 10000-4 7.4.4.5): a server given OfType(ConditionType) delivers every
// alarm SUBTYPE through that filter, so the client-side demux must accept subtypes of the requested type.
// The second consumer is what makes this observable - it turns the backbone's filter into a union, so the
// demux, not the server's filter, decides who sees the event.
TEST(EventSubscriberDemux, ConsumerReceivesSubtypesOfTheTypeItRequested)
{
  Fixture f;
  // typeA has a subtype; the server will deliver an event OF THAT SUBTYPE through OfType(typeA).
  const ua::NodeId subtypeOfA{ua::ObjectTypeId::SemanticChangeEventType};
  f.ops->subtypeChildren[typeA] = {subtypeOfA};
  auto subscriber = f.make();

  std::vector<ua::NodeId> aDelivered;
  std::vector<ua::NodeId> bDelivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification event) { aDelivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  // The SECOND consumer is what makes this observable: it turns the backbone's filter into a union, so
  // the client-side demux - not the server's filter - decides who sees the subtype event.
  subscriber->subscribe_to_type_async(
    typeB, [&](EventNotification event) { bDelivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  ASSERT_EQ(f.ops->creates.size(), 1u) << "precondition: both consumers coalesced onto one backbone";

  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;
  subscriber->on_publish_events_async(backboneHandle, {make_event(0, subtypeOfA)}, [] {});
  f.drain();

  ASSERT_EQ(aDelivered.size(), 1u) << "a subtype of the requested type must reach the consumer that asked "
                                      "for the supertype - this is what OfType means";
  EXPECT_EQ(aDelivered.front(), subtypeOfA);
  EXPECT_TRUE(bDelivered.empty()) << "and must NOT reach the consumer that asked for an unrelated type";
}

// The closure is transitive, not one level: an alarm type is typically several HasSubtype hops below
// ConditionType, and a one-level expansion would still drop it.
TEST(EventSubscriberDemux, SubtypeMatchIsTransitive)
{
  Fixture f;
  const ua::NodeId child{ua::ObjectTypeId::SemanticChangeEventType};
  const ua::NodeId grandchild{ua::ObjectTypeId::GeneralModelChangeEventType};
  f.ops->subtypeChildren[typeA] = {child};
  f.ops->subtypeChildren[child] = {grandchild};
  auto subscriber = f.make();

  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification event) { delivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;
  subscriber->on_publish_events_async(backboneHandle, {make_event(0, grandchild)}, [] {});
  f.drain();

  ASSERT_EQ(delivered.size(), 1u) << "a type two HasSubtype hops down still IS-A the requested type";
  EXPECT_EQ(delivered.front(), grandchild);
}

// A sibling type that is NOT in the closure must still be filtered out - the fix must not become
// "deliver everything to everyone", which would be a different silent defect (cross-talk between
// consumers) wearing the same clothes.
TEST(EventSubscriberDemux, UnrelatedTypeIsStillFilteredOut)
{
  Fixture f;
  f.ops->subtypeChildren[typeA] = {ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType}};
  auto subscriber = f.make();

  std::vector<ua::NodeId> aDelivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification event) { aDelivered.push_back(event.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;
  subscriber->on_publish_events_async(backboneHandle, {make_event(0, typeB)}, [] {});
  f.drain();

  EXPECT_TRUE(aDelivered.empty()) << "a type outside the requested closure must not be delivered";
}

// When the hierarchy cannot be resolved the consumer is ISOLATED on its own backbone, so the SERVER's
// OfType filter is the only filter deciding what it sees. Falling back to exact matching would be the
// original defect, not a degraded mode of the fix.
TEST(EventSubscriberDemux, UnresolvableHierarchyIsolatesTheConsumerOnItsOwnBackbone)
{
  Fixture f;
  f.ops->subtypeStatus = ua::Status::BadNodeIdUnknown;
  auto subscriber = f.make();

  std::optional<SubscribeResult> aResult;
  std::vector<ua::NodeId> aDelivered;
  subscriber->subscribe_to_type_async(
    typeA,
    [&](EventNotification event) { aDelivered.push_back(event.eventTypeId); },
    [&](SubscribeResult r) { aResult = std::move(r); });
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  ASSERT_TRUE(aResult && aResult->is_good()) << "an unresolvable hierarchy must not fail the subscribe";
  ASSERT_EQ(f.ops->creates.size(), 2u)
    << "the consumer whose closure could not be resolved gets its OWN backbone";

  // On its own backbone every delivered event is for it, subtype or not - the server filtered already.
  const std::uint32_t isolatedHandle = f.ops->creates[0].clientHandle;
  subscriber->on_publish_events_async(
    isolatedHandle, {make_event(0, ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType})}, [] {});
  f.drain();
  EXPECT_EQ(aDelivered.size(), 1u)
    << "on a dedicated backbone the server's OfType filter is authoritative; nothing is dropped locally";
}

// The client-side type test acts on the subtype closure, so an Uncertain closure is not used: the consumer is
// isolated on its own backbone exactly as for an unresolvable one, and nothing is cached.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(EventSubscriberDemux, AnUncertainHierarchyIsNotUsedAndIsolatesTheConsumer)
{
  Fixture f;
  f.ops->subtypeStatus = ua::Status::UncertainLastUsableValue;
  auto subscriber = f.make();

  std::optional<SubscribeResult> aResult;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult r) { aResult = std::move(r); });
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  ASSERT_TRUE(aResult.has_value()) << "the subscribe completes";
  EXPECT_TRUE(aResult->is_good()) << "an Uncertain hierarchy must not fail the subscribe";
  EXPECT_GE(f.ops->creates.size(), 2u) << "the consumer whose closure was Uncertain gets its OWN backbone";
  EXPECT_EQ(f.ops->subtypeResolveCalls.size(), 3u) << "an Uncertain closure is not cached";
}

// The hierarchy is server state that cannot change within a session, so a second consumer asking for the
// same type must not pay another round-trip.
TEST(EventSubscriberDemux, SubtypeClosureIsResolvedOncePerType)
{
  Fixture f;
  f.ops->subtypeChildren[typeA] = {ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType}};
  auto subscriber = f.make();

  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  subscriber->subscribe_to_type_async(typeA, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();

  EXPECT_EQ(f.ops->subtypeResolveCalls.size(), 1u)
    << "the second subscribe for the same type must be served from the per-Connection cache";
}

TEST(EventSubscriberDemux, FieldCountMismatchDropsTheEvent)
{
  Fixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();

  ua::EventFieldList shortList;
  shortList.event_fields().push_back(ua::Variant{typeA});  // only 1 field vs 8 in the filter
  subscriber->on_publish_events_async(f.ops->creates[0].clientHandle, {shortList}, [] {});
  f.drain();
  EXPECT_TRUE(delivered.empty());  // CL-EVT-002: field-count mismatch -> drop
}

// The inbound demux keys on the CLIENT-assigned backbone handle (what the server echoes in
// EventFieldList.client_handle) - NOT the server-assigned monitoredItemId. A real Publish carries no
// monitored-item id, so keying by it could never match; keying by the client handle is the only wire-correct
// route (and is reconnect-stable). Falsifiable because the fake assigns a distinct clientHandle vs
// monitoredItemId(500).
TEST(EventSubscriberDemux, DispatchKeysByBackboneClientHandleNotServerMonitoredItemId)
{
  Fixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();

  ASSERT_EQ(f.ops->creates.size(), 1u);
  const std::uint32_t clientHandle = f.ops->creates[0].clientHandle;  // the inbound demux key
  ASSERT_NE(clientHandle, 500u) << "test needs distinct client-handle vs server monitoredItemId to falsify";

  subscriber->on_publish_events_async(clientHandle, {make_event(clientHandle, typeA)}, [] {});
  f.drain();

  ASSERT_EQ(delivered.size(), 1u) << "an event keyed by the backbone client handle must dispatch";
  EXPECT_EQ(delivered.front(), typeA);
}

// BaseEventType/SourceName is a String (OPC 10000-5 section 6.4.2), not a LocalizedText. The SDK's own
// server side agrees: ua::BaseEvent::sourceName is a String, and that is what goes on the wire.
// A client that decodes the field as a LocalizedText silently surfaces nothing, because the
// conversion fails and the guarded assignment never runs. This test carries the field as a real
// server carries it.
TEST(EventSubscriberDecode, SurfacesStringSourceName)
{
  Fixture f;
  auto subscriber = f.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { received = std::move(e); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(backboneHandle, typeA);
  event.event_fields()[3] = ua::Variant{ua::String{"Tank"}};  // SourceName, as a server sends it
  subscriber->on_publish_events_async(backboneHandle, {event}, [] {});
  f.drain();

  ASSERT_TRUE(received.has_value());
  EXPECT_EQ(static_cast<std::string_view>(received->sourceName), "Tank")
    << "SourceName is a String on the wire; decoding it as another type loses it silently";
}

// --- Three-state selected-field surfacing (CL-MI-017, Part 4 section 7.22.3 lines 8898-8906) ---
// A selected field that is ABSENT arrives as an empty Variant on the wire; decode_notification must surface
// it as nullopt (positionally), preserving the "field absent" state distinctly from a value - not collapse it
// to a default-constructed Variant. Now reachable end-to-end because the inbound demux is wired
// (feed_publish_response -> on_publish_events_async).
// @verifies CL-MI-017
// @relation(CL-MI-017, scope=function)
TEST(EventSubscriberDecode, DecodesNullSelectedFieldAsNullopt)
{
  Fixture f;
  auto subscriber = f.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { received = std::move(e); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(backboneHandle, typeA);
  event.event_fields()[3] = ua::Variant{};  // SourceName absent (empty Variant == null on the wire)
  subscriber->on_publish_events_async(backboneHandle, {event}, [] {});
  f.drain();

  ASSERT_TRUE(received.has_value())
    << "a well-formed event carrying one null selected field must still be delivered";
  ASSERT_EQ(received->fields.size(), 8u);
  EXPECT_FALSE(received->fields[3].has_value())
    << "an absent (empty Variant) selected field must surface as nullopt, not a default value";
  EXPECT_TRUE(received->fields[7].has_value())
    << "a present field (Severity) alongside a null one must still carry its value";
}

// A selected field that is present-but-unavailable arrives as a Variant carrying a StatusCode; decode must
// surface it as a value (the StatusCode-bearing Variant), NOT collapse it to nullopt - the unavailability
// reason (per-field StatusCode) must survive verbatim to the user.
// @verifies CL-MI-017
// @relation(CL-MI-017, scope=function)
TEST(EventSubscriberDecode, DecodesStatusCodeSelectedFieldAsValue)
{
  Fixture f;
  auto subscriber = f.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { received = std::move(e); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t backboneHandle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(backboneHandle, typeA);
  event.event_fields()[3] = ua::Variant{ua::StatusCode{ua::Status::BadNoData}};  // SourceName unavailable
  subscriber->on_publish_events_async(backboneHandle, {event}, [] {});
  f.drain();

  ASSERT_TRUE(received.has_value());
  ASSERT_EQ(received->fields.size(), 8u);
  ASSERT_TRUE(received->fields[3].has_value())
    << "a StatusCode-carrying field must NOT be collapsed to null - the unavailability reason is preserved";
  ASSERT_TRUE(received->fields[3]->is_status_code());
  EXPECT_EQ(received->fields[3]->as<ua::StatusCode>(), ua::StatusCode{ua::Status::BadNoData})
    << "the exact per-field StatusCode must survive decode verbatim";
}

// @verifies CL-AUDIT-004
// @verifies CL-AUDIT-005
// @relation(CL-AUDIT-004, CL-AUDIT-005, scope=function)
TEST(EventSubscriberAuditDecode, SelectsAndDecodesAllMandatoryAuditFields)
{
  Fixture fixture;
  auto subscriber = fixture.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditEventType},
    [&](EventNotification event) { received = std::move(event); },
    [](SubscribeResult) {});
  fixture.drain();
  ASSERT_EQ(fixture.ops->creates.size(), 1U);
  const auto& created = fixture.ops->creates.front();
  for (const std::string_view expected :
    {"ActionTimeStamp", "Status", "ServerId", "ClientAuditEntryId", "ClientUserId"})
  {
    EXPECT_TRUE(std::ranges::any_of(created.filter.select_clauses(),
      [expected](const auto& clause)
      {
        return clause.browse_path().size() == 1 &&
               static_cast<std::string_view>(clause.browse_path()[0].name()) == expected;
      }))
      << expected;
  }

  auto event = make_audit_event(created.clientHandle, created.filter);
  subscriber->on_publish_events_async(created.clientHandle, {std::move(event)}, [] {});
  fixture.drain();

  ASSERT_TRUE(received.has_value());
  ASSERT_TRUE(received->audit.has_value());
  EXPECT_TRUE(received->audit->status);
  EXPECT_EQ(received->audit->serverId, ua::String{"server-1"});
  EXPECT_EQ(received->audit->clientAuditEntryId, ua::String{"audit-42"});
  EXPECT_EQ(received->audit->clientUserId, ua::String{"operator"});
}

// @verifies CL-AUDIT-004
// @relation(CL-AUDIT-004, scope=function)
TEST(EventSubscriberAuditDecode, MissingMandatoryAuditFieldAdvisesAndStillDeliversGenericEvent)
{
  SinkFixture fixture;
  auto subscriber = fixture.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditEventType},
    [&](EventNotification event) { received = std::move(event); },
    [](SubscribeResult) {});
  fixture.drain();
  const auto& created = fixture.ops->creates.front();
  auto event = make_audit_event(created.clientHandle, created.filter);
  for (std::size_t index = 0; index < created.filter.select_clauses().size(); ++index)
  {
    const auto& path = created.filter.select_clauses()[index].browse_path();
    if (path.size() == 1 && static_cast<std::string_view>(path[0].name()) == "ServerId")
      event.event_fields()[index] = ua::Variant{};
  }

  subscriber->on_publish_events_async(created.clientHandle, {std::move(event)}, [] {});
  fixture.drain();

  ASSERT_TRUE(received.has_value()) << "audit-specific damage must not hide the generic event";
  EXPECT_FALSE(received->audit.has_value());
  EXPECT_EQ(fixture.observer->advisoryCount.load(), 1);
  ASSERT_NE(fixture.observer->lastDetail, nullptr);
  EXPECT_EQ(fixture.observer->lastDetail->code, "AuditEventMandatoryFieldInvalid");
}

// @verifies CL-AUDIT-006
// @relation(CL-AUDIT-006, scope=function)
TEST(EventSubscriberAuditDecode, RecognisesStandardCategoriesAndUnknownCustomSubtype)
{
  Fixture fixture;
  auto subscriber = fixture.make();
  std::vector<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditEventType},
    [&](EventNotification event) { received.push_back(std::move(event)); },
    [](SubscribeResult) {});
  fixture.drain();
  const auto& created = fixture.ops->creates.front();

  const std::array eventTypes{
    ua::NodeId{ua::ObjectTypeId::AuditCertificateInvalidEventType},
    ua::NodeId{ua::ObjectTypeId::AuditOpenSecureChannelEventType},
    ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType},
    ua::NodeId{ua::ObjectTypeId::AuditWriteUpdateEventType},
    ua::NodeId{ua::ObjectTypeId::AuditUpdateMethodEventType},
    ua::NodeId{2, 999U},
  };
  for (const auto& eventType : eventTypes)
  {
    auto event = make_audit_event(created.clientHandle, created.filter, eventType);
    subscriber->on_publish_events_async(created.clientHandle, {std::move(event)}, [] {});
    fixture.drain();
  }

  ASSERT_EQ(received.size(), eventTypes.size())
    << "the AuditEvent root consumer must receive standard and unknown server-specific subtypes";
  ASSERT_TRUE(received[0].auditSubtype);
  EXPECT_EQ(received[0].auditSubtype->category, ua::client::AuditEventCategory::Security);
  ASSERT_TRUE(received[1].auditSubtype);
  EXPECT_EQ(received[1].auditSubtype->category, ua::client::AuditEventCategory::Channel);
  EXPECT_EQ(received[1].auditSubtype->secureChannelId, ua::String{"channel-7"});
  ASSERT_TRUE(received[2].auditSubtype);
  EXPECT_EQ(received[2].auditSubtype->category, ua::client::AuditEventCategory::Session);
  EXPECT_EQ(received[2].auditSubtype->sessionId, ua::NodeId(2, 700U));
  ASSERT_TRUE(received[3].auditSubtype);
  EXPECT_EQ(received[3].auditSubtype->category, ua::client::AuditEventCategory::Update);
  ASSERT_TRUE(received[4].auditSubtype);
  EXPECT_EQ(received[4].auditSubtype->category, ua::client::AuditEventCategory::UpdateMethod);
  EXPECT_EQ(received[4].auditSubtype->methodId, ua::NodeId(2, 701U));
  EXPECT_TRUE(received[4].auditSubtype->inputArguments.has_value());
  ASSERT_TRUE(received[5].auditSubtype);
  EXPECT_EQ(received[5].auditSubtype->category, ua::client::AuditEventCategory::UnknownSubtype);
  EXPECT_TRUE(received[5].audit.has_value()) << "unknown subtypes retain the base AuditEvent payload";
}

// @verifies CL-AUDIT-007
// @relation(CL-AUDIT-007, scope=function)
TEST(EventSubscriberAuditDecode, SecurityStatusCodeIdIsSelectedSurfacedAndOptional)
{
  SinkFixture fixture;
  auto subscriber = fixture.make();
  std::vector<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditSessionEventType},
    [&](EventNotification event) { received.push_back(std::move(event)); },
    [](SubscribeResult) {});
  fixture.drain();
  const auto& created = fixture.ops->creates.front();

  const auto statusClause = std::ranges::find_if(created.filter.select_clauses(),
    [](const auto& clause)
    {
      return clause.browse_path().size() == 1 &&
             static_cast<std::string_view>(clause.browse_path()[0].name()) == "StatusCodeId";
    });
  ASSERT_NE(statusClause, created.filter.select_clauses().end());
  EXPECT_EQ(statusClause->type_definition_id(), ua::NodeId{ua::ObjectTypeId::AuditSecurityEventType});

  auto present = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType});
  auto absent = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditActivateSessionEventType});
  auto wrongType = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditCancelEventType});
  const auto statusIndex =
    static_cast<std::size_t>(std::distance(created.filter.select_clauses().begin(), statusClause));
  absent.event_fields()[statusIndex] = ua::Variant{};
  wrongType.event_fields()[statusIndex] = ua::Variant{ua::String{"not-a-status-code"}};

  subscriber->on_publish_events_async(
    created.clientHandle, {std::move(present), std::move(absent), std::move(wrongType)}, [] {});
  fixture.drain();

  ASSERT_EQ(received.size(), 3U);
  ASSERT_TRUE(received[0].auditSubtype);
  ASSERT_TRUE(received[0].auditSubtype->statusCodeId);
  EXPECT_EQ(*received[0].auditSubtype->statusCodeId, ua::StatusCode{ua::Status::BadUserAccessDenied});
  ASSERT_TRUE(received[1].auditSubtype);
  EXPECT_FALSE(received[1].auditSubtype->statusCodeId.has_value());
  ASSERT_TRUE(received[2].auditSubtype);
  EXPECT_FALSE(received[2].auditSubtype->statusCodeId.has_value());
  EXPECT_EQ(fixture.observer->advisoryCount.load(), 1)
    << "absence is conformant; only the present-but-wrong-typed value is advisory-worthy";
  ASSERT_NE(fixture.observer->lastDetail, nullptr);
  EXPECT_EQ(fixture.observer->lastDetail->code, "AuditEventMandatoryFieldInvalid");
}

// @verifies CL-AUDIT-008
// @relation(CL-AUDIT-008, scope=function)
TEST(EventSubscriberAuditDecode, ChannelAndCreateSessionExposeSameSecureChannelId)
{
  Fixture fixture;
  auto subscriber = fixture.make();
  std::vector<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditEventType},
    [&](EventNotification event) { received.push_back(std::move(event)); },
    [](SubscribeResult) {});
  fixture.drain();
  const auto& created = fixture.ops->creates.front();

  auto channel = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditOpenSecureChannelEventType});
  auto session = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType});
  std::size_t secureChannelClauseCount = 0;
  for (std::size_t index = 0; index < created.filter.select_clauses().size(); ++index)
  {
    const auto& clause = created.filter.select_clauses()[index];
    if (clause.browse_path().size() != 1 ||
        static_cast<std::string_view>(clause.browse_path()[0].name()) != "SecureChannelId")
      continue;
    ++secureChannelClauseCount;
    const bool channelDeclaration =
      clause.type_definition_id() == ua::NodeId{ua::ObjectTypeId::AuditChannelEventType};
    const bool createSessionDeclaration =
      clause.type_definition_id() == ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType};
    ASSERT_TRUE(channelDeclaration || createSessionDeclaration);
    channel.event_fields()[index] =
      channelDeclaration ? ua::Variant{ua::String{"shared-channel-42"}} : ua::Variant{};
    session.event_fields()[index] =
      createSessionDeclaration ? ua::Variant{ua::String{"shared-channel-42"}} : ua::Variant{};
  }
  ASSERT_EQ(secureChannelClauseCount, 2U)
    << "the duplicate BrowseName must be selected from both declaring EventTypes";

  subscriber->on_publish_events_async(created.clientHandle, {std::move(channel), std::move(session)}, [] {});
  fixture.drain();

  ASSERT_EQ(received.size(), 2U);
  ASSERT_TRUE(received[0].auditSubtype);
  ASSERT_TRUE(received[1].auditSubtype);
  EXPECT_EQ(received[0].auditSubtype->category, ua::client::AuditEventCategory::Channel);
  EXPECT_EQ(received[1].auditSubtype->category, ua::client::AuditEventCategory::Session);
  EXPECT_EQ(received[0].auditSubtype->secureChannelId, ua::String{"shared-channel-42"});
  EXPECT_EQ(received[1].auditSubtype->secureChannelId, received[0].auditSubtype->secureChannelId);
}

// @verifies CL-AUDIT-008
// @relation(CL-AUDIT-008, scope=function)
TEST(EventSubscriberAuditDecode, MalformedCreateSessionSecureChannelIdAdvisesWithoutDroppingEvent)
{
  SinkFixture fixture;
  auto subscriber = fixture.make();
  std::vector<EventNotification> received;
  subscriber->subscribe_to_type_async(
    ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType},
    [&](EventNotification event) { received.push_back(std::move(event)); },
    [](SubscribeResult) {});
  fixture.drain();
  const auto& created = fixture.ops->creates.front();
  const auto secureChannelClause = std::ranges::find_if(created.filter.select_clauses(),
    [](const auto& clause)
    {
      return clause.type_definition_id() == ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType} &&
             clause.browse_path().size() == 1 &&
             static_cast<std::string_view>(clause.browse_path()[0].name()) == "SecureChannelId";
    });
  ASSERT_NE(secureChannelClause, created.filter.select_clauses().end());
  const auto index =
    static_cast<std::size_t>(std::distance(created.filter.select_clauses().begin(), secureChannelClause));

  auto missing = make_audit_event(
    created.clientHandle, created.filter, ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType});
  auto wrongType = missing;
  missing.event_fields()[index] = ua::Variant{};
  wrongType.event_fields()[index] = ua::Variant{ua::NodeId{2, 42U}};
  subscriber->on_publish_events_async(
    created.clientHandle, {std::move(missing), std::move(wrongType)}, [] {});
  fixture.drain();

  ASSERT_EQ(received.size(), 2U);
  ASSERT_TRUE(received[0].auditSubtype);
  ASSERT_TRUE(received[1].auditSubtype);
  EXPECT_FALSE(received[0].auditSubtype->secureChannelId);
  EXPECT_FALSE(received[1].auditSubtype->secureChannelId);
  EXPECT_EQ(fixture.observer->advisoryCount.load(), 2);
  ASSERT_NE(fixture.observer->lastDetail, nullptr);
  EXPECT_EQ(fixture.observer->lastDetail->code, "AuditEventMandatoryFieldInvalid");
}

// --- CL-EVT-001/002: mandatory-field enforcement + drop-advisory ---
// The four fields Part 5 section 6.4.2 names as "shall always be returned as value and the Server is not
// allowed to return a StatusCode ... indicating an error" - EventId, EventType, Time, ReceiveTime - are
// enforced as present-as-value. A missing (empty Variant) or status-coded value in ANY of the four drops the
// event and fires ClientObserver::on_advisory_diagnostic (the malformed event must not be delivered
// silently). The OPTIONAL fields (SourceNode/SourceName/Message/Severity) stay best-effort and NEVER
// hard-drop.

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, WellFormedEventDispatchesAndPopulatesTimes)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { received = std::move(e); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  // Distinct (non-default) Time / ReceiveTime so the assertion proves decode_notification POPULATED them (a
  // default DateTime{} would pass trivially against the struct's default-constructed field).
  const ua::DateTime time{2026, 7, 21, 12, 30, 15.0};
  const ua::DateTime receiveTime{2026, 7, 21, 12, 30, 16.0};
  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[4] = ua::Variant{time};  // slot 4: Time
  event.event_fields()[5] = ua::Variant{receiveTime};  // slot 5: ReceiveTime
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  ASSERT_TRUE(received.has_value()) << "a well-formed event with all four mandatory fields must dispatch";
  EXPECT_EQ(f.observer->advisoryCount.load(), 0) << "a well-formed event raises no advisory";
  EXPECT_EQ(received->time, time) << "decode_notification must populate EventNotification.time (CL-EVT-001)";
  EXPECT_EQ(received->receiveTime, receiveTime)
    << "decode_notification must populate EventNotification.receiveTime (CL-EVT-001)";
}

// @verifies CL-MI-015
// @relation(CL-MI-015, scope=function)
TEST(EventSubscriberDecode, EventQueueOverflowDispatchesAndEmitsAdvisory)
{
  SinkFixture f;
  auto subscriber = f.make();
  const ua::NodeId overflowType{ua::ObjectTypeId::EventQueueOverflowEventType};
  std::vector<EventNotification> delivered;
  subscriber->subscribe_to_type_async(
    overflowType,
    [&delivered](EventNotification event) { delivered.push_back(std::move(event)); },
    [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  subscriber->on_publish_events_async(handle, {make_event(handle, overflowType)}, [] {});
  f.drain();

  ASSERT_EQ(delivered.size(), 1u) << "overflow remains ordinary event data";
  EXPECT_EQ(delivered.front().eventTypeId, overflowType);
  ASSERT_EQ(f.observer->advisoryCount.load(), 1);
  ASSERT_NE(f.observer->lastDetail, nullptr);
  EXPECT_EQ(f.observer->lastDetail->code, "EventQueueOverflow");
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.queue_overflow");
}

// @verifies CL-EVT-002
// @verifies CL-DIAG-003
// @relation(CL-DIAG-003, CL-EVT-002, scope=function)
TEST(EventSubscriberMandatoryField, FieldCountMismatchDropsAndAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();

  ua::EventFieldList shortList;
  shortList.event_fields().push_back(ua::Variant{typeA});  // 1 field vs 8 SelectClauses
  subscriber->on_publish_events_async(f.ops->creates[0].clientHandle, {shortList}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a field-count mismatch drops the malformed event";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1) << "the drop must surface an advisory (was log-only)";
  ASSERT_NE(f.observer->lastDetail, nullptr) << "the advisory ErrorDetail must never be discarded";
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.field_count_mismatch");
}

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, MissingEventIdDropsAndAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[0] = ua::Variant{};  // slot 0: EventId absent (empty Variant == null on the wire)
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a missing mandatory EventId drops the event (CL-EVT-001)";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1) << "the drop must surface an advisory";
  ASSERT_NE(f.observer->lastDetail, nullptr);
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.mandatory_field_missing");
}

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, StatusCodedEventIdDropsAndAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  // The server returned a StatusCode for EventId (the spec forbids this) - treat as malformed, not as value.
  event.event_fields()[0] = ua::Variant{ua::StatusCode{ua::Status::BadNoData}};
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a status-coded mandatory EventId drops the event (CL-EVT-001)";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1) << "the drop must surface an advisory";
  ASSERT_NE(f.observer->lastDetail, nullptr);
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.mandatory_field_status_coded");
}

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, MissingReceiveTimeDropsAndAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[5] = ua::Variant{};  // slot 5: ReceiveTime absent
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a missing mandatory ReceiveTime drops the event (CL-EVT-001)";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1) << "the drop must surface an advisory";
  ASSERT_NE(f.observer->lastDetail, nullptr);
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.mandatory_field_missing");
}

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, MissingTimeDropsAndAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[4] = ua::Variant{};  // slot 4: Time absent
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a missing mandatory Time drops the event (CL-EVT-001)";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1) << "the drop must surface an advisory";
}

// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, MissingEventTypeDropsAndNowAdvises)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::vector<ua::NodeId> delivered;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { delivered.push_back(e.eventTypeId); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[1] = ua::Variant{};  // slot 1: EventType absent
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  EXPECT_TRUE(delivered.empty()) << "a missing mandatory EventType drops the event (CL-EVT-001)";
  ASSERT_EQ(f.observer->advisoryCount.load(), 1)
    << "the EventType drop now surfaces an advisory (was log-only)";
  ASSERT_NE(f.observer->lastDetail, nullptr);
  EXPECT_EQ(f.observer->lastDetail->source, "client.tier2.event_subscriber.mandatory_field_missing");
}

// section 3.1 falsifiability pin (over-strict-enforcement guard). SourceName is NOT one of the four
// normatively guaranteed fields; an event that omits it (empty Variant) must STILL DISPATCH - surfacing
// SourceName as nullopt (CL-MI-017 three-state) - never drop. This test fails if anyone widens the hard-drop
// beyond the four mandatory fields.
// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, MissingNonMandatorySourceNameStillDispatched)
{
  SinkFixture f;
  auto subscriber = f.make();
  std::optional<EventNotification> received;
  subscriber->subscribe_to_type_async(
    typeA, [&](EventNotification e) { received = std::move(e); }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  ua::EventFieldList event = make_event(handle, typeA);
  event.event_fields()[3] = ua::Variant{};  // slot 3: SourceName absent (a NON-mandatory field)
  subscriber->on_publish_events_async(handle, {event}, [] {});
  f.drain();

  ASSERT_TRUE(received.has_value())
    << "an event missing only the OPTIONAL SourceName must STILL dispatch - the hard-drop is scoped to the "
       "four normatively-guaranteed fields, not all eight";
  EXPECT_EQ(f.observer->advisoryCount.load(), 0) << "omitting a non-mandatory field raises no advisory";
  ASSERT_EQ(received->fields.size(), 8u);
  EXPECT_FALSE(received->fields[3].has_value()) << "the absent SourceName surfaces as nullopt (CL-MI-017)";
}

// section 3.1 DoS pin: N malformed events in one publish -> O(N) advisories (one per drop, O(1) each), never
// O(N^2) or an unbounded storm. Pins that a flood of malformed events is handled linearly and none are
// dispatched.
// @verifies CL-EVT-001
// @relation(CL-EVT-001, scope=function)
TEST(EventSubscriberMandatoryField, ManyMalformedEventsProduceOneAdvisoryEachNoneDispatched)
{
  SinkFixture f;
  auto subscriber = f.make();
  int delivered = 0;
  subscriber->subscribe_to_type_async(typeA, [&](EventNotification) { ++delivered; }, [](SubscribeResult) {});
  f.drain();
  const std::uint32_t handle = f.ops->creates[0].clientHandle;

  constexpr int count = 100;
  std::vector<ua::EventFieldList> malformed;
  malformed.reserve(count);
  for (int i = 0; i < count; ++i)
  {
    ua::EventFieldList event = make_event(handle, typeA);
    event.event_fields()[0] = ua::Variant{};  // each event: missing EventId
    malformed.push_back(std::move(event));
  }
  subscriber->on_publish_events_async(handle, std::move(malformed), [] {});
  f.drain();

  EXPECT_EQ(delivered, 0) << "every malformed event is dropped";
  EXPECT_EQ(f.observer->advisoryCount.load(), count) << "exactly one advisory per dropped event (O(N))";
}

// --- Consumer delete: the S9 event MonitoredItemOwner path ---

TEST(EventSubscriberOwner, DeletingOneConsumerKeepsTheSharedBackbone)
{
  Fixture f;
  auto subscriber = f.make();

  std::optional<SubscribeResult> aResult;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult r) { aResult = std::move(r); });
  f.drain();
  subscriber->subscribe_to_type_async(typeB, [](EventNotification) {}, [](SubscribeResult) {});
  f.drain();
  ASSERT_TRUE(aResult && aResult->is_good());

  // Delete consumer A via the unified MonitoredItem self-action (owner == EventSubscriberImpl).
  std::optional<VoidResult> deleteResult;
  aResult->value().delete_async([&](VoidResult r) { deleteResult = r; });
  f.drain();

  ASSERT_TRUE(deleteResult && deleteResult->is_good());
  EXPECT_TRUE(f.ops->deletes.empty());  // MUST NOT delete the shared backbone
  EXPECT_EQ(EventSubscriberTestAccess::created_backbone_count(*subscriber), 1u);
  EXPECT_EQ(EventSubscriberTestAccess::consumer_count(*subscriber), 1u);  // only B remains
}

TEST(EventSubscriberOwner, LastConsumerOnDedicatedBackboneTearsItDown)
{
  Fixture f;
  auto subscriber = f.make();

  EventSubscription subscription;
  subscription.notifier = ua::NodeId{ua::ObjectId::Server};
  subscription.requestDedicatedBackbone = true;

  std::optional<SubscribeResult> result;
  subscriber->subscribe_async(
    subscription, [](EventNotification) {}, [&](SubscribeResult r) { result = std::move(r); });
  f.drain();
  ASSERT_TRUE(result && result->is_good());

  std::optional<VoidResult> deleteResult;
  result->value().delete_async([&](VoidResult r) { deleteResult = r; });
  f.drain();

  ASSERT_TRUE(deleteResult && deleteResult->is_good());
  EXPECT_EQ(f.ops->deletes.size(), 1u);  // dedicated backbone -> last consumer tears it down
  EXPECT_EQ(EventSubscriberTestAccess::created_backbone_count(*subscriber), 0u);
}

TEST(EventSubscriberOwner, DefaultServerBackboneIsKeptWarmOnLastConsumerDrop)
{
  Fixture f;
  auto subscriber = f.make();

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult r) { result = std::move(r); });
  f.drain();
  ASSERT_TRUE(result && result->is_good());

  std::optional<VoidResult> deleteResult;
  result->value().delete_async([&](VoidResult r) { deleteResult = r; });
  f.drain();

  ASSERT_TRUE(deleteResult && deleteResult->is_good());
  EXPECT_TRUE(f.ops->deletes.empty());  // default Server backbone kept warm (section 8.13.3)
  EXPECT_EQ(EventSubscriberTestAccess::consumer_count(*subscriber), 0u);
}

TEST(EventSubscriberOwner, UnsubscribeUnknownHandleIsIdempotentGood)
{
  Fixture f;
  auto subscriber = f.make();

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult r) { result = std::move(r); });
  f.drain();
  ASSERT_TRUE(result && result->is_good());

  std::optional<VoidResult> first;
  subscriber->unsubscribe_async(result->value(), [&](VoidResult r) { first = r; });
  f.drain();
  ASSERT_TRUE(first && first->is_good());

  // Second unsubscribe of the (now unknown) handle is idempotent Good (section 8.13.6).
  std::optional<VoidResult> second;
  subscriber->unsubscribe_async(result->value(), [&](VoidResult r) { second = r; });
  f.drain();
  ASSERT_TRUE(second && second->is_good());
}

// --- Entry validation (CL-MI-016) ---

TEST(EventSubscriberValidation, EmptySelectClausesRejectedAtEntry)
{
  Fixture f;
  auto subscriber = f.make();

  EventSubscription subscription;
  subscription.filter = ua::EventFilter{};  // present but empty SelectClauses

  std::optional<SubscribeResult> result;
  subscriber->subscribe_async(
    subscription, [](EventNotification) {}, [&](SubscribeResult r) { result = std::move(r); });
  // Rejected synchronously at the entry point - no strand hop, no backbone create.
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_uint32(), StatusCode{Status::BadEventFilterInvalid}.as_uint32());
  EXPECT_TRUE(f.ops->creates.empty());
}

// --- Lifetime: weak owner, no strong cycle (own-strand component) ---

TEST(EventSubscriberLifetime, EventItemHoldsWeakOwnerNoStrongCycle)
{
  Fixture f;
  auto subscriber = f.make();

  std::optional<SubscribeResult> result;
  subscriber->subscribe_to_type_async(
    typeA, [](EventNotification) {}, [&](SubscribeResult r) { result = std::move(r); });
  f.drain();
  ASSERT_TRUE(result && result->is_good());
  MonitoredItem item = result->value();

  // The handle holds only a weak owner ref: the subscriber is the sole strong owner.
  EXPECT_EQ(subscriber.use_count(), 1L);

  subscriber.reset();  // drop the only strong ref

  // A self-action on the orphaned handle fails Bad_ConnectionClosed (the weak owner lock fails).
  std::optional<VoidResult> deleteResult;
  item.delete_async([&](VoidResult r) { deleteResult = r; });
  f.drain();
  ASSERT_TRUE(deleteResult.has_value());
  EXPECT_TRUE(deleteResult->is_bad());
  EXPECT_EQ(deleteResult->status_code().as_uint32(), StatusCode{Status::BadConnectionClosed}.as_uint32());
}

}  // namespace
