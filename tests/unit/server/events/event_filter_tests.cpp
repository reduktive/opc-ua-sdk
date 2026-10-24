// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_value.h"
#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_base_event.h"
#include "ua_byte_string.h"
#include "ua_compiled_event_filter.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_element_operand.h"
#include "ua_event_filter.h"
#include "ua_event_type_model.h"
#include "ua_expanded_node_id.h"
#include "ua_filter_operator.h"
#include "ua_generic_event.h"
#include "ua_guid.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_to_string.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_simple_attribute_operand.h"
#include "ua_attribute_operand.h"
#include "ua_status_code.h"
#include "ua_session_security.h"

#include "access_control_test_support.h"
#include "ua_access_control.h"
#include "ua_default_namespace.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace ua::server
{

struct CompiledEventFilterTestAccess
{
  static bool retains_declaration_accessors(const CompiledEventFilter& filter)
  {
    if (std::ranges::any_of(filter.mSelectClauses,
          [](const ResolvedSelectClause& clause) { return clause.declarationAccessor.has_value(); }))
    {
      return true;
    }
    for (const auto& element : filter.mWhereElements)
    {
      for (const auto& operand : element.operands)
      {
        if (const auto* clause = std::get_if<ResolvedSelectClause>(&operand);
            clause && clause->declarationAccessor.has_value())
        {
          return true;
        }
      }
    }
    return false;
  }
};

}  // namespace ua::server

namespace
{

class EventFilterTypeModelFixture
{
public:
  EventFilterTypeModelFixture()
    : mAddressSpace(AddressSpace::create("urn:test:event-filter-model", mThreadPool.get_executor()))
  {
    RolePermissionType permission;
    permission.role_id() = ua::test_helpers::test_access_role_id();
    permission.permissions() = ua::test_helpers::all_permissions();
    for (uint16_t namespaceIndex = 0; namespaceIndex < 2; ++namespaceIndex)
    {
      auto configurable = std::dynamic_pointer_cast<default_ns::Namespace>(
        mAddressSpace.namespace_array().get_namespace(namespaceIndex));
      if (!configurable)
        throw std::logic_error{"the Event model fixture requires configurable namespaces"};
      configurable->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
    }
    const auto baseEventType =
      create(NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType, "BaseEventType");
    const auto conditionType =
      create(NodeId{ObjectTypeId::ConditionType}, NodeClass::ObjectType, "ConditionType");
    const auto acknowledgeableType = create(NodeId{ObjectTypeId::AcknowledgeableConditionType},
      NodeClass::ObjectType,
      "AcknowledgeableConditionType");
    const auto alarmType =
      create(NodeId{ObjectTypeId::AlarmConditionType}, NodeClass::ObjectType, "AlarmConditionType");
    add_supertype(conditionType, baseEventType);
    add_supertype(acknowledgeableType, baseEventType);
    add_supertype(alarmType, baseEventType);

    const auto aggregates =
      create(NodeId{ReferenceTypeId::Aggregates}, NodeClass::ReferenceType, "Aggregates");
    const NodeId customAggregateId{1, 1950001u};
    const auto customAggregate =
      create(customAggregateId, NodeClass::ReferenceType, "HasEventFieldComponent");
    add_supertype(customAggregate, aggregates);

    const auto enabledState = create(NodeId{1, 1950010u}, NodeClass::Variable, "EnabledState");
    const auto enabledId = create(NodeId{1, 1950011u}, NodeClass::Variable, "Id");
    add_child(conditionType, enabledState, NodeId{ReferenceTypeId::HasComponent});
    add_child(enabledState, enabledId, NodeId{ReferenceTypeId::HasProperty});

    const auto acknowledge = create(NodeId{1, 1950020u}, NodeClass::Method, "Acknowledge");
    const auto acknowledgeInput = create(NodeId{1, 1950021u}, NodeClass::Variable, "InputArguments");
    add_child(acknowledgeableType, acknowledge, NodeId{ReferenceTypeId::HasComponent});
    add_child(acknowledge, acknowledgeInput, NodeId{ReferenceTypeId::HasProperty});

    const auto shelvingState = create(NodeId{1, 1950030u}, NodeClass::Object, "ShelvingState");
    const auto currentState = create(NodeId{1, 1950031u}, NodeClass::Variable, "CurrentState");
    const auto currentId = create(NodeId{1, 1950032u}, NodeClass::Variable, "Id");
    const auto unshelveTime = create(NodeId{1, 1950033u}, NodeClass::Variable, "UnshelveTime");
    const auto timedShelve = create(NodeId{1, 1950034u}, NodeClass::Method, "TimedShelve");
    const auto timedShelveInput = create(NodeId{1, 1950035u}, NodeClass::Variable, "InputArguments");
    add_child(alarmType, shelvingState, customAggregateId);
    add_child(shelvingState, currentState, NodeId{ReferenceTypeId::HasComponent});
    add_child(currentState, currentId, NodeId{ReferenceTypeId::HasProperty});
    add_child(shelvingState, unshelveTime, NodeId{ReferenceTypeId::HasProperty});
    add_child(shelvingState, timedShelve, NodeId{ReferenceTypeId::HasComponent});
    add_child(timedShelve, timedShelveInput, NodeId{ReferenceTypeId::HasProperty});
  }

  ~EventFilterTypeModelFixture()
  {
    mThreadPool.join();
  }

  CompiledEventFilterResult compile(EventFilter filter)
  {
    std::promise<event_type_model::SelectClauseStatusesResult> promise;
    auto future = promise.get_future();
    event_type_model::validate_select_clauses_async(mAddressSpace,
      filter,
      [&promise](event_type_model::SelectClauseStatusesResult result)
      { promise.set_value(std::move(result)); });
    auto modelStatuses = future.get();
    return CompiledEventFilter::compile(filter, {}, std::move(modelStatuses).value());
  }

  event_type_model::SelectClauseModelsResult resolve(const EventFilter& filter)
  {
    std::promise<event_type_model::SelectClauseModelsResult> promise;
    auto future = promise.get_future();
    event_type_model::resolve_select_clause_models_async(mAddressSpace,
      filter,
      [&promise](event_type_model::SelectClauseModelsResult result)
      { promise.set_value(std::move(result)); });
    return future.get();
  }

  AddressSpace address_space() const
  {
    return mAddressSpace;
  }

private:
  NodeAccessor create(NodeId nodeId, NodeClass nodeClass, std::string_view browseName)
  {
    auto node = mAddressSpace.try_create_node_sync(nodeId, nodeClass).value();
    node.set_browse_name(QualifiedName{0, String{browseName}});
    return node;
  }

  static void add_supertype(NodeAccessor subtype, const NodeAccessor& supertype)
  {
    subtype.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, supertype.get_node_id(), false);
  }

  static void add_child(NodeAccessor parent, const NodeAccessor& child, const NodeId& referenceType)
  {
    parent.add_reference_sync(referenceType, child.get_node_id(), true);
  }

  boost::asio::thread_pool mThreadPool{2};
  AddressSpace mAddressSpace;
};

// --- Helper: build a SimpleAttributeOperand for a BaseEventType field ---

SimpleAttributeOperand make_select_clause(std::string_view fieldName)
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, String{fieldName}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  return clause;
}

// --- Helper: build a minimal valid EventFilter with select clauses only ---

EventFilter make_select_only_filter(std::initializer_list<std::string_view> fields)
{
  EventFilter filter;
  for (auto field : fields)
    filter.select_clauses().push_back(make_select_clause(field));
  return filter;
}

// --- Helper: build a LiteralOperand RefStructure ---

RefStructure<Structure> make_literal(Variant value)
{
  auto lit = std::make_unique<LiteralOperand>();
  lit->value() = std::move(value);
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(lit);
  return ref;
}

// --- Helper: build an ElementOperand RefStructure ---

RefStructure<Structure> make_element_ref(uint32_t index)
{
  auto elem = std::make_unique<ElementOperand>();
  elem->index() = index;
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(elem);
  return ref;
}

// --- Helper: build a SimpleAttributeOperand RefStructure for where clause ---

RefStructure<Structure> make_sao_operand(std::string_view fieldName)
{
  auto sao = std::make_unique<SimpleAttributeOperand>();
  sao->type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  sao->browse_path().push_back(QualifiedName{0, String{fieldName}});
  sao->attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(sao);
  return ref;
}

// --- Helper: build a ConditionId SimpleAttributeOperand (empty browse path + NodeId attribute) ---

RefStructure<Structure> make_condition_id_operand()
{
  auto sao = std::make_unique<SimpleAttributeOperand>();
  sao->type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  // browse_path intentionally empty - selects the instance NodeId (ConditionId) per Part 4 section 7.4.4.5
  sao->attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(sao);
  return ref;
}

// --- Helper: add a where clause element ---

void add_where_element(
  EventFilter& filter, FilterOperator op, std::initializer_list<RefStructure<Structure>> operands)
{
  ContentFilterElement element;
  element.filter_operator() = op;
  for (auto& operand : operands)
    element.filter_operands().push_back(operand);
  filter.where_clause().elements().push_back(std::move(element));
}

// --- Helper: create a test event ---

BaseEvent make_test_event(uint16_t severity = 500)
{
  BaseEvent event;
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"Server"};
  event.message = LocalizedText{LocaleId{}, String{"Test event"}};
  event.severity = severity;
  event.eventId = ByteString{0x01, 0x02, 0x03};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();
  return event;
}

// Set the resolved EventType supertype chain (`[event_type, ..., BaseEventType]`)
// on an event, exactly as the EventBus does at dispatch from the address-space
// HasSubtype hierarchy. EventFilter OfType matching is a membership test over
// this chain, so a unit test that exercises subtype matching must populate it.
void set_event_type_hierarchy(BaseEvent& event, std::vector<NodeId> chain)
{
  event.eventType = chain.empty() ? event.eventType : chain.front();
  event.eventTypeHierarchy = std::make_shared<const std::vector<NodeId>>(std::move(chain));
}

// --- Helper: make a GenericEvent with a custom string field ---

GenericEvent make_event_with_string_field(std::string_view fieldName, std::string_view value)
{
  auto typeId = NodeId{ObjectTypeId::BaseEventType};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{value};
  event.message = LocalizedText{LocaleId{}, String{"Test event"}};
  event.severity = 500;
  event.eventId = ByteString{0x01, 0x02, 0x03};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();
  event.set_field({QualifiedName{0, String{fieldName}}}, Variant{String{value}});
  return event;
}

// Minimal live Session-security interface for field-projection tests. The context identity is intentionally
// replaceable so a test can model same-Session reactivation without exposing production test hooks.
class MutableEventSessionSecurityContext final : public SessionSecurityContext
{
public:
  MutableEventSessionSecurityContext()
    : mEndpointSecurity(std::make_shared<const EndpointSecurityContext>()),
      mUserIdentity(std::make_shared<const UserIdentity>(
        UserIdentity{.userId = "event-user", .displayName = "Event User", .kind = UserTokenKind::Anonymous}))
  {
    set_roles({ua::test_helpers::test_access_role_id()});
  }

  NodeId session_id() const override
  {
    return NodeId{1, 9000u};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mEndpointSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUserIdentity;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  void set_roles(std::vector<NodeId> roles)
  {
    mAccessIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{mNextIdentityKey++},
      std::move(roles),
      mUserIdentity,
      mEndpointSecurity,
      String{"urn:test:event-client"});
  }

  void clear_access_identity()
  {
    mAccessIdentity.reset();
  }

private:
  std::shared_ptr<const EndpointSecurityContext> mEndpointSecurity;
  std::shared_ptr<const UserIdentity> mUserIdentity;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
  uint64_t mNextIdentityKey{1};
};

EventFieldList project_authorized_fields(AddressSpace addressSpace, const CompiledEventFilter& filter,
  const BaseEvent& event, IntegerId clientHandle,
  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel,
  const MutableEventSessionSecurityContext& security)
{
  auto accessControl = SessionAccessControl::create(security, addressSpace, 1s);
  if (!accessControl)
    throw std::logic_error{"authorized Event projection requires an activated AccessIdentity"};

  std::vector<AccessControl::Item> items;
  for (const auto& subject : filter.authorization_subjects(event, declarationModel))
  {
    auto resolved = addressSpace.try_find_node_sync(subject.nodeId);
    if (resolved.is_good())
      items.push_back(AccessControl::Item{std::move(resolved).value(), subject.operation});
  }
  std::promise<std::vector<AccessControl::Verdict>> promise;
  auto future = promise.get_future();
  accessControl->authorize_async(ua::RequestInfo{},
    items,
    [&promise](std::vector<AccessControl::Verdict> verdicts) { promise.set_value(std::move(verdicts)); });
  auto verdicts = future.get();
  return filter.project_authorized(event, clientHandle, declarationModel, *accessControl, items, verdicts);
}

class EventFieldAuthorizationTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace = AddressSpace::create("urn:test:event-field-authorization", mThreadPool.get_executor());
    auto eventNamespace =
      std::dynamic_pointer_cast<default_ns::Namespace>(mAddressSpace->namespace_array().get_namespace(1));
    ASSERT_NE(eventNamespace, nullptr);
    RolePermissionType permission;
    permission.role_id() = ua::test_helpers::test_access_role_id();
    permission.permissions() = ua::test_helpers::all_permissions();
    eventNamespace->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
    mMessage = create_field(NodeId{1, 1960001u}, "Message");
    mSeverity = create_field(NodeId{1, 1960002u}, "Severity");
    mAlternateSeverity = create_field(NodeId{1, 1960003u}, "Severity");
  }

  void TearDown() override
  {
    mMessage.reset();
    mSeverity.reset();
    mAlternateSeverity.reset();
    mAddressSpace.reset();
    mThreadPool.join();
  }

  NodeAccessor message() const
  {
    return *mMessage;
  }

  NodeAccessor severity() const
  {
    return *mSeverity;
  }

  NodeAccessor alternate_severity() const
  {
    return *mAlternateSeverity;
  }

  AddressSpace address_space() const
  {
    return *mAddressSpace;
  }

  static event_type_model::Declaration declaration(const NodeAccessor& accessor, std::string_view browseName)
  {
    return event_type_model::Declaration{.browsePath = {QualifiedName{0, String{browseName}}},
      .nodeId = accessor.get_node_id(),
      .accessor = accessor,
      .nodeClass = NodeClass::Variable};
  }

  static CompiledEventFilterResult compile_with_declarations(
    EventFilter filter, std::vector<std::optional<NodeAccessor>> declarations)
  {
    std::vector<StatusCode> statuses(filter.select_clauses().size(), StatusCode{Status::Good});
    return CompiledEventFilter::compile(filter, {}, statuses, declarations);
  }

  SessionAccessControl access_control(const MutableEventSessionSecurityContext& security) const
  {
    auto accessControl = try_access_control(security);
    if (!accessControl)
      throw std::logic_error{"the Event projection fixture requires an activated AccessIdentity"};
    return std::move(*accessControl);
  }

  std::optional<SessionAccessControl> try_access_control(
    const MutableEventSessionSecurityContext& security) const
  {
    return SessionAccessControl::create(security, *mAddressSpace, 1s);
  }

  static std::shared_ptr<const event_type_model::DeclarationsResult> empty_declaration_model()
  {
    return std::make_shared<const event_type_model::DeclarationsResult>(event_type_model::Declarations{});
  }

  static void set_permissions(NodeAccessor node, PermissionType permissions)
  {
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

private:
  NodeAccessor create_field(
    NodeId nodeId, std::string_view browseName, NodeClass nodeClass = NodeClass::Variable)
  {
    auto accessor = mAddressSpace->try_create_node_sync(nodeId, nodeClass).value();
    accessor.set_browse_name(QualifiedName{0, String{browseName}});
    return accessor;
  }

  boost::asio::thread_pool mThreadPool{1};
  std::optional<AddressSpace> mAddressSpace;
  std::optional<NodeAccessor> mMessage;
  std::optional<NodeAccessor> mSeverity;
  std::optional<NodeAccessor> mAlternateSeverity;
};

// --- Helper: make a NodeId for a DataType (ns=0 numeric) ---

RefStructure<Structure> make_datatype_literal(DataTypeId id)
{
  return make_literal(Variant{NodeId{0, static_cast<uint32_t>(id)}});
}

// --- Helper: build a where clause that Casts a field and compares to an expected value ---
// Element 0: Equals(element[1], literal(expected))
// Element 1: Cast(field, targetType)
void add_cast_filter(EventFilter& filter, std::string_view field, DataTypeId target, Variant expected)
{
  add_where_element(filter, FilterOperator::Equals, {make_element_ref(1), make_literal(std::move(expected))});
  add_where_element(filter, FilterOperator::Cast, {make_sao_operand(field), make_datatype_literal(target)});
}

// --- Helper: build a where clause that checks Cast result is non-null (truthy) ---
// For boolean casts: element 0 is the Cast itself (result is boolean).
void add_cast_boolean_filter(EventFilter& filter, std::string_view field, DataTypeId target)
{
  add_where_element(filter, FilterOperator::Cast, {make_sao_operand(field), make_datatype_literal(target)});
}

}  // namespace

// ============================================================================
// Compilation: select clause validation
// ============================================================================

// @relation(SVR-MI-EVT-008, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, CompileEmptySelectClausesReturnsError)
{
  EventFilter filter;
  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
  EXPECT_EQ(result.overallStatus.as_status(), Status::BadMonitoredItemFilterInvalid);
  EXPECT_FALSE(result.filter);
}

TEST(EventFilterTests, CompileValidSelectClauseSucceeds)
{
  auto filter = make_select_only_filter({"EventId", "EventType", "Severity"});
  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);
  EXPECT_EQ(result.filter->select_clauses().size(), 3u);
}

TEST(EventFilterTests, CompileSelectClauseWithNullBrowseNameReturnsBadBrowseName)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, String{}});
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_EQ(result.filterResult.select_clause_results()[0].as_status(), Status::BadBrowseNameInvalid);
}

// @relation(SVR-MI-EVT-003, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, CompileSelectClauseWithInvalidAttributeIdReturnsError)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, "EventId"});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_EQ(result.filterResult.select_clause_results()[0].as_status(), Status::BadAttributeIdInvalid);
}

// An empty browse path selects the event instance (an Object) node itself; per Part 4 section 7.22.3 a
// Server is only required to support the NodeId Attribute for Object Nodes, so Value is invalid.
TEST(EventFilterTests, CompileSelectClauseEmptyBrowsePathWithValueAttributeReturnsBadAttributeId)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  // browse_path intentionally empty
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_EQ(result.filterResult.select_clause_results()[0].as_status(), Status::BadAttributeIdInvalid);
}

// Empty browse path + NodeId selects the event/Condition NodeId itself - valid (Part 4 section 7.4.4.5).
TEST(EventFilterTests, CompileSelectClauseEmptyBrowsePathWithNodeIdAttributeIsValid)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_TRUE(result.filterResult.select_clause_results()[0].is_good());
}

// @relation(SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, CompileAllBadSelectClausesReturnsOverallError)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.browse_path().push_back(QualifiedName{0, String{}});
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
}

// @relation(SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, CompileMixedValidInvalidSelectClauses)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));

  SimpleAttributeOperand badClause;
  badClause.browse_path().push_back(QualifiedName{0, String{}});
  filter.select_clauses().push_back(std::move(badClause));

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);

  auto& scr = result.filterResult.select_clause_results();
  ASSERT_EQ(scr.size(), 2u);
  EXPECT_TRUE(scr[0].is_good());
  EXPECT_TRUE(scr[1].is_bad());
}

// ============================================================================
// Compilation: where clause validation
// ============================================================================

// @relation(SVR-MI-EVT-011, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, CompileEmptyWhereClauseSucceeds)
{
  auto filter = make_select_only_filter({"EventId"});
  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);
}

// @relation(SVR-MI-EVT-011, scope=function)
TEST(EventFilterTests, CompileWhereClauseWithDisallowedOperatorFails)
{
  auto filter = make_select_only_filter({"EventId"});
  auto viewNodeId = NodeId{0, 1u};
  add_where_element(filter, FilterOperator::InView, {make_literal(Variant{viewNodeId})});

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
}

TEST(EventFilterTests, CompileWhereClauseWithWrongOperandCountFails)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::Equals, {make_literal(Variant{42})});

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
}

TEST(EventFilterTests, CompileWhereClauseWithCycleFails)
{
  auto filter = make_select_only_filter({"EventId"});

  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_literal(Variant{true})});

  add_where_element(filter, FilterOperator::Or, {make_element_ref(0), make_literal(Variant{false})});

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
}

// Stage 3c #5: a where clause whose TOTAL operand count exceeds MaxWhereClauseParameters must be
// rejected at compile (BadMonitoredItemFilterInvalid), before any per-event evaluation. InList's operand
// arity is otherwise unbounded (expected_operand_count max == UINT32_MAX), so the element-count limit
// alone does not bound the per-event matching cost (post-auth CPU-amplification DoS).
TEST(EventFilterTests, CompileWhereClauseTotalOperandCountExceedingLimitFails)
{
  auto filter = make_select_only_filter({"EventId"});

  // One InList element with 21 operands (field + 20 literals): element count 1, total operands 21.
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::InList;
  element.filter_operands().push_back(make_sao_operand("Severity"));
  for (int32_t k = 0; k < 20; ++k)
    element.filter_operands().push_back(make_literal(Variant{k}));
  filter.where_clause().elements().push_back(std::move(element));

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 100;
  limits.maxWhereClauseElements =
    10;  // operand budget; element count (1) passes, operand count (21) does not

  auto result = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(result.overallStatus.is_bad());
  EXPECT_EQ(result.overallStatus.as_status(), Status::BadMonitoredItemFilterInvalid);
  EXPECT_FALSE(result.filter);
}

// Control / falsifiability for the test above: the SAME filter shape with the budget raised above the
// operand count compiles, proving the rejection is specifically the total-operand budget.
TEST(EventFilterTests, CompileWhereClauseTotalOperandCountWithinLimitSucceeds)
{
  auto filter = make_select_only_filter({"EventId"});

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::InList;
  element.filter_operands().push_back(make_sao_operand("Severity"));
  for (int32_t k = 0; k < 20; ++k)
    element.filter_operands().push_back(make_literal(Variant{k}));
  filter.where_clause().elements().push_back(std::move(element));

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 100;
  limits.maxWhereClauseElements = 100;  // budget >= 21 operands

  auto result = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(result.overallStatus.is_good()) << "0x" << std::hex << result.overallStatus.as_uint32();
  EXPECT_TRUE(result.filter);
}

// Stage 3c #6: a where clause whose TOTAL string-literal operand bytes exceed the byte budget must be
// rejected at compile (BadMonitoredItemFilterInvalid). `Like` is O(text x pattern) per event and the
// pattern literal is bounded only by mMaxStringLength (up to 1 MB), so a long pattern multiplies the
// per-event cost (post-auth slow-burn DoS) - a dimension the operand-COUNT cap does not bound.
TEST(EventFilterTests, CompileWhereClauseLiteralBytesExceedingBudgetFails)
{
  auto filter = make_select_only_filter({"EventId"});

  // One Like element: Message field + a 5000-byte pattern literal.
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::Like;
  element.filter_operands().push_back(make_sao_operand("Message"));
  element.filter_operands().push_back(make_literal(Variant{String{std::string(5000, 'a')}}));
  filter.where_clause().elements().push_back(std::move(element));

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 100;
  limits.maxWhereClauseElements = 100;
  limits.maxWhereClauseOperandBytes = 1024;  // 5000-byte literal exceeds the byte budget

  auto result = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(result.overallStatus.is_bad());
  EXPECT_EQ(result.overallStatus.as_status(), Status::BadMonitoredItemFilterInvalid);
  EXPECT_FALSE(result.filter);
}

// Control / falsifiability: the SAME filter with the byte budget raised above the literal size compiles,
// proving the rejection is specifically the literal-byte budget (not the operator or operand count).
TEST(EventFilterTests, CompileWhereClauseLiteralBytesWithinBudgetSucceeds)
{
  auto filter = make_select_only_filter({"EventId"});

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::Like;
  element.filter_operands().push_back(make_sao_operand("Message"));
  element.filter_operands().push_back(make_literal(Variant{String{std::string(5000, 'a')}}));
  filter.where_clause().elements().push_back(std::move(element));

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 100;
  limits.maxWhereClauseElements = 100;
  limits.maxWhereClauseOperandBytes = 64 * 1024;  // budget >= 5000 bytes

  auto result = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(result.overallStatus.is_good()) << "0x" << std::hex << result.overallStatus.as_uint32();
  EXPECT_TRUE(result.filter);
}

TEST(EventFilterTests, CompileWhereClauseWithAttributeOperandFails)
{
  auto filter = make_select_only_filter({"EventId"});

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::IsNull;

  auto ao = std::make_unique<AttributeOperand>();
  RefStructure<Structure> ref;
  ref.inner_unique_ptr() = std::move(ao);
  element.filter_operands().push_back(std::move(ref));

  filter.where_clause().elements().push_back(std::move(element));

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_bad());
}

TEST(EventFilterTests, CompileValidWhereClauseSucceeds)
{
  auto filter = make_select_only_filter({"EventId", "Severity"});

  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{100}})});

  auto result = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);
}

// ============================================================================
// Runtime: where clause evaluation
// ============================================================================

TEST(EventFilterTests, EmptyWhereClausePassesAll)
{
  auto filter = make_select_only_filter({"EventId"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, GreaterThanOrEqualPassesMatchingEvent)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{400}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
}

TEST(EventFilterTests, GreaterThanOrEqualRejectsNonMatchingEvent)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{600}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(500)));
}

TEST(EventFilterTests, EqualsOperator)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("Severity"), make_literal(Variant{uint16_t{500}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(499)));
}

TEST(EventFilterTests, AndOperator)
{
  auto filter = make_select_only_filter({"Severity"});

  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_element_ref(2)});

  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{400}})});

  add_where_element(filter,
    FilterOperator::LessThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{600}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(300)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(700)));
}

// @relation(AC-SVR-MI-EVT-010-SHARED-ELEMENT-SAME-RESULT, scope=function)
TEST(EventFilterTests, AnElementTwoOperandsReferenceAnswersBothWithItsResult)
{
  // 0: Or(1, 2); 1: And(3, 4); 2: And(3, 5); element 3 is referenced by both 1 and 2.
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Or, {make_element_ref(1), make_element_ref(2)});
  add_where_element(filter, FilterOperator::And, {make_element_ref(3), make_element_ref(4)});
  add_where_element(filter, FilterOperator::And, {make_element_ref(3), make_element_ref(5)});
  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{400}})});
  add_where_element(filter,
    FilterOperator::LessThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{450}})});
  add_where_element(filter,
    FilterOperator::GreaterThanOrEqual,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{550}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // 600 passes only through element 2, the second reference to element 3.
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(600)));
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(420)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(300)));
}

TEST(EventFilterTests, OrOperator)
{
  auto filter = make_select_only_filter({"Severity"});

  add_where_element(filter, FilterOperator::Or, {make_element_ref(1), make_element_ref(2)});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("Severity"), make_literal(Variant{uint16_t{100}})});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("Severity"), make_literal(Variant{uint16_t{900}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(100)));
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(900)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(500)));
}

TEST(EventFilterTests, NotOperator)
{
  auto filter = make_select_only_filter({"Severity"});

  add_where_element(filter, FilterOperator::Not, {make_element_ref(1)});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("Severity"), make_literal(Variant{uint16_t{500}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(499)));
}

TEST(EventFilterTests, IsNullOperator)
{
  auto filter = make_select_only_filter({"ConditionClassId"});

  add_where_element(filter, FilterOperator::IsNull, {make_sao_operand("ConditionClassId")});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  EXPECT_TRUE(compiled.filter->evaluate(event));

  event.conditionClassId = NodeId{0, 12345u};
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, BetweenOperator)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::Between,
    {make_sao_operand("Severity"),
      make_literal(Variant{uint16_t{400}}),
      make_literal(Variant{uint16_t{600}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(400)));
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(600)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(399)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(601)));
}

// @relation(SVR-MI-EVT-010, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, NullOperandEvaluatesToNull)
{
  auto filter = make_select_only_filter({"EventId"});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("NonExistent"), make_literal(Variant{42})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_FALSE(compiled.filter->evaluate(make_test_event()));
}

// ============================================================================
// Runtime: OfType operator
// ============================================================================

TEST(EventFilterTests, OfTypeMatchesExactType)
{
  auto filter = make_select_only_filter({"EventId"});
  auto baseEventTypeId = NodeId{ObjectTypeId::BaseEventType};
  add_where_element(filter, FilterOperator::OfType, {make_literal(Variant{baseEventTypeId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, OfTypeMatchesSubtype)
{
  auto filter = make_select_only_filter({"EventId"});
  auto systemEventTypeId = NodeId{ObjectTypeId::SystemEventType};
  add_where_element(filter, FilterOperator::OfType, {make_literal(Variant{systemEventTypeId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // OfType matches the event's type or any supertype. The EventBus resolves the
  // supertype chain at dispatch; here we set it directly. SystemStatusChangeEventType
  //  subset of  SystemEventType  subset of  BaseEventType, so OfType(SystemEventType) matches.
  auto event = make_test_event();
  set_event_type_hierarchy(event,
    {NodeId{ObjectTypeId::SystemStatusChangeEventType},
      NodeId{ObjectTypeId::SystemEventType},
      NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

// A client watching several event families sends ONE filter whose root is an Or over the OfType
// elements - that is the only shape OPC 10000-4 7.4.1 gives it, because a ContentFilter is a tree and
// only elements[0] is evaluated. An Or whose branches are OfType must therefore admit an event
// matching EITHER branch; a server that evaluated only one of them would silently drop every family
// but the first, with the subscription reporting Good throughout.
TEST(EventFilterTests, OrOverTwoOfTypeBranchesAdmitsEitherFamily)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::Or, {make_element_ref(1), make_element_ref(2)});
  add_where_element(
    filter, FilterOperator::OfType, {make_literal(Variant{NodeId{ObjectTypeId::SystemEventType}})});
  add_where_element(
    filter, FilterOperator::OfType, {make_literal(Variant{NodeId{ObjectTypeId::BaseModelChangeEventType}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter) << "the Or-of-OfType tree must compile";
  EXPECT_TRUE(compiled.overallStatus.is_good());

  auto leftBranch = make_test_event();
  set_event_type_hierarchy(leftBranch,
    {NodeId{ObjectTypeId::SystemStatusChangeEventType},
      NodeId{ObjectTypeId::SystemEventType},
      NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_TRUE(compiled.filter->evaluate(leftBranch)) << "the FIRST Or branch must admit its family";

  auto rightBranch = make_test_event();
  set_event_type_hierarchy(
    rightBranch, {NodeId{ObjectTypeId::BaseModelChangeEventType}, NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_TRUE(compiled.filter->evaluate(rightBranch))
    << "the SECOND Or branch must admit its family - dropping it is the silent multi-type failure";

  auto neither = make_test_event();
  set_event_type_hierarchy(
    neither, {NodeId{ObjectTypeId::DeviceFailureEventType}, NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_FALSE(compiled.filter->evaluate(neither)) << "and a family in neither branch stays out";
}

// Three families chain: Or(1, 2) / OfType(A) / Or(3, 4) / OfType(B) / OfType(C). Every leaf must stay
// reachable from the root - a chain that mis-numbers one index silently drops the branch below it.
TEST(EventFilterTests, ChainedOrAdmitsEveryFamilyInTheChain)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::Or, {make_element_ref(1), make_element_ref(2)});
  add_where_element(
    filter, FilterOperator::OfType, {make_literal(Variant{NodeId{ObjectTypeId::SystemEventType}})});
  add_where_element(filter, FilterOperator::Or, {make_element_ref(3), make_element_ref(4)});
  add_where_element(
    filter, FilterOperator::OfType, {make_literal(Variant{NodeId{ObjectTypeId::BaseModelChangeEventType}})});
  add_where_element(
    filter, FilterOperator::OfType, {make_literal(Variant{NodeId{ObjectTypeId::DeviceFailureEventType}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  for (const auto& family : {NodeId{ObjectTypeId::SystemEventType},
         NodeId{ObjectTypeId::BaseModelChangeEventType},
         NodeId{ObjectTypeId::DeviceFailureEventType}})
  {
    auto event = make_test_event();
    set_event_type_hierarchy(event, {family, NodeId{ObjectTypeId::BaseEventType}});
    EXPECT_TRUE(compiled.filter->evaluate(event))
      << "every leaf of the Or chain must be reachable from the root";
  }
}

TEST(EventFilterTests, OfTypeBaseEventTypeMatchesAll)
{
  auto filter = make_select_only_filter({"EventId"});
  auto baseEventTypeId = NodeId{ObjectTypeId::BaseEventType};
  add_where_element(filter, FilterOperator::OfType, {make_literal(Variant{baseEventTypeId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // Every event type's chain ends at BaseEventType, so OfType(BaseEventType) matches all.
  auto event = make_test_event();
  set_event_type_hierarchy(event,
    {NodeId{ObjectTypeId::AuditCreateSessionEventType},
      NodeId{ObjectTypeId::AuditSessionEventType},
      NodeId{ObjectTypeId::AuditEventType},
      NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, OfTypeDoesNotMatchDifferentBranch)
{
  auto filter = make_select_only_filter({"EventId"});
  auto auditEventTypeId = NodeId{ObjectTypeId::AuditEventType};
  add_where_element(filter, FilterOperator::OfType, {make_literal(Variant{auditEventTypeId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // A System-branch event is not a subtype of AuditEventType - its chain does
  // not contain AuditEventType.
  auto event = make_test_event();
  set_event_type_hierarchy(event,
    {NodeId{ObjectTypeId::SystemStatusChangeEventType},
      NodeId{ObjectTypeId::SystemEventType},
      NodeId{ObjectTypeId::BaseEventType}});
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, OfTypeWithNonNodeIdOperandReturnsFalse)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::OfType, {make_literal(Variant{42})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_FALSE(compiled.filter->evaluate(make_test_event()));
}

// ============================================================================

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, DeniedFieldIsReplacedWhileAllowedFieldAndEventArePreserved)
{
  set_permissions(message(), ua::test_helpers::all_permissions());
  auto severityPermissions = ua::test_helpers::all_permissions();
  severityPermissions.reset(PermissionType::Bit::Read);
  set_permissions(severity(), severityPermissions);
  MutableEventSessionSecurityContext security;

  auto compiled = compile_with_declarations(make_select_only_filter({"Message", "Severity"}),
    {std::optional<NodeAccessor>{message()}, std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);

  auto declarationModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(message(), "Message"), declaration(severity(), "Severity")});
  auto projected = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(712), 44, std::move(declarationModel), security);
  EXPECT_EQ(projected.client_handle(), 44u);
  ASSERT_EQ(projected.event_fields().size(), 2u);
  ASSERT_TRUE(projected.event_fields()[0].is_localized_text());
  EXPECT_EQ(projected.event_fields()[0].as<LocalizedText>().text(), String{"Test event"});
  ASSERT_TRUE(projected.event_fields()[1].is_status_code());
  const auto denied = projected.event_fields()[1].as<StatusCode>();
  EXPECT_EQ(denied.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(denied.shared_detail(), nullptr);
  EXPECT_EQ(denied.shared_detail()->code, "RoleNotGranted");
}

// @relation(AC-SVR-AUTHZ-023-EVENT-FILTER-SUBJECTS-AUTHORIZED, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-01-AUTHORIZED-VIEW, scope=function)
TEST_F(EventFieldAuthorizationTest, SelectedDenialIsStatusAndWhereDenialIsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::Equals,
    {make_sao_operand("WhereSecret"), make_literal(Variant{String{"secret"}})});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_event_with_string_field("WhereSecret", "secret");
  ASSERT_TRUE(compiled.filter->evaluate(event))
    << "the raw where operand must pass so only authorization can suppress it";
  auto model = std::make_shared<const event_type_model::DeclarationsResult>(event_type_model::Declarations{
    declaration(severity(), "Severity"), declaration(message(), "WhereSecret")});
  const auto subjects = compiled.filter->authorization_subjects(event, model);
  ASSERT_EQ(subjects.size(), 2u);
  EXPECT_EQ(subjects[0].nodeId, severity().get_node_id());
  EXPECT_EQ(subjects[0].operation, AccessOperation::Read);
  EXPECT_EQ(subjects[1].nodeId, message().get_node_id());
  EXPECT_EQ(subjects[1].operation, AccessOperation::Read);

  MutableEventSessionSecurityContext security;
  auto accessControl = access_control(security);
  const std::vector<AccessControl::Item> items{
    {severity(), AccessOperation::Read}, {message(), AccessOperation::Read}};
  const auto allowed = [](const NodeAccessor& node)
  {
    return AccessControl::Verdict{.subject = node.get_node_id(),
      .operation = AccessOperation::Read,
      .permitted = true,
      .mask = ua::test_helpers::all_permissions(),
      .cause = StatusCode{Status::Good}};
  };
  const auto denied = [](const NodeAccessor& node)
  {
    return AccessControl::Verdict{.subject = node.get_node_id(),
      .operation = AccessOperation::Read,
      .permitted = false,
      .cause = StatusCode{Status::BadUserAccessDenied,
        ErrorDetail::build("SentinelEventFieldDenial",
          "The test-controlled Event declaration is inaccessible",
          "EventFieldAuthorizationTest")}};
  };

  const std::array selectedDenied{denied(severity()), allowed(message())};
  EXPECT_TRUE(compiled.filter->evaluate_authorized(event, model, selectedDenied));
  const auto selectedFields =
    compiled.filter->project_authorized(event, 41, model, accessControl, items, selectedDenied)
      .event_fields();
  ASSERT_EQ(selectedFields.size(), 1u);
  ASSERT_TRUE(selectedFields[0].is_status_code());
  const auto selectedStatus = selectedFields[0].as<StatusCode>();
  EXPECT_EQ(selectedStatus.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(selectedStatus.shared_detail(), nullptr);
  EXPECT_EQ(selectedStatus.shared_detail()->code, "SentinelEventFieldDenial");

  const std::array whereDenied{allowed(severity()), denied(message())};
  EXPECT_FALSE(compiled.filter->evaluate_authorized(event, model, whereDenied))
    << "the inaccessible operand must become null before Equals sees the raw secret";
  const auto allowedFields =
    compiled.filter->project_authorized(event, 42, model, accessControl, items, whereDenied).event_fields();
  ASSERT_EQ(allowedFields.size(), 1u);
  ASSERT_TRUE(allowedFields[0].is_uint16());
  EXPECT_EQ(allowedFields[0].as<uint16_t>(), 500u);
}

// @relation(AC-SVR-AUTHZ-023-EVENT-FILTER-SUBJECTS-AUTHORIZED, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-01-AUTHORIZED-VIEW, scope=function)
TEST_F(EventFieldAuthorizationTest, InviolateFieldsRemainValuesAfterTheEventGate)
{
  auto filter = make_select_only_filter({"EventId", "EventType", "ReceiveTime", "Severity"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);
  auto event = make_test_event();
  auto model = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});
  const std::array deniedSeverity{AccessControl::Verdict{.subject = severity().get_node_id(),
    .operation = AccessOperation::Read,
    .permitted = false,
    .cause = StatusCode{Status::BadUserAccessDenied}}};
  const std::array items{AccessControl::Item{severity(), AccessOperation::Read}};
  MutableEventSessionSecurityContext security;
  auto accessControl = access_control(security);

  const auto fields =
    compiled.filter->project_authorized(event, 51, model, accessControl, items, deniedSeverity)
      .event_fields();
  ASSERT_EQ(fields.size(), 4u);
  ASSERT_TRUE(fields[0].is_byte_string());
  EXPECT_EQ(fields[0].as<ByteString>(), event.eventId);
  ASSERT_TRUE(fields[1].is_node_id());
  EXPECT_EQ(fields[1].as<NodeId>(), event.eventType);
  ASSERT_TRUE(fields[2].is_date_time());
  EXPECT_EQ(fields[2].as<DateTime>(), event.receiveTime);
  ASSERT_TRUE(fields[3].is_status_code());
  EXPECT_EQ(fields[3].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, NonValueAttributeUsesBrowseAuthorization)
{
  MutableEventSessionSecurityContext security;

  EventFilter filter;
  SimpleAttributeOperand conditionId;
  conditionId.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  conditionId.attribute_id() = utils::to_underlying(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(conditionId));
  auto compiled = compile_with_declarations(std::move(filter), {std::optional<NodeAccessor>{}});
  ASSERT_TRUE(compiled.filter);
  auto conditionType =
    address_space().try_create_node_sync(NodeId{ObjectTypeId::ConditionType}, NodeClass::ObjectType).value();

  auto event = make_test_event();
  const NodeId expectedConditionId{1, 1960200u};
  event.conditionNodeId = expectedConditionId;

  set_permissions(conditionType, PermissionType{PermissionType::Bit::Browse});
  const auto allowed = project_authorized_fields(
    address_space(), *compiled.filter, event, 1, empty_declaration_model(), security)
                         .event_fields();
  ASSERT_EQ(allowed.size(), 1u);
  ASSERT_TRUE(allowed[0].is_node_id());
  EXPECT_EQ(allowed[0].as<NodeId>(), expectedConditionId);

  set_permissions(conditionType, PermissionType{PermissionType::Bit::Read});
  const auto denied = project_authorized_fields(
    address_space(), *compiled.filter, event, 1, empty_declaration_model(), security)
                        .event_fields();
  ASSERT_EQ(denied.size(), 1u);
  ASSERT_TRUE(denied[0].is_status_code());
  EXPECT_EQ(denied[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, SelectedRawRolePermissionsRequiresReadRolePermissionsBit)
{
  MutableEventSessionSecurityContext security;

  auto filter = make_select_only_filter({"Severity"});
  filter.select_clauses()[0].attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  auto compiled = compile_with_declarations(std::move(filter), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);

  set_permissions(severity(), PermissionType{PermissionType::Bit::Browse});
  auto declarationModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});
  const auto fields = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 1, declarationModel, security)
                        .event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_status_code());
  const auto denied = fields[0].as<StatusCode>();
  EXPECT_EQ(denied.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(denied.shared_detail(), nullptr);
  EXPECT_EQ(denied.shared_detail()->code, "RoleNotGranted");

  RolePermissionType permission;
  permission.role_id() = ua::test_helpers::test_access_role_id();
  permission.permissions().set(PermissionType::Bit::ReadRolePermissions);
  severity().set_role_permissions(std::vector<RolePermissionType>{permission});
  const auto allowed = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 2, declarationModel, security)
                         .event_fields();
  ASSERT_EQ(allowed.size(), 1u);
  EXPECT_EQ(allowed[0], severity().read_attribute(AttributeId::RolePermissions));
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, DeniedAbsentFieldStillCarriesUserAccessDeniedWhileAllowedRemainsNull)
{
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"AbsentField"}), {std::optional<NodeAccessor>{message()}});
  ASSERT_TRUE(compiled.filter);

  set_permissions(message(), PermissionType{});
  auto declarationModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(message(), "AbsentField")});
  const auto denied = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 1, declarationModel, security)
                        .event_fields();
  ASSERT_EQ(denied.size(), 1u);
  ASSERT_TRUE(denied[0].is_status_code());
  EXPECT_EQ(denied[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);

  set_permissions(message(), PermissionType{PermissionType::Bit::Read});
  const auto allowed = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 1, declarationModel, security)
                         .event_fields();
  ASSERT_EQ(allowed.size(), 1u);
  EXPECT_TRUE(allowed[0].empty());
}

// @relation(AC-COMP-SVR-EVENTDECL-07-TYPE-DEPENDENT-ABSENCE, scope=function)
// @defect(D-EVENT-FIELD-AUTHORIZATION-DENIES-KNOWN-TYPE-DEPENDENT-ABSENCE)
TEST_F(EventFieldAuthorizationTest, TypeDependentAbsentConcreteFieldProjectsNullWithoutAuthorization)
{
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"TypeSpecificField"}), {std::optional<NodeAccessor>{}});
  ASSERT_TRUE(compiled.filter);

  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    std::vector<event_type_model::Declaration>{});
  const auto fields = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 1, concreteModel, security)
                        .event_fields();

  ASSERT_EQ(fields.size(), 1u);
  EXPECT_TRUE(fields[0].empty())
    << "a good concrete model with no declaration proves per-Event absence, not authorization failure";
}

// @relation(AC-COMP-SVR-EVENTDECL-07-TYPE-DEPENDENT-ABSENCE, scope=function)
TEST_F(EventFieldAuthorizationTest, TypeDependentPresentConcreteFieldIsAuthorizedAndProjected)
{
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"TypeSpecificField"}), {std::optional<NodeAccessor>{}});
  ASSERT_TRUE(compiled.filter);

  auto event = make_event_with_string_field("TypeSpecificField", "present");
  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(message(), "TypeSpecificField")});
  set_permissions(message(), PermissionType{PermissionType::Bit::Read});
  const auto fields =
    project_authorized_fields(address_space(), *compiled.filter, event, 1, concreteModel, security)
      .event_fields();

  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_string());
  EXPECT_EQ(fields[0].as<String>(), String{"present"});

  set_permissions(message(), PermissionType{});
  const auto denied =
    project_authorized_fields(address_space(), *compiled.filter, event, 1, concreteModel, security)
      .event_fields();
  ASSERT_EQ(denied.size(), 1u);
  ASSERT_TRUE(denied[0].is_status_code());
  EXPECT_EQ(denied[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied)
    << "the present-field control must prove that the declaration is authorized";
}

// @relation(AC-COMP-SVR-EVENTDECL-08-EMPTY-PATH-INSTANCE-AUTHORIZATION, scope=function)
// @defect(D-EVENT-FIELD-AUTHORIZATION-DROPS-EMPTY-PATH-CONDITIONID)
TEST(EventTypeModelTests, EmptyPathNodeIdRetainsTypeDeclarationForAuthorizedProjection)
{
  EventFilter filter;
  SimpleAttributeOperand conditionIdClause;
  conditionIdClause.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  conditionIdClause.attribute_id() = utils::to_underlying(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(conditionIdClause));

  EventFilterTypeModelFixture model;
  auto modelResult = model.resolve(filter);
  ASSERT_TRUE(modelResult.is_good()) << to_string(modelResult.status_code().as_status());
  ASSERT_EQ(modelResult.value().size(), 1u);
  ASSERT_TRUE(modelResult.value()[0].status.is_good());
  ASSERT_TRUE(modelResult.value()[0].declarationAccessor.has_value())
    << "an empty browse path names the TypeDefinition Object itself; it is not a missing declaration";
  EXPECT_EQ(modelResult.value()[0].declarationAccessor->get_node_id(), NodeId{ObjectTypeId::ConditionType});

  std::vector<StatusCode> statuses{modelResult.value()[0].status};
  std::vector<std::optional<NodeAccessor>> declarations{modelResult.value()[0].declarationAccessor};
  auto compiled = CompiledEventFilter::compile(filter, {}, statuses, declarations);
  ASSERT_TRUE(compiled.filter);

  MutableEventSessionSecurityContext security;
  auto event = make_test_event();
  event.eventType = NodeId{ObjectTypeId::AlarmConditionType};
  event.eventTypeHierarchy =
    std::make_shared<const std::vector<NodeId>>(std::vector<NodeId>{NodeId{ObjectTypeId::AlarmConditionType},
      NodeId{ObjectTypeId::ConditionType},
      NodeId{ObjectTypeId::BaseEventType}});
  const NodeId conditionId{2, 4242u};
  event.conditionNodeId = conditionId;
  auto concreteModel =
    std::make_shared<const event_type_model::DeclarationsResult>(event_type_model::Declarations{});

  const auto fields =
    project_authorized_fields(model.address_space(), *compiled.filter, event, 1, concreteModel, security)
      .event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_node_id())
    << "the present ConditionId must not be replaced by a missing-declaration denial";
  EXPECT_EQ(fields[0].as<NodeId>(), conditionId);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
// @relation(AC-COMP-SVR-EVENTDECL-03-AUTH-FAIL-CLOSED, scope=function)
TEST_F(EventFieldAuthorizationTest, ChannelFailureIsMappedToDeniedAndRetainsTheRichCause)
{
  severity().set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::SigningRequired});
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);
  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});

  const auto fields = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 1, concreteModel, security)
                        .event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_status_code());
  const auto denied = fields[0].as<StatusCode>();
  EXPECT_EQ(denied.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(denied.shared_detail(), nullptr);
  EXPECT_EQ(denied.shared_detail()->code, "EventFieldReadDenied");
  ASSERT_NE(denied.shared_detail()->cause, nullptr);
  EXPECT_EQ(denied.shared_detail()->cause->code, "AccessRestrictionsNotSatisfied");
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, ConcreteEventTypeDeclarationsResolveTypeDependentFields)
{
  set_permissions(severity(), PermissionType{});
  set_permissions(alternate_severity(), PermissionType{PermissionType::Bit::Read});
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);

  auto firstEvent = make_test_event(321);
  firstEvent.eventType = NodeId{1, 1960100u};
  auto firstModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});
  const auto first =
    project_authorized_fields(address_space(), *compiled.filter, firstEvent, 1, firstModel, security)
      .event_fields();
  ASSERT_EQ(first.size(), 1u);
  ASSERT_TRUE(first[0].is_status_code());
  EXPECT_EQ(first[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);

  auto secondEvent = make_test_event(654);
  secondEvent.eventType = NodeId{1, 1960101u};
  auto secondModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(alternate_severity(), "Severity")});
  const auto second =
    project_authorized_fields(address_space(), *compiled.filter, secondEvent, 1, secondModel, security)
      .event_fields();
  ASSERT_EQ(second.size(), 1u);
  ASSERT_TRUE(second[0].is_uint16());
  EXPECT_EQ(second[0].as<uint16_t>(), 654u);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(EventFieldAuthorizationTest, ProjectionUsesCurrentIdentityAndDoesNotRetainTheOldIdentity)
{
  const NodeId permittedRole{1, 1960999u};
  RolePermissionType restrictedPermission;
  restrictedPermission.role_id() = ua::test_helpers::test_access_role_id();
  restrictedPermission.permissions() = PermissionType{};
  RolePermissionType permittedPermission;
  permittedPermission.role_id() = permittedRole;
  permittedPermission.permissions() = PermissionType{PermissionType::Bit::Read};
  severity().set_role_permissions(std::vector<RolePermissionType>{restrictedPermission, permittedPermission});

  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);
  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});

  auto restrictedIdentity = security.access_identity();
  std::weak_ptr<const AccessIdentity> oldIdentity = restrictedIdentity;
  {
    const auto denied = project_authorized_fields(
      address_space(), *compiled.filter, make_test_event(200), 1, concreteModel, security)
                          .event_fields();
    ASSERT_EQ(denied.size(), 1u);
    ASSERT_TRUE(denied[0].is_status_code());
    EXPECT_EQ(denied[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
  }

  security.set_roles({permittedRole});
  restrictedIdentity.reset();
  EXPECT_TRUE(oldIdentity.expired()) << "the compiled filter must not retain a stale AccessIdentity";

  const auto allowed = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(201), 1, concreteModel, security)
                         .event_fields();
  ASSERT_EQ(allowed.size(), 1u);
  ASSERT_TRUE(allowed[0].is_uint16());
  EXPECT_EQ(allowed[0].as<uint16_t>(), 201u);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
// @relation(AC-COMP-SVR-EVENTDECL-03-AUTH-FAIL-CLOSED, scope=function)
TEST_F(EventFieldAuthorizationTest, AuthorizationFailsClosedWithoutAccessIdentityOrDeclaration)
{
  MutableEventSessionSecurityContext security;
  security.clear_access_identity();

  auto withDeclaration = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(withDeclaration.filter);
  auto unavailable = try_access_control(security);
  ASSERT_FALSE(unavailable.has_value());
  // There is deliberately no synchronous/null-context projection fallback: the Event head cannot
  // start its authorization transaction until Session activation has supplied an AccessIdentity.

  security.set_roles({ua::test_helpers::test_access_role_id()});
  auto withoutDeclaration =
    compile_with_declarations(make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{}});
  ASSERT_TRUE(withoutDeclaration.filter);
  const auto noDeclaration = project_authorized_fields(
    address_space(), *withoutDeclaration.filter, make_test_event(), 1, empty_declaration_model(), security)
                               .event_fields();
  ASSERT_EQ(noDeclaration.size(), 1u);
  ASSERT_TRUE(noDeclaration[0].is_status_code());
  const auto noDeclarationStatus = noDeclaration[0].as<StatusCode>();
  EXPECT_EQ(noDeclarationStatus.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(noDeclarationStatus.shared_detail(), nullptr);
  EXPECT_EQ(noDeclarationStatus.shared_detail()->code, "EventFieldDeclarationUnavailable");
}

// @relation(AC-COMP-SVR-EVENTDECL-03-AUTH-FAIL-CLOSED, scope=function)
TEST_F(EventFieldAuthorizationTest, FailedConcreteModelDeniesFieldAndRetainsTheRichCause)
{
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);

  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build(
      "ConcreteModelLookupFailed", "The concrete model lookup failed", "EventFieldAuthorizationTest")};
  auto failedModel = std::make_shared<const event_type_model::DeclarationsResult>(sentinel);
  const auto fields = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(515), 1, std::move(failedModel), security)
                        .event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_status_code());
  const auto denied = fields[0].as<StatusCode>();
  EXPECT_EQ(denied.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(denied.shared_detail(), nullptr);
  EXPECT_EQ(denied.shared_detail()->code, "EventFieldDeclarationModelUnavailable");
  ASSERT_NE(denied.shared_detail()->cause, nullptr);
  EXPECT_EQ(denied.shared_detail()->cause, sentinel.shared_detail());
}

// @relation(AC-COMP-SVR-EVENTDECL-06-MODEL-GENERATION-INVALIDATION, scope=function)
TEST_F(EventFieldAuthorizationTest, ProjectionUsesTheCurrentImmutableDeclarationModel)
{
  set_permissions(severity(), PermissionType{PermissionType::Bit::Read});
  set_permissions(alternate_severity(), PermissionType{});
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event(616);
  event.eventType = NodeId{1, 1960200u};
  auto firstModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});
  const auto allowed =
    project_authorized_fields(address_space(), *compiled.filter, event, 1, firstModel, security)
      .event_fields();
  ASSERT_EQ(allowed.size(), 1u);
  ASSERT_TRUE(allowed[0].is_uint16());
  EXPECT_EQ(allowed[0].as<uint16_t>(), 616u);

  auto replacementModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(alternate_severity(), "Severity")});
  const auto denied =
    project_authorized_fields(address_space(), *compiled.filter, event, 1, replacementModel, security)
      .event_fields();
  ASSERT_EQ(denied.size(), 1u);
  ASSERT_TRUE(denied[0].is_status_code());
  EXPECT_EQ(denied[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
}

// @relation(AC-COMP-SVR-EVENTDECL-05-RETAINED-FILTER-STATE, scope=function)
TEST_F(EventFieldAuthorizationTest, RetainedFilterDropsNodeHandlesAndUsesOnlyTheCurrentDeclarationModel)
{
  set_permissions(severity(), PermissionType{});
  set_permissions(alternate_severity(), PermissionType{PermissionType::Bit::Read});
  MutableEventSessionSecurityContext security;
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);
  ASSERT_TRUE(CompiledEventFilterTestAccess::retains_declaration_accessors(*compiled.filter));

  const auto retained = compiled.filter->retained_copy();
  ASSERT_NE(retained, nullptr);
  EXPECT_FALSE(CompiledEventFilterTestAccess::retains_declaration_accessors(*retained));

  auto event = make_test_event(401);
  event.eventType = NodeId{1, 1962000u};
  auto currentModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(alternate_severity(), "Severity")});
  const auto fields =
    project_authorized_fields(address_space(), *retained, event, 1, currentModel, security).event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_uint16());
  EXPECT_EQ(fields[0].as<uint16_t>(), 401u);
}

// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
// @relation(AC-COMP-SVR-EVENTDECL-04-NO-AUTH-BYPASS, scope=function)
TEST_F(EventFieldAuthorizationTest, NamespacePermissionsRemainMandatoryWithoutAnApplicationHook)
{
  MutableEventSessionSecurityContext security;
  set_permissions(severity(), PermissionType{});
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Severity"}), {std::optional<NodeAccessor>{severity()}});
  ASSERT_TRUE(compiled.filter);
  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(severity(), "Severity")});

  const auto fields = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(808), 1, concreteModel, security)
                        .event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_status_code());
  EXPECT_EQ(fields[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
}

// Runtime: select clause projection
// ============================================================================

// @relation(SVR-EVT-ATTR-012, SVR-MI-EVT-001, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, ProjectReturnsFieldsInSelectOrder)
{
  auto filter = make_select_only_filter({"Severity", "EventType", "SourceName"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event(750);
  auto fieldList = compiled.filter->project(event, 42);

  EXPECT_EQ(fieldList.client_handle(), 42u);

  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 3u);

  ASSERT_TRUE(fields[0].is_uint16());
  EXPECT_EQ(fields[0].as<uint16_t>(), 750);

  ASSERT_TRUE(fields[1].is_node_id());
  auto expectedType = NodeId{ObjectTypeId::BaseEventType};
  EXPECT_EQ(fields[1].as<NodeId>(), expectedType);

  ASSERT_TRUE(fields[2].is_string());
}

// @relation(AC-SVR-MI-EVT-007-ENCODINGLIMITS, scope=function)
TEST(EventFilterTests, OversizeFieldProjectsAsEncodingLimitsExceededWithoutDroppingItsSiblings)
{
  auto compiled = CompiledEventFilter::compile(make_select_only_filter({"Message", "Severity"}));
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event(321);
  event.message = LocalizedText{"", std::string(1024, 'x')};
  const auto fields = compiled.filter->project(event, 9, 64).event_fields();

  ASSERT_EQ(fields.size(), 2u);
  ASSERT_TRUE(fields[0].is_status_code());
  EXPECT_EQ(fields[0].as<StatusCode>().as_status(), Status::BadEncodingLimitsExceeded);
  ASSERT_TRUE(fields[1].is_uint16());
  EXPECT_EQ(fields[1].as<uint16_t>(), 321);
}

// @relation(AC-SVR-MI-EVT-007-ENCODINGLIMITS, scope=function)
TEST(EventFilterTests, ZeroMaxResponseMessageSizeLeavesProjectedFieldsUnbounded)
{
  auto compiled = CompiledEventFilter::compile(make_select_only_filter({"Message"}));
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.message = LocalizedText{"", std::string(1024, 'x')};
  const auto fields = compiled.filter->project(event, 9, 0).event_fields();

  ASSERT_EQ(fields.size(), 1u);
  EXPECT_TRUE(fields[0].is_localized_text());
}

TEST(EventFilterTests, ProjectReturnsNullForInvalidSelectClause)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));

  SimpleAttributeOperand badClause;
  badClause.browse_path().push_back(QualifiedName{0, String{}});
  filter.select_clauses().push_back(std::move(badClause));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fieldList = compiled.filter->project(make_test_event(), 1);
  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 2u);

  EXPECT_FALSE(fields[0].empty());
  EXPECT_TRUE(fields[1].empty());
}

// An empty browse path is a valid SelectClause (Part 4 section 7.4.4.5): it refers to the typeDefinition
// instance itself. With the NodeId attribute it selects the ConditionId of a condition event.
TEST(EventFilterTests, CompileSelectClauseWithEmptyBrowsePathAndNodeIdSucceeds)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  // browse_path intentionally left empty
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);
  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_TRUE(result.filterResult.select_clause_results()[0].is_good());
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);
}

TEST(EventFilterTests, ProjectEmptyBrowsePathNodeIdReturnsConditionId)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(clause));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  const auto conditionId = NodeId{2, 4242u};
  event.conditionNodeId = conditionId;

  auto fieldList = compiled.filter->project(event, 7);
  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 1u);
  ASSERT_TRUE(fields[0].is_node_id());
  EXPECT_EQ(fields[0].as<NodeId>(), conditionId);
}

// A ConditionId operand (empty browse path + NodeId attribute, Part 4 section 7.7.4.5 Table 133) must
// resolve to the event's ConditionId in WHERE-clause evaluation, not only in select projection.
// The UACTT A&C Basic per-unit monitor filters on exactly this: WhereClause = InList(ConditionId,
// [<ids under test>]). Resolving it only during projection (and returning null in the where clause)
// silently drops every alarm event from that monitor.
TEST(EventFilterTests, WhereClauseConditionIdOperandResolvesInListMatch)
{
  const auto conditionId = NodeId{2, 4242u};

  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  add_where_element(
    filter, FilterOperator::InList, {make_condition_id_operand(), make_literal(Variant{conditionId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.conditionNodeId = conditionId;
  EXPECT_TRUE(compiled.filter->evaluate(event));  // ConditionId in the list -> event passes
}

TEST(EventFilterTests, WhereClauseConditionIdOperandRejectsNonMatch)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  add_where_element(
    filter, FilterOperator::InList, {make_condition_id_operand(), make_literal(Variant{NodeId{2, 4242u}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.conditionNodeId = NodeId{2, 9999u};  // different ConditionId
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

// Equals is the other operator the conformance helpers use to scope a single condition.
TEST(EventFilterTests, WhereClauseConditionIdOperandEqualsMatch)
{
  const auto conditionId = NodeId{2, 4242u};

  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  add_where_element(
    filter, FilterOperator::Equals, {make_condition_id_operand(), make_literal(Variant{conditionId})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.conditionNodeId = conditionId;
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

// OPC 10000-9 section 4.5: RefreshStartEventType, RefreshEndEventType and RefreshRequiredEventType "ignore
// the Event content filtering associated with a Subscription and will always be delivered to the Client".
// The where clause here excludes every other event: the UACTT A&C Refresh monitor filters with
// InList(ConditionId, [...]), which a refresh event, having no ConditionId, never matches.
// @relation(AC-SVR-AC-220-REFRESH-BRACKET-IGNORES-WHERE, AC-SVR-AC-220-REFRESHREQUIRED-IGNORES-WHERE, scope=function)
TEST(EventFilterTests, TheRefreshEventTypesIgnoreTheWhereClause)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  add_where_element(
    filter, FilterOperator::InList, {make_condition_id_operand(), make_literal(Variant{NodeId{2, 4242u}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  const auto ordinary = make_test_event();
  EXPECT_FALSE(compiled.filter->evaluate(ordinary)) << "control: the where clause excludes an ordinary event";
  EXPECT_FALSE(compiled.filter->evaluate_authorized(ordinary, nullptr, {})) << "control, authorized path";
  for (const auto type : {ObjectTypeId::RefreshStartEventType,
         ObjectTypeId::RefreshEndEventType,
         ObjectTypeId::RefreshRequiredEventType})
  {
    auto refresh = make_test_event();
    refresh.eventType = NodeId{type};
    EXPECT_TRUE(compiled.filter->evaluate(refresh)) << ua::to_string(NodeId{type});
    EXPECT_TRUE(compiled.filter->evaluate_authorized(refresh, nullptr, {})) << ua::to_string(NodeId{type});
  }
}

// Part 4 section 7.7.4.5 Table 133: an operand applies only to instances of its typeDefinitionId or a
// subtype. Two operands for the SAME field (Severity) differ only in typeDefinitionId - one a
// supertype the event is an instance of (resolves), one an unrelated type it is not (null), even
// though the event carries Severity. Needs the event's supertype chain, as the EventBus attaches it.
TEST(EventFilterTests, SelectClauseTypeDefinitionIdRestrictsResolution)
{
  auto event = make_test_event(700);
  set_event_type_hierarchy(event,
    {NodeId{ObjectTypeId::AlarmConditionType},
      NodeId{ObjectTypeId::ConditionType},
      NodeId{ObjectTypeId::BaseEventType}});

  EventFilter filter;

  // [0] typeDefinitionId = AlarmConditionType - in the event's chain -> Severity resolves.
  SimpleAttributeOperand applicable;
  applicable.type_definition_id() = NodeId{ObjectTypeId::AlarmConditionType};
  applicable.browse_path().push_back(QualifiedName{0, String{"Severity"}});
  applicable.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(applicable));

  // [1] typeDefinitionId = LimitAlarmType - NOT in the chain -> null, despite the event having Severity.
  SimpleAttributeOperand inapplicable;
  inapplicable.type_definition_id() = NodeId{ObjectTypeId::LimitAlarmType};
  inapplicable.browse_path().push_back(QualifiedName{0, String{"Severity"}});
  inapplicable.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(inapplicable));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fields = compiled.filter->project(event, 1).event_fields();
  ASSERT_EQ(fields.size(), 2u);
  ASSERT_FALSE(fields[0].empty());
  EXPECT_EQ(fields[0].as<uint16_t>(), uint16_t{700});  // AlarmConditionType operand applies
  EXPECT_TRUE(fields[1].empty());  // LimitAlarmType operand does not apply -> null
}

// Off the EventBus a hand-built event has no supertype chain, so the typeDefinitionId restriction
// cannot be evaluated. It must not be turned into a false non-match that drops a requested field.
TEST(EventFilterTests, SelectClauseTypeDefinitionIdAppliesWhenHierarchyUnknown)
{
  auto event = make_test_event(500);  // no event_type_hierarchy set

  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::AlarmConditionType};
  clause.browse_path().push_back(QualifiedName{0, String{"Severity"}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(clause));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fields = compiled.filter->project(event, 1).event_fields();
  ASSERT_EQ(fields.size(), 1u);
  EXPECT_FALSE(fields[0].empty());  // unknown hierarchy -> operand applies, field resolves
}

// Covers SVR-MI-EVT-004 (coverage-audit retag).
// @relation(SVR-MI-EVT-004, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, ProjectReturnsNullForUnknownField)
{
  auto filter = make_select_only_filter({"EventId", "NonExistent"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fieldList = compiled.filter->project(make_test_event(), 1);
  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 2u);

  EXPECT_FALSE(fields[0].empty());
  EXPECT_TRUE(fields[1].empty());
}

// @relation(SVR-MI-EVT-001, scope=function)
TEST(EventFilterTests, ProjectFieldCountMatchesSelectClauseCount)
{
  auto filter = make_select_only_filter(
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fieldList = compiled.filter->project(make_test_event(), 1);
  EXPECT_EQ(fieldList.event_fields().size(), 8u);
}

// ============================================================================
// GenericEvent with filter
// ============================================================================

TEST(EventFilterTests, FilterWorksWithGenericEvent)
{
  auto typeId = NodeId{1, 5000u};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{1, 100u};
  event.sourceName = String{"Device/Pump-1"};
  event.message = LocalizedText{LocaleId{}, String{"Pressure exceeded"}};
  event.severity = 600;
  event.eventId = ByteString{0x04, 0x05};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();
  event.set_field({QualifiedName{1, "PressureValue"}}, Variant{4.82});

  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("Severity"));

  SimpleAttributeOperand customClause;
  customClause.type_definition_id() = typeId;
  customClause.browse_path().push_back(QualifiedName{1, "PressureValue"});
  customClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(customClause));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto fieldList = compiled.filter->project(event, 99);
  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 2u);

  EXPECT_EQ(fields[0].as<uint16_t>(), 600);
  EXPECT_DOUBLE_EQ(fields[1].as<double>(), 4.82);
}

// ============================================================================
// Three-valued logic
// ============================================================================

// @relation(SVR-MI-EVT-010, scope=function)
TEST(EventFilterTests, AndWithNullOperand)
{
  auto filter = make_select_only_filter({"EventId"});

  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_literal(Variant{true})});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("NonExistent"), make_literal(Variant{42})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // null AND true -> null -> does not pass
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, AndNullAndFalseReturnsFalse)
{
  auto filter = make_select_only_filter({"EventId"});

  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_literal(Variant{false})});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("NonExistent"), make_literal(Variant{42})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_FALSE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, OrNullAndTrueReturnsTrue)
{
  auto filter = make_select_only_filter({"EventId"});

  add_where_element(filter, FilterOperator::Or, {make_element_ref(1), make_literal(Variant{true})});

  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("NonExistent"), make_literal(Variant{42})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // null OR true -> true
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// ============================================================================
// TEST-FLT-014: EventId, EventType, ReceiveTime always valid
// ============================================================================

// @relation(SVR-MI-EVT-001, scope=function)
TEST(EventFilterTests, MandatoryFieldsAlwaysValidInProjection)
{
  // SVR-EVT-FLT-014: EventId, EventType, ReceiveTime cannot contain StatusCode or null
  auto filter = make_select_only_filter({"EventId", "EventType", "ReceiveTime"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  BaseEvent event;
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  event.eventId = ByteString{0xAA};
  event.receiveTime = DateTime::now();

  auto fieldList = compiled.filter->project(event, 1);
  auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 3u);

  // EventId - always non-empty ByteString
  EXPECT_FALSE(fields[0].empty());
  EXPECT_TRUE(fields[0].is_byte_string());

  // EventType - always NodeId
  EXPECT_FALSE(fields[1].empty());
  EXPECT_TRUE(fields[1].is_node_id());

  // ReceiveTime - always DateTime
  EXPECT_FALSE(fields[2].empty());
  EXPECT_TRUE(fields[2].is_date_time());
}

// ============================================================================
// TEST-FLT-019-P2: basic operators accepted in where clause
// ============================================================================

TEST(EventFilterTests, BasicOperatorsAcceptedInWhereClause)
{
  // Equals, GreaterThan, And, Or, Not - all accepted
  auto filter = make_select_only_filter({"EventId"});

  // Element 0: And(element[1], element[2])
  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_element_ref(2)});

  // Element 1: Or(element[3], literal(true))
  add_where_element(filter, FilterOperator::Or, {make_element_ref(3), make_literal(Variant{true})});

  // Element 2: Not(literal(false))
  add_where_element(filter, FilterOperator::Not, {make_literal(Variant{false})});

  // Element 3: GreaterThan(Severity, 100)
  add_where_element(filter,
    FilterOperator::GreaterThan,
    {make_sao_operand("Severity"), make_literal(Variant{uint16_t{100}})});

  auto compiled = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(compiled.overallStatus.is_good());
  ASSERT_TRUE(compiled.filter);
}

// ============================================================================
// TEST-CAP: MaxSelectClauseParameters / MaxWhereClauseParameters
// ============================================================================

// @relation(SVR-MI-EVT-007, SVR-MI-EVT-015, scope=function)
TEST(EventFilterTests, MaxSelectClauseParametersEnforced)
{
  // SVR-EVT-CAP-001: reject if more select clauses than limit
  auto filter = make_select_only_filter({"EventId", "EventType", "Severity"});

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 2;

  auto compiled = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(compiled.overallStatus.is_bad());
}

TEST(EventFilterTests, MaxSelectClauseParametersNotExceeded)
{
  auto filter = make_select_only_filter({"EventId", "EventType"});

  EventFilterCompileLimits limits;
  limits.maxSelectClauses = 2;

  auto compiled = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(compiled.overallStatus.is_good());
}

TEST(EventFilterTests, MaxWhereClauseParametersEnforced)
{
  // SVR-EVT-CAP-002: reject if more where clause elements than limit
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(
    filter, FilterOperator::Equals, {make_sao_operand("Severity"), make_literal(Variant{uint16_t{500}})});
  add_where_element(filter, FilterOperator::IsNull, {make_sao_operand("ConditionClassId")});

  EventFilterCompileLimits limits;
  limits.maxWhereClauseElements = 1;

  auto compiled = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(compiled.overallStatus.is_bad());
}

TEST(EventFilterTests, MaxWhereClauseParametersNotExceeded)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::IsNull, {make_sao_operand("ConditionClassId")});

  EventFilterCompileLimits limits;
  limits.maxWhereClauseElements = 1;

  auto compiled = CompiledEventFilter::compile(filter, limits);
  EXPECT_TRUE(compiled.overallStatus.is_good());
}

// ============================================================================
// Like operator
// ============================================================================

TEST(EventFilterTests, LikeExactLiteralMatch)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"MainPump"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"MainPump"};
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikeExactLiteralMismatch)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"MainPump"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"AuxPump"};
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikePercentAtEnd)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"Main%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"MainPump-1"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"AuxPump"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikePercentAtStart)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"%A"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"SensorA"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"SensorB"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikePercentInMiddle)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"abc%def"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"abc123def"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"abc123xyz"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikePercentMatchesEmpty)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"Main%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"Main"};
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikePercentAlone)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"anything"};
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikeUnderscoreSingleChar)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"a_"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"ab"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"abc"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeCharacterSet)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"abc[123]"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"abc1"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"abc4"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeCharacterRange)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"xyz[a-f]"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"xyzd"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"xyzg"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeNegatedCharacterSet)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"ABC[^135]"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"ABC2"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"ABC1"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeCombinedWildcards)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(filter,
    FilterOperator::Like,
    {make_sao_operand("SourceName"), make_literal(Variant{String{"Th[ia][ts]%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"That is fine"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"Then at any"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeEscapePercent)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"50\\%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"50%"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"500"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeEscapeUnderscore)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"a\\_b"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"a_b"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"axb"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeEscapeBackslash)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"a\\\\b"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"a\\b"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"axb"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikePercentInCharSet)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"5[%]"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"5%"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"55"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

TEST(EventFilterTests, LikeCaseSensitive)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"main"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"Main"};
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikeEmptyPatternMatchesEmpty)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{""}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{""};
  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikeEmptyPatternRejectsNonEmpty)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{""}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto event = make_test_event();
  event.sourceName = String{"abc"};
  EXPECT_FALSE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, LikeNonStringOperandReturnsFalse)
{
  // Spec: Like returns FALSE (not NULL) if operands are not strings.
  // Severity is uint16, not string. Verify false (not null) by wrapping in Not:
  // Not(false) = true (if null, Not(null) = null -> event fails).
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Not, {make_element_ref(1)});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("Severity"), make_literal(Variant{String{"500"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
}

TEST(EventFilterTests, LikeNullOperandReturnsFalse)
{
  // Spec: Like returns FALSE (not NULL) if operands cannot resolve to strings.
  // NonExistent field -> null operand. Verify false via Not(Like(...)) = true.
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(filter, FilterOperator::Not, {make_element_ref(1)});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("NonExistent"), make_literal(Variant{String{"%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, LikeInWhereClauseFiltersEvents)
{
  auto filter = make_select_only_filter({"SourceName"});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"Pump%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event();
  matching.sourceName = String{"Pump-Station-1"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatching = make_test_event();
  nonMatching.sourceName = String{"Valve-Station-1"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching));
}

// ============================================================================
// Cast operator
// ============================================================================

// --- Numeric conversions ---

TEST(EventFilterTests, CastInt16ToInt32)
{
  auto typeId = NodeId{ObjectTypeId::BaseEventType};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{ObjectId::Server};
  event.eventId = ByteString{0x01};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();
  event.severity = 500;
  event.set_field({QualifiedName{0, "Value"}}, Variant{int16_t{42}});

  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));

  SimpleAttributeOperand customClause;
  customClause.type_definition_id() = typeId;
  customClause.browse_path().push_back(QualifiedName{0, "Value"});
  customClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(customClause));

  auto sao = std::make_unique<SimpleAttributeOperand>();
  sao->type_definition_id() = typeId;
  sao->browse_path().push_back(QualifiedName{0, "Value"});
  sao->attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  RefStructure<Structure> saoRef;
  saoRef.inner_unique_ptr() = std::move(sao);

  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{42}})});
  add_where_element(
    filter, FilterOperator::Cast, {std::move(saoRef), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(event));
}

TEST(EventFilterTests, CastInt32ToInt16OutOfRange)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{40000}}), make_datatype_literal(DataTypeId::Int16)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastDoubleToInt32Rounds)
{
  // Spec: float->int rounds by adding 0.5 and truncating. 3.7 + 0.5 = 4.2 -> 4.
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{4}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{double{3.7}}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastNegativeToUnsignedReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{-1}}), make_datatype_literal(DataTypeId::UInt32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastInt32ToUInt64)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{uint64_t{42}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{42}}), make_datatype_literal(DataTypeId::UInt64)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastDoubleToInt32RoundsNegative)
{
  // Spec: -3.7 + 0.5 = -3.2, truncate toward zero -> -3.
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{-3}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{double{-3.7}}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- Boolean conversions ---

TEST(EventFilterTests, CastBoolTrueToInt32)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{1}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_literal(Variant{true}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastZeroToBool)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Not, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{0}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // Not(false) = true.
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastNonZeroToBool)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{42}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastBoolToString)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"1"}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_literal(Variant{true}), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringTrueToBool)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"true"}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringFalseToBool)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Not, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"false"}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  // Not(false) = true.
  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringTRUECaseInsensitive)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"TRUE"}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastInvalidStringToBoolReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"yes"}}), make_datatype_literal(DataTypeId::Boolean)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- String conversions ---

TEST(EventFilterTests, CastInt32ToString)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"42"}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{42}}), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringToInt32)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{42}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"42"}}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastInvalidStringToInt32ReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"abc"}}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastLocalizedTextToString)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"Hello"}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{LocalizedText{LocaleId{"en"}, String{"Hello"}}}),
      make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringToLocalizedText)
{
  // String -> LT -> String roundtrip.
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"Hello"}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_element_ref(2), make_datatype_literal(DataTypeId::String)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"Hello"}}), make_datatype_literal(DataTypeId::LocalizedText)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastQualifiedNameToString)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"MyName"}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{QualifiedName{5, "MyName"}}), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringToQualifiedName)
{
  // String -> QN -> String roundtrip.
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"MyName"}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_element_ref(2), make_datatype_literal(DataTypeId::String)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"MyName"}}), make_datatype_literal(DataTypeId::QualifiedName)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastNodeIdToString)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"i=2253"}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{NodeId{ObjectId::Server}}), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringToNodeId)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{NodeId{ObjectId::Server}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{"i=2253"}}), make_datatype_literal(DataTypeId::NodeId)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastGuidToString)
{
  Guid guid = Guid::parse("550e8400-e29b-41d4-a716-446655440000");
  auto expected = guid.as_string();

  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{expected}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_literal(Variant{guid}), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStringToGuid)
{
  Guid expected = Guid::parse("550e8400-e29b-41d4-a716-446655440000");

  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{expected})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{String{expected.as_string()}}), make_datatype_literal(DataTypeId::Guid)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- StatusCode conversions ---

TEST(EventFilterTests, CastStatusCodeToUInt32)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{uint32_t{0x80350000u}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{StatusCode{0x80350000u}}), make_datatype_literal(DataTypeId::UInt32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastUInt32ToStatusCode)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{StatusCode{0x80350000u}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{uint32_t{0x80350000u}}), make_datatype_literal(DataTypeId::StatusCode)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastStatusCodeToUInt16)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{uint16_t{0x8035u}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{StatusCode{0x80350000u}}), make_datatype_literal(DataTypeId::UInt16)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- Guid/ByteString conversions ---

TEST(EventFilterTests, CastGuidToByteString)
{
  Guid guid = Guid::parse("550e8400-e29b-41d4-a716-446655440000");
  auto expectedBytes = guid.as_ua_binary();
  ByteString expectedBs{span<const byte>{expectedBytes.data(), expectedBytes.size()}};

  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{expectedBs})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{guid}), make_datatype_literal(DataTypeId::ByteString)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastByteStringToGuid)
{
  Guid expectedGuid = Guid::parse("550e8400-e29b-41d4-a716-446655440000");
  auto bytes = expectedGuid.as_ua_binary();
  ByteString bs{span<const byte>{bytes.data(), bytes.size()}};

  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{expectedGuid})});
  add_where_element(
    filter, FilterOperator::Cast, {make_literal(Variant{bs}), make_datatype_literal(DataTypeId::Guid)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- Error cases ---

// @relation(SVR-MI-EVT-010, scope=function)
TEST(EventFilterTests, CastNullOperandReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_sao_operand("NonExistent"), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastImpossibleConversionReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{DateTime::now()}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastInvalidTargetNodeIdReturnsNull)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::IsNull, {make_element_ref(1)});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{42}}), make_literal(Variant{NodeId{1, 999u}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

TEST(EventFilterTests, CastIdentityReturnsOriginal)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{int32_t{42}})});
  add_where_element(filter,
    FilterOperator::Cast,
    {make_literal(Variant{int32_t{42}}), make_datatype_literal(DataTypeId::Int32)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event()));
}

// --- Integration ---

TEST(EventFilterTests, CastInWhereClauseFiltersEvents)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(
    filter, FilterOperator::Equals, {make_element_ref(1), make_literal(Variant{String{"500"}})});
  add_where_element(
    filter, FilterOperator::Cast, {make_sao_operand("Severity"), make_datatype_literal(DataTypeId::String)});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  EXPECT_TRUE(compiled.filter->evaluate(make_test_event(500)));
  EXPECT_FALSE(compiled.filter->evaluate(make_test_event(501)));
}

TEST(EventFilterTests, CastChainedWithOtherOperators)
{
  auto filter = make_select_only_filter({"Severity"});
  add_where_element(filter, FilterOperator::And, {make_element_ref(1), make_element_ref(2)});
  add_where_element(
    filter, FilterOperator::Cast, {make_sao_operand("Severity"), make_datatype_literal(DataTypeId::Boolean)});
  add_where_element(
    filter, FilterOperator::Like, {make_sao_operand("SourceName"), make_literal(Variant{String{"Pump%"}})});

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  auto matching = make_test_event(500);
  matching.sourceName = String{"Pump-1"};
  EXPECT_TRUE(compiled.filter->evaluate(matching));

  auto nonMatchingName = make_test_event(500);
  nonMatchingName.sourceName = String{"Valve-1"};
  EXPECT_FALSE(compiled.filter->evaluate(nonMatchingName));
}

// ============================================================================
// Select clause: TwoStateVariable meta-data Properties
// ============================================================================

// Part 9 section 5.2 (lines 1300-1302): "Since the two Properties provide meta-data for the Type,
// Servers shall not allow these Properties to be selected in the Event filter for a MonitoredItem."
// A select-clause validator that only checks the browse names are non-empty and the attributeId is
// one of Value/NodeId - the two checks any SimpleAttributeOperand needs - accepts TrueState happily,
// and every notification then carries a constant column paid for on every publish.
// @verifies AC-SVR-AC-043-TRUESTATE-NOT-SELECTABLE
TEST(EventFilterTests, TrueStateIsNotSelectableInAnEventFilter)
{
  EventFilter filter;

  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  clause.browse_path().push_back(QualifiedName{0, String{"AckedState"}});
  clause.browse_path().push_back(QualifiedName{0, String{"TrueState"}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(clause));

  auto result = CompiledEventFilter::compile(filter);

  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  EXPECT_TRUE(result.filterResult.select_clause_results()[0].is_bad())
    << "selecting the TrueState meta-data Property must be refused at the clause";
  EXPECT_TRUE(result.overallStatus.is_bad())
    << "the filter's only select clause is refused, so the filter itself is refused";
}

// Part 9 section 5.2, stated for the TwoStateVariableType definition: BOTH TrueState and FalseState
// are Type meta-data and neither may be selected. The refusal must also be specific - a server that
// rejected the whole TwoStateVariable would deny clients the state they are entitled to select, so
// the parent EnabledState clause is the control and must still compile.
// @verifies AC-SVR-AC-119-TWOSTATE-METADATA-NOT-SELECTABLE
TEST(EventFilterTests, TwoStateVariableMetadataPropertiesAreNotSelectable)
{
  EventFilter filter;

  // [0] control: the TwoStateVariable itself is ordinary Event content and stays selectable.
  SimpleAttributeOperand enabledState;
  enabledState.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  enabledState.browse_path().push_back(QualifiedName{0, String{"EnabledState"}});
  enabledState.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(enabledState));

  // [1] TrueState and [2] FalseState: the two meta-data Properties of the same TwoStateVariable.
  for (std::string_view property : {"TrueState", "FalseState"})
  {
    SimpleAttributeOperand metadata;
    metadata.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
    metadata.browse_path().push_back(QualifiedName{0, String{"EnabledState"}});
    metadata.browse_path().push_back(QualifiedName{0, String{property}});
    metadata.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(metadata));
  }

  auto result = CompiledEventFilter::compile(filter);

  const auto& results = result.filterResult.select_clause_results();
  ASSERT_EQ(results.size(), 3u);
  EXPECT_TRUE(results[0].is_good()) << "the TwoStateVariable itself must remain selectable";
  EXPECT_TRUE(results[1].is_bad()) << "EnabledState/TrueState must be refused";
  EXPECT_TRUE(results[2].is_bad()) << "EnabledState/FalseState must be refused";
}

// ============================================================================
// Select clause contract: one field per clause, guaranteed attributes, bad-status Values
// ============================================================================

// Part 4 section 7.22: the Event Notification carries the fields the selectClauses name, one per
// clause and in clause order. The fields travel without names, so positional correspondence is the
// whole contract - a server that merged, reordered or dropped a clause's field shifts every field
// after it and the client silently misreads the remainder as the wrong field.
// @verifies AC-SVR-MI-EVT-001-SELECTCLAUSE-FIELDS
TEST(EventFilterTests, EventNotificationCarriesOneFieldPerSelectClauseInClauseOrder)
{
  auto filter = make_select_only_filter({"Severity", "EventType", "SourceNode", "SourceName"});
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);
  ASSERT_EQ(compiled.filter->select_clauses().size(), 4u);

  auto event = make_test_event(825);
  auto fieldList = compiled.filter->project(event, 11);
  EXPECT_EQ(fieldList.client_handle(), 11u);

  const auto& fields = fieldList.event_fields();
  ASSERT_EQ(fields.size(), 4u) << "exactly one field per select clause";

  ASSERT_TRUE(fields[0].is_uint16());
  EXPECT_EQ(fields[0].as<uint16_t>(), uint16_t{825});

  // EventType and SourceNode are both NodeIds, so only their VALUES prove the order held.
  auto expectedEventType = NodeId{ObjectTypeId::BaseEventType};
  ASSERT_TRUE(fields[1].is_node_id());
  EXPECT_EQ(fields[1].as<NodeId>(), expectedEventType);

  auto expectedSourceNode = NodeId{ObjectId::Server};
  ASSERT_TRUE(fields[2].is_node_id());
  EXPECT_EQ(fields[2].as<NodeId>(), expectedSourceNode);

  EXPECT_TRUE(fields[3].is_string());
  EXPECT_FALSE(fields[3].empty());
}

// Part 4 section 7.22.3: "The Server is only required to support the Value Attribute for Variable
// Nodes and the NodeId Attribute for Object Nodes in the EventFilter." Both halves of that floor
// must hold together: a validator that accepted only Value would refuse the standard ConditionId
// operand (empty browse path + NodeId), and one that accepted only NodeId would refuse every
// ordinary field selection. Compiling is not enough either - the clause must actually project.
// @verifies AC-SVR-MI-EVT-003-REQUIRED-ATTRIBUTES
TEST(EventFilterTests, ValueOnAVariableAndNodeIdOnAnObjectAreBothSupported)
{
  EventFilter filter;

  // Value on a Variable field (Severity is a Property of BaseEventType).
  SimpleAttributeOperand variableValue;
  variableValue.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  variableValue.browse_path().push_back(QualifiedName{0, String{"Severity"}});
  variableValue.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(variableValue));

  // NodeId on an Object node: an empty browse path names the instance of the typeDefinition itself.
  SimpleAttributeOperand objectNodeId;
  objectNodeId.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  objectNodeId.attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  filter.select_clauses().push_back(std::move(objectNodeId));

  auto result = CompiledEventFilter::compile(filter);

  const auto& results = result.filterResult.select_clause_results();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_TRUE(results[0].is_good()) << "Value on a Variable field must be supported";
  EXPECT_TRUE(results[1].is_good()) << "NodeId on an Object node must be supported";
  EXPECT_TRUE(result.overallStatus.is_good());
  ASSERT_TRUE(result.filter);

  auto event = make_test_event(640);
  const auto conditionId = NodeId{3, 77u};
  event.conditionNodeId = conditionId;

  const auto fields = result.filter->project(event, 5).event_fields();
  ASSERT_EQ(fields.size(), 2u);
  ASSERT_TRUE(fields[0].is_uint16());
  EXPECT_EQ(fields[0].as<uint16_t>(), uint16_t{640});
  ASSERT_TRUE(fields[1].is_node_id());
  EXPECT_EQ(fields[1].as<NodeId>(), conditionId);
}

// Part 4 section 7.22.3: "If a Value Attribute has an uncertain or bad StatusCode associated with it
// then the Server shall provide the StatusCode instead of the Value Attribute." An Event field is a
// bare Variant with no room for a status beside the value, so the status must REPLACE it. A
// projection that simply copies whatever the field holds hands the client either the stale value
// with the bad status stripped off, or the whole DataValue - the first is silently wrong data, the
// second is not the encoding the field position promises. A Good status must still deliver the
// value, otherwise the substitution is unconditional rather than status-driven.
// @verifies AC-SVR-MI-EVT-006-BAD-VALUE-BECOMES-STATUS
TEST(EventFilterTests, ValueWithUncertainOrBadStatusIsReportedAsTheStatusCode)
{
  auto typeId = NodeId{ObjectTypeId::BaseEventType};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"Pump-1"};
  event.message = LocalizedText{LocaleId{}, String{"Test event"}};
  event.severity = 500;
  event.eventId = ByteString{0x01, 0x02, 0x03};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();

  event.set_field(
    {QualifiedName{1, "BadValue"}}, Variant{DataValue{Variant{4.82}, StatusCode{Status::BadDeviceFailure}}});
  event.set_field({QualifiedName{1, "UncertainValue"}},
    Variant{DataValue{Variant{7.15}, StatusCode{Status::UncertainLastUsableValue}}});
  event.set_field(
    {QualifiedName{1, "GoodValue"}}, Variant{DataValue{Variant{1.25}, StatusCode{Status::Good}}});

  EventFilter filter;
  for (std::string_view field : {"BadValue", "UncertainValue", "GoodValue"})
  {
    SimpleAttributeOperand clause;
    clause.type_definition_id() = typeId;
    clause.browse_path().push_back(QualifiedName{1, String{field}});
    clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(clause));
  }

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  const auto fields = compiled.filter->project(event, 3).event_fields();
  ASSERT_EQ(fields.size(), 3u);

  // Bad status: the StatusCode, and specifically NOT the value it was attached to.
  EXPECT_FALSE(fields[0].is_double()) << "a bad-status Value must not be delivered as its value";
  EXPECT_FALSE(fields[0].is_data_value()) << "the field carries the status, not the value+status pair";
  ASSERT_TRUE(fields[0].is_status_code());
  EXPECT_EQ(fields[0].as<StatusCode>().as_status(), Status::BadDeviceFailure);

  // Uncertain status: the same substitution.
  EXPECT_FALSE(fields[1].is_double()) << "an uncertain-status Value must not be delivered as its value";
  EXPECT_FALSE(fields[1].is_data_value());
  ASSERT_TRUE(fields[1].is_status_code());
  EXPECT_EQ(fields[1].as<StatusCode>().as_status(), Status::UncertainLastUsableValue);

  // Good status: the value is delivered, proving the substitution is driven by the status.
  ASSERT_TRUE(fields[2].is_double()) << "a Good-status Value must still deliver its value";
  EXPECT_DOUBLE_EQ(fields[2].as<double>(), 1.25);
}

// ============================================================================
// Where clause: per-Event evaluation errors
// ============================================================================

// Part 4 section 7.22.3: "The Server shall use a null value if any error occurs when a whereClause is
// evaluated for a particular Event." The scope is the single Event, not the filter: an implementation
// that treated an evaluation error as a fault of the filter would stop admitting every later Event
// that does match, while the MonitoredItem kept reporting Good - the client simply stops receiving.
// The unit-level reading of "the MonitoredItem is not torn down" is that the compiled filter survives
// the error with its behaviour unchanged, which is what the subscription layer keeps using.
// @verifies AC-SVR-MI-EVT-010-WHERECLAUSE-ERROR-NULL
TEST(EventFilterTests, WhereClauseEvaluationErrorNullsOnlyTheEventThatCausedIt)
{
  auto filter = make_select_only_filter({"EventId"});
  add_where_element(
    filter, FilterOperator::GreaterThan, {make_sao_operand("Reading"), make_literal(Variant{int32_t{10}})});

  auto compiled = CompiledEventFilter::compile(filter);
  EXPECT_TRUE(compiled.overallStatus.is_good());
  ASSERT_TRUE(compiled.filter);

  auto makeReadingEvent = [](Variant reading)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = String{"Pump-1"};
    event.message = LocalizedText{LocaleId{}, String{"Test event"}};
    event.severity = 500;
    event.eventId = ByteString{0x01, 0x02, 0x03};
    event.time = DateTime::now();
    event.receiveTime = DateTime::now();
    event.set_field({QualifiedName{0, String{"Reading"}}}, std::move(reading));
    return event;
  };

  // A String Reading cannot be ordered against the numeric literal: evaluating THIS Event errors.
  const auto erroring = makeReadingEvent(Variant{String{"not-a-number"}});
  const auto matching = makeReadingEvent(Variant{int32_t{50}});
  const auto nonMatching = makeReadingEvent(Variant{int32_t{5}});

  EXPECT_TRUE(compiled.filter->evaluate(matching)) << "a clean Event above the threshold is delivered";
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching)) << "a clean Event below the threshold is not";

  EXPECT_FALSE(compiled.filter->evaluate(erroring))
    << "the erroring Event evaluates to null, and null is not true, so it is not delivered";

  // The error was scoped to that one Event: the same filter still admits and still rejects exactly as
  // before, so nothing about the MonitoredItem's filtering has been invalidated by it.
  EXPECT_TRUE(compiled.filter->evaluate(matching))
    << "a clean Event AFTER the erroring one must still be delivered";
  EXPECT_FALSE(compiled.filter->evaluate(nonMatching))
    << "and the filter must still discriminate rather than pass everything";

  // Repeat the sequence: a second error must not accumulate into a permanent refusal either.
  EXPECT_FALSE(compiled.filter->evaluate(erroring));
  EXPECT_TRUE(compiled.filter->evaluate(matching))
    << "a second evaluation error must not disable the filter for subsequent Events";
}

// ============================================================================
// Select clause: browsePath InstanceDeclaration NodeClass
// ============================================================================

// Part 4 section 7.4.4.5: a SimpleAttributeOperand's browsePath walks InstanceDeclarations of the
// typeDefinition, and each one must be an Object or a Variable. A validator that checks only what a
// SimpleAttributeOperand can be checked for without the address space - non-empty browse names and a
// supported attributeId - accepts a path through a Method, because a Method's browse name is as valid
// as any other. The client then gets a Good selectClauseResult for a clause that can only ever yield
// an error per Event, on every Event, for the life of the MonitoredItem.
// @verifies AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS
TEST(EventFilterTests, SimpleAttributeOperandBrowsePathMustTraverseOnlyObjectsAndVariables)
{
  EventFilter filter;

  // [0] control: a Variable InstanceDeclaration (ConditionType.EnabledState).
  SimpleAttributeOperand variablePath;
  variablePath.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  variablePath.browse_path().push_back(QualifiedName{0, String{"EnabledState"}});
  variablePath.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(variablePath));

  // [1] control: Variable -> Property (ConditionType.EnabledState/Id).
  SimpleAttributeOperand variableThenProperty;
  variableThenProperty.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  variableThenProperty.browse_path().push_back(QualifiedName{0, String{"EnabledState"}});
  variableThenProperty.browse_path().push_back(QualifiedName{0, String{"Id"}});
  variableThenProperty.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(variableThenProperty));

  // [2] control: Object -> Variable (AlarmConditionType.ShelvingState/CurrentState).
  SimpleAttributeOperand objectThenVariable;
  objectThenVariable.type_definition_id() = NodeId{ObjectTypeId::AlarmConditionType};
  objectThenVariable.browse_path().push_back(QualifiedName{0, String{"ShelvingState"}});
  objectThenVariable.browse_path().push_back(QualifiedName{0, String{"CurrentState"}});
  objectThenVariable.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(objectThenVariable));

  // [3] a Method InstanceDeclaration (AcknowledgeableConditionType.Acknowledge) - no value to select.
  SimpleAttributeOperand methodTerminal;
  methodTerminal.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  methodTerminal.browse_path().push_back(QualifiedName{0, String{"Acknowledge"}});
  methodTerminal.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(methodTerminal));

  // [4] a Method as an INTERMEDIATE path element (Acknowledge/InputArguments).
  SimpleAttributeOperand throughMethod;
  throughMethod.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  throughMethod.browse_path().push_back(QualifiedName{0, String{"Acknowledge"}});
  throughMethod.browse_path().push_back(QualifiedName{0, String{"InputArguments"}});
  throughMethod.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(throughMethod));

  EventFilterTypeModelFixture model;
  auto result = model.compile(std::move(filter));

  const auto& results = result.filterResult.select_clause_results();
  ASSERT_EQ(results.size(), 5u);

  EXPECT_TRUE(results[0].is_good()) << "a Variable InstanceDeclaration is a valid path element";
  EXPECT_TRUE(results[1].is_good()) << "a Property under a Variable is a valid path";
  EXPECT_TRUE(results[2].is_good()) << "an Object InstanceDeclaration is a valid path element";

  EXPECT_TRUE(results[3].is_bad())
    << "a browsePath naming a Method InstanceDeclaration must be refused at compile time";
  EXPECT_NE(results[3].shared_detail(), nullptr)
    << "the NodeClass refusal must retain its EventType-model context on the StatusCode";
  EXPECT_TRUE(results[4].is_bad())
    << "a browsePath traversing a Method to reach a child must be refused at compile time";
}

// The live model lookup is part of compile-time operand validation. A missing EventType must be a
// per-clause refusal with the failed address-space lookup preserved as the numeric inner status;
// flattening it to BadTypeDefinitionInvalid plus prose would lose the actionable root cause.
// @relation(AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS, scope=function)
TEST(EventFilterTests, UnresolvedEventTypeRetainsItsRichModelLookupFailure)
{
  EventFilter filter;
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{1, 1950099u};
  clause.browse_path().push_back(QualifiedName{1, String{"MissingField"}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(clause));

  EventFilterTypeModelFixture model;
  auto result = model.compile(std::move(filter));

  ASSERT_EQ(result.filterResult.select_clause_results().size(), 1u);
  const auto& status = result.filterResult.select_clause_results()[0];
  EXPECT_EQ(status.as_status(), Status::BadTypeDefinitionInvalid);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(StatusCode{status.shared_detail()->innerStatus}.as_status(), Status::BadNodeIdUnknown);
  EXPECT_EQ(result.overallStatus.as_status(), Status::BadMonitoredItemFilterInvalid);
  EXPECT_NE(result.overallStatus.shared_detail(), nullptr);
}

// Part 4 section 7.22.3: select-clause validation rejects only errors that hold for every possible
// Event. A declaration absent from one named type is deferred to per-Event projection, while an
// invalid EventType and a declaration with an impossible NodeClass remain invariant errors.
// @relation(AC-SVR-MI-EVT-009-NO-STATE-ERRORS, scope=function)
TEST(EventFilterTests, SelectClauseValidationSeparatesTypeDependentAbsenceFromInvariantErrors)
{
  EventFilter filter;

  SimpleAttributeOperand typeDependent;
  typeDependent.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  typeDependent.browse_path().push_back(QualifiedName{0, String{"ActiveState"}});
  typeDependent.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(typeDependent));

  SimpleAttributeOperand declaredVariable;
  declaredVariable.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  declaredVariable.browse_path().push_back(QualifiedName{0, String{"EnabledState"}});
  declaredVariable.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(declaredVariable));

  SimpleAttributeOperand invalidType;
  invalidType.type_definition_id() = NodeId{1, 1950099u};
  invalidType.browse_path().push_back(QualifiedName{0, String{"ActiveState"}});
  invalidType.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(invalidType));

  SimpleAttributeOperand methodDeclaration;
  methodDeclaration.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  methodDeclaration.browse_path().push_back(QualifiedName{0, String{"Acknowledge"}});
  methodDeclaration.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(methodDeclaration));

  EventFilterTypeModelFixture model;
  auto result = model.compile(std::move(filter));

  const auto& statuses = result.filterResult.select_clause_results();
  ASSERT_EQ(statuses.size(), 4u);
  EXPECT_TRUE(statuses[0].is_good())
    << "a declaration absent from this type can still be supplied by the concrete Event";
  EXPECT_TRUE(statuses[1].is_good()) << "a declared Variable remains an accepted control";

  EXPECT_EQ(statuses[2].as_status(), Status::BadTypeDefinitionInvalid);
  ASSERT_NE(statuses[2].shared_detail(), nullptr);
  EXPECT_EQ(statuses[2].shared_detail()->code, "EventTypeDefinitionInvalid");
  EXPECT_EQ(StatusCode{statuses[2].shared_detail()->innerStatus}.as_status(), Status::BadNodeIdUnknown);
  ASSERT_EQ(statuses[2].shared_detail()->context.size(), 2u);
  EXPECT_EQ(statuses[2].shared_detail()->context[0].key, ContextKeys::nodeId.value());
  EXPECT_EQ(statuses[2].shared_detail()->context[1].key, ContextKeys::errorMessage.value());

  EXPECT_EQ(statuses[3].as_status(), Status::BadFilterOperandInvalid);
  ASSERT_NE(statuses[3].shared_detail(), nullptr);
  EXPECT_EQ(statuses[3].shared_detail()->code, "EventFieldNodeClassInvalid");
  ASSERT_EQ(statuses[3].shared_detail()->context.size(), 4u);
  EXPECT_EQ(statuses[3].shared_detail()->context[0].key, ContextKeys::index.value());
  EXPECT_EQ(statuses[3].shared_detail()->context[1].key, ContextKeys::nodeBrowseName.value());
  EXPECT_EQ(statuses[3].shared_detail()->context[2].key, ContextKeys::nodeId.value());
  EXPECT_EQ(statuses[3].shared_detail()->context[3].key, ContextKeys::value.value());
}

// @relation(AC-COMP-SVR-EVENTTYPEMODEL-01-FRESH-STACK, scope=function)
TEST(EventTypeModelTests, LargeSynchronousModelCompletesOnFreshStacks)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:event-type-model-depth", threadPool.get_executor());
  auto eventType = addressSpace.try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(eventType.is_good());
  eventType.value().set_browse_name(QualifiedName{0, "BaseEventType"});

  constexpr uint32_t declarationCount = 2048;
  for (uint32_t index = 0; index < declarationCount; ++index)
  {
    const NodeId declarationId{1, 1980000u + index};
    auto declaration = addressSpace.try_create_sync<VariableAccessor>(declarationId, NodeClass::Variable);
    ASSERT_TRUE(declaration.is_good());
    declaration.value().set_browse_name(QualifiedName{1, String{"Field" + std::to_string(index)}});
    eventType.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, declarationId, true);
  }

  std::atomic_bool callReturned{false};
  std::atomic_bool callbackSawReturn{false};
  std::atomic_uint32_t completionCount{0};
  std::promise<event_type_model::DeclarationsResult> completion;
  auto future = completion.get_future();
  event_type_model::collect_declarations_async(addressSpace,
    NodeId{ObjectTypeId::BaseEventType},
    [&](event_type_model::DeclarationsResult result)
    {
      callbackSawReturn.store(callReturned.load());
      completionCount.fetch_add(1);
      completion.set_value(std::move(result));
    });
  callReturned.store(true);

  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
  EXPECT_EQ(result.value().size(), declarationCount);
  EXPECT_TRUE(callbackSawReturn.load());
  EXPECT_EQ(completionCount.load(), 1u);
  threadPool.join();
}

// @relation(AC-COMP-SVR-EVENTTYPEMODEL-02-CALLBACK-ONCE, scope=function)
TEST(EventTypeModelTests, ThrowingCompletionIsContainedAndInvokedOnce)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:event-type-model-callback", threadPool.get_executor());
  auto eventType = addressSpace.try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(eventType.is_good());

  std::atomic_uint32_t completionCount{0};
  std::promise<void> completion;
  auto future = completion.get_future();
  event_type_model::collect_declarations_async(addressSpace,
    NodeId{ObjectTypeId::BaseEventType},
    [&](event_type_model::DeclarationsResult result)
    {
      EXPECT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
      completionCount.fetch_add(1);
      completion.set_value();
      throw std::runtime_error{"sentinel completion failure"};
    });

  future.get();
  threadPool.join();
  EXPECT_EQ(completionCount.load(), 1u);
}

// ============================================================================
// Select clause: the three inviolate Event fields
// ============================================================================

// Part 4 section 7.22.3: "The EventId, EventType and ReceiveTime cannot contain a StatusCode or a
// null value." The general rule one clause earlier is the opposite - a field that is absent or whose
// Value carries a bad/uncertain status is replaced BY a StatusCode - so the uniform projection, the
// one that treats every select clause the same way, produces exactly what this clause forbids. It
// does so on the three fields a client needs to correlate, acknowledge and order notifications, and
// the failure only shows on the Events where a sibling field happens to be unavailable.
// @verifies AC-SVR-MI-EVT-014-MANDATORY-EVENT-FIELDS
TEST(EventFilterTests, EventIdEventTypeAndReceiveTimeNeverCarryAStatusCodeOrNull)
{
  auto typeId = NodeId{ObjectTypeId::BaseEventType};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"Pump-1"};
  event.message = LocalizedText{LocaleId{}, String{"Test event"}};
  event.severity = 500;
  event.eventId = ByteString{0x11, 0x22, 0x33, 0x44};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();

  // Two sibling fields that DO take the StatusCode substitution: one absent at the source, one whose
  // Value carries a bad status. They are the antecedent - the Event on which a uniform projection
  // would also stamp a StatusCode into the three inviolate fields.
  event.set_field({QualifiedName{1, String{"AbsentField"}}},
    Variant{DataValue{Variant{}, StatusCode{Status::BadNodeIdUnknown}}});
  event.set_field({QualifiedName{1, String{"BadValue"}}},
    Variant{DataValue{Variant{4.82}, StatusCode{Status::BadDeviceFailure}}});

  // Interleave the inviolate fields with the substituting siblings so no positional accident can
  // explain a pass.
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));

  SimpleAttributeOperand absentClause;
  absentClause.type_definition_id() = typeId;
  absentClause.browse_path().push_back(QualifiedName{1, String{"AbsentField"}});
  absentClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(absentClause));

  filter.select_clauses().push_back(make_select_clause("EventType"));

  SimpleAttributeOperand badValueClause;
  badValueClause.type_definition_id() = typeId;
  badValueClause.browse_path().push_back(QualifiedName{1, String{"BadValue"}});
  badValueClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(badValueClause));

  filter.select_clauses().push_back(make_select_clause("ReceiveTime"));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  const auto fields = compiled.filter->project(event, 21).event_fields();
  ASSERT_EQ(fields.size(), 5u);

  // Antecedent: the siblings really are carrying StatusCodes on this Event.
  ASSERT_TRUE(fields[1].is_status_code()) << "the absent sibling must carry its StatusCode";
  EXPECT_EQ(fields[1].as<StatusCode>().as_status(), Status::BadNodeIdUnknown);
  ASSERT_TRUE(fields[3].is_status_code()) << "the bad-status sibling must carry its StatusCode";
  EXPECT_EQ(fields[3].as<StatusCode>().as_status(), Status::BadDeviceFailure);

  // EventId: its actual value, neither null nor a StatusCode.
  EXPECT_FALSE(fields[0].empty()) << "EventId cannot contain a null value";
  EXPECT_FALSE(fields[0].is_status_code()) << "EventId cannot contain a StatusCode";
  ASSERT_TRUE(fields[0].is_byte_string());
  EXPECT_EQ(fields[0].as<ByteString>(), event.eventId);

  // EventType: its actual value, neither null nor a StatusCode.
  EXPECT_FALSE(fields[2].empty()) << "EventType cannot contain a null value";
  EXPECT_FALSE(fields[2].is_status_code()) << "EventType cannot contain a StatusCode";
  ASSERT_TRUE(fields[2].is_node_id());
  EXPECT_EQ(fields[2].as<NodeId>(), typeId);

  // ReceiveTime: its actual value, neither null nor a StatusCode.
  EXPECT_FALSE(fields[4].empty()) << "ReceiveTime cannot contain a null value";
  EXPECT_FALSE(fields[4].is_status_code()) << "ReceiveTime cannot contain a StatusCode";
  ASSERT_TRUE(fields[4].is_date_time());
  EXPECT_EQ(fields[4].as<DateTime>(), event.receiveTime);
}

// ============================================================================
// Select clause: browsePath InstanceDeclaration NodeClass below the first element
// ============================================================================

// Part 4 section 7.4.4.5: EVERY InstanceDeclaration a SimpleAttributeOperand's browsePath names must
// be an Object or a Variable - the rule is quantified over the whole path, not over its first or its
// last element alone. AlarmConditionType.ShelvingState is an Object InstanceDeclaration whose own
// children include Methods (TimedShelve, Unshelve), so a validator that inspects only browsePath[0],
// or only the terminal element, admits a clause whose path runs into a Method one level down. A
// Method has no value to select, so that clause can only ever yield an error per Event, on every
// Event, for the life of the MonitoredItem - after the selectClauseResult told the client it was
// Good and the filter was accepted.
// @verifies AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS
TEST(EventFilterTests, EveryInstanceDeclarationInANestedBrowsePathMustBeAnObjectOrVariable)
{
  EventFilter filter;

  auto addClause = [&filter](std::initializer_list<std::string_view> path)
  {
    SimpleAttributeOperand clause;
    clause.type_definition_id() = NodeId{ObjectTypeId::AlarmConditionType};
    for (auto element : path)
      clause.browse_path().push_back(QualifiedName{0, String{element}});
    clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(clause));
  };

  // [0] control: Object -> Variable -> Property. Three levels, every one of them a valid NodeClass.
  addClause({"ShelvingState", "CurrentState", "Id"});

  // [1] control: Object -> Property.
  addClause({"ShelvingState", "UnshelveTime"});

  // [2] a Method nested UNDER an Object InstanceDeclaration - the terminal element is the Method.
  addClause({"ShelvingState", "TimedShelve"});

  // [3] the same nested Method as an INTERMEDIATE element, with a Property below it.
  addClause({"ShelvingState", "TimedShelve", "InputArguments"});

  EventFilterTypeModelFixture model;
  auto result = model.compile(std::move(filter));

  const auto& results = result.filterResult.select_clause_results();
  ASSERT_EQ(results.size(), 4u);

  EXPECT_TRUE(results[0].is_good()) << "Object -> Variable -> Property is a valid path and must be kept";
  EXPECT_TRUE(results[1].is_good()) << "Object -> Property is a valid path and must be kept";

  EXPECT_TRUE(results[2].is_bad())
    << "a Method one level below an Object must be refused, not only a Method at the path root";
  EXPECT_TRUE(results[3].is_bad())
    << "a path traversing a nested Method to reach its child must be refused too";
}

// ============================================================================
// Two field-authorization regressions, both from the same branch: a select clause with no
// field DECLARATION was turned into BadUserAccessDenied whatever the reason it had none.
// ============================================================================

// The empty-browsePath + NodeId operand (Part 4 Table 133) is not a field of the event: it yields
// the instance node the event refers to, which for a Condition is its ConditionId. It therefore has
// no declaration to authorize against, and denying it put a StatusCode where every client expects a
// NodeId - so a tracked condition had a NULL ConditionId and Acknowledge failed with
// BadNodeIdUnknown. Part 9 requires the ConditionId to reach the client, because Acknowledge
// addresses the condition by it.
// @relation(AC-COMP-SDK-POST-EVENT-AUTHZ, scope=function)
TEST_F(EventFieldAuthorizationTest, ConditionIdOperandSurvivesAuthorizationWithNoFieldDeclaration)
{
  MutableEventSessionSecurityContext security;

  EventFilter filter;
  SimpleAttributeOperand conditionId;
  conditionId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  conditionId.attribute_id() = static_cast<IntegerId>(AttributeId::NodeId);
  filter.select_clauses().push_back(conditionId);

  // No declaration for it - there cannot be one, it names no field.
  auto compiled = compile_with_declarations(filter, {std::optional<NodeAccessor>{}});
  ASSERT_TRUE(compiled.filter);

  BaseEvent event = make_test_event();
  event.conditionNodeId = NodeId{2, String{"inst:1"}};  // the condition instance's own node

  auto baseEventType =
    address_space().try_create_node_sync(NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType).value();
  set_permissions(baseEventType, PermissionType{PermissionType::Bit::Browse});
  auto projected = project_authorized_fields(
    address_space(), *compiled.filter, event, 7, empty_declaration_model(), security);
  ASSERT_EQ(projected.event_fields().size(), 1u);
  ASSERT_FALSE(projected.event_fields()[0].is_status_code())
    << "the ConditionId must not come back as a denial";
  ASSERT_TRUE(projected.event_fields()[0].is_node_id());
  const NodeId expectedConditionId{2, String{"inst:1"}};
  EXPECT_EQ(projected.event_fields()[0].as<NodeId>(), expectedConditionId);
}

// A select clause naming a field the event type does not have resolves to nothing, and Part 4
// 7.22.3 requires the slot to come back NULL - "the field is not part of this event" is one of the
// two causes it gives for an empty slot. Denying it instead refuses the caller something that does
// not exist, and puts a value where the standard promises absence, so a client reading fields by
// position sees a value in an empty slot.
// @relation(AC-COMP-SDK-POST-EVENT-AUTHZ, scope=function)
TEST_F(EventFieldAuthorizationTest, AFieldTheEventTypeDoesNotHaveProjectsNullRatherThanADenial)
{
  MutableEventSessionSecurityContext security;

  // "Mesage" is a misspelling of "Message": no such field, so no declaration for it.
  auto compiled = compile_with_declarations(
    make_select_only_filter({"Message", "Mesage"}), {std::optional<NodeAccessor>{message()}, std::nullopt});
  ASSERT_TRUE(compiled.filter);
  auto concreteModel = std::make_shared<const event_type_model::DeclarationsResult>(
    event_type_model::Declarations{declaration(message(), "Message")});

  auto projected = project_authorized_fields(
    address_space(), *compiled.filter, make_test_event(), 8, concreteModel, security);
  ASSERT_EQ(projected.event_fields().size(), 2u);
  // The field that does exist is unaffected.
  ASSERT_TRUE(projected.event_fields()[0].is_localized_text());
  // The one that does not comes back empty, not denied.
  EXPECT_TRUE(projected.event_fields()[1].empty()) << "an absent field must be a null slot, not a StatusCode";
  EXPECT_FALSE(projected.event_fields()[1].is_status_code());
}
