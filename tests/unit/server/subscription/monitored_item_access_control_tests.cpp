// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for monitored item access control (S13).
///
/// Part 4, Section 5.12.2.1: "When a user adds a monitored item that the user is denied
/// read access to, the add operation shall succeed and BadUserAccessDenied shall be
/// returned in the Publish response."
///
/// The implementation gates each item per the Part 3 section 8.55 bit: a data item by
/// AccessOperation::Read, an event item by AccessOperation::ReceiveEvents (Part 4
/// section 5.12.2.1). Denied items are created with Good status but receive
/// BadUserAccessDenied as initial value. Allowed items start with an empty queue -
/// the sampling engine delivers the first real value. Event items with denied
/// access skip EventBus registration.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"

#include "ua_subscription_id_allocator.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_content_filter_element.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_notification.h"
#include "ua_error_detail.h"
#include "ua_default_namespace.h"
#include "ua_event_bus.h"
#include "ua_event_filter.h"
#include "ua_event_notification_list.h"
#include "ua_event_notifier_type.h"
#include "ua_event_type_model.h"
#include "ua_filter_operator.h"
#include "ua_generic_event.h"
#include "ua_literal_operand.h"
#include "ua_node_accessor.h"
#include "ua_value_source.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_simple_attribute_operand.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include "access_control_test_support.h"
#include "batch_recording_namespace.h"
#include "deferred_namespace.h"
#include "ua_access_control.h"
#include "ua_session_security.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;
using MTA = SubscriptionsPipelineTestAccess;

/// Polls on the strand until `expected` event deliveries are queued, bounded.
///
/// `wait_for_pending_resolutions()` answers about RESOLUTIONS, not about an emitted event's delivery
/// having been enqueued, so reading the delivery count straight after it races the last emit. Every
/// assertion on `pending_event_deliveries().size()` in this file follows such a wait, and two of them
/// have flaked in CI on exactly that - `EventHeadDeadlineIsFixedAcrossIdentityRestartAndAdvancesOnce`
/// in pipeline 2855283290 and `IdentityChangeRestartsTheSameEventHeadAndRejectsStaleCompletion` in
/// 2856863252.
///
/// This hides nothing: the assertion still runs and still fails if the count is wrong. It only stops
/// the test asserting before the thing it asserts about has had a chance to happen.
template<typename SubscriptionT>
void wait_for_pending_deliveries(SubscriptionT& subscription, std::size_t expected,
  std::chrono::milliseconds budget = std::chrono::milliseconds{2000})
{
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    std::size_t current = 0;
    STA::on_strand(
      subscription, [&current](auto& guarded) { current = guarded.pending_event_deliveries().size(); });
    if (current >= expected)
    {
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
}

namespace
{

SimpleAttributeOperand make_event_field_operand(const NodeId& typeDefinition, const QualifiedName& browseName)
{
  SimpleAttributeOperand operand;
  operand.type_definition_id() = typeDefinition;
  operand.browse_path().push_back(browseName);
  operand.attribute_id() = utils::to_underlying(AttributeId::Value);
  return operand;
}

RefStructure<Structure> make_event_field_filter_operand(
  const NodeId& typeDefinition, const QualifiedName& browseName)
{
  auto operand =
    std::make_unique<SimpleAttributeOperand>(make_event_field_operand(typeDefinition, browseName));
  RefStructure<Structure> result;
  result.inner_unique_ptr() = std::move(operand);
  return result;
}

RefStructure<Structure> make_event_literal_operand(Variant value)
{
  auto operand = std::make_unique<LiteralOperand>();
  operand->value() = std::move(value);
  RefStructure<Structure> result;
  result.inner_unique_ptr() = std::move(operand);
  return result;
}

EventFilter make_controlled_event_filter(
  const NodeId& eventType, const QualifiedName& selectedField, const QualifiedName& whereField)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_event_field_operand(eventType, selectedField));

  ContentFilterElement where;
  where.filter_operator() = FilterOperator::Equals;
  where.filter_operands().push_back(make_event_field_filter_operand(eventType, whereField));
  where.filter_operands().push_back(make_event_literal_operand(Variant{String{"match"}}));
  filter.where_clause().elements().push_back(std::move(where));
  return filter;
}

template<typename Notification>
void append_notification(NotificationMessage& message, std::unique_ptr<Notification> notification)
{
  RefStructure<Structure> reference;
  reference.inner_unique_ptr() = std::move(notification);
  message.notification_data().push_back(std::move(reference));
}

DataValue int32_value(int32_t value)
{
  return DataValue{Variant{value}};
}

MonitoredItemNotification data_notification(IntegerId clientHandle, int32_t value)
{
  MonitoredItemNotification notification;
  notification.client_handle() = clientHandle;
  notification.value() = int32_value(value);
  return notification;
}

EventFieldList event_notification(IntegerId clientHandle, Variant value)
{
  EventFieldList notification;
  notification.client_handle() = clientHandle;
  notification.event_fields().push_back(std::move(value));
  return notification;
}

struct RecordedEventAuthorizationLog
{
  LogLevel level{LogLevel::Trace};
  std::string message;
  std::map<std::string, std::string> fields;
};

class EventAuthorizationLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    RecordedEventAuthorizationLog copy{entry.level, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      if (const auto* value = std::get_if<std::string_view>(&field.value))
        copy.fields.emplace(field.key, *value);
    }
    const std::lock_guard lock(mMutex);
    mEntries.push_back(std::move(copy));
  }

  bool contains_detail(std::string_view detail) const
  {
    const std::lock_guard lock(mMutex);
    return std::ranges::any_of(mEntries,
      [detail](const RecordedEventAuthorizationLog& entry)
      {
        const auto found = entry.fields.find("detail");
        return found != entry.fields.end() && found->second.find(detail) != std::string::npos;
      });
  }

  /// True when an entry with exactly @p message, whose detail contains @p detail, was logged at @p level.
  bool contains_at(std::string_view message, std::string_view detail, LogLevel level) const
  {
    const std::lock_guard lock(mMutex);
    return std::ranges::any_of(mEntries,
      [message, detail, level](const RecordedEventAuthorizationLog& entry)
      {
        const auto found = entry.fields.find("detail");
        return entry.level == level && entry.message == message && found != entry.fields.end() &&
               found->second.find(detail) != std::string::npos;
      });
  }

  /// Every warning or error, one per line with its detail, for an assertion message; empty when none.
  std::string warnings_and_errors() const
  {
    const std::lock_guard lock(mMutex);
    std::string text;
    for (const auto& entry : mEntries)
    {
      if (entry.level < LogLevel::Warning)
        continue;
      const auto detail = entry.fields.find("detail");
      text += entry.message + (detail != entry.fields.end() ? " [" + detail->second + "]" : "") + "\n";
    }
    return text;
  }

private:
  mutable std::mutex mMutex;
  std::vector<RecordedEventAuthorizationLog> mEntries;
};

struct ControlledEventNodes
{
  uint16_t namespaceIndex{};
  NodeId source;
  NodeId eventType;
  NodeId selectedField;
  NodeId whereField;
  QualifiedName selectedBrowseName;
  QualifiedName whereBrowseName;
};

Variant role_permissions_value(const std::vector<RolePermissionType>& permissions)
{
  Array<RefStructure<Structure>> encoded;
  for (const auto& permission : permissions)
  {
    RefStructure<Structure> entry;
    entry = std::unique_ptr<Structure>{std::make_unique<RolePermissionType>(permission).release()};
    encoded.payload().push_back(std::move(entry));
  }
  return Variant{std::move(encoded)};
}

std::vector<RolePermissionType> decoded_role_permissions(const DataValue& value)
{
  std::vector<RolePermissionType> decoded;
  if (!value.value().is_array_of_structure())
  {
    return decoded;
  }
  for (const auto& entry : value.value().as<Array<RefStructure<Structure>>>())
  {
    if (const auto* permission = dynamic_cast<const RolePermissionType*>(entry.get()))
    {
      decoded.push_back(*permission);
    }
  }
  return decoded;
}

/// Minimal fake SessionSecurityContext for access control tests.
class FakeSessionSecurityContext final : public SessionSecurityContext
{
public:
  explicit FakeSessionSecurityContext(
    bool accessAllowed = true, bool identityAvailable = true, uint64_t firstIdentityKey = 1)
    : mNextIdentityKey(firstIdentityKey)
  {
    mEndpointSecurity = std::make_shared<const EndpointSecurityContext>();
    mUserIdentity = std::make_shared<const UserIdentity>(
      UserIdentity{.userId = "test-user", .displayName = "Test User", .kind = UserTokenKind::Anonymous});
    if (identityAvailable)
      set_access_allowed(accessAllowed);
  }

  NodeId session_id() const override
  {
    return NodeId{1, 42u};
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

  void set_access_allowed(bool allowed)
  {
    std::vector<NodeId> roles;
    if (allowed)
      roles.push_back(ua::test_helpers::test_access_role_id());
    set_roles(std::move(roles));
  }

  void set_roles(std::vector<NodeId> roles)
  {
    mAccessIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{mNextIdentityKey++},
      std::move(roles),
      mUserIdentity,
      mEndpointSecurity,
      String{"urn:test:monitored-item-client"});
  }

  void clear_access_identity()
  {
    mAccessIdentity.reset();
  }

private:
  std::shared_ptr<const EndpointSecurityContext> mEndpointSecurity;
  std::shared_ptr<const UserIdentity> mUserIdentity;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
  uint64_t mNextIdentityKey;
};

class MonitoredItemAccessControlTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();

    mAddressSpace = AddressSpace::create("urn:test", mExecutor);
    auto monitoringNs = default_ns::Namespace::create("urn:test:ns1", mExecutor);
    mNsIndex = mAddressSpace->add_namespace_sync(monitoringNs);
    RolePermissionType permission;
    permission.role_id() = ua::test_helpers::test_access_role_id();
    permission.permissions() = ua::test_helpers::all_permissions();
    RolePermissionType observerPermission;
    observerPermission.role_id() = NodeId{ObjectId::WellKnownRole_Observer};
    observerPermission.permissions() = ua::test_helpers::all_permissions();
    RolePermissionType operatorPermission;
    operatorPermission.role_id() = NodeId{ObjectId::WellKnownRole_Operator};
    operatorPermission.permissions() = ua::test_helpers::all_permissions();
    monitoringNs->set_namespace_defaults(
      std::vector<RolePermissionType>{permission, observerPermission, operatorPermission}, std::nullopt);

    mAddressSpace->create_node_sync(NodeId{mNsIndex, 1000}, NodeClass::Variable);
    mAddressSpace->create_node_sync(NodeId{mNsIndex, 1001}, NodeClass::Variable);
    mAddressSpace->create_node_sync(NodeId{mNsIndex, 1002}, NodeClass::Variable);

    auto baseEventType =
      mAddressSpace->try_create_node_sync(NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType).value();
    baseEventType.set_browse_name(QualifiedName{0, String{"BaseEventType"}});
    auto message = mAddressSpace->try_create_node_sync(NodeId{mNsIndex, 1003u}, NodeClass::Variable).value();
    message.set_browse_name(QualifiedName{0, String{"Message"}});
    baseEventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, message.get_node_id(), true);
  }

  void TearDown() override
  {
    // Destroy subscription first (cancels publishing timer, detaches sample sink).
    mSubscription.reset();
    // Destroy address space (destroys namespaces + SamplingEngine timers) before stopping pool.
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription =
      Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    return mSubscription;
  }

  /// Create monitored items via the public async API (posts to subscription strand internally).
  std::vector<MonitoredItemCreateResult> create_items(std::shared_ptr<Subscription>& sub,
    CreateMonitoredItemsRequest request, std::shared_ptr<SessionSecurityContext> secCtx = nullptr,
    std::weak_ptr<EventBus> eventBus = {})
  {
    std::promise<std::vector<MonitoredItemCreateResult>> promise;
    auto future = promise.get_future();

    sub->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      std::move(secCtx),
      std::move(eventBus),
      nullptr,
      [&promise](std::vector<MonitoredItemCreateResult> results) { promise.set_value(std::move(results)); });

    return future.get();
  }

  static std::vector<StatusCode> set_mode_blocking(std::shared_ptr<Subscription>& subscription,
    std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode)
  {
    std::promise<std::vector<StatusCode>> completion;
    auto completed = completion.get_future();
    subscription->set_monitoring_mode_async(std::move(monitoredItemIds),
      newMode,
      [&completion](std::vector<StatusCode> results) { completion.set_value(std::move(results)); });
    return completed.get();
  }

  void wait_for_event_registration(const std::shared_ptr<EventBus>& eventBus, IntegerId subscriptionId)
  {
    std::promise<Result<bool>> promise;
    auto future = promise.get_future();
    eventBus->has_event_items_async(
      subscriptionId, [&promise](Result<bool> result) { promise.set_value(std::move(result)); });
    const auto result = future.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    ASSERT_TRUE(result.value());
  }

  static GenericEvent make_controlled_event(
    const ControlledEventNodes& nodes, std::string_view selected, std::string_view where)
  {
    GenericEvent event{nodes.eventType};
    event.sourceNode = nodes.source;
    event.sourceName = String{"ControlledSource"};
    event.message = LocalizedText{LocaleId{}, String{selected}};
    event.eventId = ByteString{0x31};
    event.time = DateTime::now();
    event.receiveTime = DateTime::now();
    event.set_field({nodes.selectedBrowseName}, Variant{String{selected}});
    event.set_field({nodes.whereBrowseName}, Variant{String{where}});
    return event;
  }

  std::shared_ptr<const event_type_model::DeclarationsResult> base_message_declaration_model()
  {
    auto message = mAddressSpace->find_node_sync(NodeId{mNsIndex, 1003u});
    event_type_model::Declarations declarations;
    declarations.push_back(event_type_model::Declaration{.browsePath = {QualifiedName{0, String{"Message"}}},
      .nodeId = message.get_node_id(),
      .accessor = message,
      .nodeClass = NodeClass::Variable});
    return std::make_shared<const event_type_model::DeclarationsResult>(std::move(declarations));
  }

  static std::shared_ptr<const BaseEvent> make_base_event(
    NodeId source, NodeId eventType, std::string_view message)
  {
    auto event = std::make_shared<BaseEvent>();
    event->sourceNode = std::move(source);
    event->eventType = std::move(eventType);
    event->sourceName = String{"DirectSource"};
    event->message = LocalizedText{LocaleId{}, String{message}};
    event->eventId = ByteString{0x41};
    event->time = DateTime::now();
    event->receiveTime = DateTime::now();
    return event;
  }

  /// Drive one access-recheck cycle deterministically (no wall-clock dependency) and block on the
  /// main test thread until it completes.
  void trigger_recheck(Subscription& sub)
  {
    std::promise<void> done;
    auto future = done.get_future();
    STA::on_strand(sub, [&](auto& g) { g.run_access_recheck([&done] { done.set_value(); }); });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "access recheck cycle did not complete";
  }

  /// Create an event-capable Object node (SubscribeToEvents) and return its NodeId.
  NodeId create_event_source(IntegerId numericId)
  {
    NodeId id{mNsIndex, numericId};
    auto result = mAddressSpace->try_create_sync<ObjectAccessor>(id, NodeClass::Object);
    EXPECT_TRUE(result.is_good()) << "failed to create event source object";
    EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
    result.value().set_event_notifier(notifier);
    return id;
  }

  ControlledEventNodes create_controlled_event_nodes(
    const std::shared_ptr<ua::test::DeferredNamespace>& controlledNamespace, uint32_t firstNumericId)
  {
    ControlledEventNodes nodes;
    nodes.namespaceIndex = mAddressSpace->add_namespace_sync(controlledNamespace);
    nodes.source = NodeId{nodes.namespaceIndex, firstNumericId};
    nodes.eventType = NodeId{nodes.namespaceIndex, firstNumericId + 1};
    nodes.selectedField = NodeId{nodes.namespaceIndex, firstNumericId + 2};
    nodes.whereField = NodeId{nodes.namespaceIndex, firstNumericId + 3};
    nodes.selectedBrowseName = QualifiedName{nodes.namespaceIndex, String{"SelectedSecret"}};
    nodes.whereBrowseName = QualifiedName{nodes.namespaceIndex, String{"WhereSecret"}};

    auto source = mAddressSpace->try_create_sync<ObjectAccessor>(nodes.source, NodeClass::Object).value();
    source.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    auto eventType = mAddressSpace->try_create_node_sync(nodes.eventType, NodeClass::ObjectType).value();
    eventType.set_browse_name(QualifiedName{nodes.namespaceIndex, String{"ControlledEventType"}});
    eventType.add_reference_sync(
      NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

    auto selected = mAddressSpace->try_create_node_sync(nodes.selectedField, NodeClass::Variable).value();
    selected.set_browse_name(nodes.selectedBrowseName);
    eventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, nodes.selectedField, true);
    auto where = mAddressSpace->try_create_node_sync(nodes.whereField, NodeClass::Variable).value();
    where.set_browse_name(nodes.whereBrowseName);
    eventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, nodes.whereField, true);
    return nodes;
  }

  /// An EventNotifier MonitoredItem request carrying a one-clause EventFilter.
  CreateMonitoredItemsRequest make_event_request(
    IntegerId subscriptionId, NodeId nodeId, IntegerId clientHandle) const
  {
    EventFilter filter;
    filter.select_clauses().push_back(
      make_event_field_operand(NodeId{ObjectTypeId::BaseEventType}, QualifiedName{0, String{"Message"}}));
    return make_event_request(subscriptionId, std::move(nodeId), clientHandle, std::move(filter));
  }

  CreateMonitoredItemsRequest make_event_request(
    IntegerId subscriptionId, NodeId nodeId, IntegerId clientHandle, EventFilter filter) const
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;

    MonitoredItemCreateRequest itemReq;
    itemReq.item_to_monitor().node_id() = std::move(nodeId);
    itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
    itemReq.monitoring_mode() = MonitoringMode::Reporting;
    itemReq.requested_parameters().client_handle() = clientHandle;
    itemReq.requested_parameters().queue_size() = 10;
    itemReq.requested_parameters().discard_oldest() = true;

    itemReq.requested_parameters().filter().inner_unique_ptr() =
      std::make_unique<EventFilter>(std::move(filter));

    request.items_to_create().push_back(std::move(itemReq));
    return request;
  }

  void set_node_permission(const NodeId& nodeId, PermissionType::Bit bit, bool allowed)
  {
    auto node = mAddressSpace->find_node_sync(nodeId);
    auto permissions = ua::test_helpers::all_permissions();
    if (!allowed)
      permissions.reset(bit);
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

  void enable_test_role_on_namespace(uint16_t namespaceIndex)
  {
    auto nameSpace = std::dynamic_pointer_cast<default_ns::Namespace>(
      mAddressSpace->namespace_array().get_namespace(namespaceIndex));
    ASSERT_NE(nameSpace, nullptr);
    RolePermissionType permission;
    permission.role_id() = ua::test_helpers::test_access_role_id();
    permission.permissions() = ua::test_helpers::all_permissions();
    nameSpace->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
  }

  DataValue project_completed_read(AccessControl& accessControl, const FakeSessionSecurityContext& security,
    const NodeAccessor& node, AttributeId attribute, DataValue userIndependentValue)
  {
    std::promise<std::vector<AccessControl::Verdict>> promise;
    auto future = promise.get_future();
    const auto operation = AccessControl::attribute_read_operation(attribute);
    const std::array items{AccessControl::Item{node, operation}};
    accessControl.authorize_async(ua::RequestInfo{},
      security.access_identity(),
      items,
      *security.endpoint_security(),
      [&promise](std::vector<AccessControl::Verdict> verdicts) { promise.set_value(std::move(verdicts)); });
    auto verdicts = future.get();
    if (verdicts.size() != 1)
      throw std::logic_error{"single-item authorization returned the wrong cardinality"};
    return accessControl.make_client_attribute_value(*security.access_identity(),
      node,
      attribute,
      std::move(userIndependentValue),
      verdicts.front(),
      *security.endpoint_security());
  }

  DataValue stored_projection_input(const NodeAccessor& node, AttributeId attribute) const
  {
    if (attribute == AttributeId::UserAccessLevel)
    {
      const auto variable = node.as<VariableAccessor>();
      if (!variable)
        throw std::logic_error{"UserAccessLevel test subject is not a Variable"};
      return DataValue{Variant{variable->get_access_level().as_underlying_type()}};
    }
    if (attribute == AttributeId::UserWriteMask)
    {
      const auto writeMask = node.get_write_mask();
      if (!writeMask)
        throw std::logic_error{"UserWriteMask test subject has no WriteMask"};
      return DataValue{Variant{writeMask->as_underlying_type()}};
    }
    return DataValue{};
  }

  CreateMonitoredItemsRequest make_create_request(
    IntegerId subscriptionId, std::vector<std::pair<NodeId, uint32_t>> items) const
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;

    for (auto& [nodeId, clientHandle] : items)
    {
      MonitoredItemCreateRequest itemReq;
      itemReq.item_to_monitor().node_id() = std::move(nodeId);
      itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
      itemReq.monitoring_mode() = MonitoringMode::Reporting;
      itemReq.requested_parameters().client_handle() = clientHandle;
      itemReq.requested_parameters().sampling_interval() = 1000;
      itemReq.requested_parameters().queue_size() = 5;
      itemReq.requested_parameters().discard_oldest() = true;
      request.items_to_create().push_back(std::move(itemReq));
    }

    return request;
  }

  CreateMonitoredItemsRequest make_attribute_request(
    IntegerId subscriptionId, std::vector<std::tuple<NodeId, AttributeId, uint32_t>> items) const
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& [nodeId, attribute, clientHandle] : items)
    {
      MonitoredItemCreateRequest itemRequest;
      itemRequest.item_to_monitor().node_id() = std::move(nodeId);
      itemRequest.item_to_monitor().attribute_id() = utils::to_underlying(attribute);
      itemRequest.monitoring_mode() = MonitoringMode::Reporting;
      itemRequest.requested_parameters().client_handle() = clientHandle;
      itemRequest.requested_parameters().sampling_interval() = 1000;
      itemRequest.requested_parameters().queue_size() = 5;
      itemRequest.requested_parameters().discard_oldest() = true;
      request.items_to_create().push_back(std::move(itemRequest));
    }
    return request;
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;
  uint16_t mNsIndex{0};

  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

class AccessControlMissTest : public MonitoredItemAccessControlTest
{};

/// The authorization of an Event's subjects before it is queued (COMP-SVR-NAMESPACE-CALLS-16 rule 4).
class EventDelivery : public MonitoredItemAccessControlTest
{};

/// The consistency check a monitored item applies to a ranged value, and the narrowing it still applies to
/// the five attributes the service produces (COMP-SVR-NAMESPACE-CALLS-15).
class MonitoredItemRangeCheck : public MonitoredItemAccessControlTest
{
protected:
  /// One RolePermissions entry granting @p permissions to @p role.
  static RolePermissionType role_permission(NodeId role, PermissionType permissions)
  {
    RolePermissionType entry;
    entry.role_id() = std::move(role);
    entry.permissions() = permissions;
    return entry;
  }

  /// The Roles named by the RolePermissions entries @p value holds, in order; empty when it holds none.
  static std::vector<NodeId> roles_of(const Variant& value)
  {
    std::vector<NodeId> roles;
    if (!value.is_array())
      return roles;
    for (const auto& entry : value.as<Array<RefStructure<Structure>>>())
    {
      const auto* permission = dynamic_cast<const RolePermissionType*>(entry.get());
      roles.push_back(permission != nullptr ? permission->role_id() : NodeId{});
    }
    return roles;
  }

  /// The value of @p detail's context entry @p key, or "(absent)".
  static std::string context_value(const ErrorDetail& detail, const ContextKey& key)
  {
    for (const auto& entry : detail.context)
    {
      if (entry.key == key.value())
        return entry.value;
    }
    return "(absent)";
  }

  /// Publishes @p subscription until the item with @p clientHandle reports, or 3 s pass; its first
  /// notification.
  static std::optional<DataValue> first_notification(Subscription& subscription, uint32_t clientHandle)
  {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline)
    {
      const auto published = STA::on_strand(subscription,
        [](auto& guard)
        {
          guard.set_publish_req_queued(true);
          return guard.fulfill_publish(1);
        });
      for (const auto& result : published)
      {
        for (const auto& data : result.message.notification_data())
        {
          const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
          if (change == nullptr)
            continue;
          for (const auto& notification : change->monitored_items())
          {
            if (notification.client_handle() == clientHandle)
              return notification.value();
          }
        }
      }
      std::this_thread::sleep_for(5ms);
    }
    return std::nullopt;
  }
};

// ---------------------------------------------------------------------------
// Test 1: a missing Session security context fails closed while preserving the Part 4 rule that
// CreateMonitoredItems itself succeeds and reports the denial through the initial notification.
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, NullSecurityContext_ItemCreatedWithAccessDeniedInitialValue)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto results = create_items(sub, std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_NE(results[0].monitored_item_id(), IntegerId{0});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      // Part 4 par. 7.25.2: initial value shall be queued without applying the filter.
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// ---------------------------------------------------------------------------
// Test 2: Namespace permits Subscribe-item created normally with initial value
// ---------------------------------------------------------------------------

// @relation(AC-SVR-AUTHZ-023-RULE-BASED-NAMESPACE-NEVER-MISSES, scope=function)
TEST_F(MonitoredItemAccessControlTest, RolePermissionsAllow_ItemCreatedWithInitialValue)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_NE(results[0].monitored_item_id(), IntegerId{0});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      // Allowed items get the initial value (which may be a bad status if the node has no
      // value handler), but must NOT be BadUserAccessDenied.
      EXPECT_NE(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// ---------------------------------------------------------------------------
// Test 3: Namespace denies Subscribe-item created (Good) but initial value
//         is BadUserAccessDenied (Part 4, Section 5.12.2.1)
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, RolePermissionsDeny_ItemCreatedGoodButInitialValueAccessDenied)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>(false);

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_NE(results[0].monitored_item_id(), IntegerId{0});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// ---------------------------------------------------------------------------
// Test 3b (Stage-2 Theme-1): no committed AccessIdentity at creation -> fail closed.
// A concurrent same-channel ActivateSession identity change can make the identity temporarily
// unavailable. A fresh monitored item must receive a denied snapshot rather than skip access control.
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, AccessIdentityUnavailable_ItemDeniedFailClosed)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>(true, false);

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_NE(results[0].monitored_item_id(), IntegerId{0});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied})
        << "a monitored item must be denied when no activated AccessIdentity is available";
    });
}

// ---------------------------------------------------------------------------
// Test 4: Mixed batch -- some allowed, some denied, each gets correct initial value
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, MixedBatch_AllowedAndDeniedItemsGetCorrectInitialValues)
{
  auto sub = create_subscription();
  auto request = make_create_request(
    1, {{NodeId{mNsIndex, 1000}, 10}, {NodeId{mNsIndex, 1001}, 11}, {NodeId{mNsIndex, 1002}, 12}});

  set_node_permission(NodeId{mNsIndex, 1001}, PermissionType::Bit::Read, false);
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(results[1].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(results[2].status_code(), StatusCode{Status::Good});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item0 = g.find_monitored_item(results[0].monitored_item_id());
      auto* item1 = g.find_monitored_item(results[1].monitored_item_id());
      auto* item2 = g.find_monitored_item(results[2].monitored_item_id());

      ASSERT_NE(item0, nullptr);
      ASSERT_FALSE(item0->queue.empty());
      EXPECT_NE(item0->queue.front().status(), StatusCode{Status::BadUserAccessDenied});

      ASSERT_NE(item1, nullptr);
      ASSERT_FALSE(item1->queue.empty());
      EXPECT_EQ(item1->queue.front().status(), StatusCode{Status::BadUserAccessDenied});

      ASSERT_NE(item2, nullptr);
      ASSERT_FALSE(item2->queue.empty());
      EXPECT_NE(item2->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });

  auto count = STA::on_strand(*sub, [](auto& g) { return g.monitored_items().size(); });
  EXPECT_EQ(count, 3u);
}

// ---------------------------------------------------------------------------
// Test 5: Namespace returns a bad status-treated as denied (fail-closed)
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, AccessRestrictionFailure_TreatedAsDenied)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto node = mAddressSpace->find_node_sync(NodeId{mNsIndex, 1000});
  node.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::SigningRequired});
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// ---------------------------------------------------------------------------
// Test 6: a committed AccessIdentity uses ordinary Namespace RolePermissions;
// no second authorization object is required.
// ---------------------------------------------------------------------------

TEST_F(MonitoredItemAccessControlTest, AccessIdentityUsesNamespaceRolePermissions)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      // Allowed items get the initial value (which may be a bad status if the node has no
      // value handler), but must NOT be BadUserAccessDenied.
      EXPECT_NE(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// ---------------------------------------------------------------------------
// Test 7a: per-item Subscribe retains the session's resolved AccessIdentity
// ---------------------------------------------------------------------------

// The subscription pipeline snapshots the session's immutable AccessIdentity
// once, then uses it for the namespace-owned permission batch.
TEST_F(MonitoredItemAccessControlTest, PerItemSubscribeUsesSessionAccessIdentity)
{
  auto sub = create_subscription();
  auto request = make_create_request(
    1, {{NodeId{mNsIndex, 1000}, 10}, {NodeId{mNsIndex, 1001}, 11}, {NodeId{mNsIndex, 1002}, 12}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>(false);

  auto results = create_items(sub, std::move(request), secCtx);
  ASSERT_EQ(results.size(), 3u);

  for (const auto& result : results)
    STA::on_strand(*sub,
      [&](auto& guarded)
      {
        auto* item = guarded.find_monitored_item(result.monitored_item_id());
        ASSERT_NE(item, nullptr);
        EXPECT_TRUE(item->access_denied());
      });
}

// ---------------------------------------------------------------------------
// Test 7: namespace authorization receives the correct operation and subject
// ---------------------------------------------------------------------------

// The permission request carries the Read operation and resolved Node subject.
// User and endpoint facts live on the immutable AccessIdentity; the per-item
// Namespace request remains intentionally narrow.
TEST_F(MonitoredItemAccessControlTest, DataMonitoredItemUsesReadPermissionBit)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  set_node_permission(NodeId{mNsIndex, 1000}, PermissionType::Bit::Read, false);
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);

  ASSERT_EQ(results.size(), 1u);
  STA::on_strand(*sub,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(results[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->access_denied());
    });
}

// @relation(AC-SVR-AUTHZ-011-SUBSCRIPTION-MATCHES-READ, scope=function)
// @verifies AC-SVR-AUTHZ-011-SUBSCRIPTION-MATCHES-READ
TEST_F(MonitoredItemAccessControlTest, SubscribedProjectionMatchesRead)
{
  const NodeId nodeId{mNsIndex, 1000};
  auto node = mAddressSpace->find_node_sync(nodeId);
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable->set_write_mask(
    AttributeWriteMask{AttributeWriteMask::Bit::DisplayName, AttributeWriteMask::Bit::Description});

  const NodeId readOnlyRole{1, 7001u};
  const NodeId browseOnlyRole{1, 7002u};
  RolePermissionType readOnlyPermission;
  readOnlyPermission.role_id() = readOnlyRole;
  readOnlyPermission.permissions() = PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  RolePermissionType browseOnlyPermission;
  browseOnlyPermission.role_id() = browseOnlyRole;
  browseOnlyPermission.permissions() = PermissionType{PermissionType::Bit::Browse};
  node.set_role_permissions(std::vector<RolePermissionType>{readOnlyPermission, browseOnlyPermission});

  auto readOnlySecurity = std::make_shared<FakeSessionSecurityContext>();
  readOnlySecurity->set_roles({readOnlyRole});
  auto browseOnlySecurity = std::make_shared<FakeSessionSecurityContext>();
  browseOnlySecurity->set_roles({browseOnlyRole});

  auto readOnlySubscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto browseOnlySubscription =
    Subscription::create(2, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto readOnlyResults = create_items(readOnlySubscription,
    make_attribute_request(
      1, {{nodeId, AttributeId::UserAccessLevel, 61}, {nodeId, AttributeId::UserWriteMask, 62}}),
    readOnlySecurity);
  auto browseOnlyResults = create_items(browseOnlySubscription,
    make_attribute_request(
      2, {{nodeId, AttributeId::UserAccessLevel, 71}, {nodeId, AttributeId::UserWriteMask, 72}}),
    browseOnlySecurity);
  ASSERT_EQ(readOnlyResults.size(), 2u);
  ASSERT_EQ(browseOnlyResults.size(), 2u);

  AccessControl canonicalRead{*mAddressSpace, 100ms};
  const std::array attributes{AttributeId::UserAccessLevel, AttributeId::UserWriteMask};
  const auto assertProjection = [&](Subscription& subscription,
                                  const std::vector<MonitoredItemCreateResult>& results,
                                  const FakeSessionSecurityContext& security)
  {
    for (size_t index = 0; index < attributes.size(); ++index)
    {
      ASSERT_EQ(results[index].status_code(), StatusCode{Status::Good});
      const auto expected = project_completed_read(
        canonicalRead, security, node, attributes[index], stored_projection_input(node, attributes[index]));
      STA::on_strand(subscription,
        [&](auto& guarded)
        {
          auto* item = guarded.find_monitored_item(results[index].monitored_item_id());
          ASSERT_NE(item, nullptr);
          ASSERT_FALSE(item->queue.empty());
          if (expected.status() && expected.status()->is_bad())
          {
            EXPECT_EQ(item->queue.front().status(), expected.status());
          }
          else
          {
            EXPECT_TRUE(!item->queue.front().status() || item->queue.front().status()->is_good());
          }
          EXPECT_EQ(item->queue.front().value(), expected.value());
        });
    }
  };
  assertProjection(*readOnlySubscription, readOnlyResults, *readOnlySecurity);
  assertProjection(*browseOnlySubscription, browseOnlyResults, *browseOnlySecurity);

  const auto readOnlyAccessLevel = project_completed_read(canonicalRead,
    *readOnlySecurity,
    node,
    AttributeId::UserAccessLevel,
    stored_projection_input(node, AttributeId::UserAccessLevel));
  const auto browseOnlyAccessLevel = project_completed_read(canonicalRead,
    *browseOnlySecurity,
    node,
    AttributeId::UserAccessLevel,
    stored_projection_input(node, AttributeId::UserAccessLevel));
  EXPECT_NE(readOnlyAccessLevel.value(), browseOnlyAccessLevel.value())
    << "the identity-sensitive control must not collapse to one cached projection";

  const auto assertSampleProjection = [&](Subscription& subscription,
                                        const std::vector<MonitoredItemCreateResult>& results,
                                        const FakeSessionSecurityContext& security)
  {
    STA::on_strand(subscription,
      [&](auto& guarded)
      {
        std::vector<std::pair<IntegerId, DataValue>> samples;
        samples.emplace_back(
          results[0].monitored_item_id(), DataValue{Variant{uint8_t{0xff}}, StatusCode{Status::Good}});
        samples.emplace_back(
          results[1].monitored_item_id(), DataValue{Variant{uint32_t{0xffffffff}}, StatusCode{Status::Good}});
        guarded.on_samples_received(std::move(samples));
      });
    for (size_t index = 0; index < attributes.size(); ++index)
    {
      DataValue sampledInput = index == 0
                                 ? DataValue{Variant{uint8_t{0xff}}, StatusCode{Status::Good}}
                                 : DataValue{Variant{uint32_t{0xffffffff}}, StatusCode{Status::Good}};
      const auto expected =
        project_completed_read(canonicalRead, security, node, attributes[index], std::move(sampledInput));
      STA::on_strand(subscription,
        [&](auto& guarded)
        {
          auto* item = guarded.find_monitored_item(results[index].monitored_item_id());
          ASSERT_NE(item, nullptr);
          ASSERT_FALSE(item->queue.empty());
          if (expected.status() && expected.status()->is_bad())
          {
            EXPECT_EQ(item->queue.back().status(), expected.status());
          }
          else
          {
            EXPECT_TRUE(!item->queue.back().status() || item->queue.back().status()->is_good());
          }
          EXPECT_EQ(item->queue.back().value(), expected.value())
            << "a sampler-supplied raw value must be replaced by the per-Session projection";
        });
    }
  };
  assertSampleProjection(*readOnlySubscription, readOnlyResults, *readOnlySecurity);
  assertSampleProjection(*browseOnlySubscription, browseOnlyResults, *browseOnlySecurity);
}

// @relation(AC-SVR-AUTHZ-014-SUBSCRIPTION-IS-GATED-LIKE-READ, scope=function)
// @verifies AC-SVR-AUTHZ-014-SUBSCRIPTION-IS-GATED-LIKE-READ
TEST_F(MonitoredItemAccessControlTest, SubscribedRolePermissionsIsGatedLikeRead)
{
  const NodeId nodeId{mNsIndex, 1000};
  auto node = mAddressSpace->find_node_sync(nodeId);
  const NodeId administratorRole{ObjectId::WellKnownRole_SecurityAdmin};
  const NodeId ordinaryRole{1, 7101u};
  RolePermissionType administratorPermission;
  administratorPermission.role_id() = administratorRole;
  administratorPermission.permissions() =
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::ReadRolePermissions};
  RolePermissionType ordinaryPermission;
  ordinaryPermission.role_id() = ordinaryRole;
  ordinaryPermission.permissions() = PermissionType{PermissionType::Bit::Browse};
  node.set_role_permissions(std::vector<RolePermissionType>{administratorPermission, ordinaryPermission});

  auto administratorSecurity = std::make_shared<FakeSessionSecurityContext>();
  administratorSecurity->set_roles({administratorRole});
  auto ordinarySecurity = std::make_shared<FakeSessionSecurityContext>();
  ordinarySecurity->set_roles({ordinaryRole});
  auto administratorSubscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto ordinarySubscription =
    Subscription::create(2, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto administratorResults = create_items(administratorSubscription,
    make_attribute_request(1, {{nodeId, AttributeId::RolePermissions, 71}}),
    administratorSecurity);
  auto ordinaryResults = create_items(ordinarySubscription,
    make_attribute_request(2, {{nodeId, AttributeId::RolePermissions, 72}}),
    ordinarySecurity);
  ASSERT_EQ(administratorResults.size(), 1u);
  ASSERT_EQ(ordinaryResults.size(), 1u);

  AccessControl canonicalRead{*mAddressSpace, 100ms};
  const auto administratorRead = project_completed_read(
    canonicalRead, *administratorSecurity, node, AttributeId::RolePermissions, DataValue{});
  const auto ordinaryRead =
    project_completed_read(canonicalRead, *ordinarySecurity, node, AttributeId::RolePermissions, DataValue{});
  EXPECT_TRUE(!administratorRead.status() || administratorRead.status()->is_good());
  EXPECT_FALSE(administratorRead.value().empty());
  EXPECT_EQ(ordinaryRead.status(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(ordinaryRead.value().empty());

  const auto assertMatchesRead =
    [](Subscription& subscription, const MonitoredItemCreateResult& result, const DataValue& expected)
  {
    ASSERT_EQ(result.status_code(), StatusCode{Status::Good});
    STA::on_strand(subscription,
      [&](auto& guarded)
      {
        auto* item = guarded.find_monitored_item(result.monitored_item_id());
        ASSERT_NE(item, nullptr);
        ASSERT_FALSE(item->queue.empty());
        if (expected.status() && expected.status()->is_bad())
        {
          EXPECT_EQ(item->queue.front().status(), expected.status());
        }
        else
        {
          EXPECT_TRUE(!item->queue.front().status() || item->queue.front().status()->is_good());
        }
        EXPECT_EQ(item->queue.front().value(), expected.value());
      });
  };
  assertMatchesRead(*administratorSubscription, administratorResults[0], administratorRead);
  assertMatchesRead(*ordinarySubscription, ordinaryResults[0], ordinaryRead);
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 3 (NR-10 rule 8): a Value item does not narrow what its namespace
// delivers. A sample larger than the item's IndexRange is the namespace's broken contract: the item queues
// Bad_InternalError naming the dimension and the sizes, with no Value and the sample's timestamps.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SAMPLE-LARGER-THAN-THE-RANGE-FAILS-THE-CONSISTENCY-CHECK, scope=function)
TEST_F(MonitoredItemRangeCheck, ASampleLargerThanTheRangeFailsTheConsistencyCheck)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 100;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 4;
  item.discardOldest = true;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::None;
  item.namespaceIndex = mNsIndex;
  item.itemToMonitor.node_id() = NodeId{mNsIndex, 1000};
  item.itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::Value);
  item.itemToMonitor.index_range() = "1:2";

  const DateTime sourceTimestamp = DateTime::now();
  DataValue sample;
  sample.value() = Variant{Array<int32_t>{10, 20, 30, 40}};
  sample.source_timestamp() = sourceTimestamp;
  auto userIndependentValue = sample;
  item.evaluate_and_enqueue(std::move(sample), std::move(userIndependentValue));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(0, notifications);
  ASSERT_EQ(notifications.size(), 1u);
  const DataValue& queued = notifications[0].value();
  const StatusCode status = queued.status().value_or(StatusCode{Status::Good});
  EXPECT_EQ(status.as_status(), Status::BadInternalError)
    << "the item queued " << to_string(queued.value()) << " [" << to_string(status)
    << "] for the four-element sample and the range 1:2";
  const auto detail = status.shared_detail();
  ASSERT_NE(detail, nullptr) << "the queued status names no ErrorDetail";
  EXPECT_EQ(detail->code, "NamespaceValueExceedsRange");
  EXPECT_EQ(context_value(*detail, ContextKeys::index), "0");
  EXPECT_EQ(context_value(*detail, ContextKeys::sizeExpected), "2");
  EXPECT_EQ(context_value(*detail, ContextKeys::sizeActual), "4");
  EXPECT_TRUE(queued.value().empty()) << "the failure carries the Value " << to_string(queued.value());
  EXPECT_EQ(queued.source_timestamp(), std::optional<DateTime>{sourceTimestamp})
    << "the failure does not keep the sample's SourceTimestamp";
}

// COMP-SVR-NAMESPACE-CALLS-15 rules 1 and 3, a guard: RolePermissions is one of the five attributes the
// service produces, so the item narrows its projected value to the IndexRange, as before B4c.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SERVICE-PRODUCED-ATTRIBUTE-IS-STILL-NARROWED, scope=function)
TEST_F(MonitoredItemRangeCheck, AServiceProducedAttributeIsStillNarrowed)
{
  const NodeId nodeId{mNsIndex, 1000};
  auto node = mAddressSpace->find_node_sync(nodeId);
  const NodeId allowedRole = ua::test_helpers::test_access_role_id();
  const NodeId secondRole{1, 7201u};
  const NodeId thirdRole{1, 7202u};
  node.set_role_permissions(
    std::vector<RolePermissionType>{role_permission(allowedRole, ua::test_helpers::all_permissions()),
      role_permission(secondRole, PermissionType{PermissionType::Bit::Browse}),
      role_permission(thirdRole, PermissionType{PermissionType::Bit::Browse})});
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto subscription = create_subscription();
  auto request = make_attribute_request(1, {{nodeId, AttributeId::RolePermissions, 81}});
  request.items_to_create()[0].item_to_monitor().index_range() = "0";

  const auto results = create_items(subscription, std::move(request), security);

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good}) << to_string(results[0].status_code());
  const auto first = first_notification(*subscription, 81);
  ASSERT_TRUE(first.has_value()) << "the item reported nothing";
  EXPECT_TRUE(!first->status().has_value() || first->status()->is_good())
    << "the item reported " << to_string(*first->status());
  EXPECT_EQ(roles_of(first->value()), (std::vector<NodeId>{allowedRole}))
    << "the item reported " << to_string(first->value()) << ", not the first of the three entries";
}

// @relation(AC-SVR-AUTHZ-028-SUBSCRIBED-USER-PROPERTY-IS-FILTERED, scope=function)
// @verifies AC-SVR-AUTHZ-028-SUBSCRIBED-USER-PROPERTY-IS-FILTERED
TEST_F(MonitoredItemAccessControlTest, SubscribedUserPropertyIsFilteredPerSession)
{
  const NodeId propertyId{mNsIndex, 1010U};
  auto property = mAddressSpace->try_create_sync<VariableAccessor>(propertyId, NodeClass::Variable);
  ASSERT_TRUE(property);
  property.value().set_browse_name(QualifiedName{0, "DefaultUserRolePermissions"});
  property.value().set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

  RolePermissionType observerPermission;
  observerPermission.role_id() = NodeId{ObjectId::WellKnownRole_Observer};
  observerPermission.permissions() = ua::test_helpers::all_permissions();
  RolePermissionType operatorPermission;
  operatorPermission.role_id() = NodeId{ObjectId::WellKnownRole_Operator};
  operatorPermission.permissions() = ua::test_helpers::all_permissions();
  DataValue storedValue;
  storedValue.value() = role_permissions_value({observerPermission, operatorPermission});
  ASSERT_TRUE(property.value().try_write_value_sync(std::move(storedValue)));

  // The per-Session answer is produced by the node that serves it, from the identity passed to the
  // read - there is no central registration any more, and nothing downstream knows which nodes differ
  // per caller.
  const std::vector<RolePermissionType> published{observerPermission, operatorPermission};
  auto* valueSource = property.value()->external_value_source();
  ASSERT_NE(valueSource, nullptr);
  (void)valueSource->set_value_source(ua::make_value_source(
    [published](const ua::ValueSource::ReadContext& context,
      const ua::Node&,
      const ua::ReadValueId&,
      std::function<void(ua::DataValueResult)>
        complete)
    {
      const ua::AccessIdentity* identity =
        context.caller != nullptr ? context.caller->identity.get() : nullptr;
      std::vector<RolePermissionType> filtered;
      if (identity)
      {
        for (const auto& entry : published)
        {
          const auto& roles = identity->granted_roles();
          if (std::find(roles.begin(), roles.end(), entry.role_id()) != roles.end())
          {
            filtered.push_back(entry);
          }
        }
      }
      DataValue answer;
      answer.value() = role_permissions_value(filtered);
      answer.status() = ua::Status::Good;
      complete(ua::DataValueResult{std::move(answer)});
    }));

  auto observerSecurity = std::make_shared<FakeSessionSecurityContext>();
  observerSecurity->set_roles({NodeId{ObjectId::WellKnownRole_Observer}});
  auto operatorSecurity = std::make_shared<FakeSessionSecurityContext>();
  operatorSecurity->set_roles({NodeId{ObjectId::WellKnownRole_Operator}});
  auto observerSubscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto operatorSubscription =
    Subscription::create(2, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto observerResults =
    create_items(observerSubscription, make_create_request(1, {{propertyId, 81}}), observerSecurity);
  auto operatorResults =
    create_items(operatorSubscription, make_create_request(2, {{propertyId, 82}}), operatorSecurity);
  ASSERT_EQ(observerResults.size(), 1u);
  ASSERT_EQ(operatorResults.size(), 1u);

  const auto queuedPermissions = [](Subscription& subscription, IntegerId monitoredItemId)
  {
    return STA::on_strand(subscription,
      [monitoredItemId](auto& guarded)
      {
        auto* item = guarded.find_monitored_item(monitoredItemId);
        if (!item || item->queue.empty())
        {
          return std::vector<RolePermissionType>{};
        }
        return decoded_role_permissions(item->queue.front());
      });
  };
  const auto observerPermissions =
    queuedPermissions(*observerSubscription, observerResults.front().monitored_item_id());
  const auto operatorPermissions =
    queuedPermissions(*operatorSubscription, operatorResults.front().monitored_item_id());
  ASSERT_EQ(observerPermissions.size(), 1u);
  ASSERT_EQ(operatorPermissions.size(), 1u);
  EXPECT_EQ(observerPermissions.front().role_id(), NodeId{ObjectId::WellKnownRole_Observer});
  EXPECT_EQ(operatorPermissions.front().role_id(), NodeId{ObjectId::WellKnownRole_Operator});
}

// @relation(AC-COMP-SVR-MONITORED-ACCESS-SNAPSHOT-01-EXACT-REUSE, scope=function)
TEST_F(MonitoredItemAccessControlTest, InitialAndSampleProjectionReuseCompletedNonCachingSnapshot)
{
  auto deferred = ua::test::DeferredNamespace::create("urn:test:monitored-snapshot", mExecutor);
  const uint16_t namespaceIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId variableId{namespaceIndex, 8101u};
  auto variable = mAddressSpace->try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variable);
  const AccessLevelType storedAccess{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
  variable.value().set_access_level(storedAccess);

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 501);
  const PermissionType permissions{
    PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write};
  deferred->set_async_permissions(security->access_identity()->key(), variableId, permissions);
  deferred->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto subscription = create_subscription();

  std::promise<std::vector<MonitoredItemCreateResult>> completion;
  auto resultsFuture = completion.get_future();
  subscription->create_monitored_items_async(
    make_attribute_request(1, {{variableId, AttributeId::UserAccessLevel, 91}}),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    security,
    {},
    nullptr,
    [&completion](std::vector<MonitoredItemCreateResult> results)
    { completion.set_value(std::move(results)); });

  ASSERT_TRUE(deferred->wait_for_pending_resolutions());
  EXPECT_EQ(resultsFuture.wait_for(0ms), std::future_status::timeout);
  deferred->complete_pending_resolutions();
  ASSERT_EQ(resultsFuture.wait_for(2s), std::future_status::ready);
  auto results = resultsFuture.get();
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results[0].monitored_item_id();

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.back().value().template as<uint8_t>(), storedAccess.as_underlying_type());
      ASSERT_TRUE(item->accessSnapshot.has_value());
      EXPECT_EQ(item->accessSnapshot->verdict.mask, permissions);
    });
  ASSERT_EQ(deferred->permission_questions(), 1u);
  ASSERT_EQ(deferred->effective_permissions_calls().size(), 1u);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      item->queue.clear();
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(
        monitoredItemId, DataValue{Variant{storedAccess.as_underlying_type()}, StatusCode{Status::Good}});
      guarded.on_samples_received(std::move(samples));
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.back().value().template as<uint8_t>(), storedAccess.as_underlying_type());
    });

  EXPECT_EQ(deferred->permission_questions(), 1u)
    << "sampling shall consume the retained verdict rather than probing again";
  EXPECT_EQ(deferred->effective_permissions_calls().size(), 1u)
    << "sampling shall never suspend for permission resolution";
  deferred->wait_idle();
}

// @relation(AC-SVR-AUTHZ-011-MONITORED-SNAPSHOT-REPROJECTS, scope=function)
// @relation(AC-COMP-SVR-MONITORED-ACCESS-SNAPSHOT-02-SAME-ALLOW-REPROJECTS, scope=function)
TEST_F(MonitoredItemAccessControlTest, PermissionRefreshReprojectsWithoutAllowDenyTransition)
{
  auto deferred = ua::test::DeferredNamespace::create("urn:test:monitored-refresh", mExecutor);
  const uint16_t namespaceIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId variableId{namespaceIndex, 8102u};
  auto variable = mAddressSpace->try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variable);
  const AccessLevelType storedAccess{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
  variable.value().set_access_level(storedAccess);

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 511);
  const auto identityKey = security->access_identity()->key();
  const PermissionType readWrite{
    PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write};
  deferred->set_async_permissions(identityKey, variableId, readWrite);
  deferred->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto subscription = create_subscription();

  std::promise<std::vector<MonitoredItemCreateResult>> createCompletion;
  auto createFuture = createCompletion.get_future();
  subscription->create_monitored_items_async(
    make_attribute_request(1, {{variableId, AttributeId::UserAccessLevel, 92}}),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    security,
    {},
    nullptr,
    [&createCompletion](std::vector<MonitoredItemCreateResult> results)
    { createCompletion.set_value(std::move(results)); });
  ASSERT_TRUE(deferred->wait_for_pending_resolutions());
  deferred->complete_pending_resolutions();
  ASSERT_EQ(createFuture.wait_for(2s), std::future_status::ready);
  auto results = createFuture.get();
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(1h, security, mAddressSpace->weak(), {});
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->access_denied());
      ASSERT_TRUE(item->lastUserIndependentValue.has_value());
      item->queue.clear();
    });

  const PermissionType readOnly{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  deferred->set_async_permissions(identityKey, variableId, readOnly);
  std::promise<void> refreshCompletion;
  auto refreshFuture = refreshCompletion.get_future();
  STA::on_strand(*subscription,
    [&](auto& guarded)
    { guarded.run_access_recheck([&refreshCompletion] { refreshCompletion.set_value(); }); });
  ASSERT_TRUE(deferred->wait_for_pending_resolutions());
  EXPECT_EQ(refreshFuture.wait_for(0ms), std::future_status::timeout);
  deferred->complete_pending_resolutions();
  ASSERT_EQ(refreshFuture.wait_for(2s), std::future_status::ready);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied());
      ASSERT_TRUE(item->accessSnapshot.has_value());
      EXPECT_EQ(item->accessSnapshot->identity, identityKey);
      EXPECT_EQ(item->accessSnapshot->verdict.mask, readOnly);
      ASSERT_EQ(item->queue.size(), 1u);
      const AccessLevelType projected{item->queue.back().value().template as<uint8_t>()};
      EXPECT_TRUE(projected.test(AccessLevelType::Bit::CurrentRead));
      EXPECT_FALSE(projected.test(AccessLevelType::Bit::CurrentWrite));
    });
  deferred->wait_idle();
}

// @relation(AC-SVR-AUTHZ-011-MONITORED-SNAPSHOT-REPROJECTS, scope=function)
// @relation(AC-COMP-SVR-MONITORED-ACCESS-SNAPSHOT-02-IDENTITY-MISMATCH-SUPPRESSES, scope=function)
TEST_F(MonitoredItemAccessControlTest, IdentityChangeSuppressesSamplesUntilItsSnapshotCompletes)
{
  auto deferred = ua::test::DeferredNamespace::create("urn:test:monitored-identity", mExecutor);
  const uint16_t namespaceIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId variableId{namespaceIndex, 8103u};
  auto variable = mAddressSpace->try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variable);
  variable.value().set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 521);
  const AccessIdentityKey originalIdentity = security->access_identity()->key();
  const PermissionType readAccess{PermissionType::Bit::Browse, PermissionType::Bit::Read};
  deferred->grant(originalIdentity, variableId, readAccess);
  auto subscription = create_subscription();
  auto results = create_items(subscription, make_create_request(1, {{variableId, 93}}), security);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_TRUE(item->accessSnapshot.has_value());
      EXPECT_EQ(item->accessSnapshot->identity, originalIdentity);
      item->queue.clear();
    });

  security->set_roles({ua::test_helpers::test_access_role_id()});
  const AccessIdentityKey replacementIdentity = security->access_identity()->key();
  ASSERT_NE(replacementIdentity, originalIdentity);
  deferred->set_async_permissions(replacementIdentity, variableId, readAccess);
  deferred->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  std::promise<VoidResult> reauthorizationCompletion;
  auto reauthorizationFuture = reauthorizationCompletion.get_future();
  subscription->reauthorize_all_async([&reauthorizationCompletion](VoidResult result)
    { reauthorizationCompletion.set_value(std::move(result)); });
  ASSERT_TRUE(deferred->wait_for_pending_resolutions());
  EXPECT_EQ(reauthorizationFuture.wait_for(0ms), std::future_status::timeout);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(monitoredItemId, DataValue{Variant{int32_t{111}}, StatusCode{Status::Good}});
      guarded.on_samples_received(std::move(samples));
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->queue.empty())
        << "a sample under the replacement identity must not use the original snapshot";
      ASSERT_TRUE(item->accessSnapshot.has_value());
      EXPECT_EQ(item->accessSnapshot->identity, originalIdentity);
    });

  deferred->complete_pending_resolutions();
  ASSERT_EQ(reauthorizationFuture.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(reauthorizationFuture.get().is_good());

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(monitoredItemId, DataValue{Variant{int32_t{222}}, StatusCode{Status::Good}});
      guarded.on_samples_received(std::move(samples));
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_TRUE(item->accessSnapshot.has_value());
      EXPECT_EQ(item->accessSnapshot->identity, replacementIdentity);
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.back().value().template as<int32_t>(), 222);
    });
  deferred->wait_idle();
}

// ---------------------------------------------------------------------------
// Periodic per-MonitoredItem authorization re-evaluation (Part 4 5.12.2.1).
//
// "This is the same behaviour for the case where the access rights are changed after the call to
// CreateMonitoredItems... If the access rights change to read rights, the Server shall start sending
// data." The recheck is driven deterministically via the test-access trigger (run_access_recheck),
// not the wall-clock timer.
// ---------------------------------------------------------------------------

// A live data item must transition allow -> deny (enqueueing BadUserAccessDenied) and deny -> allow
// (clearing the gate) as the node permission flips. Falsifiable: without the recheck the flag never
// changes after create, so both transition assertions fail.
// @relation(AC-SVR-AUTHZ-009-RECOVERS-ON-REGRANT, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckRevokesThenRestoresDataItemAccess)
{
  using namespace std::chrono_literals;
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto miId = results[0].monitored_item_id();

  // Large interval: the wall-clock timer never fires within the test; the cycle is driven manually.
  sub->configure_access_recheck(1h, secCtx, mAddressSpace->weak(), {});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied());
    });

  // Revoke Read -> next recheck denies and surfaces BadUserAccessDenied on the queue.
  set_node_permission(NodeId{mNsIndex, 1000}, PermissionType::Bit::Read, false);
  trigger_recheck(*sub);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->access_denied());
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.back().status(), StatusCode{Status::BadUserAccessDenied})
        << "a revoked permission must deliver BadUserAccessDenied (Part 4 5.12.2.1)";
    });

  // Restore Read -> next recheck clears the gate so the sampler resumes delivery.
  set_node_permission(NodeId{mNsIndex, 1000}, PermissionType::Bit::Read, true);
  trigger_recheck(*sub);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied()) << "a regained permission must resume delivery";
    });
}

// @relation(AC-SVR-AUTHZ-009-REVOCATION-PURGES-QUEUED-CONTENT, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckPurgesQueuedDataBeforePublishingOneDenial)
{
  auto subscription = create_subscription();
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}}), security);
  ASSERT_EQ(results.size(), 1u);
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(1h, security, mAddressSpace->weak(), {});

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      item->queueSize = 4;
      item->queue.clear();
      item->queuedUserIndependentValues.clear();
      item->lastQueuedValue.reset();
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(monitoredItemId, DataValue{Variant{int32_t{111}}});
      samples.emplace_back(monitoredItemId, DataValue{Variant{int32_t{222}}});
      guarded.on_samples_received(std::move(samples));
      ASSERT_EQ(item->queue.size(), 2u);
      ASSERT_EQ(item->queuedUserIndependentValues.size(), 2u);
    });

  set_node_permission(NodeId{mNsIndex, 1000}, PermissionType::Bit::Read, false);
  trigger_recheck(*subscription);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 1u);
      ASSERT_EQ(item->queuedUserIndependentValues.size(), 1u);
      EXPECT_FALSE(item->queuedUserIndependentValues.front().has_value());
      EXPECT_TRUE(item->queue.front().value().empty());
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
    });
}

// @relation(AC-SVR-AUTHZ-009-REVOCATION-PURGES-QUEUED-CONTENT, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckPurgesQueuedAndPendingEventsOnRevocation)
{
  auto subscription = create_subscription();
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  const auto eventSource = create_event_source(2010);
  auto results = create_items(subscription, make_event_request(1, eventSource, 77), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(1h, security, mAddressSpace->weak(), eventBus);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      item->enqueue_event(event_notification(77, Variant{String{"queued-secret"}}));
      guarded.reportable_item_count() = 1;
      guarded.seed_pending_event_delivery(monitoredItemId);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      ASSERT_EQ(guarded.pending_event_deliveries().size(), 1u);
    });

  set_node_permission(eventSource, PermissionType::Bit::ReceiveEvents, false);
  trigger_recheck(*subscription);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->eventQueue.empty());
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      EXPECT_EQ(item->eventBusHandle, 0u);
      EXPECT_EQ(guarded.reportable_item_count(), 0u);
    });
}

// @relation(AC-SVR-AUTHZ-009-PERIODIC-FAILURE-FAILS-CLOSED, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckFailsClosedWhenAccessIdentityIsUnavailable)
{
  using namespace std::chrono_literals;
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  // Create the item ALLOWED with a valid context.
  auto createCtx = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(sub, std::move(request), createCtx);
  ASSERT_EQ(results.size(), 1u);
  const auto miId = results[0].monitored_item_id();

  auto nullCtx = std::make_shared<FakeSessionSecurityContext>(true, false);
  auto logSink = std::make_shared<EventAuthorizationLogSink>();
  auto logLevel = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  sub->set_logger(Logger{logSink, logLevel, "periodic-recheck-test"});
  sub->configure_access_recheck(1h, nullCtx, mAddressSpace->weak(), {});

  trigger_recheck(*sub);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->access_denied());
      ASSERT_EQ(item->queue.size(), 1u);
      const auto status = item->queue.front().status().value();
      EXPECT_EQ(status, StatusCode{Status::BadUserAccessDenied});
      ASSERT_NE(status.shared_detail(), nullptr);
      EXPECT_EQ(status.shared_detail()->code, "PeriodicAccessRecheckIdentityUnavailable");
      ASSERT_NE(status.shared_detail()->cause, nullptr);
      EXPECT_EQ(status.shared_detail()->cause->code, "AccessIdentityUnavailable");
    });
  EXPECT_TRUE(logSink->contains_detail("PeriodicAccessRecheckIdentityUnavailable"));
}

// @relation(AC-SVR-AUTHZ-009-PERIODIC-FAILURE-FAILS-CLOSED, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckMissingNodeDeniesThatItemAndContinuesTheCycle)
{
  auto subscription = create_subscription();
  auto security = std::make_shared<FakeSessionSecurityContext>();
  const NodeId removedNode{mNsIndex, 1001};
  const NodeId survivingNode{mNsIndex, 1002};
  auto results =
    create_items(subscription, make_create_request(1, {{removedNode, 51}, {survivingNode, 52}}), security);
  ASSERT_EQ(results.size(), 2u);
  const auto removedItemId = results[0].monitored_item_id();
  const auto survivingItemId = results[1].monitored_item_id();
  subscription->configure_access_recheck(1h, security, mAddressSpace->weak(), {});

  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(removedNode, false).is_good());
  trigger_recheck(*subscription);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* removed = guarded.find_monitored_item(removedItemId);
      auto* surviving = guarded.find_monitored_item(survivingItemId);
      ASSERT_NE(removed, nullptr);
      ASSERT_NE(surviving, nullptr);
      EXPECT_TRUE(removed->access_denied());
      ASSERT_EQ(removed->queue.size(), 1u);
      EXPECT_EQ(removed->queue.front().status(), StatusCode{Status::BadNodeIdUnknown});
      EXPECT_FALSE(surviving->access_denied()) << "one lookup failure must not abort later items";
    });

  ASSERT_TRUE(mAddressSpace->try_create_node_sync(removedNode, NodeClass::Variable).is_good());
  trigger_recheck(*subscription);
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* removed = guarded.find_monitored_item(removedItemId);
      ASSERT_NE(removed, nullptr);
      EXPECT_FALSE(removed->access_denied()) << "a later successful refresh restores access";
    });
}

// @relation(AC-SVR-AUTHZ-009-PERIODIC-FAILURE-FAILS-CLOSED, scope=function)
TEST_F(MonitoredItemAccessControlTest, RecheckFailsClosedWhenAddressSpaceIsUnavailable)
{
  auto subscription = create_subscription();
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 61}}), security);
  ASSERT_EQ(results.size(), 1u);
  const auto monitoredItemId = results[0].monitored_item_id();

  WeakAddressSpace expiredAddressSpace;
  {
    auto transient = AddressSpace::create("urn:test:expired-periodic", mExecutor);
    expiredAddressSpace = transient.weak();
  }
  subscription->configure_access_recheck(1h, security, std::move(expiredAddressSpace), {});
  STA::on_strand(*subscription, [](auto&) {});
  trigger_recheck(*subscription);

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 1u);
      const auto status = item->queue.front().status().value();
      EXPECT_EQ(status, StatusCode{Status::BadUserAccessDenied});
      ASSERT_NE(status.shared_detail(), nullptr);
      EXPECT_EQ(status.shared_detail()->code, "PeriodicAccessRecheckAddressSpaceUnavailable");
      ASSERT_NE(status.shared_detail()->cause, nullptr);
    });
}

// An event item must be deregistered from the EventBus on allow -> deny and re-registered on
// deny -> allow (ReceiveEvents gate). The EventBus handle (0 == not registered) is the observable.
TEST_F(MonitoredItemAccessControlTest, RecheckDeregistersThenReregistersEventItem)
{
  using namespace std::chrono_literals;
  auto sub = create_subscription();
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto eventSource = create_event_source(2000);
  auto request = make_event_request(1, eventSource, 77);

  auto secCtx = std::make_shared<FakeSessionSecurityContext>();

  auto results = create_items(sub, std::move(request), secCtx, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto miId = results[0].monitored_item_id();

  sub->configure_access_recheck(1h, secCtx, mAddressSpace->weak(), eventBus);

  // Allowed: registered with the bus.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->isEventItem);
      EXPECT_FALSE(item->access_denied());
      EXPECT_NE(item->eventBusHandle, 0u);
    });

  // Revoke ReceiveEvents -> recheck deregisters (handle cleared).
  set_node_permission(eventSource, PermissionType::Bit::ReceiveEvents, false);
  trigger_recheck(*sub);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->access_denied());
      EXPECT_EQ(item->eventBusHandle, 0u) << "a denied event item must be deregistered from the EventBus";
    });

  // Restore -> recheck re-registers (fresh handle).
  set_node_permission(eventSource, PermissionType::Bit::ReceiveEvents, true);
  trigger_recheck(*sub);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied());
      EXPECT_NE(item->eventBusHandle, 0u)
        << "a re-allowed event item must be re-registered with the EventBus";
    });
}

// @relation(AC-SVR-AUTHZ-023-EVENT-MISS-DOES-NOT-LOSE-THE-EVENT, scope=function)
// @verifies AC-SVR-AUTHZ-023-EVENT-MISS-DOES-NOT-LOSE-THE-EVENT
TEST_F(MonitoredItemAccessControlTest, ColdEventIsRetainedUntilPermissionResolutionCompletes)
{
  enable_test_role_on_namespace(0);
  auto deferred = ua::test::DeferredNamespace::create("urn:test:event-cold", mExecutor);
  const auto deferredIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId sourceId{deferredIndex, 3000};
  const NodeId eventTypeId{deferredIndex, 3001};
  auto source = mAddressSpace->try_create_sync<ObjectAccessor>(sourceId, NodeClass::Object).value();
  source.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto eventType = mAddressSpace->try_create_node_sync(eventTypeId, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{deferredIndex, String{"ColdEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 101);
  deferred->grant(AccessIdentityKey{101}, sourceId, ua::test_helpers::all_permissions());
  deferred->grant(AccessIdentityKey{101}, eventTypeId, ua::test_helpers::all_permissions());

  std::promise<void> readyPromise;
  auto ready = readyPromise.get_future();
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&readyPromise](IntegerId) { readyPromise.set_value(); },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto results = create_items(subscription, make_event_request(1, sourceId, 77), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();

  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  std::promise<Result<bool>> registrationPromise;
  auto registration = registrationPromise.get_future();
  eventBus->has_event_items_async(
    1, [&registrationPromise](Result<bool> result) { registrationPromise.set_value(std::move(result)); });
  ASSERT_TRUE(registration.get().value());

  deferred->forget(AccessIdentityKey{101}, sourceId);
  deferred->forget(AccessIdentityKey{101}, eventTypeId);
  deferred->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  BaseEvent event;
  event.eventType = eventTypeId;
  event.sourceNode = sourceId;
  event.sourceName = String{"ColdSource"};
  event.message = LocalizedText{LocaleId{}, String{"retained while permissions are cold"}};
  eventBus->emit(event);

  ASSERT_TRUE(deferred->wait_for_pending_resolutions())
    << "Event authorization never reached asynchronous permission resolution";
  const auto permissionCalls = deferred->effective_permissions_calls();
  ASSERT_EQ(permissionCalls.size(), 1u);
  EXPECT_EQ(permissionCalls[0].identity, AccessIdentityKey{101});
  ASSERT_TRUE(permissionCalls[0].nodes.has_value());
  EXPECT_NE(std::ranges::find(*permissionCalls[0].nodes, sourceId), permissionCalls[0].nodes->end());
  EXPECT_NE(std::ranges::find(*permissionCalls[0].nodes, eventTypeId), permissionCalls[0].nodes->end());
  EXPECT_EQ(ready.wait_for(50ms), std::future_status::timeout)
    << "a cold Event must not be delivered before permission resolution completes";

  deferred->grant(AccessIdentityKey{101}, sourceId, ua::test_helpers::all_permissions());
  deferred->grant(AccessIdentityKey{101}, eventTypeId, ua::test_helpers::all_permissions());
  deferred->complete_pending_resolutions();
  ASSERT_EQ(ready.wait_for(2s), std::future_status::ready)
    << "the Event was lost instead of retained across permission resolution";
  STA::on_strand(*subscription,
    [monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 1u);
    });
  subscription.reset();
  eventBus.reset();
  deferred->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-FILTER-SUBJECTS-AUTHORIZED, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-01-COMPLETE-PLAN, scope=function)
TEST_F(MonitoredItemAccessControlTest, EventAuthorizationBatchIncludesSourceTypeSelectAndWhereSubjects)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-complete-plan", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3400);
  const AccessIdentityKey identityKey{401};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->grant(identityKey, node, ua::test_helpers::all_permissions());
  }

  std::promise<void> readyPromise;
  auto ready = readyPromise.get_future();
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&readyPromise](IntegerId) { readyPromise.set_value(); },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 117, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->forget(identityKey, node);
    controlledNamespace->set_async_permissions(identityKey, node, ua::test_helpers::all_permissions());
  }
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto event = make_controlled_event(nodes, "selected", "match");
  eventBus->emit(event);

  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions())
    << "the complete Event authorization plan never reached the namespace";
  const auto permissionCalls = controlledNamespace->effective_permissions_calls();
  ASSERT_EQ(permissionCalls.size(), 1u);
  EXPECT_EQ(permissionCalls[0].identity, identityKey);
  ASSERT_TRUE(permissionCalls[0].nodes.has_value());
  const std::array expectedNodes{nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField};
  EXPECT_EQ(permissionCalls[0].nodes->size(), expectedNodes.size());
  for (const auto& expected : expectedNodes)
  {
    EXPECT_NE(std::ranges::find(*permissionCalls[0].nodes, expected), permissionCalls[0].nodes->end());
  }

  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      const auto& plan = guarded.event_delivery_plan();
      ASSERT_EQ(plan.size(), 4u);
      EXPECT_EQ(plan[0].nodeId, nodes.source);
      EXPECT_EQ(plan[0].operation, AccessOperation::ReceiveEvents);
      EXPECT_EQ(plan[1].nodeId, nodes.eventType);
      EXPECT_EQ(plan[1].operation, AccessOperation::ReceiveEvents);
      EXPECT_EQ(plan[2].nodeId, nodes.selectedField);
      EXPECT_EQ(plan[2].operation, AccessOperation::Read);
      EXPECT_EQ(plan[3].nodeId, nodes.whereField);
      EXPECT_EQ(plan[3].operation, AccessOperation::Read);
    });
  const auto permissionQuestionsAtBarrier = controlledNamespace->permission_questions();
  EXPECT_EQ(ready.wait_for(50ms), std::future_status::timeout)
    << "filtering or projection ran before the authorization barrier completed";

  controlledNamespace->complete_pending_resolutions();
  ASSERT_EQ(ready.wait_for(2s), std::future_status::ready);
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      ASSERT_EQ(item->eventQueue.front().fields.event_fields().size(), 1u);
      ASSERT_TRUE(item->eventQueue.front().fields.event_fields()[0].is_string());
      EXPECT_EQ(item->eventQueue.front().fields.event_fields()[0].template as<String>(), String{"selected"});
    });
  EXPECT_EQ(controlledNamespace->permission_questions(), permissionQuestionsAtBarrier)
    << "authorized filtering/projection must consume the completed verdict view, not re-query permissions";
  EXPECT_EQ(controlledNamespace->effective_permissions_calls().size(), 1u);

  subscription.reset();
  eventBus.reset();
  controlledNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-HEAD-CANNOT-BE-OVERTAKEN, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-02-FIFO, scope=function)
TEST_F(MonitoredItemAccessControlTest, DeferredFrontEventCannotBeOvertakenByImmediateLaterEvent)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-fifo", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3500);
  const AccessIdentityKey identityKey{411};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->grant(identityKey, node, ua::test_helpers::all_permissions());
  }

  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 118, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  controlledNamespace->forget(identityKey, nodes.selectedField);
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto first = make_controlled_event(nodes, "first", "match");
  auto second = make_controlled_event(nodes, "second", "match");
  eventBus->emit(first);
  eventBus->emit(second);

  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions());
  wait_for_pending_deliveries(*subscription, 2u);
  EXPECT_EQ(controlledNamespace->effective_permissions_calls().size(), 1u)
    << "the later Event must not begin authorization while the front head is deferred";
  {
    std::unique_lock lock(readyMutex);
    EXPECT_FALSE(readyCondition.wait_for(lock, 50ms, [&] { return readyCount != 0; }))
      << "an Event was delivered before the front authorization completed";
  }
  STA::on_strand(*subscription,
    [](auto& guarded)
    {
      EXPECT_TRUE(guarded.event_delivery_active());
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  controlledNamespace->grant(identityKey, nodes.selectedField, ua::test_helpers::all_permissions());
  controlledNamespace->complete_pending_resolutions();
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 2; }));
  }
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 2u);
      const auto& firstFields = item->eventQueue[0].fields.event_fields();
      const auto& secondFields = item->eventQueue[1].fields.event_fields();
      ASSERT_EQ(firstFields.size(), 1u);
      ASSERT_EQ(secondFields.size(), 1u);
      EXPECT_EQ(firstFields[0].template as<String>(), String{"first"});
      EXPECT_EQ(secondFields[0].template as<String>(), String{"second"});
      EXPECT_FALSE(guarded.event_delivery_active());
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
    });
  EXPECT_EQ(controlledNamespace->effective_permissions_calls().size(), 1u)
    << "the second Event must be an immediate hit after the front head completes";

  subscription.reset();
  eventBus.reset();
  controlledNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-016-DISABLED-EVENT-HEAD-DISCARDED, scope=function)
// @verifies AC-SVR-AUTHZ-016-DISABLED-EVENT-HEAD-DISCARDED
TEST_F(MonitoredItemAccessControlTest, DisableDiscardsDeferredEventHeadBeforeReenable)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-disable-order", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3550);
  const AccessIdentityKey identityKey{416};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
    controlledNamespace->grant(identityKey, node, ua::test_helpers::all_permissions());

  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 122, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results.front().status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results.front().monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  controlledNamespace->forget(identityKey, nodes.selectedField);
  controlledNamespace->set_async_permissions(
    identityKey, nodes.selectedField, ua::test_helpers::all_permissions());
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto beforeDisable = make_controlled_event(nodes, "before-disable", "match");
  eventBus->emit(beforeDisable);
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions());

  auto disabled = set_mode_blocking(subscription, {monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  EXPECT_EQ(disabled.front(), StatusCode{Status::Good});
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      const auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->monitoringMode, MonitoringMode::Disabled);
      EXPECT_TRUE(item->eventQueue.empty());
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      EXPECT_FALSE(guarded.event_delivery_active());
    });

  auto reenabled = set_mode_blocking(subscription, {monitoredItemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  EXPECT_EQ(reenabled.front(), StatusCode{Status::Good});

  controlledNamespace->complete_pending_resolutions();
  controlledNamespace->wait_idle();
  STA::on_strand(*subscription, [](auto&) {});
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      const auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->eventQueue.empty())
        << "the Event from the Disabled interval was queued after re-enable";
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
    });

  controlledNamespace->grant(identityKey, nodes.selectedField, ua::test_helpers::all_permissions());
  auto afterReenable = make_controlled_event(nodes, "after-reenable", "match");
  eventBus->emit(afterReenable);
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 1; }));
  }
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      const auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      const auto& fields = item->eventQueue.front().fields.event_fields();
      ASSERT_EQ(fields.size(), 1u);
      EXPECT_EQ(fields[0].template as<String>(), String{"after-reenable"});
    });

  subscription.reset();
  eventBus.reset();
  controlledNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-IDENTITY-CHANGE-RESTARTS-HEAD, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-02-IDENTITY-EPOCH, scope=function)
TEST_F(MonitoredItemAccessControlTest, IdentityChangeRestartsTheSameEventHeadAndRejectsStaleCompletion)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-identity-epoch", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3600);
  const AccessIdentityKey oldIdentity{421};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, oldIdentity.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->grant(oldIdentity, node, ua::test_helpers::all_permissions());
  }

  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 119, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  controlledNamespace->forget(oldIdentity, nodes.selectedField);
  controlledNamespace->set_async_permissions(
    oldIdentity, nodes.selectedField, ua::test_helpers::all_permissions());
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto first = make_controlled_event(nodes, "first-under-new-identity", "match");
  auto second = make_controlled_event(nodes, "later", "match");
  eventBus->emit(first);
  eventBus->emit(second);
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions());
  wait_for_pending_deliveries(*subscription, 2u);

  uint64_t originalOrdinal = 0;
  uint64_t originalEpoch = 0;
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      originalOrdinal = guarded.active_event_delivery_ordinal();
      originalEpoch = guarded.event_delivery_attempt_epoch();
      ASSERT_NE(originalOrdinal, 0u);
      ASSERT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  security->set_roles({ua::test_helpers::test_access_role_id()});
  const auto newIdentity = security->access_identity()->key();
  ASSERT_NE(newIdentity, oldIdentity);
  controlledNamespace->grant(newIdentity, nodes.source, ua::test_helpers::all_permissions());
  controlledNamespace->grant(newIdentity, nodes.eventType, ua::test_helpers::all_permissions());
  controlledNamespace->grant(newIdentity, nodes.whereField, ua::test_helpers::all_permissions());

  std::promise<VoidResult> reauthorizationPromise;
  auto reauthorization = reauthorizationPromise.get_future();
  subscription->reauthorize_all_async(
    [&reauthorizationPromise](VoidResult result) { reauthorizationPromise.set_value(std::move(result)); });
  const auto reauthorizationResult = reauthorization.get();
  ASSERT_TRUE(reauthorizationResult.is_good()) << to_string(reauthorizationResult.status_code());
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions(2))
    << "identity replacement did not restart authorization for the same head";
  wait_for_pending_deliveries(*subscription, 2u);
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      EXPECT_EQ(guarded.active_event_delivery_ordinal(), originalOrdinal);
      EXPECT_GT(guarded.event_delivery_attempt_epoch(), originalEpoch);
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  controlledNamespace->complete_next_pending_resolution();
  controlledNamespace->wait_released_resolutions_idle();
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      EXPECT_EQ(guarded.active_event_delivery_ordinal(), originalOrdinal);
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });
  {
    const std::lock_guard lock(readyMutex);
    EXPECT_EQ(readyCount, 0u) << "the old-identity grant must be inert after the attempt epoch changes";
  }

  controlledNamespace->grant(newIdentity, nodes.selectedField, ua::test_helpers::all_permissions());
  controlledNamespace->complete_next_pending_resolution();
  controlledNamespace->wait_released_resolutions_idle();
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 2; }));
  }
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 2u);
      EXPECT_EQ(item->eventQueue[0].fields.event_fields()[0].template as<String>(),
        String{"first-under-new-identity"});
      EXPECT_EQ(item->eventQueue[1].fields.event_fields()[0].template as<String>(), String{"later"});
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
    });
  const auto calls = controlledNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 2u);
  EXPECT_EQ(calls[0].identity, oldIdentity);
  EXPECT_EQ(calls[1].identity, newIdentity);

  subscription.reset();
  eventBus.reset();
  controlledNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-IDENTITY-CHANGE-RESTARTS-HEAD, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-02-FIXED-DEADLINE, scope=function)
TEST_F(MonitoredItemAccessControlTest, EventHeadDeadlineIsFixedAcrossIdentityRestartAndAdvancesOnce)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-fixed-deadline", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3700);
  const AccessIdentityKey oldIdentity{431};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, oldIdentity.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->grant(oldIdentity, node, ua::test_helpers::all_permissions());
  }

  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  // Keep the real timer out of this state-transition test. The exact deadline value is asserted across the
  // identity restart below, then the existing strand test-access interface fires that ordinal's deadline
  // deterministically. A short wall-clock timeout races the assertions under the standard sharded load.
  subscription->set_access_control_timeout(1h);
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 120, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  controlledNamespace->forget(oldIdentity, nodes.eventType);
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto blocked = make_controlled_event(nodes, "must-time-out", "match");
  auto control = make_controlled_event(nodes, "control", "match");
  eventBus->emit(blocked);
  eventBus->emit(control);
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions());
  wait_for_pending_deliveries(*subscription, 2u);

  uint64_t ordinal = 0;
  std::chrono::steady_clock::time_point originalDeadline;
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      ordinal = guarded.active_event_delivery_ordinal();
      originalDeadline = guarded.event_delivery_deadline();
      ASSERT_NE(ordinal, 0u);
      ASSERT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  security->set_roles({ua::test_helpers::test_access_role_id()});
  const auto newIdentity = security->access_identity()->key();
  for (const auto& node : {nodes.source, nodes.selectedField, nodes.whereField})
    controlledNamespace->grant(newIdentity, node, ua::test_helpers::all_permissions());

  std::promise<VoidResult> reauthorizationPromise;
  auto reauthorization = reauthorizationPromise.get_future();
  subscription->reauthorize_all_async(
    [&reauthorizationPromise](VoidResult result) { reauthorizationPromise.set_value(std::move(result)); });
  ASSERT_TRUE(reauthorization.get().is_good());
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions(2));
  wait_for_pending_deliveries(*subscription, 2u);
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      EXPECT_EQ(guarded.active_event_delivery_ordinal(), ordinal);
      EXPECT_EQ(guarded.event_delivery_deadline(), originalDeadline)
        << "identity replacement must retain the head-start deadline exactly";
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  controlledNamespace->grant(newIdentity, nodes.eventType, ua::test_helpers::all_permissions());
  STA::on_strand(*subscription, [ordinal](auto& guarded) { guarded.on_event_delivery_deadline(ordinal); });
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 1; }))
      << "the original fixed deadline did not release the blocked head";
  }
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      EXPECT_EQ(item->eventQueue.front().fields.event_fields()[0].template as<String>(), String{"control"});
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      EXPECT_FALSE(guarded.event_delivery_active());
    });

  controlledNamespace->complete_pending_resolutions();
  controlledNamespace->wait_idle();
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 1u)
        << "late completions must not deliver or advance either head again";
    });
  {
    const std::lock_guard lock(readyMutex);
    EXPECT_EQ(readyCount, 1u);
  }

  subscription.reset();
  eventBus.reset();
}

// The EventBus is server-wide and outlives every Subscription: an event item still registered after its
// Subscription closed is scanned and called for every event the server emits from then on. Closing the
// Subscription (DeleteSubscriptions, session close, lifetime expiry) takes its event items off the bus.
// @relation(AC-SVR-SUB-GEN-033-CLOSE-DEREGISTERS-EVENT-ITEMS, scope=function)
TEST_F(MonitoredItemAccessControlTest, ClosingASubscriptionDeregistersItsEventItemsFromTheEventBus)
{
  using namespace std::chrono_literals;
  auto sub = create_subscription();
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto eventSource = create_event_source(2100);
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(sub, make_event_request(1, eventSource, 78), secCtx, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});

  const auto subscriptionId = sub->get_info().id;
  const auto hasEventItems = [&eventBus, subscriptionId]
  {
    std::promise<Result<bool>> promise;
    auto future = promise.get_future();
    eventBus->has_event_items_async(
      subscriptionId, [&promise](Result<bool> result) { promise.set_value(std::move(result)); });
    return future.get();
  };
  const auto before = hasEventItems();
  ASSERT_TRUE(before.is_good()) << to_string(before.status_code());
  ASSERT_TRUE(before.value()) << "the event item was never registered, so the close arm proves nothing";

  std::promise<void> closePromise;
  auto closed = closePromise.get_future();
  sub->close_async([&closePromise] { closePromise.set_value(); });
  ASSERT_EQ(closed.wait_for(2s), std::future_status::ready);

  // Both the deregistration and this query are posted to the bus's dispatch strand, so the query
  // observes the registry after the deregistration.
  const auto after = hasEventItems();
  ASSERT_TRUE(after.is_good()) << to_string(after.status_code());
  EXPECT_FALSE(after.value()) << "a closed Subscription's event item is still registered on the EventBus";
}

// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-CLOSE, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-STRAND, scope=function)
TEST_F(MonitoredItemAccessControlTest, EventCloseInvalidatesActiveAndQueuedDelivery)
{
  enable_test_role_on_namespace(0);
  auto controlledNamespace = ua::test::DeferredNamespace::create("urn:test:event-close", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 3800);
  const AccessIdentityKey identityKey{441};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  for (const auto& node : {nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField})
  {
    controlledNamespace->grant(identityKey, node, ua::test_helpers::all_permissions());
  }

  std::atomic_size_t readyCount{0};
  auto subscription = Subscription::create(
    1, 1000, 100, 3, 0, true, 0, mExecutor, [&](IntegerId) { readyCount.fetch_add(1); }, [](IntegerId) {});
  subscription->set_access_control_timeout(1h);
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto filter =
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName);
  auto results = create_items(
    subscription, make_event_request(1, nodes.source, 121, std::move(filter)), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  controlledNamespace->forget(identityKey, nodes.selectedField);
  controlledNamespace->set_async_permissions(
    identityKey, nodes.selectedField, ua::test_helpers::all_permissions());
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  auto active = make_controlled_event(nodes, "active", "match");
  auto queued = make_controlled_event(nodes, "queued", "match");
  eventBus->emit(active);
  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions());
  wait_for_pending_deliveries(*subscription, 1u);

  uint64_t activeOrdinal = 0;
  std::shared_ptr<const BaseEvent> queuedEvent = std::make_shared<GenericEvent>(std::move(queued));
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      activeOrdinal = guarded.active_event_delivery_ordinal();
      ASSERT_NE(activeOrdinal, 0u);
      ASSERT_EQ(guarded.pending_event_deliveries().size(), 1u);
      const auto declarationModel = guarded.pending_event_deliveries().front().declarationModel;
      guarded.enqueue_event_delivery(monitoredItemId, queuedEvent, declarationModel);
      ASSERT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  std::promise<void> closePromise;
  auto closed = closePromise.get_future();
  subscription->close_async([&closePromise] { closePromise.set_value(); });
  ASSERT_EQ(closed.wait_for(2s), std::future_status::ready);
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      EXPECT_FALSE(guarded.event_delivery_active());
      guarded.on_event_delivery_deadline(activeOrdinal);
    });

  controlledNamespace->complete_pending_resolutions();
  controlledNamespace->wait_idle();
  STA::on_strand(*subscription,
    [](auto& guarded)
    {
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      EXPECT_FALSE(guarded.event_delivery_active());
    });
  EXPECT_EQ(readyCount.load(), 0u);

  subscription.reset();
  eventBus.reset();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-TERMINAL-PATHS-ADVANCE-ONCE, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-TERMINAL-ONCE, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-STRAND, scope=function)
TEST_F(MonitoredItemAccessControlTest, EventRichNamespaceFailureAdvancesFifoAndLogsOriginalDetail)
{
  enable_test_role_on_namespace(0);
  const auto notifier = create_event_source(3900);
  auto failingNamespace = ua::test::DeferredNamespace::create("urn:test:event-rich-failure", mExecutor);
  const auto failingIndex = mAddressSpace->add_namespace_sync(failingNamespace);
  const NodeId failingSource{failingIndex, 3901u};
  const NodeId failingType{failingIndex, 3902u};
  auto source = mAddressSpace->try_create_sync<ObjectAccessor>(failingSource, NodeClass::Object).value();
  source.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto eventType = mAddressSpace->try_create_node_sync(failingType, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{failingIndex, String{"FailingEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  const AccessIdentityKey identityKey{451};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto logSink = std::make_shared<EventAuthorizationLogSink>();
  auto logLevel = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  subscription->set_logger(Logger{logSink, logLevel, "event-authorization-test"});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto results = create_items(subscription, make_event_request(1, notifier, 122), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  failingNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Failing);
  const auto declarationModel = base_message_declaration_model();
  const auto failed = make_base_event(failingSource, failingType, "suppressed");
  const auto control =
    make_base_event(notifier, NodeId{ObjectTypeId::BaseEventType}, "control-after-rich-failure");
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      guarded.enqueue_event_delivery(monitoredItemId, failed, declarationModel);
      guarded.enqueue_event_delivery(monitoredItemId, control, declarationModel);
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 1; }));
  }
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      const auto& fields = item->eventQueue.front().fields.event_fields();
      ASSERT_EQ(fields.size(), 1u);
      ASSERT_TRUE(fields[0].is_localized_text());
      EXPECT_EQ(fields[0].template as<LocalizedText>().text(), String{"control-after-rich-failure"});
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
    });
  EXPECT_TRUE(logSink->contains_detail("DeferredNamespaceResolutionFailed"))
    << "the terminal log must retain the namespace failure's original ErrorDetail";
  EXPECT_TRUE(logSink->contains_at(
    "Event delivery authorization failed closed", "DeferredNamespaceResolutionFailed", LogLevel::Warning))
    << "a namespace that could not answer withholds an Event the session may be entitled to - a warning";
  const auto calls = failingNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_TRUE(calls[0].nodes.has_value());
  EXPECT_EQ(calls[0].nodes->size(), 2u);

  subscription.reset();
  eventBus.reset();
  failingNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-023-EVENT-TERMINAL-PATHS-ADVANCE-ONCE, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-TERMINAL-ONCE, scope=function)
TEST_F(MonitoredItemAccessControlTest, EventNodeLossAdvancesFifoExactlyOnce)
{
  enable_test_role_on_namespace(0);
  const auto notifier = create_event_source(4000);
  auto disappearingNamespace = ua::test::DeferredNamespace::create("urn:test:event-node-loss", mExecutor);
  const auto disappearingIndex = mAddressSpace->add_namespace_sync(disappearingNamespace);
  const NodeId missingSource{disappearingIndex, 4001u};
  const NodeId eventTypeId{disappearingIndex, 4002u};
  auto source = mAddressSpace->try_create_sync<ObjectAccessor>(missingSource, NodeClass::Object).value();
  source.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto eventType = mAddressSpace->try_create_node_sync(eventTypeId, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{disappearingIndex, String{"NodeLossEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  const AccessIdentityKey identityKey{461};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  disappearingNamespace->grant(identityKey, missingSource, ua::test_helpers::all_permissions());
  disappearingNamespace->grant(identityKey, eventTypeId, ua::test_helpers::all_permissions());
  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      const std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto results = create_items(subscription, make_event_request(1, notifier, 123), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(missingSource, false).is_good());
  const auto declarationModel = base_message_declaration_model();
  const auto missing = make_base_event(missingSource, eventTypeId, "suppressed-node-loss");
  const auto control =
    make_base_event(notifier, NodeId{ObjectTypeId::BaseEventType}, "control-after-node-loss");
  uint64_t missingOrdinal = 0;
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      guarded.enqueue_event_delivery(monitoredItemId, missing, declarationModel);
      missingOrdinal = guarded.active_event_delivery_ordinal();
      guarded.enqueue_event_delivery(monitoredItemId, control, declarationModel);
      ASSERT_NE(missingOrdinal, 0u);
      EXPECT_EQ(guarded.pending_event_deliveries().size(), 2u);
    });

  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 1; }));
  }
  STA::on_strand(*subscription,
    [&, monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 1u);
      EXPECT_EQ(item->eventQueue.front().fields.event_fields()[0].template as<LocalizedText>().text(),
        String{"control-after-node-loss"});
      EXPECT_TRUE(guarded.pending_event_deliveries().empty());
      guarded.on_event_delivery_deadline(missingOrdinal);
      EXPECT_EQ(item->eventQueue.size(), 1u)
        << "a late terminal notifier must not advance the already removed ordinal again";
    });
  {
    const std::lock_guard lock(readyMutex);
    EXPECT_EQ(readyCount, 1u);
  }

  subscription.reset();
  eventBus.reset();
  disappearingNamespace->wait_idle();
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 4, DL-69 (E5): an Uncertain lookup answer holds no Node, so the Event
// whose SourceNode it answers is denied at once with that answer as its cause, as a Bad answer is. It does
// not wait for the 10 s access-control deadline, so the control Event behind it is queued within 2 s.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-AN-UNCERTAIN-SUBJECT-LOOKUP-DENIES-THE-EVENT-AT-ONCE, scope=function)
TEST_F(EventDelivery, AnUncertainSubjectLookupDeniesTheEventAtOnce)
{
  enable_test_role_on_namespace(0);
  const auto notifier = create_event_source(4100);
  auto uncertainNamespace =
    std::make_shared<ua::test::BatchRecordingNamespace>("urn:test:event-uncertain-subject", mExecutor);
  const auto uncertainIndex = mAddressSpace->add_namespace_sync(uncertainNamespace);
  const NodeId uncertainSource{uncertainIndex, 4101u};
  uncertainNamespace->answer_lookup_of(uncertainSource,
    StatusCode{Status::UncertainNoCommunicationLastUsableValue,
      ErrorDetail::build(
        "SourceLookupUncertain", "The namespace holds no Node it is sure of", "EventDeliveryTest")});

  const AccessIdentityKey identityKey{471};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  subscription->set_access_control_timeout(10s);
  auto logSink = std::make_shared<EventAuthorizationLogSink>();
  auto logLevel = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  subscription->set_logger(Logger{logSink, logLevel, "event-authorization-test"});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto results = create_items(subscription, make_event_request(1, notifier, 124), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});
  wait_for_event_registration(eventBus, 1);

  const auto declarationModel = base_message_declaration_model();
  const auto uncertain =
    make_base_event(uncertainSource, NodeId{ObjectTypeId::BaseEventType}, "uncertain-source");
  const auto control =
    make_base_event(notifier, NodeId{ObjectTypeId::BaseEventType}, "control-after-uncertain-source");
  const auto enqueued = std::chrono::steady_clock::now();
  STA::on_strand(*subscription,
    [&](auto& guarded)
    {
      guarded.enqueue_event_delivery(monitoredItemId, uncertain, declarationModel);
      guarded.enqueue_event_delivery(monitoredItemId, control, declarationModel);
    });

  // What the item's queue holds, polled until the control Event is in it or 2 s have passed.
  std::size_t queued = 0;
  bool controlQueued = false;
  bool uncertainQueued = false;
  for (;;)
  {
    STA::on_strand(*subscription,
      [&](auto& guarded)
      {
        queued = 0;
        controlQueued = false;
        uncertainQueued = false;
        auto* item = guarded.find_monitored_item(monitoredItemId);
        if (item == nullptr)
          return;
        for (const auto& entry : item->eventQueue)
        {
          ++queued;
          const auto& fields = entry.fields.event_fields();
          if (fields.empty() || !fields[0].is_localized_text())
            continue;
          const auto& text = fields[0].template as<LocalizedText>().text();
          controlQueued = controlQueued || text == String{"control-after-uncertain-source"};
          uncertainQueued = uncertainQueued || text == String{"uncertain-source"};
        }
      });
    if (controlQueued || std::chrono::steady_clock::now() >= enqueued + 2s)
      break;
    std::this_thread::sleep_for(5ms);
  }

  EXPECT_TRUE(controlQueued) << "the control Event was not queued within 2 s of being enqueued";
  EXPECT_FALSE(uncertainQueued) << "the Event whose SourceNode lookup answered Uncertain was delivered";
  EXPECT_EQ(queued, 1u) << "the item's queue does not hold the control Event alone";
  const bool deniedWithTheLookupAsCause =
    logSink->contains_at(
      "Event delivery authorization failed closed", "SourceLookupUncertain", LogLevel::Warning) ||
    logSink->contains_at("Event withheld by access control", "SourceLookupUncertain", LogLevel::Debug);
  EXPECT_TRUE(deniedWithTheLookupAsCause)
    << "the Event's denial was not logged with the lookup's answer as its cause; warnings and errors:\n"
    << logSink->warnings_and_errors();

  subscription.reset();
  eventBus.reset();
}

// @relation(AC-SVR-AUTHZ-023-STALLED-RESOLUTION-DOES-NOT-STALL-EVENTS, scope=function)
// @verifies AC-SVR-AUTHZ-023-STALLED-RESOLUTION-DOES-NOT-STALL-EVENTS
TEST_F(AccessControlMissTest, StalledResolutionDoesNotStallEventDelivery)
{
  enable_test_role_on_namespace(0);
  auto stalledNamespace = ua::test::DeferredNamespace::create("urn:test:event-stalled", mExecutor);
  auto eventNamespace = ua::test::DeferredNamespace::create("urn:test:event-independent", mExecutor);
  const auto stalledIndex = mAddressSpace->add_namespace_sync(stalledNamespace);
  const auto eventIndex = mAddressSpace->add_namespace_sync(eventNamespace);

  const NodeId stalledNodeId{stalledIndex, 3200};
  mAddressSpace->create_node_sync(stalledNodeId, NodeClass::Variable);
  const NodeId eventSourceId{eventIndex, 3201};
  auto eventSource = mAddressSpace->try_create_sync<ObjectAccessor>(eventSourceId, NodeClass::Object).value();
  eventSource.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId eventTypeId{eventIndex, 3202};
  auto eventType = mAddressSpace->try_create_node_sync(eventTypeId, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{eventIndex, String{"IndependentEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  const AccessIdentityKey identityKey{301};
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, identityKey.value());
  eventNamespace->grant(identityKey, eventSourceId, ua::test_helpers::all_permissions());
  eventNamespace->grant(identityKey, eventTypeId, ua::test_helpers::all_permissions());

  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t readyCount = 0;
  auto subscription = Subscription::create(
    1,
    1000,
    100,
    3,
    0,
    true,
    0,
    mExecutor,
    [&](IntegerId)
    {
      std::lock_guard lock(readyMutex);
      ++readyCount;
      readyCondition.notify_all();
    },
    [](IntegerId) {});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto results = create_items(subscription, make_event_request(1, eventSourceId, 91), security, eventBus);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const auto monitoredItemId = results[0].monitored_item_id();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), eventBus);
  subscription->set_publish_req_queued_async(true);
  STA::on_strand(*subscription, [](auto&) {});

  std::promise<Result<bool>> registrationPromise;
  auto registration = registrationPromise.get_future();
  eventBus->has_event_items_async(
    1, [&registrationPromise](Result<bool> result) { registrationPromise.set_value(std::move(result)); });
  ASSERT_TRUE(registration.get().value());

  stalledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::NeverCompletes);
  std::promise<std::vector<AccessControl::Verdict>> stalledPromise;
  auto stalledResult = stalledPromise.get_future();
  AccessControl stalledAccessControl{*mAddressSpace, 150ms};
  const auto stalledNode = mAddressSpace->find_node_sync(stalledNodeId);
  const std::array stalledItems{AccessControl::Item{stalledNode, AccessOperation::Read}};
  stalledAccessControl.authorize_async(ua::RequestInfo{},
    security->access_identity(),
    stalledItems,
    *security->endpoint_security(),
    [&stalledPromise](std::vector<AccessControl::Verdict> verdicts)
    { stalledPromise.set_value(std::move(verdicts)); });
  ASSERT_EQ(stalledNamespace->effective_permissions_calls().size(), 1u)
    << "the first namespace did not enter the miss protocol";
  ASSERT_EQ(stalledResult.wait_for(0ms), std::future_status::timeout)
    << "the injected never-completing resolution was not left outstanding";

  auto emitColdEvent = [&](string_view message)
  {
    eventNamespace->forget(identityKey, eventSourceId);
    eventNamespace->forget(identityKey, eventTypeId);
    eventNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

    BaseEvent event;
    event.eventType = eventTypeId;
    event.sourceNode = eventSourceId;
    event.sourceName = String{"IndependentSource"};
    event.message = LocalizedText{LocaleId{}, String{message}};
    eventBus->emit(event);

    ASSERT_TRUE(eventNamespace->wait_for_pending_resolutions())
      << "the independent Event namespace did not enter the miss protocol";
    eventNamespace->grant(identityKey, eventSourceId, ua::test_helpers::all_permissions());
    eventNamespace->grant(identityKey, eventTypeId, ua::test_helpers::all_permissions());
    eventNamespace->complete_pending_resolutions();
  };

  emitColdEvent("delivered while the unrelated permission resolution is outstanding");
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 1; }))
      << "the unrelated stalled namespace blocked Event delivery";
  }
  ASSERT_EQ(stalledResult.wait_for(0ms), std::future_status::timeout)
    << "the first Event was observed only after the unrelated resolution completed";

  ASSERT_EQ(stalledResult.wait_for(2s), std::future_status::ready)
    << "the unrelated miss did not reach its operation-wide timeout";
  const auto stalledVerdicts = stalledResult.get();
  ASSERT_EQ(stalledVerdicts.size(), 1u);
  EXPECT_FALSE(stalledVerdicts[0].permitted);

  emitColdEvent("delivered after the unrelated permission resolution timed out");
  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(readyCondition.wait_for(lock, 2s, [&] { return readyCount >= 2; }))
      << "Event delivery remained stalled after the unrelated permission resolution timed out";
  }
  STA::on_strand(*subscription,
    [monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 2u);
    });

  subscription.reset();
  eventBus.reset();
  eventNamespace->wait_idle();
  stalledNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-007-EVENT-SOURCE-HALF, scope=function)
// @relation(AC-SVR-AUTHZ-016-CONDITION-REFRESH-REAUTHORIZES, scope=function)
// @relation(AC-SVR-AUTHZ-023-EVENT-DENIAL-IS-PER-RECIPIENT, scope=function)
// @relation(AC-SVR-AUTHZ-023-EVENT-FILTER-SUBJECTS-AUTHORIZED, scope=function)
// @relation(AC-SVR-AUTHZ-023-EVENT-TERMINAL-PATHS-ADVANCE-ONCE, scope=function)
// @relation(AC-COMP-SVR-EVENT-AUTHORIZATION-HEAD-03-TERMINAL-ONCE, scope=function)
// @verifies AC-SVR-AUTHZ-007-EVENT-SOURCE-HALF
// @verifies AC-SVR-AUTHZ-016-CONDITION-REFRESH-REAUTHORIZES
// @verifies AC-SVR-AUTHZ-023-EVENT-DENIAL-IS-PER-RECIPIENT
TEST_F(MonitoredItemAccessControlTest, EventDeliveryIsDeniedPerRecipientAndLaterEventsRemainOrdered)
{
  enable_test_role_on_namespace(0);
  auto deferred = ua::test::DeferredNamespace::create("urn:test:event-recipient", mExecutor);
  const auto deferredIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId notifierId{deferredIndex, 3100};
  const NodeId restrictedSourceId{deferredIndex, 3101};
  const NodeId sharedSourceId{deferredIndex, 3102};
  const NodeId restrictedEventTypeId{deferredIndex, 3103};
  const NodeId sharedEventTypeId{deferredIndex, 3104};
  auto notifier = mAddressSpace->try_create_sync<ObjectAccessor>(notifierId, NodeClass::Object).value();
  notifier.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto restrictedSource =
    mAddressSpace->try_create_sync<ObjectAccessor>(restrictedSourceId, NodeClass::Object).value();
  auto sharedSource =
    mAddressSpace->try_create_sync<ObjectAccessor>(sharedSourceId, NodeClass::Object).value();
  restrictedSource.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  sharedSource.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto restrictedEventType =
    mAddressSpace->try_create_node_sync(restrictedEventTypeId, NodeClass::ObjectType).value();
  restrictedEventType.set_browse_name(QualifiedName{deferredIndex, String{"RestrictedEventType"}});
  restrictedEventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);
  auto sharedEventType =
    mAddressSpace->try_create_node_sync(sharedEventTypeId, NodeClass::ObjectType).value();
  sharedEventType.set_browse_name(QualifiedName{deferredIndex, String{"SharedEventType"}});
  sharedEventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);
  notifier.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, restrictedSourceId, true);
  restrictedSource.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, notifierId, false);
  notifier.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, sharedSourceId, true);
  sharedSource.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, notifierId, false);

  const AccessIdentityKey firstIdentity{201};
  const AccessIdentityKey secondIdentity{202};
  for (const auto identity : {firstIdentity, secondIdentity})
  {
    deferred->grant(identity, notifierId, ua::test_helpers::all_permissions());
    deferred->grant(identity, sharedSourceId, ua::test_helpers::all_permissions());
    deferred->grant(identity, sharedEventTypeId, ua::test_helpers::all_permissions());
  }
  deferred->grant(firstIdentity, restrictedSourceId, ua::test_helpers::all_permissions());
  deferred->deny(secondIdentity, restrictedSourceId);
  deferred->grant(firstIdentity, restrictedEventTypeId, ua::test_helpers::all_permissions());
  deferred->deny(secondIdentity, restrictedEventTypeId);

  auto firstSecurity = std::make_shared<FakeSessionSecurityContext>(true, true, firstIdentity.value());
  auto secondSecurity = std::make_shared<FakeSessionSecurityContext>(true, true, secondIdentity.value());
  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t firstReadyCount = 0;
  size_t secondReadyCount = 0;
  auto makeReady = [&](size_t& count)
  {
    return [&](IntegerId)
    {
      std::lock_guard lock(readyMutex);
      ++count;
      readyCondition.notify_all();
    };
  };
  auto first = Subscription::create(
    1, 1000, 100, 3, 0, true, 0, mExecutor, makeReady(firstReadyCount), [](IntegerId) {});
  auto second = Subscription::create(
    2, 1000, 100, 3, 0, true, 0, mExecutor, makeReady(secondReadyCount), [](IntegerId) {});
  auto secondLog = std::make_shared<EventAuthorizationLogSink>();
  second->set_logger(
    Logger{secondLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "recipient-test"});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto firstResults = create_items(first, make_event_request(1, notifierId, 81), firstSecurity, eventBus);
  auto secondResults = create_items(second, make_event_request(2, notifierId, 82), secondSecurity, eventBus);
  ASSERT_EQ(firstResults.size(), 1u);
  ASSERT_EQ(secondResults.size(), 1u);
  first->configure_access_recheck(0ms, firstSecurity, mAddressSpace->weak(), eventBus);
  second->configure_access_recheck(0ms, secondSecurity, mAddressSpace->weak(), eventBus);
  first->set_publish_req_queued_async(true);
  second->set_publish_req_queued_async(true);
  STA::on_strand(*first, [](auto&) {});
  STA::on_strand(*second, [](auto&) {});
  std::promise<Result<bool>> firstRegistrationPromise;
  auto firstRegistration = firstRegistrationPromise.get_future();
  eventBus->has_event_items_async(1,
    [&firstRegistrationPromise](Result<bool> result)
    { firstRegistrationPromise.set_value(std::move(result)); });
  ASSERT_TRUE(firstRegistration.get().value());
  std::promise<Result<bool>> secondRegistrationPromise;
  auto secondRegistration = secondRegistrationPromise.get_future();
  eventBus->has_event_items_async(2,
    [&secondRegistrationPromise](Result<bool> result)
    { secondRegistrationPromise.set_value(std::move(result)); });
  ASSERT_TRUE(secondRegistration.get().value());

  BaseEvent restrictedEvent;
  restrictedEvent.eventType = sharedEventTypeId;
  restrictedEvent.sourceNode = restrictedSourceId;
  restrictedEvent.sourceName = String{"RestrictedSource"};
  restrictedEvent.message = LocalizedText{LocaleId{}, String{"first"}};
  eventBus->emit(restrictedEvent);
  BaseEvent restrictedTypeEvent;
  restrictedTypeEvent.eventType = restrictedEventTypeId;
  restrictedTypeEvent.sourceNode = sharedSourceId;
  restrictedTypeEvent.sourceName = String{"SharedSourceRestrictedType"};
  restrictedTypeEvent.message = LocalizedText{LocaleId{}, String{"second"}};
  eventBus->emit_to_subscription(1, restrictedTypeEvent);
  eventBus->emit_to_subscription(2, restrictedTypeEvent);
  BaseEvent sharedEvent;
  sharedEvent.eventType = sharedEventTypeId;
  sharedEvent.sourceNode = sharedSourceId;
  sharedEvent.sourceName = String{"SharedSource"};
  sharedEvent.message = LocalizedText{LocaleId{}, String{"third"}};
  eventBus->emit(sharedEvent);

  {
    std::unique_lock lock(readyMutex);
    ASSERT_TRUE(
      readyCondition.wait_for(lock, 3s, [&] { return firstReadyCount >= 3 && secondReadyCount >= 1; }));
  }
  STA::on_strand(*first,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(firstResults[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 3u);
    });
  STA::on_strand(*second,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(secondResults[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 1u);
    });
  // The two Events withheld from the second recipient are Role denials - the authorization doing its job,
  // once per Event per Subscription - so they are recorded at Debug and never raise a warning.
  EXPECT_TRUE(secondLog->contains_at("Event withheld by access control", "RoleNotGranted", LogLevel::Debug));
  EXPECT_EQ(secondLog->warnings_and_errors(), "") << "a Role denial is not a failure";

  first.reset();
  second.reset();
  eventBus.reset();
  deferred->wait_idle();
}

// @relation(AC-SVR-AUTHZ-007-A-NULL-SOURCENODE-IS-DECIDED-ON-THE-SERVER-OBJECT, scope=function)
TEST_F(MonitoredItemAccessControlTest, ANullSourceNodeIsDecidedOnTheServerObject)
{
  // Namespace 0 grants everything to the test Role and nothing to an identity without it, so the Server
  // Object decides ReceiveEvents per identity; the deferred namespace grants both identities the EventType
  // and the notifier by identity key, so only the Server Object differs between them.
  enable_test_role_on_namespace(0);
  auto server = mAddressSpace->try_create_sync<ObjectAccessor>(NodeId{ObjectId::Server}, NodeClass::Object);
  ASSERT_TRUE(server.is_good());
  auto baseEventType = mAddressSpace->find_node_sync(NodeId{ObjectTypeId::BaseEventType});
  auto sourceField =
    mAddressSpace->try_create_node_sync(NodeId{mNsIndex, 1004u}, NodeClass::Variable).value();
  const QualifiedName sourceNodeName{0, String{"SourceNode"}};
  sourceField.set_browse_name(sourceNodeName);
  baseEventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, sourceField.get_node_id(), true);

  auto deferred = ua::test::DeferredNamespace::create("urn:test:null-source", mExecutor);
  const auto deferredIndex = mAddressSpace->add_namespace_sync(deferred);
  const NodeId notifierId{deferredIndex, 3300};
  const NodeId eventTypeId{deferredIndex, 3301};
  auto notifier = mAddressSpace->try_create_sync<ObjectAccessor>(notifierId, NodeClass::Object).value();
  notifier.set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto eventType = mAddressSpace->try_create_node_sync(eventTypeId, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{deferredIndex, String{"NullSourceEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  auto permitted = std::make_shared<FakeSessionSecurityContext>(true, true, 301);
  auto withoutServer = std::make_shared<FakeSessionSecurityContext>(false, true, 302);
  for (const auto& security : {permitted, withoutServer})
  {
    deferred->grant(security->access_identity()->key(), notifierId, ua::test_helpers::all_permissions());
    deferred->grant(security->access_identity()->key(), eventTypeId, ua::test_helpers::all_permissions());
  }

  EventFilter filter;
  filter.select_clauses().push_back(
    make_event_field_operand(NodeId{ObjectTypeId::BaseEventType}, QualifiedName{0, String{"Message"}}));
  filter.select_clauses().push_back(
    make_event_field_operand(NodeId{ObjectTypeId::BaseEventType}, sourceNodeName));
  const auto expectNullSourceNode = [](const EventFieldList& fields)
  {
    ASSERT_EQ(fields.event_fields().size(), 2u);
    const auto& sourceNode = fields.event_fields()[1];
    const auto* nodeId = sourceNode.try_as<NodeId>();
    EXPECT_TRUE(sourceNode.empty() || (nodeId != nullptr && nodeId->is_null()))
      << "the delivered SourceNode field is not null";
  };

  // First delivery: the Event with a null SourceNode, then a control Event from the notifier that both
  // identities receive, so each Subscription has finished with the first when the second arrives.
  std::mutex readyMutex;
  std::condition_variable readyCondition;
  size_t permittedReady = 0;
  size_t withoutServerReady = 0;
  auto makeReady = [&](size_t& count)
  {
    return [&](IntegerId)
    {
      std::lock_guard lock(readyMutex);
      ++count;
      readyCondition.notify_all();
    };
  };
  auto first =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, makeReady(permittedReady), [](IntegerId) {});
  auto second = Subscription::create(
    2, 1000, 100, 3, 0, true, 0, mExecutor, makeReady(withoutServerReady), [](IntegerId) {});
  auto firstLog = std::make_shared<EventAuthorizationLogSink>();
  auto secondLog = std::make_shared<EventAuthorizationLogSink>();
  first->set_logger(
    Logger{firstLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "null-source"});
  second->set_logger(
    Logger{secondLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "null-source"});
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto firstResults = create_items(first, make_event_request(1, notifierId, 91, filter), permitted, eventBus);
  auto secondResults =
    create_items(second, make_event_request(2, notifierId, 92, filter), withoutServer, eventBus);
  ASSERT_EQ(firstResults.size(), 1u);
  ASSERT_EQ(secondResults.size(), 1u);
  ASSERT_TRUE(firstResults[0].status_code().is_good());
  ASSERT_TRUE(secondResults[0].status_code().is_good());
  first->configure_access_recheck(0ms, permitted, mAddressSpace->weak(), eventBus);
  second->configure_access_recheck(0ms, withoutServer, mAddressSpace->weak(), eventBus);
  first->set_publish_req_queued_async(true);
  second->set_publish_req_queued_async(true);

  BaseEvent nullSource;
  nullSource.eventType = eventTypeId;
  nullSource.sourceName = String{"NotSpecificToANode"};
  nullSource.message = LocalizedText{LocaleId{}, String{"null source"}};
  BaseEvent control;
  control.eventType = eventTypeId;
  control.sourceNode = notifierId;
  control.sourceName = String{"Notifier"};
  control.message = LocalizedText{LocaleId{}, String{"control"}};
  for (const IntegerId subscriptionId : {IntegerId{1}, IntegerId{2}})
  {
    eventBus->emit_to_subscription(subscriptionId, nullSource);
    eventBus->emit_to_subscription(subscriptionId, control);
  }
  {
    std::unique_lock lock(readyMutex);
    EXPECT_TRUE(
      readyCondition.wait_for(lock, 3s, [&] { return permittedReady >= 2 && withoutServerReady >= 1; }))
      << "permitted=" << permittedReady << " withoutServer=" << withoutServerReady;
  }
  STA::on_strand(*first,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(firstResults[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->eventQueue.size(), 2u) << "the Event with a null SourceNode was withheld";
      expectNullSourceNode(item->eventQueue.front().fields);
    });
  STA::on_strand(*second,
    [&](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(secondResults[0].monitored_item_id());
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueue.size(), 1u)
        << "only the control Event reaches an identity denied on the Server Object";
    });
  EXPECT_FALSE(firstLog->contains_detail("EventAuthorizationSubjectUnavailable"));
  EXPECT_FALSE(secondLog->contains_detail("EventAuthorizationSubjectUnavailable"));

  // Republish: the retained message that carried the Event, re-authorized for each identity.
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  std::shared_ptr<const CompiledEventFilter> retainedFilter{std::move(compiled.filter)};
  event_type_model::Declarations declarations;
  declarations.push_back(event_type_model::Declaration{.browsePath = {QualifiedName{0, String{"Message"}}},
    .nodeId = NodeId{mNsIndex, 1003u},
    .accessor = std::nullopt,
    .nodeClass = NodeClass::Variable});
  declarations.push_back(event_type_model::Declaration{.browsePath = {sourceNodeName},
    .nodeId = sourceField.get_node_id(),
    .accessor = std::nullopt,
    .nodeClass = NodeClass::Variable});
  auto declarationModel =
    std::make_shared<const event_type_model::DeclarationsResult>(std::move(declarations));
  auto rawEvent = std::make_shared<GenericEvent>(eventTypeId);
  rawEvent->sourceName = String{"NotSpecificToANode"};
  rawEvent->message = LocalizedText{LocaleId{}, String{"null source"}};

  const auto republish = [&](const std::shared_ptr<FakeSessionSecurityContext>& security)
  {
    auto subscription = create_subscription();
    subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
    NotificationMessage message;
    message.sequence_number() = 91;
    message.publish_time() = DateTime::now();
    auto events = std::make_unique<EventNotificationList>();
    events->events().push_back(event_notification(22, Variant{String{"published view"}}));
    append_notification(message, std::move(events));
    std::vector<RetainedEventProjection> projections{
      RetainedEventProjection{22, NodeId{}, eventTypeId, rawEvent, declarationModel, retainedFilter}};
    std::promise<Result<NotificationMessage>> completionPromise;
    auto completion = completionPromise.get_future();
    subscription->reauthorize_notification_async(std::move(message),
      std::move(projections),
      {},
      [&completionPromise](Result<NotificationMessage> result)
      { completionPromise.set_value(std::move(result)); });
    EXPECT_EQ(completion.wait_for(3s), std::future_status::ready);
    auto result = completion.get();
    std::vector<EventFieldList> republished;
    if (result.is_good())
    {
      for (const auto& notification : result.value().notification_data())
      {
        if (const auto* list = dynamic_cast<const EventNotificationList*>(notification.get()))
          republished.insert(republished.end(), list->events().begin(), list->events().end());
      }
    }
    else
    {
      ADD_FAILURE() << "Republish failed: " << to_string(result.status_code());
    }
    return republished;
  };
  const auto withPermission = republish(permitted);
  ASSERT_EQ(withPermission.size(), 1u) << "the Republish dropped the Event its identity may receive";
  EXPECT_EQ(withPermission[0].client_handle(), 22u);
  expectNullSourceNode(withPermission[0]);
  EXPECT_TRUE(republish(withoutServer).empty()) << "the Republish kept an Event the Server Object denies";

  first.reset();
  second.reset();
  eventBus.reset();
  deferred->wait_idle();
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-01-RAW-ALIGNMENT, scope=function)
// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-02-COMPLETE-CURRENT-VIEW, scope=function)
// @relation(AC-SVR-AUTHZ-016-REPUBLISH-REPROJECTS-RAW-SIDECAR, scope=function)
// @verifies AC-SVR-AUTHZ-016-REPUBLISH-REPROJECTS-RAW-SIDECAR
TEST_F(MonitoredItemAccessControlTest, RepublishReprojectsRawSidecarsForTheReceivingIdentity)
{
  auto controlledNamespace =
    ua::test::DeferredNamespace::create("urn:test:republish-current-view", mExecutor);
  const auto nodes = create_controlled_event_nodes(controlledNamespace, 5000);
  const NodeId firstDataNode{nodes.namespaceIndex, 4998u};
  const NodeId secondDataNode{nodes.namespaceIndex, 4999u};
  (void)mAddressSpace->try_create_node_sync(firstDataNode, NodeClass::Variable).value();
  (void)mAddressSpace->try_create_node_sync(secondDataNode, NodeClass::Variable).value();

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 700);
  const auto oldIdentity = security->access_identity()->key();
  security->set_roles({ua::test_helpers::test_access_role_id()});
  const auto receivingIdentity = security->access_identity()->key();
  ASSERT_NE(oldIdentity, receivingIdentity);

  auto permitted = ua::test_helpers::all_permissions();
  auto readDenied = permitted;
  readDenied.reset(PermissionType::Bit::Read);
  controlledNamespace->set_async_permissions(receivingIdentity, firstDataNode, permitted);
  controlledNamespace->set_async_permissions(receivingIdentity, secondDataNode, readDenied);
  controlledNamespace->set_async_permissions(receivingIdentity, nodes.source, permitted);
  controlledNamespace->set_async_permissions(receivingIdentity, nodes.eventType, permitted);
  controlledNamespace->set_async_permissions(receivingIdentity, nodes.selectedField, readDenied);
  controlledNamespace->set_async_permissions(receivingIdentity, nodes.whereField, permitted);
  controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  auto subscription = create_subscription();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});

  auto compiled = CompiledEventFilter::compile(
    make_controlled_event_filter(nodes.eventType, nodes.selectedBrowseName, nodes.whereBrowseName));
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<const CompiledEventFilter> retainedFilter{std::move(compiled.filter)};

  event_type_model::Declarations declarations;
  declarations.push_back(event_type_model::Declaration{.browsePath = {nodes.selectedBrowseName},
    .nodeId = nodes.selectedField,
    .accessor = std::nullopt,
    .nodeClass = NodeClass::Variable});
  declarations.push_back(event_type_model::Declaration{.browsePath = {nodes.whereBrowseName},
    .nodeId = nodes.whereField,
    .accessor = std::nullopt,
    .nodeClass = NodeClass::Variable});
  auto declarationModel =
    std::make_shared<const event_type_model::DeclarationsResult>(std::move(declarations));
  auto rawEvent = std::make_shared<GenericEvent>(make_controlled_event(nodes, "retained selected", "match"));

  NotificationMessage message;
  message.sequence_number() = 81;
  message.publish_time() = DateTime::now();
  auto firstData = std::make_unique<DataChangeNotification>();
  firstData->monitored_items().push_back(data_notification(11, 911));
  append_notification(message, std::move(firstData));
  auto events = std::make_unique<EventNotificationList>();
  events->events().push_back(event_notification(22, Variant{String{"old selected view"}}));
  append_notification(message, std::move(events));
  auto secondData = std::make_unique<DataChangeNotification>();
  secondData->monitored_items().push_back(data_notification(33, 922));
  append_notification(message, std::move(secondData));

  std::vector<RetainedDataProjection> dataProjections{
    RetainedDataProjection{1, firstDataNode, AttributeId::Value, int32_value(111)},
    RetainedDataProjection{2, secondDataNode, AttributeId::Value, int32_value(222)}};
  std::vector<RetainedEventProjection> eventProjections{RetainedEventProjection{
    22, nodes.source, nodes.eventType, rawEvent, declarationModel, std::move(retainedFilter)}};

  std::promise<Result<NotificationMessage>> completionPromise;
  auto completion = completionPromise.get_future();
  subscription->reauthorize_notification_async(std::move(message),
    std::move(eventProjections),
    std::move(dataProjections),
    [&completionPromise](Result<NotificationMessage> result)
    { completionPromise.set_value(std::move(result)); });

  ASSERT_TRUE(controlledNamespace->wait_for_pending_resolutions())
    << "Republish did not reach the non-caching namespace";
  EXPECT_EQ(completion.wait_for(50ms), std::future_status::timeout)
    << "Republish completed before the receiving identity's full permission view";
  const auto calls = controlledNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  EXPECT_EQ(calls[0].identity, receivingIdentity);
  ASSERT_TRUE(calls[0].nodes.has_value());
  const std::array expectedSubjects{
    firstDataNode, secondDataNode, nodes.source, nodes.eventType, nodes.selectedField, nodes.whereField};
  EXPECT_EQ(calls[0].nodes->size(), expectedSubjects.size());
  for (const auto& expected : expectedSubjects)
  {
    EXPECT_NE(std::ranges::find(*calls[0].nodes, expected), calls[0].nodes->end());
  }
  const auto questionsAtBarrier = controlledNamespace->permission_questions();

  controlledNamespace->complete_pending_resolutions();
  auto result = completion.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  auto projected = std::move(result).value();
  EXPECT_EQ(projected.sequence_number(), 81u);
  ASSERT_EQ(projected.notification_data().size(), 3u);

  auto* projectedFirstData = dynamic_cast<DataChangeNotification*>(projected.notification_data()[0].get());
  auto* projectedEvents = dynamic_cast<EventNotificationList*>(projected.notification_data()[1].get());
  auto* projectedSecondData = dynamic_cast<DataChangeNotification*>(projected.notification_data()[2].get());
  ASSERT_NE(projectedFirstData, nullptr);
  ASSERT_NE(projectedEvents, nullptr);
  ASSERT_NE(projectedSecondData, nullptr);
  ASSERT_EQ(projectedFirstData->monitored_items().size(), 1u);
  EXPECT_EQ(projectedFirstData->monitored_items()[0].client_handle(), 11u);
  EXPECT_EQ(projectedFirstData->monitored_items()[0].value().value(), Variant{int32_t{111}})
    << "Republish substituted the old client view or a live Value for the retained raw input";
  ASSERT_EQ(projectedSecondData->monitored_items().size(), 1u);
  EXPECT_EQ(projectedSecondData->monitored_items()[0].client_handle(), 33u);
  ASSERT_TRUE(projectedSecondData->monitored_items()[0].value().status().has_value());
  EXPECT_EQ(
    projectedSecondData->monitored_items()[0].value().status()->as_status(), Status::BadUserAccessDenied);
  EXPECT_TRUE(projectedSecondData->monitored_items()[0].value().value().empty());

  ASSERT_EQ(projectedEvents->events().size(), 1u);
  EXPECT_EQ(projectedEvents->events()[0].client_handle(), 22u);
  ASSERT_EQ(projectedEvents->events()[0].event_fields().size(), 1u);
  ASSERT_TRUE(projectedEvents->events()[0].event_fields()[0].is_status_code());
  EXPECT_EQ(
    projectedEvents->events()[0].event_fields()[0].as<StatusCode>().as_status(), Status::BadUserAccessDenied);
  EXPECT_EQ(controlledNamespace->permission_questions(), questionsAtBarrier)
    << "Event evaluation or projection re-asked the non-caching namespace";
  EXPECT_EQ(controlledNamespace->effective_permissions_calls().size(), 1u);
  controlledNamespace->wait_idle();
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-02-MISSING-INPUT, scope=function)
// @relation(AC-SVR-AUTHZ-016-MISSING-RAW-SIDECAR-REDACTS, scope=function)
// @verifies AC-SVR-AUTHZ-016-MISSING-RAW-SIDECAR-REDACTS
TEST_F(MonitoredItemAccessControlTest, MissingRepublishProjectionSidecarFailsClosedAndPreservesOrder)
{
  const NodeId eventSource = create_event_source(5100);
  const NodeId eventType{mNsIndex, 5101u};
  const NodeId selectedField{mNsIndex, 5102u};
  const QualifiedName selectedBrowseName{mNsIndex, String{"ReplaySelected"}};
  auto eventTypeNode = mAddressSpace->try_create_node_sync(eventType, NodeClass::ObjectType).value();
  eventTypeNode.set_browse_name(QualifiedName{mNsIndex, String{"ReplayEventType"}});
  eventTypeNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);
  auto selectedNode = mAddressSpace->try_create_node_sync(selectedField, NodeClass::Variable).value();
  selectedNode.set_browse_name(selectedBrowseName);
  eventTypeNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, selectedField, true);

  EventFilter filter;
  filter.select_clauses().push_back(make_event_field_operand(eventType, selectedBrowseName));
  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<const CompiledEventFilter> retainedFilter{std::move(compiled.filter)};

  event_type_model::Declarations declarations;
  declarations.push_back(event_type_model::Declaration{.browsePath = {selectedBrowseName},
    .nodeId = selectedField,
    .accessor = std::nullopt,
    .nodeClass = NodeClass::Variable});
  auto declarationModel =
    std::make_shared<const event_type_model::DeclarationsResult>(std::move(declarations));
  const auto rawEvent = [&](std::string_view selected)
  {
    auto event = std::make_shared<GenericEvent>(eventType);
    event->sourceNode = eventSource;
    event->sourceName = String{"ReplaySource"};
    event->eventId = ByteString{0x51};
    event->time = DateTime::now();
    event->receiveTime = event->time;
    event->set_field({selectedBrowseName}, Variant{String{selected}});
    return event;
  };

  NotificationMessage message;
  message.sequence_number() = 82;
  message.publish_time() = DateTime::now();
  auto data = std::make_unique<DataChangeNotification>();
  data->monitored_items().push_back(data_notification(41, 941));
  data->monitored_items().push_back(data_notification(42, 942));
  data->monitored_items().push_back(data_notification(43, 943));
  append_notification(message, std::move(data));
  auto events = std::make_unique<EventNotificationList>();
  events->events().push_back(event_notification(51, Variant{String{"old control"}}));
  events->events().push_back(event_notification(52, Variant{String{"old missing model"}}));
  events->events().push_back(event_notification(53, Variant{String{"old missing sidecar"}}));
  append_notification(message, std::move(events));

  std::vector<RetainedDataProjection> dataProjections{
    RetainedDataProjection{1, NodeId{mNsIndex, 1000u}, AttributeId::Value, int32_value(141)},
    RetainedDataProjection{2, NodeId{mNsIndex, 1001u}, AttributeId::Value, std::nullopt}};
  std::vector<RetainedEventProjection> eventProjections{
    RetainedEventProjection{
      51, eventSource, eventType, rawEvent("retained control"), declarationModel, retainedFilter},
    RetainedEventProjection{
      52, eventSource, eventType, rawEvent("retained missing model"), {}, retainedFilter}};

  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 800);
  auto subscription = create_subscription();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
  std::promise<Result<NotificationMessage>> completionPromise;
  auto completion = completionPromise.get_future();
  subscription->reauthorize_notification_async(std::move(message),
    std::move(eventProjections),
    std::move(dataProjections),
    [&completionPromise](Result<NotificationMessage> result)
    { completionPromise.set_value(std::move(result)); });

  auto result = completion.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  auto projected = std::move(result).value();
  EXPECT_EQ(projected.sequence_number(), 82u);
  ASSERT_EQ(projected.notification_data().size(), 2u);
  auto* projectedData = dynamic_cast<DataChangeNotification*>(projected.notification_data()[0].get());
  auto* projectedEvents = dynamic_cast<EventNotificationList*>(projected.notification_data()[1].get());
  ASSERT_NE(projectedData, nullptr);
  ASSERT_NE(projectedEvents, nullptr);
  ASSERT_EQ(projectedData->monitored_items().size(), 3u);
  EXPECT_EQ(projectedData->monitored_items()[0].client_handle(), 41u);
  EXPECT_EQ(projectedData->monitored_items()[0].value().value(), Variant{int32_t{141}});
  for (size_t index = 1; index < projectedData->monitored_items().size(); ++index)
  {
    const auto& denied = projectedData->monitored_items()[index].value();
    EXPECT_EQ(projectedData->monitored_items()[index].client_handle(), 41u + index);
    ASSERT_TRUE(denied.status().has_value());
    EXPECT_EQ(denied.status()->as_status(), Status::BadUserAccessDenied);
    EXPECT_TRUE(denied.value().empty());
    ASSERT_NE(denied.status()->shared_detail(), nullptr);
  }
  EXPECT_EQ(
    projectedData->monitored_items()[1].value().status()->shared_detail()->code, "RetainedDataInputMissing");
  EXPECT_EQ(projectedData->monitored_items()[2].value().status()->shared_detail()->code,
    "RetainedDataProjectionMissing");

  ASSERT_EQ(projectedEvents->events().size(), 2u)
    << "only the Event lacking its whole projection sidecar should be removed";
  EXPECT_EQ(projectedEvents->events()[0].client_handle(), 51u);
  ASSERT_EQ(projectedEvents->events()[0].event_fields().size(), 1u);
  EXPECT_EQ(projectedEvents->events()[0].event_fields()[0], Variant{String{"retained control"}});
  EXPECT_EQ(projectedEvents->events()[1].client_handle(), 52u);
  ASSERT_EQ(projectedEvents->events()[1].event_fields().size(), 1u);
  ASSERT_TRUE(projectedEvents->events()[1].event_fields()[0].is_status_code());
  const auto missingDeclaration = projectedEvents->events()[1].event_fields()[0].as<StatusCode>();
  EXPECT_EQ(missingDeclaration.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(missingDeclaration.shared_detail(), nullptr);
  EXPECT_EQ(missingDeclaration.shared_detail()->code, "EventFieldDeclarationModelUnavailable");
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-02-MISSING-INPUT, scope=function)
TEST_F(MonitoredItemAccessControlTest, RepublishUnavailableContextAndDeletedSubjectFailClosedRichly)
{
  const auto makeMessage = []
  {
    NotificationMessage message;
    message.sequence_number() = 83;
    auto data = std::make_unique<DataChangeNotification>();
    data->monitored_items().push_back(data_notification(61, 961));
    append_notification(message, std::move(data));
    return message;
  };
  const auto deniedValue = [](Result<NotificationMessage> result) -> DataValue
  {
    if (result.is_bad() || result.value().notification_data().empty())
      return DataValue{result.status_code()};
    const auto* data =
      dynamic_cast<const DataChangeNotification*>(result.value().notification_data()[0].get());
    if (!data || data->monitored_items().empty())
      return DataValue{StatusCode{Status::BadUnexpectedError}};
    return data->monitored_items()[0].value();
  };

  {
    auto subscription = create_subscription();
    std::atomic<size_t> callbackCount{0};
    std::promise<Result<NotificationMessage>> promise;
    auto completion = promise.get_future();
    subscription->reauthorize_notification_async(makeMessage(),
      {},
      {RetainedDataProjection{1, NodeId{mNsIndex, 1000u}, AttributeId::Value, int32_value(171)}},
      [&callbackCount, &promise](Result<NotificationMessage> result)
      {
        if (callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
          promise.set_value(std::move(result));
      });

    const auto denied = deniedValue(completion.get());
    ASSERT_TRUE(denied.status().has_value());
    EXPECT_EQ(denied.status()->as_status(), Status::BadUserAccessDenied);
    ASSERT_NE(denied.status()->shared_detail(), nullptr);
    EXPECT_EQ(denied.status()->shared_detail()->code, "RepublishAuthorizationContextUnavailable");
    STA::on_strand(*subscription, [](auto&) {});
    EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  }

  auto deferredNamespace = ua::test::DeferredNamespace::create("urn:test:republish-deleted", mExecutor);
  const auto namespaceIndex = mAddressSpace->add_namespace_sync(deferredNamespace);
  const NodeId subject{namespaceIndex, 5500u};
  (void)mAddressSpace->try_create_node_sync(subject, NodeClass::Variable).value();
  auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 930);
  deferredNamespace->set_async_permissions(
    security->access_identity()->key(), subject, ua::test_helpers::all_permissions());
  deferredNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  auto subscription = create_subscription();
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
  std::atomic<size_t> callbackCount{0};
  std::promise<Result<NotificationMessage>> promise;
  auto completion = promise.get_future();
  subscription->reauthorize_notification_async(makeMessage(),
    {},
    {RetainedDataProjection{1, subject, AttributeId::Value, int32_value(172)}},
    [&callbackCount, &promise](Result<NotificationMessage> result)
    {
      if (callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
        promise.set_value(std::move(result));
    });

  ASSERT_TRUE(deferredNamespace->wait_for_pending_resolutions());
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(subject, false).is_good());
  deferredNamespace->complete_pending_resolutions();
  const auto denied = deniedValue(completion.get());
  ASSERT_TRUE(denied.status().has_value());
  EXPECT_EQ(denied.status()->as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(denied.status()->shared_detail(), nullptr);
  EXPECT_EQ(denied.status()->shared_detail()->code, "RetainedDataReadDenied");
  EXPECT_EQ(StatusCode{denied.status()->shared_detail()->innerStatus}, Status::BadNodeIdUnknown);
  ASSERT_NE(denied.status()->shared_detail()->cause, nullptr);
  STA::on_strand(*subscription, [](auto&) {});
  EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  deferredNamespace->wait_idle();
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-02-CALLBACK-ONCE, scope=function)
TEST_F(MonitoredItemAccessControlTest, RepublishProjectionCompletesExactlyOnceAcrossFailureAndClose)
{
  const auto startProjection = [](const std::shared_ptr<Subscription>& subscription,
                                 const NodeId& subject,
                                 std::atomic<size_t>& callbackCount,
                                 std::promise<Result<NotificationMessage>>& completionPromise)
  {
    NotificationMessage message;
    message.sequence_number() = 83;
    auto data = std::make_unique<DataChangeNotification>();
    data->monitored_items().push_back(data_notification(61, 961));
    append_notification(message, std::move(data));
    std::vector<RetainedDataProjection> sidecars{
      RetainedDataProjection{1, subject, AttributeId::Value, int32_value(161)}};
    subscription->reauthorize_notification_async(std::move(message),
      {},
      std::move(sidecars),
      [&callbackCount, &completionPromise](Result<NotificationMessage> result)
      {
        if (callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
          completionPromise.set_value(std::move(result));
      });
  };

  {
    auto failingNamespace = ua::test::DeferredNamespace::create("urn:test:republish-failure", mExecutor);
    const auto namespaceIndex = mAddressSpace->add_namespace_sync(failingNamespace);
    const NodeId subject{namespaceIndex, 5200u};
    (void)mAddressSpace->try_create_node_sync(subject, NodeClass::Variable).value();
    failingNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Failing);
    auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 900);
    auto subscription =
      Subscription::create(91, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
    std::atomic<size_t> callbackCount{0};
    std::promise<Result<NotificationMessage>> promise;
    auto completion = promise.get_future();
    startProjection(subscription, subject, callbackCount, promise);
    auto result = completion.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    auto projected = std::move(result).value();
    auto* data = dynamic_cast<DataChangeNotification*>(projected.notification_data()[0].get());
    ASSERT_NE(data, nullptr);
    const auto& denied = data->monitored_items()[0].value();
    ASSERT_TRUE(denied.status().has_value());
    ASSERT_NE(denied.status()->shared_detail(), nullptr);
    EXPECT_EQ(denied.status()->shared_detail()->code, "RetainedDataReadDenied");
    ASSERT_NE(denied.status()->shared_detail()->cause, nullptr);
    const auto& resolutionFailure = denied.status()->shared_detail()->cause;
    EXPECT_EQ(resolutionFailure->code, "AuthorizationResolutionFailed");
    ASSERT_NE(resolutionFailure->cause, nullptr);
    EXPECT_EQ(resolutionFailure->cause->code, "DeferredNamespaceResolutionFailed");
    STA::on_strand(*subscription, [](auto&) {});
    EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  }

  {
    auto timeoutNamespace = ua::test::DeferredNamespace::create("urn:test:republish-timeout", mExecutor);
    const auto namespaceIndex = mAddressSpace->add_namespace_sync(timeoutNamespace);
    const NodeId subject{namespaceIndex, 5300u};
    (void)mAddressSpace->try_create_node_sync(subject, NodeClass::Variable).value();
    timeoutNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::NeverCompletes);
    auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 910);
    auto subscription =
      Subscription::create(92, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    subscription->set_access_control_timeout(20ms);
    subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
    std::atomic<size_t> callbackCount{0};
    std::promise<Result<NotificationMessage>> promise;
    auto completion = promise.get_future();
    startProjection(subscription, subject, callbackCount, promise);
    ASSERT_EQ(completion.wait_for(2s), std::future_status::ready)
      << "a namespace that never completes wedged Republish past its authorization deadline";
    auto result = completion.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    auto projected = std::move(result).value();
    auto* data = dynamic_cast<DataChangeNotification*>(projected.notification_data()[0].get());
    ASSERT_NE(data, nullptr);
    ASSERT_TRUE(data->monitored_items()[0].value().status().has_value());
    EXPECT_EQ(data->monitored_items()[0].value().status()->as_status(), Status::BadUserAccessDenied);
    STA::on_strand(*subscription, [](auto&) {});
    EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  }

  {
    auto duplicateNamespace = ua::test::DeferredNamespace::create("urn:test:republish-close", mExecutor);
    const auto namespaceIndex = mAddressSpace->add_namespace_sync(duplicateNamespace);
    const NodeId subject{namespaceIndex, 5400u};
    (void)mAddressSpace->try_create_node_sync(subject, NodeClass::Variable).value();
    auto security = std::make_shared<FakeSessionSecurityContext>(true, true, 920);
    duplicateNamespace->set_async_permissions(
      security->access_identity()->key(), subject, ua::test_helpers::all_permissions());
    duplicateNamespace->set_duplicate_completion(true);
    duplicateNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
    auto subscription =
      Subscription::create(93, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
    std::atomic<size_t> callbackCount{0};
    std::promise<Result<NotificationMessage>> promise;
    auto completion = promise.get_future();
    startProjection(subscription, subject, callbackCount, promise);
    ASSERT_TRUE(duplicateNamespace->wait_for_pending_resolutions());
    std::promise<void> closedPromise;
    auto closed = closedPromise.get_future();
    subscription->close_async([&closedPromise] { closedPromise.set_value(); });
    closed.get();
    duplicateNamespace->complete_pending_resolutions();
    auto result = completion.get();
    EXPECT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code().as_status(), Status::BadSubscriptionIdInvalid);
    duplicateNamespace->wait_idle();
    STA::on_strand(*subscription, [](auto&) {});
    EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u)
      << "duplicate collaborator completion escaped the replay flow's terminal guard";
  }
}

// A recheck cycle whose authorization decision is unchanged must be idempotent: it must not flip
// denied state or enqueue a spurious notification (which would otherwise churn the Publish stream).
TEST_F(MonitoredItemAccessControlTest, RecheckIsNoOpWhenPermissionUnchanged)
{
  using namespace std::chrono_literals;
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}});

  auto secCtx = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(sub, std::move(request), secCtx);
  ASSERT_EQ(results.size(), 1u);
  const auto miId = results[0].monitored_item_id();

  sub->configure_access_recheck(1h, secCtx, mAddressSpace->weak(), {});

  size_t queueBefore = 0;
  STA::on_strand(*sub, [&](auto& g) { queueBefore = g.find_monitored_item(miId)->queue.size(); });

  trigger_recheck(*sub);  // permission unchanged (still allowed)
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied());
      EXPECT_EQ(item->queue.size(), queueBefore) << "an unchanged permission must not enqueue anything";
    });
}

// @relation(AC-SVR-SESS-031-REEVALUATE-ON-IDENTITY-CHANGE, scope=function)
// @relation(AC-COMP-SVR-IDENTITY-REAUTH-01-EXHAUSTIVE, scope=function)
TEST_F(
  MonitoredItemAccessControlTest, IdentityChangeReauthorizesEveryItemAcrossEverySubscriptionAndRestoresAccess)
{
  auto first =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto second =
    Subscription::create(2, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto createSecurity = std::make_shared<FakeSessionSecurityContext>();

  auto firstResults = create_items(first,
    make_create_request(1, {{NodeId{mNsIndex, 1000}, 10}, {NodeId{mNsIndex, 1001}, 11}}),
    createSecurity);
  auto secondResults = create_items(second,
    make_create_request(2, {{NodeId{mNsIndex, 1001}, 20}, {NodeId{mNsIndex, 1002}, 21}}),
    createSecurity);
  ASSERT_EQ(firstResults.size(), 2u);
  ASSERT_EQ(secondResults.size(), 2u);
  first->configure_access_recheck(0ms, createSecurity, mAddressSpace->weak(), {});
  second->configure_access_recheck(0ms, createSecurity, mAddressSpace->weak(), {});
  STA::on_strand(*first, [](auto&) {});
  STA::on_strand(*second, [](auto&) {});

  SubscriptionIdAllocator idAllocator;
  auto pipeline = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = mExecutor,
    .sessionStrand = boost::asio::make_strand(mExecutor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = std::make_shared<ServerSummaryCounters>(),
    .capabilities = {},
    .subscriptionLimits = {},
    .sendResponse = [](Response) {},
    .addressSpace = mAddressSpace->weak(),
  });
  MTA::on_strand(*pipeline,
    [&](auto& manager)
    {
      manager.subscriptions().emplace(1, first);
      manager.subscriptions().emplace(2, second);
    });

  createSecurity->set_access_allowed(false);
  std::promise<VoidResult> deniedPromise;
  auto deniedFuture = deniedPromise.get_future();
  pipeline->reauthorize_all_async(
    [&deniedPromise](VoidResult result) { deniedPromise.set_value(std::move(result)); });
  auto deniedResult = deniedFuture.get();
  ASSERT_TRUE(deniedResult.is_good());

  auto assertDenied = [](Subscription& subscription, const auto& results)
  {
    STA::on_strand(subscription,
      [&](auto& guarded)
      {
        for (const auto& result : results)
        {
          auto* item = guarded.find_monitored_item(result.monitored_item_id());
          ASSERT_NE(item, nullptr);
          EXPECT_TRUE(item->access_denied());
          ASSERT_FALSE(item->queue.empty());
          EXPECT_EQ(item->queue.back().status(), StatusCode{Status::BadUserAccessDenied});
        }
      });
  };
  assertDenied(*first, firstResults);
  assertDenied(*second, secondResults);

  createSecurity->set_access_allowed(true);
  std::promise<VoidResult> allowedPromise;
  auto allowedFuture = allowedPromise.get_future();
  pipeline->reauthorize_all_async(
    [&allowedPromise](VoidResult result) { allowedPromise.set_value(std::move(result)); });
  auto allowedResult = allowedFuture.get();
  ASSERT_TRUE(allowedResult.is_good());

  auto assertAllowed = [](Subscription& subscription, const auto& results)
  {
    STA::on_strand(subscription,
      [&](auto& guarded)
      {
        for (const auto& result : results)
        {
          auto* item = guarded.find_monitored_item(result.monitored_item_id());
          ASSERT_NE(item, nullptr);
          EXPECT_FALSE(item->access_denied());
        }
      });
  };
  assertAllowed(*first, firstResults);
  assertAllowed(*second, secondResults);
}

// @relation(AC-COMP-SVR-IDENTITY-REAUTH-02-CALLBACK-ONCE, scope=function)
TEST_F(MonitoredItemAccessControlTest, IdentityChangeWithNoSubscriptionsCompletesOnceWithGood)
{
  SubscriptionIdAllocator idAllocator;
  auto pipeline = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = mExecutor,
    .sessionStrand = boost::asio::make_strand(mExecutor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = std::make_shared<ServerSummaryCounters>(),
    .capabilities = {},
    .subscriptionLimits = {},
    .sendResponse = [](Response) {},
    .addressSpace = mAddressSpace->weak(),
  });
  std::atomic<size_t> callbackCalls{0};
  std::promise<VoidResult> promise;
  auto future = promise.get_future();

  pipeline->reauthorize_all_async(
    [&callbackCalls, &promise](VoidResult result)
    {
      ++callbackCalls;
      promise.set_value(std::move(result));
    });

  EXPECT_TRUE(future.get().is_good());
  MTA::on_strand(*pipeline, [](auto&) {});
  EXPECT_EQ(callbackCalls.load(), 1u);
}

// @relation(AC-COMP-SVR-IDENTITY-REAUTH-03-RICH-DEPENDENCY-FAILURE, scope=function)
TEST_F(MonitoredItemAccessControlTest, IdentityChangeFailsWhenAccessIdentityIsUnavailable)
{
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto createSecurity = std::make_shared<FakeSessionSecurityContext>();
  auto createResults =
    create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 10}}), createSecurity);
  ASSERT_EQ(createResults.size(), 1u);
  const auto monitoredItemId = createResults.front().monitored_item_id();
  subscription->configure_access_recheck(0ms, createSecurity, mAddressSpace->weak(), {});
  STA::on_strand(*subscription, [](auto&) {});

  createSecurity->clear_access_identity();
  std::promise<VoidResult> promise;
  auto future = promise.get_future();

  subscription->reauthorize_all_async(
    [&promise](VoidResult result) { promise.set_value(std::move(result)); });

  auto result = future.get();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "AccessIdentityUnavailable");
  STA::on_strand(*subscription,
    [monitoredItemId](auto& guarded)
    {
      auto* item = guarded.find_monitored_item(monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->access_denied())
        << "a non-denial authorization failure must not be converted into an access transition";
    });
}

// @relation(AC-COMP-SVR-IDENTITY-REAUTH-03-RICH-DEPENDENCY-FAILURE, scope=function)
TEST_F(MonitoredItemAccessControlTest, IdentityChangePropagatesMandatoryWalkErrorDetail)
{
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto createResults =
    create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 10}}), security);
  ASSERT_EQ(createResults.size(), 1u);

  WeakAddressSpace expiredAddressSpace;
  {
    auto transientAddressSpace = AddressSpace::create("urn:test:expired", mExecutor);
    expiredAddressSpace = transientAddressSpace.weak();
  }
  subscription->configure_access_recheck(0ms, security, std::move(expiredAddressSpace), {});
  STA::on_strand(*subscription, [](auto&) {});

  SubscriptionIdAllocator idAllocator;
  auto pipeline = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = mExecutor,
    .sessionStrand = boost::asio::make_strand(mExecutor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = std::make_shared<ServerSummaryCounters>(),
    .capabilities = {},
    .subscriptionLimits = {},
    .sendResponse = [](Response) {},
    .addressSpace = mAddressSpace->weak(),
  });
  MTA::on_strand(*pipeline, [&](auto& manager) { manager.subscriptions().emplace(1, subscription); });
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  pipeline->reauthorize_all_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });

  auto result = future.get();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "AddressSpaceExpired");
}

// A sample whose source set no ServerTimestamp is stamped as it arrives, on the user-independent value that
// Republish and ResendData project again later, so all of them carry the one stamp. Stamping only the queued
// copy would give a resend a ServerTimestamp of its own.
TEST_F(MonitoredItemAccessControlTest, ASampleWithoutAServerTimestampIsStampedOnceForEveryLaterProjection)
{
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto createResults =
    create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 10}}), security);
  ASSERT_EQ(createResults.size(), 1u);
  const auto itemId = createResults[0].monitored_item_id();

  STA::on_strand(*subscription,
    [itemId](auto& guarded)
    {
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(itemId, DataValue{Variant{int32_t{4242}}, StatusCode{Status::Good}});
      guarded.on_samples_received(std::move(samples));

      auto* item = guarded.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      ASSERT_TRUE(item->lastUserIndependentValue.has_value());
      const auto& retained = item->lastUserIndependentValue->server_timestamp();
      ASSERT_TRUE(retained.has_value()) << "the retained sample carries the arrival stamp";
      ASSERT_FALSE(item->queue.empty());
      EXPECT_EQ(item->queue.back().server_timestamp(), retained)
        << "the queued projection carries the same stamp as the value it was projected from";
    });
}

// A transferred Subscription is re-authorized for its new Session through the same mandatory walk, so a
// failure of that walk reaches the transfer with its detail intact.
// @relation(AC-COMP-SVR-IDENTITY-REAUTH-03-RICH-DEPENDENCY-FAILURE, scope=function)
TEST_F(MonitoredItemAccessControlTest, TransferReauthorizationPropagatesMandatoryWalkErrorDetail)
{
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto createResults =
    create_items(subscription, make_create_request(1, {{NodeId{mNsIndex, 1000}, 10}}), security);
  ASSERT_EQ(createResults.size(), 1u);

  WeakAddressSpace expiredAddressSpace;
  {
    auto transientAddressSpace = AddressSpace::create("urn:test:expired", mExecutor);
    expiredAddressSpace = transientAddressSpace.weak();
  }
  subscription->configure_access_recheck(0ms, security, std::move(expiredAddressSpace), {});
  STA::on_strand(*subscription, [](auto&) {});

  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  subscription->reauthorize_after_transfer_async(
    [&promise](VoidResult result) { promise.set_value(std::move(result)); });

  auto result = future.get();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "AddressSpaceExpired");
}

// @relation(AC-COMP-SVR-IDENTITY-REAUTH-04-DESTROYED-IN-FLIGHT, scope=function)
TEST(MonitoredItemIdentityReauthorizationTest, DestroyedSubscriptionCompletesOnceWithoutDereference)
{
  boost::asio::io_context io;
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, io.get_executor(), [](IntegerId) {}, [](IntegerId) {});
  std::atomic<size_t> callbackCalls{0};
  std::optional<VoidResult> completionResult;

  subscription->reauthorize_all_async(
    [&callbackCalls, &completionResult](VoidResult result)
    {
      ++callbackCalls;
      completionResult.emplace(std::move(result));
    });
  subscription.reset();
  io.run();

  ASSERT_TRUE(completionResult.has_value());
  EXPECT_EQ(completionResult->status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  EXPECT_EQ(callbackCalls.load(), 1u);
}

// @relation(AC-COMP-SVR-IDENTITY-REAUTH-05-THROWING-COMPLETION, scope=function)
TEST(MonitoredItemIdentityReauthorizationTest, ThrowingCompletionIsConvertedAndNeverFiredTwice)
{
  boost::asio::io_context io;
  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, io.get_executor(), [](IntegerId) {}, [](IntegerId) {});
  std::atomic<size_t> callbackCalls{0};

  subscription->reauthorize_all_async(
    [&callbackCalls](VoidResult)
    {
      ++callbackCalls;
      throw std::runtime_error{"completion failure"};
    });
  EXPECT_NO_THROW(for (size_t turn = 0; turn < 32 && callbackCalls.load() == 0; ++turn) {
    if (io.poll_one() == 0)
      break;
  });
  EXPECT_EQ(callbackCalls.load(), 1u);
  subscription.reset();
  io.restart();
  EXPECT_NO_THROW(io.poll());
}

// ---------------------------------------------------------------------------
// The monitoring-mode change's own body: what it holds, and when it lets go
// ---------------------------------------------------------------------------

// Re-enabling an item asks the address space to resolve its subject and the access control to decide
// its permissions, and the body holds the identity it authorized against while it does. Once the
// change has answered, nothing in the subscription may still hold it: the item keeps the identity's
// KEY, not the identity, and the decision itself was consumed.
//
// This is the rule that says WHERE that state must live. A coroutine's by-value parameters are
// released when its frame is destroyed - which for a body the subscription holds in a member is
// whenever the slot is next cleared - while its LOCALS are released when the body ends, like any
// other scope. The identity is a local of the body that resolves and authorizes, so it goes at the
// end of that body; the client's id list is a parameter of the root task, so it is what the slot
// pins and what the release post exists for. Put the identity in the wrong one of those two and
// this expectation fails.
TEST_F(MonitoredItemAccessControlTest, AFinishedMonitoringModeChangeHoldsNoIdentityItAuthorizedAgainst)
{
  auto sub = create_subscription();
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(sub, make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}}), secCtx);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results[0].monitored_item_id();

  sub->configure_access_recheck(0ms, secCtx, mAddressSpace->weak(), std::weak_ptr<EventBus>{});
  STA::on_strand(*sub, [](auto&) {});

  std::weak_ptr<const AccessIdentity> identityLifetime = secCtx->access_identity();

  auto disabled = set_mode_blocking(sub, {monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  auto reenabled = set_mode_blocking(sub, {monitoredItemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  ASSERT_EQ(reenabled.front(), StatusCode{Status::Good})
    << "the re-enable must take the path that resolves and authorizes, or there is no identity to hold";

  // Everything that held the identity on purpose is now gone: the session context itself, and the
  // subscription's own handle on it, which is weak.
  secCtx.reset();
  STA::on_strand(*sub, [](auto&) {});

  EXPECT_TRUE(identityLifetime.expired())
    << "a finished monitoring-mode change still holds the identity it authorized against";
}

// The gate the access rechecks ask about is the change's own running flag, and a change that has
// answered is not running. What used to say so was a `shared_ptr` being reset at the one place the
// answer was fired from; a body that ends in more than one place has to say so in all of them.
TEST_F(MonitoredItemAccessControlTest, ASecondMonitoringModeChangeIsAcceptedOnceTheFirstHasFinished)
{
  auto sub = create_subscription();
  auto secCtx = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(sub, make_create_request(1, {{NodeId{mNsIndex, 1000}, 42}}), secCtx);
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  const IntegerId monitoredItemId = results[0].monitored_item_id();

  sub->configure_access_recheck(0ms, secCtx, mAddressSpace->weak(), std::weak_ptr<EventBus>{});
  STA::on_strand(*sub, [](auto&) {});

  auto disabled = set_mode_blocking(sub, {monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  // The one that suspends: re-enabling resolves the subject and waits for a permission decision.
  auto reenabled = set_mode_blocking(sub, {monitoredItemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  ASSERT_EQ(reenabled.front(), StatusCode{Status::Good});

  auto again = set_mode_blocking(sub, {monitoredItemId}, MonitoringMode::Sampling);
  ASSERT_EQ(again.size(), 1u);
  EXPECT_EQ(again.front(), StatusCode{Status::Good})
    << "the change after a suspending one was refused, so that one left the gate closed";
}

// A reauthorization walk holds the one answer it owes in a member of the pipeline, so the pipeline
// is what has to answer when it goes. The chain this replaces never needed saying: every hop carried
// the caller's completion through a completion-owning post, and a pipeline that went away answered
// BadSessionClosed on its way out of that post. A body that keeps its answer in a member has to say
// it itself, and a Session left waiting on a reauthorization it will never hear about is the failure
// that stops.
TEST_F(MonitoredItemAccessControlTest, APipelineThatGoesAwayAnswersTheReauthorizationItWasRunning)
{
  auto deferredNamespace = ua::test::DeferredNamespace::create("urn:test:pipeline-teardown", mExecutor);
  const uint16_t deferredIndex = mAddressSpace->add_namespace_sync(deferredNamespace);
  const NodeId subject{deferredIndex, 1u};
  ASSERT_TRUE(mAddressSpace->try_create_node_sync(subject, NodeClass::Variable).is_good());

  auto subscription =
    Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  auto security = std::make_shared<FakeSessionSecurityContext>();
  auto results = create_items(subscription, make_create_request(1, {{subject, 10}}), security);
  ASSERT_EQ(results.size(), 1u);
  subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), {});
  STA::on_strand(*subscription, [](auto&) {});

  SubscriptionIdAllocator idAllocator;
  auto pipeline = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = mExecutor,
    .sessionStrand = boost::asio::make_strand(mExecutor),
    .logger = Logger{},
    .idAllocator = idAllocator,
    .summaryCounters = std::make_shared<ServerSummaryCounters>(),
    .capabilities = {},
    .subscriptionLimits = {},
    .sendResponse = [](Response) {},
    .addressSpace = mAddressSpace->weak(),
  });
  MTA::on_strand(*pipeline, [&](auto& manager) { manager.subscriptions().emplace(1, subscription); });

  // From here the namespace stops answering, so the walk suspends resolving its first subscription's
  // one item and stays there.
  deferredNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  std::promise<VoidResult> answered;
  auto answer = answered.get_future();
  pipeline->reauthorize_all_async([&answered](VoidResult result) { answered.set_value(std::move(result)); });

  ASSERT_TRUE(deferredNamespace->wait_for_pending_resolutions())
    << "the walk must reach the namespace and park, or this tests a walk that never started";
  ASSERT_EQ(answer.wait_for(200ms), std::future_status::timeout)
    << "the walk must still be waiting, or this tests a walk that had already finished";

  // Nothing else holds the pipeline: the walk's own awaits hold it weakly, and so does the
  // subscription's parked answer.
  pipeline.reset();

  ASSERT_EQ(answer.wait_for(5s), std::future_status::ready)
    << "the pipeline went away without answering the reauthorization it was running";
  EXPECT_EQ(answer.get().status_code(), StatusCode{Status::BadSessionClosed});

  deferredNamespace->complete_pending_resolutions();
  deferredNamespace->wait_idle();
}

}  // namespace

// --- SVC-5: the pre-authorization event FIFO is bounded per item (SVR-MI-GEN-020..023) ----------------

namespace
{
// An event item with a small queue whose head delivery is "in flight": the FIFO's head is marked active
// so nothing behind it is resolved, exactly the state an event storm meets while one permission lookup
// is outstanding.
struct BoundedFifoModel
{
  std::shared_ptr<Subscription> subscription;
  IntegerId monitoredItemId{0};
};
}  // namespace

class PendingEventFifoTest : public MonitoredItemAccessControlTest
{
protected:
  BoundedFifoModel make_model(uint32_t queueSize, bool discardOldest)
  {
    BoundedFifoModel m;
    m.subscription = create_subscription();
    auto security = std::make_shared<FakeSessionSecurityContext>();
    auto eventBus = std::make_shared<EventBus>(*mAddressSpace);
    const auto eventSource = create_event_source(2020);
    auto request = make_event_request(1, eventSource, 91);
    request.items_to_create()[0].requested_parameters().queue_size() = queueSize;
    request.items_to_create()[0].requested_parameters().discard_oldest() = discardOldest;
    auto results = create_items(m.subscription, std::move(request), security, eventBus);
    EXPECT_EQ(results.size(), 1u);
    m.monitoredItemId = results[0].monitored_item_id();
    STA::on_strand(*m.subscription,
      [&](auto& g)
      {
        g.seed_pending_event_delivery(m.monitoredItemId);  // the head
        g.event_delivery_active() = true;
        g.active_event_delivery_ordinal() = g.pending_event_deliveries().front().ordinal;
      });
    return m;
  }

  void storm(BoundedFifoModel& m, size_t count)
  {
    STA::on_strand(*m.subscription,
      [&](auto& g)
      {
        for (size_t i = 0; i < count; ++i)
        {
          auto event = std::make_shared<BaseEvent>();
          event->sourceNode = NodeId{0, 2253u};
          event->eventType = NodeId{0, 2041u};
          event->message = LocalizedText{LocaleId{}, String{"storm-" + std::to_string(i)}};
          g.enqueue_event_delivery(m.monitoredItemId,
            std::move(event),
            std::shared_ptr<const event_type_model::DeclarationsResult>{});
        }
      });
  }

  /// The real pipeline: an item on a DeferredNamespace source whose head stalls at the permission
  /// resolution of an EventType the namespace has not answered for, so later events pile into the
  /// hand-off FIFO; completing the resolution lets the head deliver through the production path.
  struct PipelineModel
  {
    std::shared_ptr<ua::test::DeferredNamespace> controlledNamespace;
    ControlledEventNodes nodes;
    NodeId stallingTypeA;  ///< subtype of the controlled EventType, never answered until the test says so
    NodeId stallingTypeB;
    AccessIdentityKey identityKey{0};
    /// The subscription and its items hold the security context weakly: the model owns it.
    std::shared_ptr<FakeSessionSecurityContext> security;
    std::shared_ptr<Subscription> subscription;
    std::shared_ptr<EventBus> eventBus;
    IntegerId monitoredItemId{0};
    std::shared_ptr<std::atomic<size_t>> readyCount = std::make_shared<std::atomic<size_t>>(0);
  };

  PipelineModel make_pipeline_model(
    uint32_t queueSize, bool discardOldest, uint32_t firstNumericId, uint32_t identity)
  {
    enable_test_role_on_namespace(0);
    PipelineModel m;
    m.controlledNamespace = ua::test::DeferredNamespace::create(
      "urn:test:event-fifo-pipeline-" + std::to_string(firstNumericId), mExecutor);
    m.nodes = create_controlled_event_nodes(m.controlledNamespace, firstNumericId);
    m.identityKey = AccessIdentityKey{identity};
    m.security = std::make_shared<FakeSessionSecurityContext>(true, true, identity);
    const auto& security = m.security;
    for (const auto& node : {m.nodes.source, m.nodes.eventType, m.nodes.selectedField, m.nodes.whereField})
    {
      m.controlledNamespace->grant(m.identityKey, node, ua::test_helpers::all_permissions());
    }
    m.stallingTypeA = NodeId{m.nodes.namespaceIndex, firstNumericId + 10};
    m.stallingTypeB = NodeId{m.nodes.namespaceIndex, firstNumericId + 11};
    for (const auto& [typeId, name] :
      {std::pair{m.stallingTypeA, "StallingEventTypeA"}, std::pair{m.stallingTypeB, "StallingEventTypeB"}})
    {
      auto type = mAddressSpace->try_create_node_sync(typeId, NodeClass::ObjectType).value();
      type.set_browse_name(QualifiedName{m.nodes.namespaceIndex, String{name}});
      type.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, m.nodes.eventType, false);
    }
    m.controlledNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
    auto readyCount = m.readyCount;
    m.subscription = Subscription::create(
      1, 1000, 100, 3, 0, true, 0, mExecutor, [readyCount](IntegerId) { ++*readyCount; }, [](IntegerId) {});
    m.eventBus = std::make_shared<EventBus>(*mAddressSpace);
    auto filter =
      make_controlled_event_filter(m.nodes.eventType, m.nodes.selectedBrowseName, m.nodes.whereBrowseName);
    auto request = make_event_request(1, m.nodes.source, 118, std::move(filter));
    request.items_to_create()[0].requested_parameters().queue_size() = queueSize;
    request.items_to_create()[0].requested_parameters().discard_oldest() = discardOldest;
    auto results = create_items(m.subscription, std::move(request), security, m.eventBus);
    EXPECT_EQ(results.size(), 1u);
    if (!results.empty())
    {
      EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
      m.monitoredItemId = results[0].monitored_item_id();
    }
    m.subscription->configure_access_recheck(0ms, security, mAddressSpace->weak(), m.eventBus);
    m.subscription->set_publish_req_queued_async(true);
    STA::on_strand(*m.subscription, [](auto&) {});
    wait_for_event_registration(m.eventBus, 1);
    return m;
  }

  /// Emits an event of `eventType` (a subtype of the controlled EventType) for the model's source.
  static void emit_typed_event(const PipelineModel& m, const NodeId& eventType, std::string_view selected,
    std::string_view where = "match")
  {
    auto event = make_controlled_event(m.nodes, selected, where);
    event.eventType = eventType;
    m.eventBus->emit(event);
  }

  /// Polls until the hand-off FIFO is empty and no delivery is active (or the budget runs out).
  static void wait_for_drain(Subscription& subscription, std::chrono::milliseconds budget = 5000ms)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      bool drained = false;
      STA::on_strand(subscription,
        [&drained](auto& g)
        { drained = g.pending_event_deliveries().empty() && !g.event_delivery_active(); });
      if (drained)
        return;
      std::this_thread::sleep_for(5ms);
    }
  }

  /// The delivered queue as a readable sequence: the selected field's text, or "<overflow>" for the
  /// EventQueueOverflowEvent.
  static std::vector<std::string> delivered_sequence(const MonitoredItem& item)
  {
    std::vector<std::string> out;
    for (const auto& queued : item.eventQueue)
    {
      if (queued.projection.eventType == NodeId{ObjectTypeId::EventQueueOverflowEventType})
      {
        out.emplace_back("<overflow>");
        continue;
      }
      const auto& fields = queued.fields.event_fields();
      out.emplace_back(!fields.empty() && fields[0].is_string() ? std::string{fields[0].template as<String>()}
                                                                : std::string{"<?>"});
    }
    return out;
  }

  /// Polls until the item's EventQueueOverflowCount reaches `expected` (bus delivery is asynchronous).
  static bool wait_for_overflow_count(
    const PipelineModel& m, uint32_t expected, std::chrono::milliseconds budget = 2000ms)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      uint32_t current = 0;
      STA::on_strand(*m.subscription,
        [&](auto& g)
        {
          if (auto* item = g.find_monitored_item(m.monitoredItemId))
            current = item->eventQueueOverflowCount;
        });
      if (current >= expected)
        return true;
      std::this_thread::sleep_for(5ms);
    }
    return false;
  }

  static void release_pipeline(PipelineModel& m)
  {
    m.subscription.reset();
    m.eventBus.reset();
    m.controlledNamespace->wait_idle();
  }
};

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
TEST_F(PendingEventFifoTest, PendingDeliveriesPerItemNeverExceedTheItemsQueueSize)
{
  auto m = make_model(/*queueSize=*/3, /*discardOldest=*/true);
  storm(m, 6);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      size_t mine = 0;
      for (const auto& pending : g.pending_event_deliveries())
        mine += pending.monitoredItemId == m.monitoredItemId ? 1u : 0u;
      EXPECT_LE(mine, 3u) << "the FIFO holds at most queueSize events for the item, head included";
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueueOverflowCount, 4u) << "one head + six storm events into three slots";
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// A loss before authorization is counted at once; its EventQueueOverflowEvent is queued with the next
// delivery, through the delivered path, so the queue's slot rules (SVR-EVT-MON-007/008) and the
// subscription's reportable bookkeeping stay the delivered path's - and it is queued only once.
TEST_F(PendingEventFifoTest, PendingOverflowRaisesTheEventQueueOverflowEventOnceWithTheNextDelivery)
{
  auto m = make_model(/*queueSize=*/2, /*discardOldest=*/true);
  storm(m, 5);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueueOverflowCount, 4u);
      EXPECT_TRUE(item->overflowEventPending) << "counted now, queued with the next delivery";
      EXPECT_FALSE(item->overflowEventInserted);
      EXPECT_TRUE(item->eventQueue.empty()) << "nothing is queued behind the client's back";
      // The next delivered event brings the overflow event with it, at the front (discardOldest).
      item->enqueue_event(event_notification(91, Variant{String{"delivered"}}), false, {});
      ASSERT_EQ(item->eventQueue.size(), 2u);
      EXPECT_EQ(
        item->eventQueue.front().projection.eventType, NodeId{ObjectTypeId::EventQueueOverflowEventType});
      EXPECT_TRUE(item->overflowEventInserted);
      EXPECT_FALSE(item->overflowEventPending);
      item->enqueue_event(event_notification(91, Variant{String{"delivered-2"}}), false, {});
      size_t overflowEvents = 0;
      for (const auto& queued : item->eventQueue)
        overflowEvents +=
          queued.projection.eventType == NodeId{ObjectTypeId::EventQueueOverflowEventType} ? 1u : 0u;
      EXPECT_EQ(overflowEvents, 1u) << "the overflow event is queued once, however many drops preceded it";
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// COND-920: a Condition event lost before authorization asks for a refresh like one lost from the
// delivered queue.
TEST_F(PendingEventFifoTest, AConditionEventLostBeforeAuthorizationRequestsARefresh)
{
  auto m = make_model(/*queueSize=*/1, /*discardOldest=*/false);  // the head fills the one slot
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->refreshRequired);
      auto conditionEvent = std::make_shared<BaseEvent>();
      conditionEvent->sourceNode = NodeId{0, 2253u};
      conditionEvent->eventType = NodeId{ObjectTypeId::ConditionType};
      g.enqueue_event_delivery(m.monitoredItemId,
        std::move(conditionEvent),
        std::shared_ptr<const event_type_model::DeclarationsResult>{});
      EXPECT_TRUE(item->refreshRequired) << "the dropped Condition event is announced by a RefreshRequired";
      EXPECT_EQ(item->eventQueueOverflowCount, 1u);
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// The ConditionRefresh events frame or announce a refresh the client is waiting for: the bound never
// drops them (they are counted, so the bound stays exact for the events that can be dropped).
TEST_F(PendingEventFifoTest, RefreshEventsAreNeverDroppedByTheBound)
{
  auto m = make_model(/*queueSize=*/1, /*discardOldest=*/false);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      for (const auto typeId : {ObjectTypeId::RefreshStartEventType,
             ObjectTypeId::RefreshRequiredEventType,
             ObjectTypeId::RefreshEndEventType})
      {
        auto refresh = std::make_shared<BaseEvent>();
        refresh->sourceNode = NodeId{ObjectId::Server};
        refresh->eventType = NodeId{typeId};
        g.enqueue_event_delivery(m.monitoredItemId,
          std::move(refresh),
          std::shared_ptr<const event_type_model::DeclarationsResult>{});
      }
      size_t mine = 0;
      for (const auto& pending : g.pending_event_deliveries())
        mine += pending.monitoredItemId == m.monitoredItemId ? 1u : 0u;
      EXPECT_EQ(mine, 4u) << "head + three refresh events, none dropped";
      EXPECT_EQ(item->eventQueueOverflowCount, 0u);
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// With discardOldest false the incoming event is the one dropped: the earliest queued events survive.
TEST_F(PendingEventFifoTest, DiscardNewestPolicyDropsTheIncomingEvent)
{
  auto m = make_model(/*queueSize=*/2, /*discardOldest=*/false);
  storm(m, 4);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      std::vector<std::string> kept;
      for (const auto& pending : g.pending_event_deliveries())
      {
        if (pending.monitoredItemId == m.monitoredItemId && pending.event &&
            !pending.event->message.text().empty())
          kept.push_back(std::string{static_cast<std::string_view>(pending.event->message.text())});
      }
      ASSERT_EQ(kept.size(), 1u) << "head + one queued event fill two slots";
      EXPECT_EQ(kept[0], "storm-0") << "the earliest storm event is kept; later ones are dropped";
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueueOverflowCount, 3u);
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// Under discard-oldest the erase victim is never a refresh event: when only refresh events (and the
// head) are pending, the newcomer is the one that goes.
TEST_F(PendingEventFifoTest, RefreshEntriesAreNeverTheEraseVictim)
{
  auto m = make_model(/*queueSize=*/1, /*discardOldest=*/true);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto refresh = std::make_shared<BaseEvent>();
      refresh->sourceNode = NodeId{ObjectId::Server};
      refresh->eventType = NodeId{ObjectTypeId::RefreshRequiredEventType};
      g.enqueue_event_delivery(
        m.monitoredItemId, std::move(refresh), std::shared_ptr<const event_type_model::DeclarationsResult>{});
    });
  storm(m, 1);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      size_t refreshPending = 0;
      for (const auto& pending : g.pending_event_deliveries())
        if (pending.monitoredItemId == m.monitoredItemId && pending.event &&
            pending.event->eventType == NodeId{ObjectTypeId::RefreshRequiredEventType})
          ++refreshPending;
      EXPECT_EQ(refreshPending, 1u) << "the RefreshRequired stayed; the regular newcomer was dropped";
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->eventQueueOverflowCount, 1u);
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// COND-920 under discard-oldest: the erased oldest entry being a Condition event requests a refresh.
TEST_F(PendingEventFifoTest, AConditionEventErasedUnderDiscardOldestRequestsARefresh)
{
  auto m = make_model(/*queueSize=*/2, /*discardOldest=*/true);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto conditionEvent = std::make_shared<BaseEvent>();
      conditionEvent->sourceNode = NodeId{0, 2253u};
      conditionEvent->eventType = NodeId{ObjectTypeId::ConditionType};
      g.enqueue_event_delivery(m.monitoredItemId,
        std::move(conditionEvent),
        std::shared_ptr<const event_type_model::DeclarationsResult>{});
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      ASSERT_FALSE(item->refreshRequired);
    });
  storm(m, 1);  // head + condition event fill both slots: the condition event is the erase victim
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->refreshRequired) << "the erased Condition event is announced by a RefreshRequired";
    });
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// Under discard-newest the overflow event belongs AFTER the newest event kept at the loss
// (SVR-EVT-MON-008), and it is the subscription's pop site that queues it, with the delivered path's
// bookkeeping: the head stalls at its permission resolution, two more events arrive (one kept, one
// dropped), the resolution completes, and what leaves the item is [head, kept, overflow].
TEST_F(PendingEventFifoTest, DeferredOverflowEventUnderDiscardNewestFollowsTheKeptEvents)
{
  auto m = make_pipeline_model(/*queueSize=*/2, /*discardOldest=*/false, 3700, 431);
  ASSERT_NE(m.monitoredItemId, 0u);
  emit_typed_event(m, m.stallingTypeA, "first");
  ASSERT_TRUE(m.controlledNamespace->wait_for_pending_resolutions()) << "the head never stalled";
  emit_typed_event(m, m.nodes.eventType, "second");
  emit_typed_event(m, m.nodes.eventType, "third");
  ASSERT_TRUE(wait_for_overflow_count(m, 1)) << "the third event was never dropped";
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      EXPECT_EQ(g.pending_event_deliveries().size(), 2u) << "head + one kept; the third was dropped";
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->overflowEventPending);
      EXPECT_TRUE(item->eventQueue.empty()) << "nothing is delivered while the head is stalled";
    });

  m.controlledNamespace->grant(m.identityKey, m.stallingTypeA, ua::test_helpers::all_permissions());
  m.controlledNamespace->complete_pending_resolutions();
  wait_for_drain(*m.subscription);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(delivered_sequence(*item), (std::vector<std::string>{"first", "second", "<overflow>"}));
      EXPECT_FALSE(item->overflowEventPending);
      EXPECT_EQ(g.reportable_item_count(), 1u);
    });
  EXPECT_GE(m.readyCount->load(), 1u) << "the subscription reported its notifications";
  release_pipeline(m);
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// A storm that outpaces authorization: losses keep happening while successive heads stall. The
// overflow event is placed by the FIRST loss of the episode and a later loss does not move it, so the
// announcement cannot be postponed for as long as the storm lasts. The client publishes between the
// two stalls (the delivered queue is drained), as a live client would.
TEST_F(PendingEventFifoTest, ASustainedDiscardNewestStormStillAnnouncesTheFirstLoss)
{
  auto m = make_pipeline_model(/*queueSize=*/2, /*discardOldest=*/false, 3800, 432);
  ASSERT_NE(m.monitoredItemId, 0u);
  emit_typed_event(m, m.stallingTypeA, "first");
  ASSERT_TRUE(m.controlledNamespace->wait_for_pending_resolutions()) << "the first head never stalled";
  emit_typed_event(m, m.stallingTypeB, "second");  // kept; stalls once it is the head
  emit_typed_event(m, m.nodes.eventType, "third");  // the first loss
  ASSERT_TRUE(wait_for_overflow_count(m, 1)) << "the third event was never dropped";

  m.controlledNamespace->grant(m.identityKey, m.stallingTypeA, ua::test_helpers::all_permissions());
  m.controlledNamespace->complete_pending_resolutions();  // "first" delivers; "second" becomes the head
  ASSERT_TRUE(m.controlledNamespace->wait_for_pending_resolutions()) << "the second head never stalled";
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(delivered_sequence(*item), (std::vector<std::string>{"first"}));
      std::vector<MonitoredItem::QueuedEvent> published;
      item->drain_events(0, published);  // the client's Publish takes "first"
      EXPECT_EQ(published.size(), 1u);
    });
  emit_typed_event(m, m.nodes.eventType, "fourth");  // kept behind "second"
  emit_typed_event(m, m.nodes.eventType, "fifth");  // a later loss of the same episode
  ASSERT_TRUE(wait_for_overflow_count(m, 2)) << "the fifth event was never dropped";

  m.controlledNamespace->grant(m.identityKey, m.stallingTypeB, ua::test_helpers::all_permissions());
  m.controlledNamespace->complete_pending_resolutions();
  wait_for_drain(*m.subscription);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      // The marker follows "second", the event kept at the FIRST loss; the pre-fix code re-targeted it
      // to "fourth" and delivered [second, fourth, overflow]. The marker takes no slot of the queue (Part
      // 4 5.12.1.5: "in addition to the size of the Queue ... without discarding any other Event"), so
      // "fourth" is kept behind it, and the counter holds the two losses before authorization.
      EXPECT_EQ(delivered_sequence(*item), (std::vector<std::string>{"second", "<overflow>", "fourth"}))
        << "the marker follows the event kept at the FIRST loss, not the one kept at the last";
      EXPECT_EQ(item->eventQueueOverflowCount, 2u);
      EXPECT_FALSE(item->overflowEventPending);
    });
  release_pipeline(m);
}

// @verifies AC-SVR-MI-GEN-020-THE-PRE-AUTHORIZATION-EVENT-FIFO-IS-BOUNDED-PER-ITEM
// The kept event the marker is pinned behind may itself never be delivered (here: it fails the where
// clause). The marker is then the item's only notification, and the pop site's own bookkeeping must
// make the item reportable and wake the Publish, or the loss is never announced.
TEST_F(PendingEventFifoTest, AMarkerBehindAnUndeliveredKeptEventStillWakesThePublish)
{
  auto m = make_pipeline_model(/*queueSize=*/2, /*discardOldest=*/false, 3900, 433);
  ASSERT_NE(m.monitoredItemId, 0u);
  emit_typed_event(m, m.stallingTypeA, "first", "no-match");  // stalls, then fails the where clause
  ASSERT_TRUE(m.controlledNamespace->wait_for_pending_resolutions()) << "the head never stalled";
  emit_typed_event(m, m.nodes.eventType, "second", "no-match");  // kept, then fails the where clause
  emit_typed_event(m, m.nodes.eventType, "third");  // the loss: the marker is pinned behind "second"
  ASSERT_TRUE(wait_for_overflow_count(m, 1)) << "the third event was never dropped";
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      EXPECT_EQ(g.reportable_item_count(), 0u);
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->eventQueue.empty());
    });
  EXPECT_EQ(m.readyCount->load(), 0u) << "nothing to publish yet";

  m.controlledNamespace->grant(m.identityKey, m.stallingTypeA, ua::test_helpers::all_permissions());
  m.controlledNamespace->complete_pending_resolutions();
  wait_for_drain(*m.subscription);
  STA::on_strand(*m.subscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(m.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(delivered_sequence(*item), (std::vector<std::string>{"<overflow>"}))
        << "neither kept event passed the filter; the marker alone announces the loss";
      EXPECT_EQ(g.reportable_item_count(), 1u) << "the marker made the item reportable";
      EXPECT_FALSE(item->overflowEventPending);
    });
  EXPECT_GE(m.readyCount->load(), 1u) << "the marker woke the Publish";
  release_pipeline(m);
}
