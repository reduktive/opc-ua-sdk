// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-SVR-NAMESPACE-CALLS-17. Rule 1: once a namespace that implements no monitoring is registered, its
// items are sampled by the registration's monitoring helper (NR-47). Rules 2 and 3: a change of a Variable's
// DataType in the in-memory namespace sets the StructureChanged bit on one data change notification of each
// of its Value items (OPC 10000-4 7.39.1 Table 180; NR-68 item 10). Every item is created, and every
// notification received, by a Client over the wire.

#include "compliance_helpers.h"
#include "requests.h"
#include "sanitizer_budget.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_create_monitored_items_request.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_described_nodes.h"
#include "ua_history_namespace.h"
#include "ua_localized_text.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_namespace.h"
#include "ua_namespace_context.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// A namespace that implements no monitoring: one Variable, whose Node a DescribedNodes store holds and whose
/// Value is a field. It overrides none of the monitoring members, so its items are what the base Namespace
/// makes of them. It counts the calls of its read_values_async.
class FieldNamespace : public Namespace
{
public:
  explicit FieldNamespace(std::string uri = "urn:test:default-monitoring:field") : mUri(std::move(uri))
  {}

  String uri() const override
  {
    return String{mUri};
  }

  /// How many times read_values_async was called.
  std::size_t read_calls() const
  {
    return mReadCalls.load();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  /// Makes the Variable `ns=index;i=1`, Int32, named "Field", with the DisplayName "A", and holds its Node.
  void hold_variable(uint16_t index)
  {
    const std::lock_guard lock{mMutex};
    mDescription = NodeDescription::variable(
      NodeId{index, uint32_t{1}}, QualifiedName{index, "Field"}, NodeId{DataTypeId::Int32})
                     .with_display_name(LocalizedText{String{"A"}});
    mVariable = mStore.node_for(*mDescription);
  }

  NodeId variable_id() const
  {
    const std::lock_guard lock{mMutex};
    return mDescription ? mDescription->node_id() : NodeId{};
  }

  /// The field the Variable's Value is read from.
  void set_value(int32_t value)
  {
    mField.store(value);
  }

  /// Changes the Node's description to carry @p displayName, as a namespace applies a change it learned of.
  void set_display_name(const LocalizedText& displayName)
  {
    const std::lock_guard lock{mMutex};
    mDescription = mDescription->with_display_name(displayName);
    mVariable = mStore.node_for(*mDescription);
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      answer.items.push_back(found(nodeId));
    }
    complete(std::move(answer));
  }

  using Namespace::find_node;

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration>) override
  {
    return found(nodeId);
  }

  /// The held Variable carries no References.
  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    for (const ReferenceQuery& query : queries)
    {
      if (lookup(query.nodeId))
      {
        answer.items.emplace_back(NodeReferences{});
      }
      else
      {
        answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
      }
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool setSourceTimestamp, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    ++mReadCalls;
    const NodeId variableId = variable_id();
    BatchResult<DataValueResult> answer;
    for (const auto& item : items)
    {
      if (item.value.node_id() != variableId)
      {
        answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
        continue;
      }
      DataValue value;
      value.value() = Variant{mField.load()};
      value.status() = StatusCode{Status::Good};
      if (setSourceTimestamp)
      {
        value.source_timestamp() = DateTime::now();
      }
      answer.items.emplace_back(std::move(value));
    }
    complete(std::move(answer));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    RolePermissionType anonymous;
    anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymous.permissions() = all_permissions();
    return std::vector<RolePermissionType>{std::move(anonymous)};
  }

private:
  shared_ptr<Node> lookup(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mMutex};
    return mDescription && nodeId == mDescription->node_id() ? mVariable : nullptr;
  }

  NodeResult found(const NodeId& nodeId) const
  {
    auto node = lookup(nodeId);
    return node ? NodeResult{std::move(node)} : NodeResult{StatusCode{Status::BadNodeIdUnknown}};
  }

  const std::string mUri;
  std::atomic<std::size_t> mReadCalls{0};
  mutable std::mutex mMutex;
  DescribedNodes mStore;
  std::optional<NodeDescription> mDescription;
  shared_ptr<Node> mVariable;
  std::atomic<int32_t> mField{1};
};

/// A FieldNamespace that registers its items with its monitoring helper as Reported and reports each change
/// of its field through the helper's attribute_changed. It overrides create_monitoring_async and no other
/// monitoring member.
class ReportingNamespace final : public FieldNamespace
{
public:
  using FieldNamespace::FieldNamespace;

  void create_monitoring_async(const RequestInfo&, const CallerInfo*,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override
  {
    using Helper = default_ns::NamespaceMonitoringSupport;
    std::vector<Helper::ResolvedMonitoringItem> resolved;
    for (const auto& item : items)
    {
      resolved.push_back(Helper::ResolvedMonitoringItem{item, Helper::Delivery::Reported});
    }
    BatchResult<MonitoringCreateItemResult> answer;
    for (auto& created : context().monitoring().create_monitoring(resolved))
    {
      answer.items.push_back(std::move(created.result));
    }
    complete(std::move(answer));
  }

  /// Sets the field to @p value and reports the Variable's new Value through the monitoring helper.
  void report_value(int32_t value)
  {
    set_value(value);
    DataValue changed;
    changed.value() = Variant{value};
    changed.status() = StatusCode{Status::Good};
    changed.source_timestamp() = DateTime::now();
    context().monitoring().attribute_changed(variable_id(), AttributeId::Value, changed);
  }
};

/// The in-memory namespace, subclassed to read its index in on_attached, which does not call the base.
class OwnIndexNamespace final : public default_ns::Namespace
{
public:
  OwnIndexNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  uint16_t attached_index() const
  {
    return mIndex.load();
  }

protected:
  VoidResult on_attached(const NamespaceContext& context) override
  {
    mIndex.store(context.index());
    return {};
  }

private:
  std::atomic<uint16_t> mIndex{0};
};

/// A subclass of the in-memory namespace that adds nothing, constructed with make_shared rather than through
/// create().
class SubclassedNamespace final : public default_ns::Namespace
{
public:
  SubclassedNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}
};

/// One notification of one monitored item, in the order the Client received it.
struct Received
{
  uint32_t clientHandle{0};
  DataValue value;
};

/// A Session's Publish loop for one Subscription: each Publish acknowledges the NotificationMessages received
/// before it, and every data change notification is kept in the order received.
class Notifications
{
public:
  Notifications(Session& session, uint32_t subscriptionId)
    : mSession(session), mSubscriptionId(subscriptionId)
  {}

  /// Publishes until @p done answers true of the notifications received, or @p timeout has passed; answers
  /// whether @p done did.
  bool publish_until(
    const std::function<bool(const std::vector<Received>&)>& done, std::chrono::milliseconds timeout)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done(mReceived))
    {
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      publish_once();
    }
    return true;
  }

  /// Publishes @p count times.
  void publish_times(std::size_t count)
  {
    for (std::size_t i = 0; i < count; ++i)
    {
      publish_once();
    }
  }

  const std::vector<Received>& received() const
  {
    return mReceived;
  }

private:
  void publish_once()
  {
    PublishRequest request;
    for (const auto sequenceNumber : std::exchange(mUnacknowledged, {}))
    {
      SubscriptionAcknowledgement acknowledgement;
      acknowledgement.subscription_id() = mSubscriptionId;
      acknowledgement.sequence_number() = sequenceNumber;
      request.subscription_acknowledgements().push_back(std::move(acknowledgement));
    }
    auto response = mSession.subscriptions().try_publish_sync(std::move(request));
    if (!response.is_good() || !response.value().response_header().service_result().is_good())
    {
      std::this_thread::sleep_for(20ms);
      return;
    }
    if (response.value().subscription_id() != mSubscriptionId)
    {
      return;
    }
    if (!response.value().notification_message().notification_data().empty())
    {
      mUnacknowledged.push_back(response.value().notification_message().sequence_number());
    }
    if (const auto* change = as_data_change(response.value()))
    {
      for (const auto& item : change->monitored_items())
      {
        mReceived.push_back(Received{item.client_handle(), item.value()});
      }
    }
  }

  Session& mSession;
  uint32_t mSubscriptionId;
  std::vector<uint32_t> mUnacknowledged;
  std::vector<Received> mReceived;
};

/// The values @p clientHandle's notifications carried, from the @p from-th received on, as text.
std::vector<std::string> values_of(
  const std::vector<Received>& received, uint32_t clientHandle, std::size_t from = 0)
{
  std::vector<std::string> values;
  for (std::size_t i = from; i < received.size(); ++i)
  {
    if (received[i].clientHandle == clientHandle)
    {
      values.push_back(to_string(received[i].value.value()));
    }
  }
  return values;
}

bool has_notification_of(const std::vector<Received>& received, uint32_t clientHandle, std::size_t from = 0)
{
  return !values_of(received, clientHandle, from).empty();
}

bool structure_changed(const Received& notification)
{
  return notification.value.status().has_value() && notification.value.status()->structure_changed();
}

std::string text(const std::vector<std::string>& values)
{
  std::string out = "{";
  for (const auto& value : values)
  {
    out += (out.size() > 1 ? ", " : "") + value;
  }
  return out + "}";
}

/// Creates @p items' monitored items in one CreateMonitoredItems on @p subscriptionId and answers their
/// results, in item order; empty when the service failed.
std::vector<MonitoredItemCreateResult> create_item_results(Session& session, uint32_t subscriptionId,
  const NodeId& nodeId, const std::vector<MonitoringOptions>& items)
{
  auto request = build_create_mi_request(subscriptionId, nodeId, items.front());
  for (std::size_t i = 1; i < items.size(); ++i)
  {
    auto next = build_create_mi_request(subscriptionId, nodeId, items[i]);
    request.items_to_create().push_back(std::move(next.items_to_create()[0]));
  }
  auto response = session.monitored_items().try_create_monitored_items_sync(std::move(request));
  std::vector<MonitoredItemCreateResult> results;
  if (response.is_good())
  {
    for (const auto& result : response.value().results())
    {
      results.push_back(result);
    }
  }
  return results;
}

/// As create_item_results, answering the results' statuses.
std::vector<StatusCode> create_items(Session& session, uint32_t subscriptionId, const NodeId& nodeId,
  const std::vector<MonitoringOptions>& items)
{
  std::vector<StatusCode> statuses;
  for (const auto& result : create_item_results(session, subscriptionId, nodeId, items))
  {
    statuses.push_back(result.status_code());
  }
  return statuses;
}

/// Whether @p notification carries the status @p status.
bool is_status(const Received& notification, Status status)
{
  return notification.value.status().has_value() && notification.value.status()->as_status() == status;
}

class DefaultMonitoring : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    mNamespace = std::make_shared<FieldNamespace>();
    const auto index = mServer.server().address_space().add_namespace_sync(mNamespace);
    mNamespace->hold_variable(index);
    mReporting = std::make_shared<ReportingNamespace>("urn:test:default-monitoring:reporting");
    const auto reportingIndex = mServer.server().address_space().add_namespace_sync(mReporting);
    mReporting->hold_variable(reportingIndex);
  }

  std::shared_ptr<FieldNamespace> mNamespace;
  std::shared_ptr<ReportingNamespace> mReporting;
};

/// The in-memory namespace with an Int32 Variable holding 5 whose WriteMask allows its DataType to be
/// written, and an Int32 Variable V holding 5; a subclass of it whose on_attached does not call the base,
/// with a Variable like the first; and a subclass of it made with make_shared and registered only through a
/// HistoryNamespace that wraps it, with a Variable like the first.
class StructureChanged : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    auto nameSpace = default_ns::Namespace::create(
      "urn:test:default-monitoring:structure", mServer.thread_pool().executor());
    grant_anonymous(*nameSpace);
    const auto index = addressSpace.add_namespace_sync(nameSpace);
    mVariableId = NodeId{index, uint32_t{1}};
    create_variable(addressSpace, mVariableId, "Restructured", true);
    mRecreatedId = NodeId{index, uint32_t{2}};
    create_variable(addressSpace, mRecreatedId, "V", false);

    auto ownIndex = std::make_shared<OwnIndexNamespace>(
      "urn:test:default-monitoring:own-index", mServer.thread_pool().executor());
    grant_anonymous(*ownIndex);
    const auto ownIndexIndex = addressSpace.add_namespace_sync(ownIndex);
    ASSERT_EQ(ownIndex->attached_index(), ownIndexIndex);
    mOwnIndexVariableId = NodeId{ownIndexIndex, uint32_t{1}};
    create_variable(addressSpace, mOwnIndexVariableId, "Restructured", true);

    auto wrapped = std::make_shared<SubclassedNamespace>(
      "urn:test:default-monitoring:wrapped", mServer.thread_pool().executor());
    grant_anonymous(*wrapped);
    const auto wrapperIndex = addressSpace.add_namespace_sync(
      std::make_shared<ua::history::HistoryNamespace>(std::move(wrapped), nullptr));
    mWrappedVariableId = NodeId{wrapperIndex, uint32_t{1}};
    create_variable(addressSpace, mWrappedVariableId, "Restructured", true);
  }

  static void grant_anonymous(default_ns::Namespace& nameSpace)
  {
    RolePermissionType anonymous;
    anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymous.permissions() = all_permissions();
    nameSpace.set_namespace_defaults(std::vector<RolePermissionType>{std::move(anonymous)}, std::nullopt);
  }

  /// An Int32 Variable holding 5, readable and writable; with @p dataTypeWritable, its WriteMask allows its
  /// DataType to be written.
  static void create_variable(
    AddressSpace addressSpace, const NodeId& nodeId, const char* name, bool dataTypeWritable)
  {
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{nodeId.namespace_index(), name});
    variable->set_display_name(LocalizedText{String{name}});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    if (dataTypeWritable)
    {
      variable->set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DataType});
    }
    variable->write_value_sync(int32_t{5});
  }

  NodeId mVariableId;
  NodeId mRecreatedId;
  NodeId mOwnIndexVariableId;
  NodeId mWrappedVariableId;
};

constexpr uint32_t firstValueItem = 1;
constexpr uint32_t secondValueItem = 2;
constexpr uint32_t displayNameItem = 3;

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-A-VALUE-OF-A-NAMESPACE-WITHOUT-MONITORING-IS-SAMPLED, scope=function)
TEST_F(DefaultMonitoring, AValueOfANamespaceWithoutMonitoringIsSampled)
{
  const NodeId variableId = mNamespace->variable_id();
  mNamespace->set_value(1);
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    variableId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].as_status(), Status::Good) << "the item was refused: " << to_string(created[0]);

  Notifications notifications{*mSession, subscriptionId};
  notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, firstValueItem); },
    test_utils::scaled(5s));
  mNamespace->set_value(2);
  notifications.publish_until([](const std::vector<Received>& received)
    { return values_of(received, firstValueItem).size() >= 2; },
    test_utils::scaled(5s));

  const auto values = values_of(notifications.received(), firstValueItem);
  EXPECT_EQ(
    values, (std::vector<std::string>{to_string(Variant{int32_t{1}}), to_string(Variant{int32_t{2}})}))
    << "the item's notifications were " << text(values);
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-A-DISPLAY-NAME-CHANGE-IS-DELIVERED-AT-THE-NEXT-TICK, scope=function)
TEST_F(DefaultMonitoring, ADisplayNameChangeIsDeliveredAtTheNextTick)
{
  const NodeId variableId = mNamespace->variable_id();
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    variableId,
    {MonitoringOptions{.attribute = AttributeId::DisplayName,
      .clientHandle = displayNameItem,
      .samplingInterval = 100.0,
      .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].as_status(), Status::Good) << "the item was refused: " << to_string(created[0]);

  Notifications notifications{*mSession, subscriptionId};
  notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, displayNameItem); },
    test_utils::scaled(5s));
  mNamespace->set_display_name(LocalizedText{String{"B"}});
  notifications.publish_until([](const std::vector<Received>& received)
    { return values_of(received, displayNameItem).size() >= 2; },
    test_utils::scaled(500ms));

  const auto values = values_of(notifications.received(), displayNameItem);
  EXPECT_EQ(values,
    (std::vector<std::string>{
      to_string(Variant{LocalizedText{String{"A"}}}), to_string(Variant{LocalizedText{String{"B"}}})}))
    << "the item's notifications were " << text(values);
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-A-DATA-TYPE-WRITE-SETS-THE-BIT-ON-ONE-NOTIFICATION, scope=function)
TEST_F(StructureChanged, ADataTypeWriteSetsTheBitOnOneNotification)
{
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    mVariableId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10},
      MonitoringOptions{.clientHandle = secondValueItem, .samplingInterval = 100.0, .queueSize = 10},
      MonitoringOptions{.attribute = AttributeId::DisplayName,
        .clientHandle = displayNameItem,
        .samplingInterval = 100.0,
        .queueSize = 10}});
  ASSERT_EQ(created.size(), 3u);
  for (const auto& status : created)
  {
    ASSERT_EQ(status.as_status(), Status::Good) << to_string(status);
  }

  Notifications notifications{*mSession, subscriptionId};
  ASSERT_TRUE(notifications.publish_until(
    [](const std::vector<Received>& received)
    {
      return has_notification_of(received, firstValueItem) &&
             has_notification_of(received, secondValueItem) && has_notification_of(received, displayNameItem);
    },
    test_utils::scaled(5s)))
    << "the three items did not report their initial values";

  const std::size_t afterDataType = notifications.received().size();
  const auto dataTypeWritten = mSession->attributes().write_sync(
    WriteRequestBuilder()
      .write(mVariableId, Variant{NodeId{DataTypeId::Number}}, AttributeId::DataType)
      .build());
  ASSERT_EQ(dataTypeWritten.results().size(), 1u);
  ASSERT_EQ(dataTypeWritten.results()[0].as_status(), Status::Good)
    << "the DataType write was refused: " << to_string(dataTypeWritten.results()[0]);
  const auto carriesTheBit = [afterDataType](const std::vector<Received>& received, uint32_t clientHandle)
  {
    for (std::size_t i = afterDataType; i < received.size(); ++i)
    {
      if (received[i].clientHandle == clientHandle && structure_changed(received[i]))
      {
        return true;
      }
    }
    return false;
  };
  notifications.publish_until([&carriesTheBit](const std::vector<Received>& received)
    { return carriesTheBit(received, firstValueItem) && carriesTheBit(received, secondValueItem); },
    test_utils::scaled(2s));

  const std::size_t afterValue = notifications.received().size();
  const auto valueWritten =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mVariableId, Variant{int32_t{6}}).build());
  ASSERT_EQ(valueWritten.results().size(), 1u);
  ASSERT_EQ(valueWritten.results()[0].as_status(), Status::Good)
    << "the Value write was refused: " << to_string(valueWritten.results()[0]);
  const std::string six = to_string(Variant{int32_t{6}});
  const auto deliveredSix = [afterValue, &six](const std::vector<Received>& received, uint32_t clientHandle)
  {
    const auto values = values_of(received, clientHandle, afterValue);
    return std::find(values.begin(), values.end(), six) != values.end();
  };
  ASSERT_TRUE(notifications.publish_until([&deliveredSix](const std::vector<Received>& received)
    { return deliveredSix(received, firstValueItem) && deliveredSix(received, secondValueItem); },
    test_utils::scaled(5s)))
    << "the Value items did not report 6";

  const auto& received = notifications.received();
  for (const uint32_t clientHandle : {firstValueItem, secondValueItem})
  {
    std::size_t marked = 0;
    for (std::size_t i = afterDataType; i < received.size(); ++i)
    {
      if (received[i].clientHandle != clientHandle)
      {
        continue;
      }
      if (structure_changed(received[i]))
      {
        ++marked;
      }
      if (i >= afterValue && to_string(received[i].value.value()) == six)
      {
        EXPECT_FALSE(structure_changed(received[i]))
          << "item " << clientHandle << ": the notification of 6 carries StructureChanged";
      }
    }
    EXPECT_EQ(marked, 1u) << "item " << clientHandle << " delivered " << marked
                          << " notifications with StructureChanged after the DataType write; its values were "
                          << text(values_of(received, clientHandle, afterDataType));
  }
  for (const auto& notification : received)
  {
    if (notification.clientHandle == displayNameItem)
    {
      EXPECT_FALSE(structure_changed(notification)) << "the DisplayName item delivered StructureChanged";
    }
  }
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-A-NAMESPACE-THAT-OVERRIDES-ON-ATTACHED-STILL-SETS-THE-BIT, scope=function)
TEST_F(StructureChanged, ANamespaceThatOverridesOnAttachedStillSetsTheBit)
{
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    mOwnIndexVariableId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].as_status(), Status::Good) << to_string(created[0]);

  Notifications notifications{*mSession, subscriptionId};
  ASSERT_TRUE(notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, firstValueItem); },
    test_utils::scaled(5s)))
    << "the item did not report its initial value";

  const std::size_t afterDataType = notifications.received().size();
  const auto written = mSession->attributes().write_sync(
    WriteRequestBuilder()
      .write(mOwnIndexVariableId, Variant{NodeId{DataTypeId::Number}}, AttributeId::DataType)
      .build());
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_EQ(written.results()[0].as_status(), Status::Good)
    << "the DataType write was refused: " << to_string(written.results()[0]);
  const auto markedCount = [afterDataType](const std::vector<Received>& received)
  {
    std::size_t marked = 0;
    for (std::size_t i = afterDataType; i < received.size(); ++i)
    {
      if (received[i].clientHandle == firstValueItem && structure_changed(received[i]))
      {
        ++marked;
      }
    }
    return marked;
  };
  notifications.publish_until([&markedCount](const std::vector<Received>& received)
    { return markedCount(received) > 0; },
    test_utils::scaled(2s));
  notifications.publish_times(2);

  EXPECT_EQ(markedCount(notifications.received()), 1u)
    << "after the DataType write the item delivered " << markedCount(notifications.received())
    << " notifications with StructureChanged; its values were "
    << text(values_of(notifications.received(), firstValueItem, afterDataType));
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-CREATING-A-VARIABLE-IS-NOT-A-DATA-TYPE-CHANGE, scope=function)
TEST_F(StructureChanged, CreatingAVariableIsNotADataTypeChange)
{
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    mRecreatedId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].as_status(), Status::Good) << to_string(created[0]);

  Notifications notifications{*mSession, subscriptionId};
  ASSERT_TRUE(notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, firstValueItem); },
    test_utils::scaled(5s)))
    << "the item did not report its initial value";

  auto addressSpace = mServer.server().address_space();
  const auto deleted = addressSpace.try_delete_node_sync(mRecreatedId, false);
  ASSERT_TRUE(deleted.is_good()) << "V could not be deleted: " << to_string(deleted.status_code());
  std::size_t afterUnknown = 0;
  ASSERT_TRUE(notifications.publish_until(
    [&afterUnknown](const std::vector<Received>& received)
    {
      for (std::size_t i = 0; i < received.size(); ++i)
      {
        if (received[i].clientHandle == firstValueItem && is_status(received[i], Status::BadNodeIdUnknown))
        {
          afterUnknown = i + 1;
          return true;
        }
      }
      return false;
    },
    test_utils::scaled(5s)))
    << "the item did not deliver Bad_NodeIdUnknown after V was deleted; its values were "
    << text(values_of(notifications.received(), firstValueItem));

  const auto recreated = addressSpace.try_create_node_sync(mRecreatedId,
    NodeClass::Variable,
    InitialAttributes{{AttributeId::DataType, Variant{NodeId{DataTypeId::Int32}}}});
  ASSERT_TRUE(recreated.is_good()) << "a Variable with V's NodeId could not be added: "
                                   << to_string(recreated.status_code());
  notifications.publish_times(2);

  std::vector<std::string> after;
  const auto& received = notifications.received();
  for (std::size_t i = afterUnknown; i < received.size(); ++i)
  {
    if (received[i].clientHandle == firstValueItem)
    {
      after.push_back(to_string(received[i].value.value()) + " " +
                      (received[i].value.status() ? to_string(*received[i].value.status()) : "Good"));
    }
  }
  EXPECT_TRUE(after.empty()) << "after Bad_NodeIdUnknown the item delivered " << text(after);
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-THE-DEFAULT-MODIFY-KEEPS-A-REPORTED-ITEM-REPORTED, scope=function)
TEST_F(DefaultMonitoring, TheDefaultModifyKeepsAReportedItemReported)
{
  const NodeId variableId = mReporting->variable_id();
  mReporting->set_value(1);
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_item_results(*mSession,
    subscriptionId,
    variableId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].status_code().as_status(), Status::Good) << to_string(created[0].status_code());

  Notifications notifications{*mSession, subscriptionId};
  ASSERT_TRUE(notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, firstValueItem); },
    test_utils::scaled(5s)))
    << "the item did not report its initial value";

  MonitoredItemModifyRequest modify;
  modify.monitored_item_id() = created[0].monitored_item_id();
  modify.requested_parameters().client_handle() = firstValueItem;
  modify.requested_parameters().sampling_interval() = 200.0;
  modify.requested_parameters().queue_size() = 10;
  modify.requested_parameters().discard_oldest() = true;
  ModifyMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_modify().push_back(std::move(modify));
  const auto modified = mSession->monitored_items().modify_monitored_items_sync(std::move(request));
  ASSERT_EQ(modified.results().size(), 1u);
  ASSERT_EQ(modified.results()[0].status_code().as_status(), Status::Good)
    << "the modify was refused: " << to_string(modified.results()[0].status_code());
  // The helper revises an interval up to its sampling bucket at or above it (NR-47 rule 3).
  EXPECT_EQ(modified.results()[0].revised_sampling_interval(), 250.0);
  const std::size_t readsAfterModify = mReporting->read_calls();

  const std::size_t beforeReport = notifications.received().size();
  mReporting->report_value(2);
  const std::string two = to_string(Variant{int32_t{2}});
  const bool delivered = notifications.publish_until(
    [beforeReport, &two](const std::vector<Received>& received)
    {
      const auto values = values_of(received, firstValueItem, beforeReport);
      return std::find(values.begin(), values.end(), two) != values.end();
    },
    test_utils::scaled(5s));
  notifications.publish_times(2);

  EXPECT_TRUE(delivered) << "the reported value was not delivered; the item's values after the report were "
                         << text(values_of(notifications.received(), firstValueItem, beforeReport));
  EXPECT_EQ(mReporting->read_calls(), readsAfterModify)
    << "the namespace was asked for Values " << (mReporting->read_calls() - readsAfterModify)
    << " times after the modify: the item is sampled";
  delete_subscription(*mSession, subscriptionId);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-A-WRAPPED-SUBCLASS-OF-THE-IN-MEMORY-NAMESPACE-SETS-THE-BIT, scope=function)
TEST_F(StructureChanged, AWrappedSubclassOfTheInMemoryNamespaceSetsTheBit)
{
  const uint32_t subscriptionId =
    create_subscription(*mSession, {.publishingInterval = 100.0, .keepAliveCount = 2});
  ASSERT_NE(subscriptionId, 0u);
  const auto created = create_items(*mSession,
    subscriptionId,
    mWrappedVariableId,
    {MonitoringOptions{.clientHandle = firstValueItem, .samplingInterval = 100.0, .queueSize = 10}});
  ASSERT_EQ(created.size(), 1u);
  ASSERT_EQ(created[0].as_status(), Status::Good) << to_string(created[0]);

  Notifications notifications{*mSession, subscriptionId};
  ASSERT_TRUE(notifications.publish_until([](const std::vector<Received>& received)
    { return has_notification_of(received, firstValueItem); },
    test_utils::scaled(5s)))
    << "the item did not report its initial value";

  const std::size_t afterDataType = notifications.received().size();
  const auto written = mSession->attributes().write_sync(
    WriteRequestBuilder()
      .write(mWrappedVariableId, Variant{NodeId{DataTypeId::Number}}, AttributeId::DataType)
      .build());
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_EQ(written.results()[0].as_status(), Status::Good)
    << "the DataType write was refused: " << to_string(written.results()[0]);
  const auto markedCount = [afterDataType](const std::vector<Received>& received)
  {
    std::size_t marked = 0;
    for (std::size_t i = afterDataType; i < received.size(); ++i)
    {
      if (received[i].clientHandle == firstValueItem && structure_changed(received[i]))
      {
        ++marked;
      }
    }
    return marked;
  };
  notifications.publish_until([&markedCount](const std::vector<Received>& received)
    { return markedCount(received) > 0; },
    test_utils::scaled(2s));
  notifications.publish_times(2);

  EXPECT_EQ(markedCount(notifications.received()), 1u)
    << "after the DataType write the item delivered " << markedCount(notifications.received())
    << " notifications with StructureChanged; its values were "
    << text(values_of(notifications.received(), firstValueItem, afterDataType));
  delete_subscription(*mSession, subscriptionId);
}
