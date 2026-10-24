// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The CreateFlow and ModifyFlow fixtures, shared by create_flow_tests.cpp and the arms of NR-70 B4c that name
// MonitoringCreateItem::indexRange (create_flow_range_tests.cpp): GoogleTest requires every test of one suite
// to use one fixture class, so the classes live here rather than in either file's anonymous namespace.

#ifndef UA_TEST_CREATE_FLOW_FIXTURE_H
#define UA_TEST_CREATE_FLOW_FIXTURE_H

#include <gtest/gtest.h>

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_deadband_type.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_event_filter.h"
#include "ua_event_notifier_type.h"
#include "ua_localized_text.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_node_accessor.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_server.h"
#include "ua_simple_attribute_operand.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

namespace ua::test::create_flow
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;
using ua::test::BatchRecordingNamespace;
using Call = BatchRecordingNamespace::Call;
using Member = BatchRecordingNamespace::Member;

/// A Session security context whose `caller()` answers the CallerInfo given; its other members are @p
/// inner's.
class CallerSecurityContext final : public server::SessionSecurityContext
{
public:
  CallerSecurityContext(
    std::shared_ptr<const server::SessionSecurityContext> inner, std::shared_ptr<const CallerInfo> caller)
    : mInner(std::move(inner)), mCaller(std::move(caller))
  {}

  NodeId session_id() const override
  {
    return mCaller->sessionId;
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mInner->endpoint_security();
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mInner->user_identity();
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mInner->access_identity();
  }

  std::shared_ptr<const CallerInfo> caller() const override
  {
    return mCaller;
  }

private:
  std::shared_ptr<const server::SessionSecurityContext> mInner;
  std::shared_ptr<const CallerInfo> mCaller;
};

using CreateResults = std::vector<MonitoredItemCreateResult>;
using ModifyResults = std::vector<MonitoredItemModifyResult>;

inline const NodeId sessionNodeId{1, uint32_t{4242}};

/// A lookup in either form: whether a scripted answer was used, or whether a Node was asked about at all.
inline bool is_lookup(const Call& call)
{
  return call.member == Member::BatchedLookup || call.member == Member::SingleLookup;
}

/// A lookup the criteria count: the batched member, which carries the request. The route's immediate
/// per-Node lookup before a batched one is not counted (COMP-SVR-NAMESPACE-CALLS-13 rule 1).
inline bool is_batched_lookup(const Call& call)
{
  return call.member == Member::BatchedLookup;
}

inline bool is_permission_call(const Call& call)
{
  return call.member == Member::PermissionsAsyncForRequest;
}

inline bool is_member(const Call& call, Member member)
{
  return call.member == member;
}

/// The calls of the kind @p kind that name at least one of @p nodeIds.
inline std::vector<Call> naming(const std::vector<Call>& calls, const std::function<bool(const Call&)>& kind,
  const std::vector<NodeId>& nodeIds)
{
  std::vector<Call> selected;
  for (const auto& call : calls)
  {
    if (!kind(call))
    {
      continue;
    }
    const bool names = std::any_of(nodeIds.begin(),
      nodeIds.end(),
      [&call](const NodeId& nodeId)
      { return std::find(call.nodeIds.begin(), call.nodeIds.end(), nodeId) != call.nodeIds.end(); });
    if (names)
    {
      selected.push_back(call);
    }
  }
  return selected;
}

/// How many times @p nodeId is named among the calls of the kind @p kind.
inline std::size_t times_named(
  const std::vector<Call>& calls, const std::function<bool(const Call&)>& kind, const NodeId& nodeId)
{
  std::size_t named = 0;
  for (const auto& call : calls)
  {
    if (kind(call))
    {
      named += static_cast<std::size_t>(std::count(call.nodeIds.begin(), call.nodeIds.end(), nodeId));
    }
  }
  return named;
}

inline std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

inline std::string member_name(Member member)
{
  switch (member)
  {
  case Member::BatchedLookup:
    return "batched lookup";
  case Member::SingleLookup:
    return "single lookup";
  case Member::PermissionsAsyncForRequest:
    return "effective_permissions_async(request)";
  case Member::ReadValues:
    return "read_values_async";
  case Member::ReadReferences:
    return "read_references_async";
  case Member::CreateMonitoring:
    return "create_monitoring";
  case Member::ModifyMonitoring:
    return "modify_monitoring";
  case Member::DeleteMonitoring:
    return "delete_monitoring";
  default:
    return "other member";
  }
}

inline std::string describe(const std::vector<Call>& calls)
{
  std::string text = "\nthe namespace's calls:";
  for (const auto& call : calls)
  {
    text += "\n  " + member_name(call.member) + (call.hasRequest ? " (request)" : "");
    for (const auto& nodeId : call.nodeIds)
    {
      text += " " + nodeId.as_definition();
    }
  }
  return text;
}

/// The ErrorDetail code of @p status, or "(none)".
inline std::string detail_code(const StatusCode& status)
{
  const auto detail = status.shared_detail();
  return detail ? detail->code : std::string{"(none)"};
}

/// The inner status of @p status's ErrorDetail, or Good when it carries none.
inline StatusCodeValue detail_cause(const StatusCode& status)
{
  const auto detail = status.shared_detail();
  return detail ? detail->innerStatus : StatusCode{Status::Good}.value();
}

inline std::unique_ptr<DataChangeFilter> absolute_deadband(double value)
{
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = value;
  return filter;
}

inline std::unique_ptr<DataChangeFilter> percent_deadband(double percent)
{
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Percent);
  filter->deadband_value() = percent;
  return filter;
}

/// A Value item on @p nodeId at interval 0, Reporting, discarding the oldest.
inline MonitoredItemCreateRequest value_item(const NodeId& nodeId, uint32_t clientHandle,
  uint32_t queueSize = 5, std::unique_ptr<DataChangeFilter> filter = nullptr)
{
  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = nodeId;
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 0;
  item.requested_parameters().queue_size() = queueSize;
  item.requested_parameters().discard_oldest() = true;
  if (filter)
  {
    item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  }
  return item;
}

/// An event item on @p nodeId's EventNotifier, whose EventFilter selects the Value of @p eventType's
/// field @p field (BaseEventType's EventId unless given).
inline MonitoredItemCreateRequest event_item(const NodeId& nodeId, uint32_t clientHandle,
  const NodeId& eventType = NodeId{ObjectTypeId::BaseEventType},
  const QualifiedName& field = QualifiedName{0, "EventId"})
{
  SimpleAttributeOperand selected;
  selected.type_definition_id() = eventType;
  selected.browse_path().push_back(field);
  selected.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  auto filter = std::make_unique<EventFilter>();
  filter->select_clauses().push_back(std::move(selected));

  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = nodeId;
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 0;
  item.requested_parameters().queue_size() = 10;
  item.requested_parameters().discard_oldest() = true;
  item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  return item;
}

/// A modify of @p monitoredItemId to interval 0 and @p queueSize.
inline MonitoredItemModifyRequest modify_item(IntegerId monitoredItemId, uint32_t clientHandle,
  uint32_t queueSize = 5, std::unique_ptr<DataChangeFilter> filter = nullptr)
{
  MonitoredItemModifyRequest item;
  item.monitored_item_id() = monitoredItemId;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 0;
  item.requested_parameters().queue_size() = queueSize;
  item.requested_parameters().discard_oldest() = true;
  if (filter)
  {
    item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  }
  return item;
}

/// The items given, in order, in a vector (the request types are moved, not copied).
template<typename T, typename... More>
std::vector<T> list_of(T first, More... more)
{
  std::vector<T> items;
  items.push_back(std::move(first));
  (items.push_back(std::move(more)), ...);
  return items;
}

inline Range make_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

class MonitoringFlow : public ::testing::Test
{
protected:
  struct Reported
  {
    uint32_t handle;
    Variant value;
    StatusCode status;
  };

  void TearDown() override
  {
    // A held answer is let go, so that nothing waits on it while the fixture drains.
    for (const auto& nameSpace : mNamespaces)
    {
      nameSpace->release_held_value_reads();
      nameSpace->release_held_modify_answers();
      nameSpace->release_held_lookups();
      nameSpace->release_held_permission_answers();
    }
    mSubscriptions.clear();
    mSecurity.reset();
    mEventBus.reset();
    mVariables.clear();
    mAddressSpace.reset();
    mNamespaces.clear();
    mSessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// Registers @p count recording namespaces on a Server's address space, then the Session, whose access
  /// identity is granted every default namespace, and whose caller has the NodeId sessionNodeId. Returns the
  /// namespaces' indexes.
  std::vector<uint16_t> setup(std::size_t count)
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};
    auto server = Server::create(mThreadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    std::vector<uint16_t> indexes;
    for (std::size_t i = 0; i < count; ++i)
    {
      auto nameSpace = std::make_shared<BatchRecordingNamespace>(
        "urn:test:monitoring-flow:" + std::to_string(i), mThreadPool.get_executor());
      indexes.push_back(server.address_space().add_namespace_sync(nameSpace));
      mNamespaces.push_back(std::move(nameSpace));
    }
    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(server), mThreadPool.get_executor());
    mAddressSpace.emplace(mSessionInfo->address_space());
    auto caller = std::make_shared<CallerInfo>();
    caller->identity = mSessionInfo->access_identity();
    caller->sessionId = sessionNodeId;
    mSecurity = std::make_shared<CallerSecurityContext>(mSessionInfo, std::move(caller));
    mCapabilities.minSupportedSampleRate = 0;
    mCapabilities.maxMonitoredItemsQueueSize = 1000u;
    return indexes;
  }

  /// @p nameSpace declines its immediate lookups and permissions from here on, and its record is cleared.
  static void measure(BatchRecordingNamespace& nameSpace)
  {
    nameSpace.decline_single_lookups();
    nameSpace.decline_immediate_permissions();
    nameSpace.reset();
  }

  /// A readable and writable Variable of @p dataType holding @p value.
  NodeId create_variable(const NodeId& nodeId, const NodeId& dataType, DataValue value)
  {
    auto created = mAddressSpace->try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    if (!created.is_good())
    {
      ADD_FAILURE() << "creating " << nodeId.as_definition() << ": " << to_string(created.status_code());
      return nodeId;
    }
    auto variable = created.value();
    variable.set_browse_name(QualifiedName{nodeId.namespace_index(), nodeId.as_definition()});
    variable.set_display_name(LocalizedText{"", nodeId.as_definition()});
    variable.set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable.set_data_type(dataType);
    variable.write_value_sync(std::move(value));
    mVariables.insert_or_assign(nodeId, variable);
    return nodeId;
  }

  /// An Object whose EventNotifier has SubscribeToEvents.
  NodeId create_notifier(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    if (!created.is_good())
    {
      ADD_FAILURE() << "creating " << nodeId.as_definition() << ": " << to_string(created.status_code());
      return nodeId;
    }
    created.value().set_browse_name(QualifiedName{nodeId.namespace_index(), nodeId.as_definition()});
    created.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    return nodeId;
  }

  /// An AnalogItem Variable of Double holding 0.0, with an EURange Property @p property holding {@p low,
  /// @p high}, its only HasProperty target.
  void create_analog_item(const NodeId& variable, const NodeId& property, double low, double high)
  {
    create_variable(variable, NodeId{DataTypeId::Double}, DataValue{Variant{0.0}});
    auto owner = mVariables.at(variable);
    ASSERT_TRUE(owner
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType})
                  .is_good());
    auto created = mAddressSpace->try_create_sync<VariableAccessor>(property, NodeClass::Variable);
    ASSERT_TRUE(created.is_good()) << "creating the EURange " << property.as_definition();
    auto range = created.value();
    range.set_browse_name(QualifiedName{0, "EURange"});
    range.set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    range.set_data_type(NodeId{DataTypeId::Range});
    range.write_value_sync(DataValue{Variant{make_range(low, high)}});
    ASSERT_TRUE(owner.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, property).is_good());
  }

  /// The DataType @p dataType, a subtype of Double.
  void create_double_subtype(const NodeId& dataType)
  {
    auto created = mAddressSpace->try_create_sync<DataTypeAccessor>(dataType, NodeClass::DataType);
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    created.value().set_browse_name(QualifiedName{dataType.namespace_index(), "D"});
    ASSERT_TRUE(created.value()
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{DataTypeId::Double}}, false)
                  .is_good());
  }

  std::shared_ptr<Subscription> subscription(IntegerId subscriptionId)
  {
    auto created = Subscription::create(
      subscriptionId,
      1'000'000.0,
      100,
      3,
      0,
      true,
      0,
      mThreadPool.get_executor(),
      [](IntegerId) {},
      [](IntegerId) {});
    mSubscriptions.push_back(created);
    return created;
  }

  /// Sends a CreateMonitoredItems of @p items to @p target. When @p completions is given it counts every
  /// completion, and only the first answers the future.
  std::future<CreateResults> start_create(Subscription& target, std::vector<MonitoredItemCreateRequest> items,
    std::shared_ptr<SessionSecurityContext> security, uint32_t timeoutHint = 0,
    std::weak_ptr<EventBus> eventBus = {}, std::shared_ptr<std::atomic_size_t> completions = nullptr)
  {
    CreateMonitoredItemsRequest request;
    request.request_header().timeout_hint() = timeoutHint;
    request.subscription_id() = target.id();
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& item : items)
    {
      request.items_to_create().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<CreateResults>>();
    auto future = promise->get_future();
    target.create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      std::move(security),
      std::move(eventBus),
      nullptr,
      [promise, completions](CreateResults results)
      {
        if (completions && completions->fetch_add(1) != 0)
        {
          return;
        }
        promise->set_value(std::move(results));
      });
    return future;
  }

  static CreateResults finish_create(std::future<CreateResults>& future, std::size_t expected)
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return {};
    }
    auto results = future.get();
    EXPECT_EQ(results.size(), expected) << "the create answered the wrong number of rows";
    return results;
  }

  CreateResults create(Subscription& target, std::vector<MonitoredItemCreateRequest> items,
    std::shared_ptr<SessionSecurityContext> security, uint32_t timeoutHint = 0,
    std::weak_ptr<EventBus> eventBus = {})
  {
    const auto expected = items.size();
    auto future =
      start_create(target, std::move(items), std::move(security), timeoutHint, std::move(eventBus));
    return finish_create(future, expected);
  }

  std::future<ModifyResults> start_modify(Subscription& target, std::vector<MonitoredItemModifyRequest> items)
  {
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = target.id();
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& item : items)
    {
      request.items_to_modify().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<ModifyResults>>();
    auto future = promise->get_future();
    target.modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [promise](ModifyResults results) { promise->set_value(std::move(results)); });
    return future;
  }

  static ModifyResults finish_modify(std::future<ModifyResults>& future, std::size_t expected)
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the modify did not answer";
      return {};
    }
    auto results = future.get();
    EXPECT_EQ(results.size(), expected) << "the modify answered the wrong number of rows";
    return results;
  }

  /// The ids of the items @p target holds, in ascending order.
  static std::vector<uint32_t> items_held(Subscription& target)
  {
    auto promise = std::make_shared<std::promise<std::vector<uint32_t>>>();
    auto future = promise->get_future();
    target.get_monitored_item_handles_async(
      [promise](MonitoredItemHandles handles) { promise->set_value(std::move(handles.serverHandles)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "GetMonitoredItems did not answer";
      return {};
    }
    auto held = future.get();
    std::sort(held.begin(), held.end());
    return held;
  }

  /// Runs nothing on @p target's strand and waits for it: what was posted to the strand before has run.
  static void strand_barrier(Subscription& target)
  {
    STA::on_strand(target, [](auto&) {});
  }

  /// The monitoredItemId @p nameSpace was given for an item on @p nodeId, or 0.
  static IntegerId monitored_item_id_of(const BatchRecordingNamespace& nameSpace, const NodeId& nodeId)
  {
    for (const auto& call : nameSpace.calls(Member::CreateMonitoring))
    {
      for (std::size_t k = 0; k < call.nodeIds.size() && k < call.monitoredItemIds.size(); ++k)
      {
        if (call.nodeIds[k] == nodeId)
        {
          return call.monitoredItemIds[k];
        }
      }
    }
    return 0;
  }

  void publish_once(Subscription& target)
  {
    auto published = STA::on_strand(target,
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
        {
          continue;
        }
        for (const auto& notification : change->monitored_items())
        {
          mReported.push_back({notification.client_handle(),
            notification.value().value(),
            notification.value().status().value_or(StatusCode{Status::Good})});
        }
      }
    }
  }

  /// Publishes, recording every notification, until @p done holds or @p timeout passes.
  bool publish_until(
    Subscription& target, const std::function<bool()>& done, std::chrono::milliseconds timeout = 3s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
      publish_once(target);
      if (done())
      {
        return true;
      }
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(5ms);
    }
  }

  void publish_for(Subscription& target, std::chrono::milliseconds duration)
  {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < deadline)
    {
      publish_once(target);
      std::this_thread::sleep_for(5ms);
    }
  }

  std::vector<Reported> reports_of(uint32_t clientHandle) const
  {
    std::vector<Reported> found;
    for (const auto& reported : mReported)
    {
      if (reported.handle == clientHandle)
      {
        found.push_back(reported);
      }
    }
    return found;
  }

  std::string reports_text(uint32_t clientHandle) const
  {
    std::string text = "the item reported:";
    for (const auto& reported : reports_of(clientHandle))
    {
      text += " " + to_string(reported.value) + " [" + to_string(reported.status) + "];";
    }
    return text;
  }

  /// Whether the item with @p clientHandle reported the Double @p value with a Good status.
  bool reported_double(uint32_t clientHandle, double value) const
  {
    const auto reports = reports_of(clientHandle);
    return std::any_of(reports.begin(),
      reports.end(),
      [value](const Reported& reported) {
        return reported.status.is_good() && reported.value.is_double() &&
               reported.value.as<double>() == value;
      });
  }

  boost::asio::thread_pool mThreadPool{4};
  std::shared_ptr<SessionInfoStub> mSessionInfo;
  std::vector<std::shared_ptr<BatchRecordingNamespace>> mNamespaces;
  std::optional<AddressSpace> mAddressSpace;
  std::map<NodeId, VariableAccessor> mVariables;
  std::shared_ptr<CallerSecurityContext> mSecurity;
  std::shared_ptr<EventBus> mEventBus;
  std::vector<std::shared_ptr<Subscription>> mSubscriptions;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
  std::vector<Reported> mReported;
};

class CreateFlow : public MonitoringFlow
{
protected:
  /// A readable Variable of Int32 with ValueRank 1 holding @p values.
  NodeId create_array_variable(const NodeId& nodeId, Array<int32_t> values)
  {
    create_variable(nodeId, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
    auto variable = mVariables.at(nodeId);
    variable.set_value_rank(ValueRank{1});
    const auto written = variable.try_write_value_sync(DataValue{Variant{std::move(values)}});
    EXPECT_TRUE(written.is_good()) << "writing the array to " << nodeId.as_definition() << ": "
                                   << to_string(written.status_code());
    return nodeId;
  }

  /// N's model for the deadband DataType arms: a DataType D, a subtype of Double; four Variables of D and
  /// four Variables of Double, each holding 0.0.
  struct DeadbandModel
  {
    NodeId d;
    std::vector<NodeId> ofD;
    std::vector<NodeId> ofDouble;
  };

  DeadbandModel create_deadband_model(uint16_t index)
  {
    DeadbandModel model;
    model.d = NodeId{index, uint32_t{50}};
    create_double_subtype(model.d);
    for (uint32_t i = 0; i < 4; ++i)
    {
      model.ofD.push_back(create_variable(NodeId{index, 100 + i}, model.d, DataValue{Variant{0.0}}));
      model.ofDouble.push_back(
        create_variable(NodeId{index, 200 + i}, NodeId{DataTypeId::Double}, DataValue{Variant{0.0}}));
    }
    return model;
  }

  /// One AbsoluteDeadband item of 1.0 on each of @p variables, client handles from 1.
  static std::vector<MonitoredItemCreateRequest> absolute_deadband_items(const std::vector<NodeId>& variables)
  {
    std::vector<MonitoredItemCreateRequest> items;
    for (std::size_t i = 0; i < variables.size(); ++i)
    {
      items.push_back(value_item(variables[i], static_cast<uint32_t>(1 + i), 5, absolute_deadband(1.0)));
    }
    return items;
  }
};

class ModifyFlow : public MonitoringFlow
{};

inline constexpr auto uncertainAnswer = Status::UncertainNoCommunicationLastUsableValue;

/// Expects @p status to be the refusal of a row whose lookup was answered Uncertain.
inline void expect_uncertain_lookup_refusal(const StatusCode& status, const std::string& row)
{
  EXPECT_EQ(status.as_status(), Status::BadInternalError) << row << ": " << to_string(status);
  EXPECT_EQ(detail_code(status), "LookupAnswerUncertain") << row << ": " << to_string(status);
  EXPECT_EQ(detail_cause(status), StatusCode{uncertainAnswer}.value())
    << row << ": the ErrorDetail's cause is not the Uncertain answer";
}

}  // namespace ua::test::create_flow

#endif  // UA_TEST_CREATE_FLOW_FIXTURE_H
