// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The client A&C surface driven against a REAL server, end to end.
///
/// The `ClientAlarm*` / `ClientConditionRefresh*` matrix clusters (75 rows across four files) drive the
/// tier-2 alarm machinery through an in-process hook interface: real subscriber, real tracker, real strand -
/// but no server, no wire, and no server-evaluated WhereClause. That is a deliberate trade for control
/// over event CONTENT, and it is also why several defects survived those rows: a WhereClause the server
/// never matched, a BranchId decoded as the wrong type, a ContentFilter whose sibling elements a
/// conforming server never evaluates. None of those are visible without a server.
///
/// These rows run the missing half: a real condition on a real server, a real subscription with a
/// server-evaluated filter, a real Publish, and the client's own decode - asserted through the public
/// API. They are the first A&C rows in the suite that fail if any hop in that chain breaks.
///
/// Four layers are covered. The EVENT path first (subscribe, server-evaluated filter, decode, deliver);
/// then the `AlarmConditionTracker` model built on it (a condition the server activates appearing in the
/// tracker's public list, and ConditionRefresh completing on its own RefreshEnd - including a refresh
/// that recovers state which changed before this client existed, which is the only mechanism that can);
/// then the METHOD surface (acknowledge, confirm, comment, enable/disable travelling to the server and
/// the resulting transition coming back); and finally LIMIT alarms, whose state the server computes from
/// a bound input rather than being handed it by a posted event.
///
/// What stays at the interface, and why - so nobody reads the remaining matrix rows as unconverted work:
///   - wire-ARGUMENT shape (which ObjectId, which MethodId, null vs empty-text LocalizedText). A live
///     server answers Good either way; only a recording wire can see what was sent.
///   - server MISBEHAVIOUR (a Bad the server would not return, a stray or malformed event). Driving it
///     needs a server built to misbehave, which is what the interface is.
///   - BRANCHES. Branch support is optional and this server emits none, so branch rows have no live
///     counterpart until it does.
///   - features the client does not have (the unbuilt method cache), which no server can exercise.
///
/// Two ordering facts these rows depend on, learned the hard way and stated so the next author does not
/// re-derive them: the tracker's attach is asynchronous, and `EventSubscriberInfo::trackerCount` is
/// republished by the same completion that hands the tracker its backbone SubscriptionId - so it is the
/// public signal that ConditionRefresh has the Mandatory argument it needs. And a condition's SOURCE
/// needs the SubscribeToEvents EventNotifier bit plus a `HasNotifier` edge from the Server Object, or
/// its events reach no subscriber at all.

#include "misbehaving_server.h"
#include "test_utilities.h"
#include "helpers/access_control_test_support.h"

#include "ua_access_level_type.h"
#include "ua_alarm_condition_logic.h"
#include "ua_attribute_id.h"
#include "ua_client.h"
#include "ua_condition_instance.h"
#include "ua_alarm_condition_tracker.h"
#include "ua_conditions.h"
#include "ua_connection.h"
#include "ua_content_filter_element.h"
#include "ua_event_filter.h"
#include "ua_event_notifier_type.h"
#include "ua_instance_utils.h"
#include "ua_datatype_id.h"
#include "ua_limit_alarm_logic.h"
#include "ua_literal_operand.h"
#include "ua_method_id.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_simple_attribute_operand.h"
#include "ua_typed_access.h"

#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"

namespace
{
using namespace std::chrono_literals;

using ua::LogLevel;
using ua::NodeId;
using ua::String;
using ua::client::Client;

/// Polls @p predicate until it holds or the deadline passes. Delivery is asynchronous from the server's
/// own strand through a Publish, so arrival is bounded-polled rather than slept on.
template<class Predicate>
bool wait_until(Predicate predicate, std::chrono::milliseconds timeout = 10s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(25ms);
  }
  return predicate();
}

/// The eight Mandatory BaseEventType select clauses (OPC 10000-5 6.4.2, Table 23). A filter without them
/// is refused `Bad_EventFilterInvalid`, so every subscription here carries them.
void add_mandatory_select_clauses(ua::EventFilter& filter)
{
  for (const auto* name :
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"})
  {
    ua::SimpleAttributeOperand clause;
    clause.type_definition_id() = NodeId{ua::ObjectTypeId::BaseEventType};
    clause.browse_path().push_back(ua::QualifiedName{0, name});
    clause.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    filter.select_clauses().push_back(std::move(clause));
  }
}

/// Appends an `OfType(typeId)` WhereClause. A single element is its own root, which is the shape a
/// one-type filter takes (OPC 10000-4 7.4.1: `elements[0]` is the root of the tree).
void add_of_type(ua::EventFilter& filter, const NodeId& typeId)
{
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{typeId};
  ua::ContentFilterElement element;
  element.filter_operator() = ua::FilterOperator::OfType;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  filter.where_clause().elements().push_back(std::move(element));
}

/// Thread-safe record of what one consumer received.
class EventRecord
{
public:
  void record(const ua::client::EventNotification& event)
  {
    const std::lock_guard lock(mMutex);
    mTypes.push_back(event.eventTypeId);
  }

  [[nodiscard]] std::size_t count() const
  {
    const std::lock_guard lock(mMutex);
    return mTypes.size();
  }

  [[nodiscard]] std::vector<NodeId> types() const
  {
    const std::lock_guard lock(mMutex);
    return mTypes;
  }

private:
  mutable std::mutex mMutex;
  std::vector<NodeId> mTypes;
};

/// A real server with an event SOURCE wired for subscription, and a real client connected to it through
/// the tier-1 managed connect. The conditions themselves belong to the derived fixtures: an
/// acknowledgeable alarm for the method and model rows, a limit alarm driven by a bound input for the
/// limit-state rows.
class LiveServerFixture
{
public:
  LiveServerFixture()
  {
    auto& server = mServer.server();
    auto addressSpace = server.address_space();
    // The fixture's own namespace declares its permissions: Part 3 8.55 gates Event delivery on the
    // SourceNode as well as the EventTypeId, and this fixture's event source is a node IN this
    // namespace. A namespace that declares nothing publishes an empty default and grants no Role
    // anything, so the source would deny every Event however the ns=0 EventType subject is stamped.
    ua::RolePermissionType adminPermissions;
    adminPermissions.role_id() = ua::NodeId{ua::ObjectId::WellKnownRole_SecurityAdmin};
    adminPermissions.permissions() = ua::test_helpers::all_permissions();
    mNamespaceIndex = addressSpace.add_namespace_sync(addressSpace.create_namespace(
      "urn:test:live-alarms", std::vector<ua::RolePermissionType>{adminPermissions}, std::nullopt));

    // The condition needs a SOURCE the server routes its events through: an Object carrying the
    // SubscribeToEvents EventNotifier bit and linked to the Server Object by HasNotifier. Without that
    // link the events never reach the Server notifier a client subscribes to, and the whole chain is
    // silent with every individual piece working (OPC 10000-3 5.9.2).
    mSourceId = NodeId{mNamespaceIndex, std::uint32_t{6000}};
    auto sourceNode = addressSpace.create_node_sync(mSourceId, ua::NodeClass::Object);
    auto sourceObject = sourceNode.as<ua::ObjectAccessor>();
    sourceObject->set_browse_name(ua::QualifiedName{mNamespaceIndex, "LiveAlarmSource"});
    sourceObject->set_display_name(ua::LocalizedText{"", "LiveAlarmSource"});
    sourceObject->set_event_notifier(ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});
    sourceNode.add_reference_sync(
      NodeId{ua::ReferenceTypeId::HasTypeDefinition}, NodeId{ua::ObjectTypeId::BaseObjectType});
    addressSpace.find_node_sync(NodeId{ua::ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, mSourceId);
    addressSpace.find_node_sync(NodeId{ua::ObjectId::Server})
      .add_reference_sync(NodeId{ua::ReferenceTypeId::HasNotifier}, mSourceId);

    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = mServer.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
      {
        appConfig.application_description_part().applicationUri = sanUris.front();
      }
    }
    ua::client::CreateConfig clientConfig{
      .identity = ua::ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.get_executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = mServer.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    ua::client::ConnectionConfig connectionConfig;
    connectionConfig.endpointUrl = mServer.endpoint_url_none();
    mConnection = mClient->connect_sync(connectionConfig);
  }

  virtual ~LiveServerFixture()
  {
    // Close before the pool joins: a live Connection keeps a keep-alive timer and an outstanding Publish
    // armed, and the drain guard reports those as a hang rather than letting them leak.
    mItems.clear();
    if (mConnection.has_value())
    {
      mConnection->close_sync();
      mConnection.reset();
    }
    if (mClient.has_value())
    {
      mClient->shutdown_sync();
      mClient.reset();
    }
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  LiveServerFixture(const LiveServerFixture&) = delete;
  LiveServerFixture& operator=(const LiveServerFixture&) = delete;

  /// The tier-2 tracker handle. `Connection::alarms()` constructs it lazily and its attach is
  /// asynchronous, so callers must gate on @ref wait_for_tracker_attached before driving it.
  ua::client::AlarmConditionTracker tracker()
  {
    return mConnection->alarms();
  }

  /// Blocks until the tracker is ATTACHED to a created backbone.
  ///
  /// `trackerCount` is republished by the same completion that publishes the backbone's SubscriptionId to
  /// the tracker, so it is the public signal that ConditionRefresh has the one Mandatory argument it needs
  /// (OPC 10000-9 5.5.7, Table 20). Gating on it is what makes these rows deterministic: a fixed sleep
  /// either races the create - and reports a real failure as a timing problem - or wastes the difference.
  [[nodiscard]] bool wait_for_tracker_attached()
  {
    auto subscriber = mConnection->events();
    return wait_until(
      [&subscriber]
      {
        const auto info = subscriber.info();
        return info != nullptr && info->trackerCount > 0 && info->backboneCount > 0;
      });
  }

  /// The tracker's current list, read through the public async surface off the executor.
  std::vector<ua::client::TrackedCondition> list(ua::client::AlarmConditionTracker& tracker)
  {
    std::promise<ua::Result<std::vector<ua::client::TrackedCondition>>> promise;
    auto future = promise.get_future();
    tracker.list_conditions_async([&promise](ua::Result<std::vector<ua::client::TrackedCondition>> result)
      { promise.set_value(std::move(result)); });
    auto result = future.get();
    return result.is_good() ? result.value() : std::vector<ua::client::TrackedCondition>{};
  }

  /// Blocking ConditionRefresh through the public handle, retried while a refresh is already in flight.
  ///
  /// The SDK issues its OWN refresh as soon as the backbone delivers a first event, so an operator
  /// pressing refresh early in a session can legitimately collide with it. `Bad_RefreshInProgress` is the
  /// documented answer to that collision and means "not now", not "failed" - an application with a
  /// refresh button either disables it until the window closes or retries, and so does this helper. What
  /// the rows assert is unchanged: a refresh must eventually COMPLETE, on its own RefreshEnd.
  ua::VoidResult refresh(ua::client::AlarmConditionTracker& tracker)
  {
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    ua::VoidResult last{ua::Status::BadTimeout};
    while (std::chrono::steady_clock::now() < deadline)
    {
      std::promise<ua::VoidResult> promise;
      auto future = promise.get_future();
      tracker.refresh_async([&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
      if (future.wait_for(20s) != std::future_status::ready)
      {
        return ua::VoidResult{ua::Status::BadTimeout};
      }
      last = future.get();
      if (last.is_good() || last.status_code().as_status() != ua::Status::BadRefreshInProgress)
      {
        return last;
      }
      std::this_thread::sleep_for(100ms);
    }
    return last;
  }

  /// Subscribes through the public tier-2 surface. The MonitoredItem handle is retained by the fixture:
  /// dropping it would unsubscribe and the row would measure nothing.
  ua::client::SubscribeResult subscribe(ua::EventFilter filter, EventRecord& record)
  {
    ua::client::EventSubscription subscription;
    subscription.notifier = NodeId{ua::ObjectId::Server};
    subscription.requestDedicatedBackbone = true;  // this consumer's filter is the one on the wire
    subscription.filter = std::move(filter);
    auto events = mConnection->events();
    auto result = events.try_subscribe_sync(
      subscription, [&record](ua::client::EventNotification event) { record.record(event); });
    if (result.is_good())
    {
      mItems.push_back(result.value());
    }
    return result;
  }

  /// The live Connection, for the rows that need the raw Call service rather than a tier-2 wrapper.
  ua::client::Connection& connection()
  {
    return *mConnection;
  }

  /// The NodeId of @p parent's HasComponent child named @p browseName, resolved on the SERVER's own
  /// address space. A row that needs an instance-level method node has no client-side way to name it.
  NodeId server_child(const NodeId& parent, const char* browseName)
  {
    std::promise<ua::NodeIdResult> promise;
    auto future = promise.get_future();
    ua::instance_utils::find_child_id_by_browse_name_async(mServer.server().address_space(),
      parent,
      NodeId{ua::ReferenceTypeId::HasComponent},
      ua::QualifiedName{0, browseName},
      [&promise](ua::NodeIdResult result) { promise.set_value(std::move(result)); });
    auto result = future.get();
    return result.is_good() ? result.value() : NodeId{};
  }

  /// Calls @p method on @p object and returns the status that actually decided the outcome. A Call has
  /// THREE nested statuses - the service Result, the per-operation CallResult, and the
  /// CallMethodResult - and a method that refused reports it on the innermost one while the outer two
  /// stay Good, so asserting on the outer Result alone reads a refusal as a success.
  ua::StatusCode call_status(const NodeId& object, const NodeId& method)
  {
    auto outcome = mConnection->typed().try_call_method_sync(object, method, {});
    if (outcome.is_bad())
    {
      return outcome.status_code();
    }
    if (outcome.value().is_bad())
    {
      return outcome.value().status_code();
    }
    return outcome.value().value().status_code();
  }

  /// The tracked entry for @p conditionId, or nullopt while it has not arrived. A fixture carrying more
  /// than one condition cannot read `list().front()` and assume which one it got.
  std::optional<ua::client::TrackedCondition> find(
    ua::client::AlarmConditionTracker& tracker, const NodeId& conditionId)
  {
    for (auto& entry : list(tracker))
    {
      if (entry.key.conditionId == conditionId)
      {
        return entry;
      }
    }
    return std::nullopt;
  }

  /// Runs @p method through the tracker and blocks for its outcome. Every tier-2 alarm method is
  /// callback-canonical, so each row would otherwise repeat the same promise/future dance.
  template<class Method>
  ua::VoidResult call(Method method)
  {
    std::promise<ua::VoidResult> promise;
    auto future = promise.get_future();
    method([&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
    if (future.wait_for(20s) != std::future_status::ready)
    {
      return ua::VoidResult{ua::Status::BadTimeout};
    }
    return future.get();
  }

protected:
  ua::test_helpers::MisbehavingServer mServer;
  std::uint16_t mNamespaceIndex = 0;
  NodeId mSourceId;

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<ua::client::Connection> mConnection;
  std::vector<ua::client::MonitoredItem> mItems;
};

/// The server carries ONE acknowledgeable alarm, with every optional sub-state the tier-2 method surface
/// can drive enabled: Confirm, Suppress, OutOfService and Silence are all Optional on
/// AlarmConditionType, and a server that does not support one answers its method with a Bad rather than
/// performing the transition, which would make those rows measure the refusal instead of the round trip.
class LiveAlarmFixture : public LiveServerFixture
{
public:
  LiveAlarmFixture()
  {
    auto alarmLogic = std::make_unique<ua::AlarmConditionLogic>();
    alarmLogic->set_supports_confirm(true);
    alarmLogic->set_supports_suppressed(true);
    alarmLogic->set_supports_out_of_service(true);
    alarmLogic->set_supports_silence(true);
    mAlarm = mServer.server().conditions().create_condition_sync(NodeId{mNamespaceIndex, std::uint32_t{0}},
      mSourceId,
      String{"LiveAlarm"},
      std::move(alarmLogic),
      NodeId{ua::ObjectTypeId::AlarmConditionType});
    mAlarm->enable_sync();
  }

  ua::ConditionInstance& alarm()
  {
    return *mAlarm;
  }

  [[nodiscard]] NodeId alarm_id() const
  {
    return mAlarm->condition_id();
  }

private:
  std::shared_ptr<ua::ConditionInstance> mAlarm;
};

/// The server carries a limit alarm bound to a Double input Variable, so the rows drive the alarm the way
/// a process does - by writing a value - and the server's own limit evaluation decides the state. The
/// exclusive/non-exclusive choice is per-fixture because the two models are different types
/// (OPC 10000-9 5.8.16/5.8.17) with different state representations.
class LiveLimitAlarmFixture : public LiveServerFixture
{
public:
  explicit LiveLimitAlarmFixture(bool exclusive)
  {
    auto addressSpace = mServer.server().address_space();
    mInputId = NodeId{mNamespaceIndex, std::uint32_t{6100}};
    auto inputNode = addressSpace.create_node_sync(mInputId, ua::NodeClass::Variable);
    auto inputVariable = inputNode.as<ua::VariableAccessor>();
    inputVariable->set_browse_name(ua::QualifiedName{mNamespaceIndex, "LiveLimitInput"});
    inputVariable->set_display_name(ua::LocalizedText{"", "LiveLimitInput"});
    inputVariable->set_data_type(NodeId{ua::DataTypeId::Double});
    inputVariable->write_value_sync(50.0);
    inputVariable->set_access_level(
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ua::ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, mInputId);

    auto limitLogic = std::make_unique<ua::LimitAlarmLogic>();
    limitLogic->set_exclusive(exclusive);
    ua::LimitConfig limits;
    limits.highHighLimit = 90.0;
    limits.highLimit = 70.0;
    limits.lowLimit = 30.0;
    limits.lowLowLimit = 10.0;
    limitLogic->set_limits(limits);
    mAlarm = mServer.server().conditions().create_condition_sync(NodeId{mNamespaceIndex, std::uint32_t{0}},
      mSourceId,
      String{"LiveLimitAlarm"},
      std::move(limitLogic),
      exclusive ? NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType}
                : NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType});
    mAlarm->enable_sync();
    mAlarm->bind_input_sync(mInputId, sInputSamplingMs);
  }

  /// Writes the bound input. The server samples it on its own interval, so every row that writes must
  /// then wait for the resulting state rather than read back immediately.
  void write_input(double value)
  {
    mServer.server().address_space().find_node_sync(mInputId).as<ua::VariableAccessor>()->write_value_sync(
      value);
  }

  [[nodiscard]] NodeId alarm_id() const
  {
    return mAlarm->condition_id();
  }

private:
  /// Fast enough that a row's write is evaluated well inside the 10s poll bound, slow enough to stay a
  /// sampled input rather than an edge-triggered one.
  static constexpr double sInputSamplingMs = 100.0;

  NodeId mInputId;
  std::shared_ptr<ua::ConditionInstance> mAlarm;
};

// The chain, end to end: a condition on a real server changes state, the server evaluates the
// subscription's WhereClause and publishes, and the client decodes the event and delivers it. Every hop
// is real; the interface-level A&C rows exercise none of them.
TEST(ClientAlarmLiveServer, ServerConditionEventReachesTheClient)
{
  LiveAlarmFixture fixture;
  EventRecord received;

  ua::EventFilter filter;
  add_mandatory_select_clauses(filter);
  add_of_type(filter, NodeId{ua::ObjectTypeId::ConditionType});
  ASSERT_TRUE(fixture.subscribe(std::move(filter), received).is_good())
    << "an OfType(ConditionType) filter carrying the eight mandatory clauses must be accepted";

  fixture.alarm().activate_sync(700);

  ASSERT_TRUE(wait_until([&received] { return received.count() > 0; }))
    << "an activated server condition must reach a subscribed client";
}

// OfType is subtype-inclusive (OPC 10000-4 7.7.3, Table 123), and this row proves the SERVER honours it:
// the subscription names ConditionType, the event is an AlarmConditionType - two HasSubtype hops below
// it - and it must still arrive. A server implementing OfType as an equality test passes every other row
// in this file and fails this one.
TEST(ClientAlarmLiveServer, SupertypeFilterAdmitsTheAlarmSubtype)
{
  LiveAlarmFixture fixture;
  EventRecord viaSupertype;
  EventRecord viaExactType;

  ua::EventFilter supertypeFilter;
  add_mandatory_select_clauses(supertypeFilter);
  add_of_type(supertypeFilter, NodeId{ua::ObjectTypeId::ConditionType});
  ASSERT_TRUE(fixture.subscribe(std::move(supertypeFilter), viaSupertype).is_good());

  ua::EventFilter exactFilter;
  add_mandatory_select_clauses(exactFilter);
  add_of_type(exactFilter, NodeId{ua::ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(fixture.subscribe(std::move(exactFilter), viaExactType).is_good());

  fixture.alarm().activate_sync(700);

  ASSERT_TRUE(wait_until([&viaExactType] { return viaExactType.count() > 0; }))
    << "precondition: the exact-type consumer receives its own event";
  ASSERT_TRUE(wait_until([&viaSupertype] { return viaSupertype.count() > 0; }))
    << "a supertype filter must admit the subtype - this is what lets one subscription cover a family";

  const auto types = viaSupertype.types();
  ASSERT_FALSE(types.empty());
  EXPECT_EQ(types.front(), NodeId{ua::ObjectTypeId::AlarmConditionType})
    << "and the event arrives as its own concrete type, not as the type that was subscribed to";
}

// A filter naming an unrelated family must NOT receive the alarm. Without this row the two above would
// also pass against a server that ignored the WhereClause entirely and delivered everything to everyone.
TEST(ClientAlarmLiveServer, UnrelatedTypeFilterDoesNotReceiveTheAlarm)
{
  LiveAlarmFixture fixture;
  EventRecord unrelated;
  EventRecord conditions;

  ua::EventFilter unrelatedFilter;
  add_mandatory_select_clauses(unrelatedFilter);
  add_of_type(unrelatedFilter, NodeId{ua::ObjectTypeId::DeviceFailureEventType});
  ASSERT_TRUE(fixture.subscribe(std::move(unrelatedFilter), unrelated).is_good());

  ua::EventFilter conditionFilter;
  add_mandatory_select_clauses(conditionFilter);
  add_of_type(conditionFilter, NodeId{ua::ObjectTypeId::ConditionType});
  ASSERT_TRUE(fixture.subscribe(std::move(conditionFilter), conditions).is_good());

  fixture.alarm().activate_sync(700);

  ASSERT_TRUE(wait_until([&conditions] { return conditions.count() > 0; }))
    << "precondition: the condition consumer received the event";
  EXPECT_EQ(unrelated.count(), 0U) << "a WhereClause naming an unrelated family must exclude the alarm";
}

// A second state change must produce a second event, which is what makes this a live feed rather than a
// single replay at subscribe time.
TEST(ClientAlarmLiveServer, EveryConditionStateChangeProducesAnEvent)
{
  LiveAlarmFixture fixture;
  EventRecord received;

  ua::EventFilter filter;
  add_mandatory_select_clauses(filter);
  add_of_type(filter, NodeId{ua::ObjectTypeId::ConditionType});
  ASSERT_TRUE(fixture.subscribe(std::move(filter), received).is_good());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&received] { return received.count() >= 1; })) << "the activation must arrive";

  fixture.alarm().deactivate_sync();
  EXPECT_TRUE(wait_until([&received] { return received.count() >= 2; }))
    << "a second state change must produce a second event on the same subscription";
}

// =====================================================================================================
// The TRACKER against a real server. The 75 interface-level rows drive this model by posting events onto its
// strand; these drive it the way an application does - server state changes, and the model follows.
// =====================================================================================================

// The model, end to end: a condition activates on the server and appears in the tracker's public list
// with its sub-states decoded. This is the row every A&C defect of this campaign would have failed -
// the unmatched WhereClause, the ByteString BranchId, the subtype demux, the sibling-element filter.
TEST(ClientAlarmLiveServer, TrackerListsAConditionTheServerActivated)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached())
    << "the tracker must be attached to a created backbone before the server emits";

  fixture.alarm().activate_sync(700);

  ASSERT_TRUE(wait_until([&] { return !fixture.list(tracker).empty(); }))
    << "an activated server condition must reach the tracker's model through a real subscription";

  const auto conditions = fixture.list(tracker);
  ASSERT_FALSE(conditions.empty());
  const auto& entry = conditions.front();
  EXPECT_TRUE(entry.key.branchId.is_null()) << "the live state is the trunk entry, not a branch";
  EXPECT_TRUE(entry.retain) << "a condition requiring operator attention is retained";
  ASSERT_TRUE(entry.activeState.has_value())
    << "ActiveState is what makes an alarm an alarm; an absent one means the decode missed it";
  ASSERT_TRUE(entry.activeState->id.has_value());
  EXPECT_TRUE(*entry.activeState->id);
  EXPECT_EQ(entry.severity, 700u);
}

// Acknowledging through the tracker handle must reach the server and come back as a state change on the
// SAME entry - which is only possible if the call carried the EventId the tracker recorded for it
// (OPC 10000-9 5.7.2: acknowledgement is keyed by EventId, not by condition).
TEST(ClientAlarmLiveServer, TrackerAcknowledgeReachesTheServerAndComesBack)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto conditions = fixture.list(tracker);
      return !conditions.empty() && conditions.front().ackedState.has_value() &&
             conditions.front().ackedState->id.has_value() && !*conditions.front().ackedState->id;
    }))
    << "precondition: the entry arrives unacknowledged";

  const auto key = fixture.list(tracker).front().key;
  std::promise<ua::VoidResult> acknowledged;
  auto future = acknowledged.get_future();
  tracker.acknowledge_async(key,
    ua::LocalizedText{"", "acknowledged by the live-server row"},
    [&acknowledged](ua::VoidResult result) { acknowledged.set_value(std::move(result)); });
  const auto outcome = future.get();
  ASSERT_TRUE(outcome.is_good()) << "acknowledge must reach the server: 0x" << std::hex
                                 << outcome.status_code().as_uint32();

  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto conditions = fixture.list(tracker);
      return !conditions.empty() && conditions.front().ackedState.has_value() &&
             conditions.front().ackedState->id.has_value() && *conditions.front().ackedState->id;
    }))
    << "the acknowledgement must come back as a state change on the same entry";
}

// ConditionRefresh over a real subscription: the tracker supplies the Mandatory SubscriptionId of the
// subscription its own backbone is monitored on, the server replays every retained condition bracketed
// by RefreshStart / RefreshEnd, and the callback completes only when that window closes. A tracker that
// never learned its SubscriptionId fails Bad_InvalidState here; one whose bracket events are filtered
// out by its own WhereClause never completes at all.
TEST(ClientAlarmLiveServer, TrackerRefreshCompletesOnItsRefreshEnd)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(650);
  ASSERT_TRUE(wait_until([&] { return !fixture.list(tracker).empty(); }))
    << "precondition: a retained condition exists to replay";

  const auto refreshed = fixture.refresh(tracker);
  EXPECT_TRUE(refreshed.is_good()) << "the refresh must complete on its RefreshEnd: 0x" << std::hex
                                   << refreshed.status_code().as_uint32();
  EXPECT_FALSE(fixture.list(tracker).empty())
    << "the replay must leave the retained condition in the list, not clear it";
}

// A refresh is what recovers state that changed while nobody was listening (OPC 10000-9 4.5). The
// condition here is activated BEFORE the tracker attaches, so the only way it can appear is the replay.
TEST(ClientAlarmLiveServer, TrackerRefreshRecoversStateThatPredatesIt)
{
  LiveAlarmFixture fixture;
  fixture.alarm().activate_sync(800);  // nobody is subscribed yet

  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  const auto refreshed = fixture.refresh(tracker);
  ASSERT_TRUE(refreshed.is_good()) << "0x" << std::hex << refreshed.status_code().as_uint32();

  EXPECT_TRUE(wait_until([&] { return !fixture.list(tracker).empty(); }))
    << "a refresh must replay a condition that was already active before this client existed";
}

// A second refresh after the first completes must be accepted: Bad_RefreshInProgress is for a refresh
// still awaiting its end, and a window that closed correctly leaves no residue to latch on.
TEST(ClientAlarmLiveServer, TrackerAcceptsASecondRefreshAfterTheFirstCompletes)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());
  fixture.alarm().activate_sync(500);
  ASSERT_TRUE(wait_until([&] { return !fixture.list(tracker).empty(); }));

  for (int attempt = 0; attempt < 2; ++attempt)
  {
    const auto refreshed = fixture.refresh(tracker);
    EXPECT_TRUE(refreshed.is_good()) << "refresh " << attempt
                                     << " must complete; a latched window would refuse this one: 0x"
                                     << std::hex << refreshed.status_code().as_uint32();
  }
}

// =====================================================================================================
// The tier-2 METHOD surface against a real server. The interface rows assert the wire ARGUMENTS a wrapper
// builds; these assert that a conforming server ACCEPTS them and that the resulting state change comes
// back. A wrapper can build a perfectly-shaped Call to a MethodId the server does not have.
// =====================================================================================================

// OPC 10000-9 5.7.2: an acknowledgement is keyed by the EventId of the event being acknowledged. This row
// sends one the server never issued, and the server's own rejection must arrive verbatim - not swallowed
// to Good, and not remapped to a generic client error.
TEST(ClientAlarmLiveServer, AcknowledgeWithAnUnknownEventIdIsRefusedByTheServer)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));

  const auto key = fixture.find(tracker, fixture.alarm_id())->key;
  const auto outcome = fixture.call(
    [&](auto callback)
    {
      tracker.acknowledge_async(
        key, ua::ByteString{0xDE, 0xAD, 0xBE, 0xEF}, std::nullopt, std::move(callback));
    });

  EXPECT_TRUE(outcome.is_bad()) << "an EventId the server never issued must not be accepted";
  EXPECT_EQ(outcome.status_code().as_status(), ua::Status::BadEventIdUnknown)
    << "the server's own status must surface verbatim, not be remapped: 0x" << std::hex
    << outcome.status_code().as_uint32();
}

// The already-acknowledged gate is a CLIENT-side short-circuit, but it is only correct if the state it
// reads came from the server. Here the first acknowledgement is real, and the second is refused locally
// on the AckedState the server sent back.
TEST(ClientAlarmLiveServer, AcknowledgingAnAlreadyAcknowledgedBranchIsRefusedLocally)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  const auto first =
    fixture.call([&](auto callback) { tracker.acknowledge_async(key, std::nullopt, std::move(callback)); });
  ASSERT_TRUE(first.is_good()) << "precondition: the first acknowledgement reaches the server: 0x" << std::hex
                               << first.status_code().as_uint32();
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->ackedState.has_value() && entry->ackedState->id.value_or(false);
    }))
    << "precondition: the acknowledged state comes back from the server";

  const auto second =
    fixture.call([&](auto callback) { tracker.acknowledge_async(key, std::nullopt, std::move(callback)); });
  EXPECT_EQ(second.status_code().as_status(), ua::Status::BadConditionBranchAlreadyAcked)
    << "a second acknowledgement of the same branch is refused on the server-reported state: 0x" << std::hex
    << second.status_code().as_uint32();
}

// Confirm is a separate step from Acknowledge (OPC 10000-9 5.7.3): a confirmable alarm is acknowledged
// first, and only then confirmed. Both transitions must appear on the SAME tracked entry.
TEST(ClientAlarmLiveServer, ConfirmFollowsAcknowledgeOnTheSameEntry)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  ASSERT_TRUE(
    fixture.call([&](auto callback) { tracker.acknowledge_async(key, std::nullopt, std::move(callback)); })
      .is_good());
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->ackedState.has_value() && entry->ackedState->id.value_or(false);
    }));

  const auto confirmed =
    fixture.call([&](auto callback) { tracker.confirm_async(key, std::nullopt, std::move(callback)); });
  ASSERT_TRUE(confirmed.is_good()) << "confirm must reach the server: 0x" << std::hex
                                   << confirmed.status_code().as_uint32();

  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->confirmedState.has_value() &&
             entry->confirmedState->id.value_or(false);
    }))
    << "the confirmation must come back on the same entry the acknowledgement did";
}

// AddComment carries an operator's text to the server (OPC 10000-9 5.5.4). The tracker models no Comment
// sub-state, so the observable here is the round trip itself: the server accepts the Call and the entry
// survives it.
TEST(ClientAlarmLiveServer, AddCommentReachesTheServer)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto entry = *fixture.find(tracker, fixture.alarm_id());

  const auto outcome = fixture.call(
    [&](auto callback)
    {
      tracker.add_comment_async(entry.key,
        entry.lastEventId,
        ua::LocalizedText{"en", "commented by the live-server row"},
        std::move(callback));
    });
  EXPECT_TRUE(outcome.is_good()) << "a comment on a tracked event must be accepted: 0x" << std::hex
                                 << outcome.status_code().as_uint32();
  EXPECT_TRUE(fixture.find(tracker, fixture.alarm_id()).has_value())
    << "commenting must not remove the condition from the model";
}

// Disabling a condition takes it out of service (OPC 10000-9 5.5.2): the server stops retaining it and
// emits nothing further until it is re-enabled. Both halves are SERVER behaviour and neither is visible
// at the event interface - the interface is where the matrix rows post events - so this is the row that
// cluster could only pin half of.
TEST(ClientAlarmLiveServer, DisableStopsTheEventStreamAndEnableResumesIt)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  ASSERT_TRUE(
    fixture.call([&](auto callback) { tracker.disable_async(key, std::move(callback)); }).is_good());

  // A disabled condition needs no operator attention, so the server stops retaining it and the model
  // drops it - the same Retain rule that removes a resolved alarm.
  ASSERT_TRUE(wait_until([&] { return !fixture.find(tracker, fixture.alarm_id()).has_value(); }))
    << "a disabled condition must leave the model";

  // A state change while disabled must produce nothing at all: the entry must not reappear.
  fixture.alarm().deactivate_sync();
  fixture.alarm().activate_sync(900);
  std::this_thread::sleep_for(500ms);  // a negative claim needs a settle window, not a poll
  EXPECT_FALSE(fixture.find(tracker, fixture.alarm_id()).has_value())
    << "a disabled condition must emit no state events";

  ASSERT_TRUE(fixture.call([&](auto callback) { tracker.enable_async(key, std::move(callback)); }).is_good());
  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->enabledState.id.value_or(false);
    }))
    << "re-enabling must resume the stream, and the condition returns with its state";
}

// Suppress and Silence, driven through the tier-2 tracker against the real server.
//
// Both are OPTIONAL on AlarmConditionType (OPC 10000-9 Table 42), so the type model alone obliges a
// Server to nothing - but this Server declares the A & C Suppression Conformance Unit, and the
// transitions were already implemented on ConditionInstance and reachable only in-process. They are now
// installed against ConditionId, which is how 5.8.7/5.8.8/5.8.10 say a Client addresses them.
TEST(ClientAlarmLiveServer, SuppressAndUnsuppressTravelToTheServer)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  const auto suppressed =
    fixture.call([&](auto callback) { tracker.suppress_async(key, std::move(callback)); });
  ASSERT_TRUE(suppressed.is_good()) << "0x" << std::hex << suppressed.status_code().as_uint32();
  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->suppressedState.has_value() &&
             entry->suppressedState->id.value_or(false);
    }))
    << "the server must report the alarm suppressed";
  EXPECT_TRUE(fixture.find(tracker, fixture.alarm_id())->suppressedOrShelved.value_or(false))
    << "and suppression feeds the aggregate an operator display filters on";

  const auto unsuppressed =
    fixture.call([&](auto callback) { tracker.unsuppress_async(key, std::move(callback)); });
  ASSERT_TRUE(unsuppressed.is_good()) << "0x" << std::hex << unsuppressed.status_code().as_uint32();
  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->suppressedState.has_value() &&
             !entry->suppressedState->id.value_or(true);
    }))
    << "and clear it again on unsuppress";
}

// Silence stops an alarm sounding without changing whether it is active (OPC 10000-9 5.8.7) - a distinct
// sub-state from suppression, and one a client must not conflate with it.
TEST(ClientAlarmLiveServer, SilenceTravelsToTheServerWithoutSuppressing)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  const auto silenced = fixture.call([&](auto callback) { tracker.silence_async(key, std::move(callback)); });
  ASSERT_TRUE(silenced.is_good()) << "0x" << std::hex << silenced.status_code().as_uint32();
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->silenceState.has_value() && entry->silenceState->id.value_or(false);
    }))
    << "the server must report the alarm silenced";

  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_TRUE(entry.activeState.has_value() && entry.activeState->id.value_or(false))
    << "silencing must not deactivate the alarm";
  EXPECT_FALSE(entry.suppressedState.value_or(ua::client::TwoStateValue{}).id.value_or(false))
    << "silencing is not suppression";
}

// =====================================================================================================
// The tracker MODEL against a real server: lifecycle and typing decided by the server, not by a posted
// event.
// =====================================================================================================

// Retain is the server's statement that a condition still needs an operator (OPC 10000-9 5.5.2). An alarm
// that goes inactive and is fully acknowledged and confirmed no longer does, and the model must drop it -
// the client never decides this itself.
TEST(ClientAlarmLiveServer, RetainFalseRemovesTheConditionFromTheModel)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  ASSERT_TRUE(
    fixture.call([&](auto callback) { tracker.acknowledge_async(key, std::nullopt, std::move(callback)); })
      .is_good());
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->ackedState.has_value() && entry->ackedState->id.value_or(false);
    }));
  ASSERT_TRUE(
    fixture.call([&](auto callback) { tracker.confirm_async(key, std::nullopt, std::move(callback)); })
      .is_good());
  fixture.alarm().deactivate_sync();

  EXPECT_TRUE(wait_until([&] { return !fixture.find(tracker, fixture.alarm_id()).has_value(); }))
    << "a condition the server stops retaining must leave the model";
}

// Every condition carries a ConditionClassId and name (OPC 10000-9 5.5.2, Mandatory). They are how an
// operator display groups alarms by kind, and an absent one means the decode missed a Mandatory field.
TEST(ClientAlarmLiveServer, ConditionClassSurfacesOnTheTrackedEntry)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));

  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_FALSE(entry.conditionClassId.is_null())
    << "ConditionClassId is Mandatory; a null one means it was not decoded";
  EXPECT_EQ(entry.conditionClassId, NodeId{ua::ObjectTypeId::BaseConditionClassType})
    << "a condition with no more specific class reports the base class";
  EXPECT_FALSE(entry.sourceNode.is_null()) << "the event must name the source it came from";
}

// =====================================================================================================
// LIMIT alarms against a real server. The state here is computed by the SERVER from a bound input, so
// these rows exercise the one thing a posted event cannot: that the client's decode agrees with what a
// limit alarm actually emits.
// =====================================================================================================

// ExclusiveLimitAlarmType carries its state as a state MACHINE whose CurrentState names the single
// violated limit (OPC 10000-9 5.8.17). The client surfaces that name verbatim.
TEST(ClientAlarmLiveServer, ExclusiveLimitStateNamesTheViolatedLimit)
{
  LiveLimitAlarmFixture fixture{true};
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.write_input(95.0);  // above HighHigh (90)

  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->activeState.has_value() && entry->activeState->id.value_or(false);
    }))
    << "an input above HighHigh must activate the alarm on the server";

  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->exclusiveLimitState.has_value() &&
             std::string{entry->exclusiveLimitState->text()} == "HighHigh";
    }))
    << "the ExclusiveLimitStateMachine's CurrentState must reach the client as the limit it names";

  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_EQ(entry.highHighLimit, 90.0) << "the alarm's own thresholds travel with it";
  EXPECT_EQ(entry.highLimit, 70.0);
  EXPECT_EQ(entry.lowLimit, 30.0);
  EXPECT_EQ(entry.lowLowLimit, 10.0);
}

// An input returning to normal deactivates the alarm, and the limit state must not be left showing the
// limit that WAS violated - a stale LimitState is the failure this row exists to catch.
TEST(ClientAlarmLiveServer, ExclusiveLimitStateDoesNotPersistOnceTheInputIsNormal)
{
  LiveLimitAlarmFixture fixture{true};
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.write_input(95.0);
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->exclusiveLimitState.has_value() &&
             std::string{entry->exclusiveLimitState->text()} == "HighHigh";
    }))
    << "precondition: the alarm is in the HighHigh limit state";

  fixture.write_input(50.0);  // back between Low and High

  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->activeState.has_value() && !entry->activeState->id.value_or(true);
    }))
    << "an input back in range must deactivate the alarm";
  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_FALSE(
    entry.exclusiveLimitState.has_value() && std::string{entry.exclusiveLimitState->text()} == "HighHigh")
    << "the cleared alarm must not still report the limit it left";
}

// NonExclusiveLimitAlarmType represents its state as INDEPENDENT per-limit flags (OPC 10000-9 5.8.16), so
// High and HighHigh are concurrently active when the input passes both - the exclusive model's single
// CurrentState cannot express that, and a client that decoded one as the other would show the wrong one.
TEST(ClientAlarmLiveServer, NonExclusiveLimitAlarmReportsConcurrentHighAndHighHigh)
{
  LiveLimitAlarmFixture fixture{false};
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.write_input(95.0);  // past High (70) AND HighHigh (90)

  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->activeState.has_value() && entry->activeState->id.value_or(false);
    }))
    << "the alarm must activate on the server";

  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->highState.has_value() && entry->highState->id.value_or(false) &&
             entry->highHighState.has_value() && entry->highHighState->id.value_or(false);
    }))
    << "both high-group states are active at once; within-group concurrency is legal";

  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_FALSE(entry.lowState.value_or(ua::client::TwoStateValue{}).id.value_or(false))
    << "a high violation must not report a low state - that combination is the invalid one";
  EXPECT_FALSE(entry.exclusiveLimitState.has_value())
    << "a non-exclusive alarm has no ExclusiveLimitStateMachine to report";
}

// The tracker's default filter names ConditionType, and OfType is subtype-inclusive - so a limit alarm
// two hops below it must be tracked, and tracked AS ITS OWN TYPE. A client that recorded the subscribed
// type instead of the event's would show every alarm as a generic condition, losing exactly the
// information an operator display groups on.
TEST(ClientAlarmLiveServer, TrackerRecordsTheConcreteAlarmSubtype)
{
  LiveLimitAlarmFixture fixture{true};
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.write_input(95.0);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }))
    << "a subtype of ConditionType must reach a tracker filtering on ConditionType";

  const auto entry = *fixture.find(tracker, fixture.alarm_id());
  EXPECT_EQ(entry.conditionTypeId, NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType})
    << "the entry must carry the event's most-derived type, not the type that was subscribed to";
}

// Shelving is implemented, exposed AND callable the way OPC 10000-9 5.8.17 requires - including the
// mandatory ConditionId form:
//
//   "all Servers shall also allow Clients to call the OneShotShelve Method by specifying ConditionId as
//    the ObjectId where the ConditionId is the Condition that has the Shelving child"  (5.8.17.6, and
//    identically 5.8.17.2 Unshelve / 5.8.17.4 TimedShelve)
//
// Both forms work, and this row proves it. What fails is the tier-2 tracker's own wrappers, and this row
// is what localises that: they pass `MethodId::ShelvedStateMachineType_OneShotShelve` - the TYPE
// DECLARATION node - where the server registers, and the spec describes, the method node found on the
// INSTANCE's Shelving child. The server is not at fault; the client is asking for a method the condition
// does not have.
TEST(ClientAlarmLiveServer, ShelvingWorksInBothFormsTheSpecRequires)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));

  const NodeId shelvingState = fixture.server_child(fixture.alarm_id(), "ShelvingState");
  ASSERT_FALSE(shelvingState.is_null()) << "the instance must carry a ShelvingState object";
  const NodeId oneShotShelve = fixture.server_child(shelvingState, "OneShotShelve");
  ASSERT_FALSE(oneShotShelve.is_null())
    << "OneShotShelve is Mandatory on ShelvedStateMachineType (10000-9 Table 73)";

  // The form 5.8.17 calls "normal": the Shelving object as ObjectId, its own method node as MethodId.
  const auto viaShelvingState = fixture.call_status(shelvingState, oneShotShelve);
  EXPECT_TRUE(viaShelvingState.is_good()) << "0x" << std::hex << viaShelvingState.as_uint32();
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->suppressedOrShelved.value_or(false);
    }))
    << "the alarm really shelves - the server-side transition is complete, not just accepted";

  fixture.call_status(shelvingState, fixture.server_child(shelvingState, "Unshelve"));
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && !entry->suppressedOrShelved.value_or(true);
    }))
    << "precondition for the second form: the alarm is unshelved again";

  // The form 5.8.17 makes MANDATORY. Its MethodId is the well-known ShelvedStateMachineType node, not
  // the instance's: the clause exists precisely for Servers that do not expose Condition instances, and
  // a Client talking to one of those cannot name an instance method node either.
  const auto viaConditionId =
    fixture.call_status(fixture.alarm_id(), NodeId{ua::MethodId::ShelvedStateMachineType_OneShotShelve});
  EXPECT_TRUE(viaConditionId.is_good())
    << "the Call service must make the 5.8.17 exception for this pairing: 0x" << std::hex
    << viaConditionId.as_uint32();
  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->suppressedOrShelved.value_or(false);
    }))
    << "and it must perform the transition, not merely return Good";
}

// The exception is exactly as wide as the clause that mandates it, and no wider. 5.8.17.2/.4/.6 also
// say "The Method cannot be called with an ObjectId of the ShelvedStateMachineType Node", and the
// qualifier on the ConditionId form is "the Condition that HAS the Shelving child" - so an Object
// without one must still fail the Part 4 Table 65 pairing rule. Without these two, the exception would
// be indistinguishable from having relaxed that rule for every Call in the server.
TEST(ClientAlarmLiveServer, ShelvingRefusesTheTypeNodeAndObjectsWithoutAShelvingChild)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());
  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));

  const auto viaTypeNode = fixture.call_status(NodeId{ua::ObjectTypeId::ShelvedStateMachineType},
    NodeId{ua::MethodId::ShelvedStateMachineType_OneShotShelve});
  EXPECT_TRUE(viaTypeNode.is_bad()) << "5.8.17 forbids the ShelvedStateMachineType Node as the ObjectId: 0x"
                                    << std::hex << viaTypeNode.as_uint32();

  // The Server Object is a perfectly good Object with no Shelving child.
  const auto viaUnrelatedObject = fixture.call_status(
    NodeId{ua::ObjectId::Server}, NodeId{ua::MethodId::ShelvedStateMachineType_OneShotShelve});
  EXPECT_EQ(viaUnrelatedObject.as_status(), ua::Status::BadMethodInvalid)
    << "an Object with no Shelving child must still fail the pairing rule: 0x" << std::hex
    << viaUnrelatedObject.as_uint32();

  const auto entry = fixture.find(tracker, fixture.alarm_id());
  ASSERT_TRUE(entry.has_value());
  EXPECT_FALSE(entry->suppressedOrShelved.value_or(false)) << "a refused call must change nothing";
}

// The tier-2 shelve wrappers, end to end. This is what the ShelvedStateMachine method resolution buys:
// before it, every one of these calls asked the Condition for a Method declared on
// ShelvedStateMachineType and got Bad_MethodInvalid from any Server that checks the pairing.
TEST(ClientAlarmLiveServer, TrackerShelveAndUnshelveMoveTheAlarm)
{
  LiveAlarmFixture fixture;
  auto tracker = fixture.tracker();
  ASSERT_TRUE(fixture.wait_for_tracker_attached());

  fixture.alarm().activate_sync(700);
  ASSERT_TRUE(wait_until([&] { return fixture.find(tracker, fixture.alarm_id()).has_value(); }));
  const auto key = fixture.find(tracker, fixture.alarm_id())->key;

  const auto shelved =
    fixture.call([&](auto callback) { tracker.one_shot_shelve_async(key, std::move(callback)); });
  ASSERT_TRUE(shelved.is_good()) << "one-shot shelve must reach the server: 0x" << std::hex
                                 << shelved.status_code().as_uint32();
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && entry->suppressedOrShelved.value_or(false);
    }))
    << "a shelved alarm reports SuppressedOrShelved";

  const auto unshelved =
    fixture.call([&](auto callback) { tracker.unshelve_async(key, std::move(callback)); });
  ASSERT_TRUE(unshelved.is_good()) << "0x" << std::hex << unshelved.status_code().as_uint32();
  EXPECT_TRUE(wait_until(
    [&]
    {
      const auto entry = fixture.find(tracker, fixture.alarm_id());
      return entry.has_value() && !entry->suppressedOrShelved.value_or(true);
    }))
    << "and unshelving clears it";

  // The second shelve exercises the cached resolution rather than a fresh TranslateBrowsePaths.
  const auto reshelved =
    fixture.call([&](auto callback) { tracker.one_shot_shelve_async(key, std::move(callback)); });
  EXPECT_TRUE(reshelved.is_good()) << "the cached ShelvingState resolution must still address the "
                                      "method: 0x"
                                   << std::hex << reshelved.status_code().as_uint32();
}

}  // namespace
