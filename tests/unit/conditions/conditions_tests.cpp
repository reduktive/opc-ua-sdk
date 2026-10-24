// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "concrete_condition_type.h"
#include "ua_audit_event_payload.h"
#include "ua_conditions.h"
#include "ua_conditions_test_access.h"

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_address_space.h"
#include "instantiation/ua_instantiation_service.h"
#include "ua_instantiation_options.h"
#include "ua_node_subtree.h"
#include "ua_alarm_condition_payload.h"
#include "ua_alarm_condition_logic.h"
#include "ua_application_configuration.h"
#include "ua_audit_condition_enable_event_payload.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_condition_payload.h"
#include "ua_event_bus.h"
#include "ua_exclusive_limit_alarm_payload.h"
#include "ua_limit_alarm_logic.h"
#include "ua_method_id.h"
#include "ua_monitored_item.h"
#include "ua_node.h"
#include "ua_condition_logic.h"
#include "ua_condition_state_snapshot.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_sinks.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_refresh_end_event_payload.h"
#include "ua_refresh_start_event_payload.h"
#include "ua_status.h"
#include "ua_system_off_normal_alarm_payload.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

#include "fmt/format.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "test_log_sink.h"
#include "../address_space/scripted_node.h"

namespace ua::test
{

/// Simple fake EventSink that records emitted events.
///
/// Thread-safe: real EventBus delivery invokes `emit()` on a worker thread while
/// the test inspects the recorded events from the main thread, so every access to
/// `events` is guarded by a mutex. Use `wait_for_count()` to block until the
/// expected number of events has arrived and `with_events()`/`size()` to read
/// them race-free. (Synchronous-refresh tests that only touch the sink from a
/// single thread, after the sync call has returned, may read `events` directly.)
class ManagerFakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    // Assign an EventId like the real EventBus does.
    if (event.eventId.empty())
    {
      ++mNextId;
      event.eventId = ByteString{std::vector<uint8_t>{
        static_cast<uint8_t>(mNextId & 0xFF), static_cast<uint8_t>((mNextId >> 8) & 0xFF)}};
    }
    // Condition audit Events reach this sink too, and no test here is about them: the recorded
    // sequence is the Condition Event stream, and folding audits into it renumbers every index.
    if (dynamic_cast<ua::AuditEventPayload*>(&event) != nullptr)
    {
      auditEvents.push_back(event.clone());
      mCondition.notify_all();
      return;
    }
    events.push_back(event.clone());
    mCondition.notify_all();
  }

  std::vector<std::unique_ptr<ua::BaseEvent>> auditEvents;

  /// Thread-safe count of recorded events.
  size_t size() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return events.size();
  }

  /// Block until at least `count` events have been recorded or `timeout`
  /// elapses; returns the number observed (>= `count` on success).
  size_t wait_for_count(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    mCondition.wait_for(lock, timeout, [&] { return events.size() >= count; });
    return events.size();
  }

  /// Block until `predicate`, given the recorded events, holds or `timeout`
  /// elapses; returns whether it held. For a test that waits for an Event to
  /// arrive: a sanitized or loaded run delivers it later than an idle one.
  template<typename Predicate>
  bool wait_until(std::chrono::milliseconds timeout, Predicate&& predicate)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCondition.wait_for(lock, timeout, [&] { return predicate(std::as_const(events)); });
  }

  /// Invoke `fn` under the lock with const access to the recorded events, so a
  /// caller can inspect them without racing concurrent `emit()` calls.
  template<typename Fn>
  auto with_events(Fn&& fn) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return fn(events);
  }

  /// As @ref with_events, over the Condition audit Events the sink kept apart from the Condition
  /// Event stream. A test about auditing reads this one; every other test here indexes the stream.
  template<typename Fn>
  auto with_audit_events(Fn&& fn) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return fn(auditEvents);
  }

  std::vector<std::unique_ptr<BaseEvent>> events;

private:
  mutable std::mutex mMutex;
  std::condition_variable mCondition;
  uint16_t mNextId{0};
};

// Records whether the registry's close actually reached this instance's logic.
class DisableRecordingLogic final : public ua::AlarmConditionLogic
{
public:
  explicit DisableRecordingLogic(std::shared_ptr<std::atomic<bool>> disabled) : mDisabled(std::move(disabled))
  {}

protected:
  void on_disabled(ua::ConditionStateTransition& transition) override
  {
    mDisabled->store(true);
    ua::AlarmConditionLogic::on_disabled(transition);
  }

private:
  std::shared_ptr<std::atomic<bool>> mDisabled;
};

class ConditionsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mSink = std::make_shared<ManagerFakeEventSink>();
    mManager = ConditionsTestAccess::create(mPool.get_executor(), mSink);
  }

  void TearDown() override
  {
    mManager.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  boost::asio::thread_pool mPool{1};
  std::shared_ptr<ManagerFakeEventSink> mSink;
  std::shared_ptr<Conditions> mManager;
};

// --- Create ---

TEST_F(ConditionsTest, CreateCondition_ReturnsInstance)
{
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());

  ASSERT_NE(instance, nullptr);
  EXPECT_EQ(instance->condition_id(), NodeId(1, 1000u));
}

// The per-condition branch cap is a memory fail-safe: a condition toggling while the operator never
// acknowledges grows its branch set without bound. `ResourceLimits::conditionBranchesPerCondition` is how a
// deployment bounds it, so the value has to reach logic created through the public create API and not only
// through the discover/attach flow.
TEST_F(ConditionsTest, ConfiguredBranchCapAppliesToLogicCreatedThroughCreateCondition)
{
  mManager->set_max_branches_per_condition(2);

  auto logic = std::make_unique<AlarmConditionLogic>();
  auto* raw = logic.get();
  raw->set_supports_branches(true);
  raw->enable();

  auto instance =
    mManager->create_condition_sync(NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::move(logic));
  ASSERT_NE(instance, nullptr);

  // Each activate() while the previous event is unacknowledged forks a branch.
  raw->activate(500);
  raw->set_last_event_id(ByteString{std::vector<uint8_t>{1}});
  raw->activate(600);
  raw->set_last_event_id(ByteString{std::vector<uint8_t>{2}});
  raw->activate(700);
  raw->set_last_event_id(ByteString{std::vector<uint8_t>{3}});
  raw->activate(800);

  EXPECT_EQ(raw->branches().size(), 2U)
    << "the configured cap must bound the live branch set; growing past it means the logic kept the "
       "compiled-in default instead of the configured value";
}

// Stage 3b #7: a user CreateConditionCallback that throws must be contained inside the strand-posted
// Asio handler (invoke_user_callback) and never escape -> std::terminate. Delivered exactly once.
TEST_F(ConditionsTest, CreateConditionAsync_ThrowingCallbackIsContainedNotTerminate)
{
  auto calls = std::make_shared<std::atomic<int>>(0);
  auto delivered = std::make_shared<std::promise<void>>();
  auto deliveredFuture = delivered->get_future();

  mManager->create_condition_async(NodeId{1, 1000u},
    NodeId{1, 100u},
    String{"Source"},
    std::make_unique<ConditionLogic>(),
    [calls, delivered](ConditionInstanceResult) mutable
    {
      calls->fetch_add(1);
      delivered->set_value();  // signal delivery BEFORE throwing
      throw std::runtime_error("application create-condition callback failed");  // must be contained
    });

  ASSERT_EQ(deliveredFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready)
    << "the create completion must be delivered";
  EXPECT_EQ(calls->load(), 1) << "a throwing create-condition callback must be delivered exactly once";
  // Reaching here proves containment: pre-fix the throw escaped the strand handler -> std::terminate.
}

// --- Find ---

TEST_F(ConditionsTest, FindCondition_AfterCreate_ReturnsInstance)
{
  auto created = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());

  auto found = mManager->find_condition_sync(NodeId{1, 1000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->condition_id(), NodeId(1, 1000u));
}

TEST_F(ConditionsTest, FindCondition_UnknownNodeId_ReturnsNullptr)
{
  auto found = mManager->find_condition_sync(NodeId{1, 9999u});
  EXPECT_EQ(found, nullptr);
}

// --- Deregister ---

TEST_F(ConditionsTest, Deregister_RemovesCondition)
{
  mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());

  mManager->deregister_condition_sync(NodeId{1, 1000u});

  auto found = mManager->find_condition_sync(NodeId{1, 1000u});
  EXPECT_EQ(found, nullptr);
}

// --- Register pre-created ---

TEST_F(ConditionsTest, RegisterCondition_MakesFindable)
{
  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 3000u},
    NodeId{1, 300u},
    String{"External"},
    mSink);

  mManager->register_condition_sync(instance);

  auto found = mManager->find_condition_sync(NodeId{1, 3000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->condition_id(), NodeId(1, 3000u));
}

// --- Retained conditions ---

TEST_F(ConditionsTest, RetainedConditions_ReturnsOnlyRetained)
{
  auto instance1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source1"}, std::make_unique<ConditionLogic>());
  auto instance2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"Source2"}, std::make_unique<ConditionLogic>());

  // Enable instance1 (sets retained=true), leave instance2 disabled (retained=false).
  instance1->enable_sync();

  auto retained = mManager->retained_conditions_sync();
  EXPECT_EQ(retained.size(), 1u);
  if (!retained.empty())
  {
    EXPECT_EQ(retained[0]->condition_id(), NodeId(1, 1000u));
  }
}

TEST_F(ConditionsTest, RetainedConditions_EmptyWhenNoneRetained)
{
  mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source1"}, std::make_unique<ConditionLogic>());

  auto retained = mManager->retained_conditions_sync();
  EXPECT_TRUE(retained.empty());
}

// --- ConditionPayload refresh ---

TEST_F(ConditionsTest, ConditionRefresh_EmitsRefreshStartAndEnd)
{
  ManagerFakeEventSink refreshSink;

  mManager->condition_refresh_sync(refreshSink);

  // With zero retained conditions: exactly RefreshStartEventPayload + RefreshEndEventPayload.
  ASSERT_EQ(refreshSink.events.size(), 2u);

  auto* startEvent = dynamic_cast<RefreshStartEventPayload*>(refreshSink.events.front().get());
  EXPECT_NE(startEvent, nullptr);

  auto* endEvent = dynamic_cast<RefreshEndEventPayload*>(refreshSink.events.back().get());
  EXPECT_NE(endEvent, nullptr);
}

TEST_F(ConditionsTest, ConditionRefresh_EmitsRetainedConditionEvents)
{
  // Create, enable, and activate a condition so it becomes retained.
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<AlarmConditionLogic>());
  instance->enable_sync();
  instance->activate_sync(500);

  ASSERT_TRUE(instance->snapshot()->retained());

  ManagerFakeEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  // Expect exactly 3 events: RefreshStart, the retained condition event, RefreshEnd.
  ASSERT_EQ(refreshSink.events.size(), 3u);

  auto* startEvent = dynamic_cast<RefreshStartEventPayload*>(refreshSink.events[0].get());
  EXPECT_NE(startEvent, nullptr) << "First event should be RefreshStartEventPayload";

  // The middle event should be the retained condition's current state.
  auto* conditionEvent = dynamic_cast<AlarmConditionPayload*>(refreshSink.events[1].get());
  EXPECT_NE(conditionEvent, nullptr) << "Middle event should be the retained condition event";

  auto* endEvent = dynamic_cast<RefreshEndEventPayload*>(refreshSink.events[2].get());
  EXPECT_NE(endEvent, nullptr) << "Last event should be RefreshEndEventPayload";
}

TEST_F(ConditionsTest, ConditionRefresh_ReEmitsRetainedLimitAlarmAsTypedEvent)
{
  // A LimitAlarm that is active (its input violates a limit) is retained; ConditionRefresh must
  // re-emit it as a typed ExclusiveLimitAlarm event with Retain=true so a client discovers it on
  // demand - independent of any prior state-change notification. (Regression guard: the SUT must be
  // discoverable via ConditionRefresh alone, without an autonomous input sweep re-firing the alarm.)
  auto limitLogic = std::make_unique<LimitAlarmLogic>();
  limitLogic->set_exclusive(true);
  LimitConfig limits;
  limits.highHighLimit = 180.0;
  limits.highLimit = 160.0;
  limits.lowLimit = 40.0;
  limits.lowLowLimit = 20.0;
  limitLogic->set_limits(limits);

  auto instance = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"LimitSource"}, std::move(limitLogic));
  instance->enable_sync();
  instance->activate_sync(500);  // models a sustained limit violation keeping the alarm active

  ASSERT_TRUE(instance->snapshot()->retained());

  ManagerFakeEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  // RefreshStart + the retained limit alarm + RefreshEnd.
  ASSERT_EQ(refreshSink.events.size(), 3u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(refreshSink.events.front().get()), nullptr);

  auto* limitEvent = dynamic_cast<ExclusiveLimitAlarmPayload*>(refreshSink.events[1].get());
  ASSERT_NE(limitEvent, nullptr) << "ConditionRefresh must re-emit the retained limit alarm as a typed event";
  EXPECT_TRUE(limitEvent->retain) << "Re-emitted limit alarm must carry Retain=true";
  // ConditionId must travel on the refresh event (empty-browsePath + NodeId-attribute operand) so a client
  // discovering via ConditionRefresh can extract it; otherwise the UACTT halts on "Unable to get
  // ConditionId".
  ASSERT_TRUE(limitEvent->conditionNodeId.has_value())
    << "Re-emitted condition event must carry the ConditionId";
  EXPECT_EQ(*limitEvent->conditionNodeId, NodeId(1, 2000u));

  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(refreshSink.events.back().get()), nullptr);
}

// Refresh reports a Condition's current state "by re-sending the last Event (i.e. the same EventId and Time
// is sent)" (OPC 10000-9 5.5.2), and the replay keeps the ReceiveTime that Event was given. A replay stamped
// when it is sent would look newer to a client than a live transition that happened after the replay was
// built, and would overwrite it.
TEST_F(ConditionsTest, ConditionRefreshResendsTheLastEventWithItsTimeAndReceiveTime)
{
  // Stamps ReceiveTime as the EventBus does on every emit (SVR-EVT-BET-005).
  class ReceiveTimeStampingSink : public ManagerFakeEventSink
  {
  public:
    void emit(BaseEvent& event) override
    {
      event.receiveTime = DateTime::now();
      ManagerFakeEventSink::emit(event);
    }
  };

  auto liveSink = std::make_shared<ReceiveTimeStampingSink>();
  auto manager = ConditionsTestAccess::create(mPool.get_executor(), liveSink);
  auto instance = manager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<AlarmConditionLogic>());
  instance->enable_sync();
  instance->activate_sync(500);
  ASSERT_TRUE(instance->snapshot()->retained());

  const AlarmConditionPayload* last = nullptr;
  for (const auto& event : liveSink->events)
  {
    if (const auto* alarm = dynamic_cast<const AlarmConditionPayload*>(event.get()))
      last = alarm;
  }
  ASSERT_NE(last, nullptr);
  ASSERT_FALSE(last->receiveTime.is_null());
  // A refresh stamped "now" must be distinguishable from the last Event's own times.
  while (DateTime::now() <= last->receiveTime)
    std::this_thread::yield();

  ManagerFakeEventSink refreshSink;
  manager->condition_refresh_sync(refreshSink);

  ASSERT_EQ(refreshSink.events.size(), 3u);
  const auto* replay = dynamic_cast<const AlarmConditionPayload*>(refreshSink.events[1].get());
  ASSERT_NE(replay, nullptr);
  EXPECT_EQ(replay->eventId, last->eventId);
  EXPECT_EQ(replay->time, last->time) << "the replay re-sends the last Event's Time";
  EXPECT_EQ(replay->receiveTime, last->receiveTime) << "and keeps the ReceiveTime that Event was given";
  manager.reset();
}

// --- Factory ---

TEST_F(ConditionsTest, RegisterFactory_FindReturnsFactory)
{
  bool factoryCalled = false;
  mManager->register_factory_sync(NodeId{ObjectTypeId::ConditionType},
    [&factoryCalled]() -> std::unique_ptr<ConditionLogic>
    {
      factoryCalled = true;
      return std::make_unique<ConditionLogic>();
    });

  auto factory = mManager->find_factory_sync(NodeId{ObjectTypeId::ConditionType});
  ASSERT_NE(factory, nullptr);

  auto logic = factory();
  EXPECT_TRUE(factoryCalled);
  EXPECT_NE(logic, nullptr);
}

TEST_F(ConditionsTest, FindFactory_UnknownType_ReturnsNullptr)
{
  auto factory = mManager->find_factory_sync(NodeId{0, 9999u});
  EXPECT_EQ(factory, nullptr);
}

// --- Close all ---

TEST_F(ConditionsTest, CloseAll_ClosesAllInstances)
{
  auto instance1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source1"}, std::make_unique<ConditionLogic>());
  auto instance2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"Source2"}, std::make_unique<ConditionLogic>());

  instance1->enable_sync();
  instance2->enable_sync();

  ConditionsTestAccess::close_sync(*mManager);

  // After close_all, instances should be disabled (closed disables them).
  auto snapshot1 = instance1->snapshot();
  auto snapshot2 = instance2->snapshot();
  EXPECT_FALSE(snapshot1->enabled());
  EXPECT_FALSE(snapshot2->enabled());
}

TEST_F(ConditionsTest, CloseAll_ClearsRegistry)
{
  mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());

  ConditionsTestAccess::close_sync(*mManager);

  // After close, the strand is shut down, so find_condition_sync throws
  // BadShutdown - use the try_* form to observe the post-close state.
  auto result = mManager->try_find_condition_sync(NodeId{1, 1000u});
  EXPECT_FALSE(result.is_good()) << "find after close must report Bad{Shutdown}, not Good{nullptr}";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadShutdown});
}

// ===========================================================================
// Discover existing conditions tests (address space integration)
// ===========================================================================

/// Test fixture for Conditions::discover_existing_conditions_coro.
/// Loads NS0 into a real AddressSpace so the manager can scan for condition objects.
class ConditionsDiscoverTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);

    sAddressSpace.emplace(AddressSpace::create("uri:test:discover", sPool.executor()));

    StructureFactory structureFactory;
    auto lookupFn = namespace_array_utils::get_index_lookup_function(as());
    const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
    register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

    FileStream inputStream{"NodeSet2.xml"};
    inputStream.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(sLimits,
      inputStream,
      structureFactory,
      as().namespace_array(),
      as().server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});

    auto importer = xml::nodeset::ImportEngine::create(sLimits, as(), nodeSets, {});
    importer->import_all_sync({}, {});
  }

  static void TearDownTestSuite()
  {
    // Release the address space, but do NOT join the static `sPool` here.
    // Under `--gtest_repeat`, gtest runs TearDownTestSuite then SetUpTestSuite
    // again for the next iteration; a joined `thread_pool` is terminal and
    // cannot be revived, so the next iteration would post to dead workers and
    // every sync call would hang forever. The pool's destructor performs the
    // final join at process exit. (Same convention as condition_instance_tests.)
    sAddressSpace.reset();
  }

  void SetUp() override
  {
    mSink = std::make_shared<ManagerFakeEventSink>();
    mManager = ConditionsTestAccess::create(sPool.executor(), mSink, as());
  }

  void TearDown() override
  {
    if (mManager)
    {
      ConditionsTestAccess::close_sync(*mManager);
    }
    mManager.reset();
  }

  /// A concrete ConditionType with ConditionType's members only: ConditionType itself is abstract.
  static NodeId plain_condition_type()
  {
    return ::ua::test_helpers::concrete_condition_type(as(), 1);
  }

  /// Instantiate a bare condition object in the AS using InstantiationService (no ConditionInstance).
  /// Returns the root NodeId of the instantiated subtree.
  NodeId instantiate_bare_condition(const NodeId& typeDefinition, const std::string& namePrefix = "BareDisc")
  {
    auto id = sNextId++;
    InstantiationService inst{as()};
    InstantiationOptions options;

    std::promise<NodeSubtreeResult> p;
    inst.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{1, fmt::format("{}_{}", namePrefix, id)},
      typeDefinition,
      options,
      [&p](NodeSubtreeResult r) { p.set_value(std::move(r)); });

    auto result = p.get_future().get();
    if (result.is_bad())
    {
      return NodeId{};
    }
    auto subtree = std::move(result).value();
    auto rootId = subtree.root();
    subtree.release();  // Keep nodes alive
    return rootId;
  }

  /// Create a condition object in the AS using Conditions::create_condition_sync.
  /// Returns the actual conditionId (after instantiation) of the created condition.
  NodeId create_condition_in_as(
    const NodeId& typeDefinition = plain_condition_type(), const std::string& namePrefix = "DiscCond")
  {
    auto id = sNextId++;
    auto logic = make_logic_for_type(typeDefinition);
    auto instance = mManager->try_create_condition_sync(NodeId{1, id},
      NodeId{ObjectId::ObjectsFolder},
      String{fmt::format("{}_{}", namePrefix, id)},
      std::move(logic),
      typeDefinition);
    EXPECT_TRUE(instance.is_good()) << "Failed to create condition in AS";
    return instance.value()->condition_id();
  }

  /// Run discover_existing_conditions_async synchronously from the test thread.
  VoidResult run_discover()
  {
    return mManager->try_discover_existing_conditions_sync();
  }

  static AddressSpace& as()
  {
    return *sAddressSpace;
  }

  /// A Method is called on an Object the address space holds: the call looks the Object up before its handler
  /// runs. A Condition made without its Object Node (the logic-only form), or an Object id that names no
  /// Condition, is given a plain Object here, so that the call reaches the handler.
  static void ensure_object(const NodeId& objectId)
  {
    if (!as().try_find_node_sync(objectId).is_good())
    {
      ASSERT_TRUE(as().try_create_node_sync(objectId, NodeClass::Object).is_good()) << to_string(objectId);
    }
  }

  static boost::asio::thread_pool sPool;
  static std::optional<AddressSpace> sAddressSpace;
  static EncodingLimits sLimits;
  static uint32_t sNextId;
  std::shared_ptr<ManagerFakeEventSink> mSink;
  std::shared_ptr<Conditions> mManager;

private:
  static std::unique_ptr<ConditionLogic> make_logic_for_type(const NodeId& typeDefinition)
  {
    if (typeDefinition == NodeId{ObjectTypeId::AlarmConditionType})
    {
      return std::make_unique<AlarmConditionLogic>();
    }
    if (typeDefinition == NodeId{ObjectTypeId::AcknowledgeableConditionType})
    {
      return std::make_unique<AcknowledgeableConditionLogic>();
    }
    return std::make_unique<ConditionLogic>();
  }
};

boost::asio::thread_pool ConditionsDiscoverTest::sPool{2};
std::optional<AddressSpace> ConditionsDiscoverTest::sAddressSpace{};
EncodingLimits ConditionsDiscoverTest::sLimits{};
uint32_t ConditionsDiscoverTest::sNextId{80000};

TEST_F(ConditionsDiscoverTest, Discover_FindsInstantiatedCondition)
{
  // Instantiate a ConditionType object directly in the AS (no ConditionInstance).
  auto condNodeId = instantiate_bare_condition(plain_condition_type());
  ASSERT_FALSE(condNodeId.is_null());

  // Not registered in our manager.
  ASSERT_EQ(mManager->find_condition_sync(condNodeId), nullptr);

  // Run discover.
  auto result = run_discover();
  EXPECT_TRUE(result.is_good());

  // Now find_condition should return the discovered instance.
  auto found = mManager->find_condition_sync(condNodeId);
  EXPECT_NE(found, nullptr) << "Discover should have found and registered the condition";
}

TEST_F(ConditionsDiscoverTest, Discover_SkipsAlreadyRegisteredConditions)
{
  // Create a condition in the AS via this manager (it will be registered).
  auto condId = create_condition_in_as();
  auto existing = mManager->find_condition_sync(condId);
  ASSERT_NE(existing, nullptr);

  // Run discover -- it should not duplicate the condition.
  auto result = run_discover();
  EXPECT_TRUE(result.is_good());

  // The same instance should still be there (not replaced).
  auto found = mManager->find_condition_sync(condId);
  EXPECT_EQ(found.get(), existing.get()) << "Discover should skip already-registered conditions";
}

TEST_F(ConditionsDiscoverTest, Discover_AttachesAlarmConditionWithCorrectLogicType)
{
  // Instantiate an AlarmConditionType object directly in the AS (no ConditionInstance).
  auto condNodeId = instantiate_bare_condition(NodeId{ObjectTypeId::AlarmConditionType}, "DiscAlarm");
  ASSERT_FALSE(condNodeId.is_null());

  // Not registered in our test manager.
  ASSERT_EQ(mManager->find_condition_sync(condNodeId), nullptr);

  // Discover.
  auto result = run_discover();
  EXPECT_TRUE(result.is_good());

  auto found = mManager->find_condition_sync(condNodeId);
  ASSERT_NE(found, nullptr);

  // The discovered instance should support activate/deactivate
  // because the factory maps AlarmConditionType to AlarmConditionLogic.
  // The condition starts enabled (Part 9 restart recovery default), so just activate.
  auto activateResult = found->try_activate_sync(500);
  EXPECT_TRUE(activateResult.is_good())
    << "Discovered alarm condition should support activate (AlarmConditionLogic)";
}

TEST_F(ConditionsDiscoverTest, Discover_NoConditionsInAS_Succeeds)
{
  // Verify ObjectsFolder is accessible in this AS
  auto objFolderResult = as().try_find_node_sync(NodeId{ObjectId::ObjectsFolder});
  ASSERT_TRUE(objFolderResult.is_good()) << "ObjectsFolder not found in AS";

  // With no user-created conditions, discover should complete without error.
  // (NS0 type nodes exist but are ObjectType nodes, not Object instances.)
  auto result = run_discover();
  EXPECT_TRUE(result.is_good()) << "Status: " << result.status_code().as_uint32();
}

// ===========================================================================
// ConditionAlarmMetrics tests
// ===========================================================================

TEST_F(ConditionsTest, AlarmMetrics_EmptyWhenNoConditions)
{
  auto metrics = mManager->compute_alarm_metrics_sync();

  EXPECT_EQ(metrics.active_count(), 0u);
  EXPECT_EQ(metrics.unacknowledged_count(), 0u);
  EXPECT_EQ(metrics.unconfirmed_count(), 0u);
  EXPECT_EQ(metrics.highest_active_severity(), 0u);
  EXPECT_EQ(metrics.highest_unack_severity(), 0u);
}

TEST_F(ConditionsTest, AlarmMetrics_CountsActiveAlarms)
{
  auto instance1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source1"}, std::make_unique<AlarmConditionLogic>());
  auto instance2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"Source2"}, std::make_unique<AlarmConditionLogic>());

  instance1->enable_sync();
  instance2->enable_sync();

  // Activate only instance1
  instance1->activate_sync(500);

  auto metrics = mManager->compute_alarm_metrics_sync();

  EXPECT_EQ(metrics.active_count(), 1u);
  EXPECT_EQ(metrics.highest_active_severity(), 500u);
}

TEST_F(ConditionsTest, AlarmMetrics_CountsUnacknowledgedAlarms)
{
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<AlarmConditionLogic>());

  instance->enable_sync();
  instance->activate_sync(700);

  auto metrics = mManager->compute_alarm_metrics_sync();

  // Active alarm with unacked state
  EXPECT_EQ(metrics.unacknowledged_count(), 1u);
  EXPECT_EQ(metrics.highest_unack_severity(), 700u);
}

TEST_F(ConditionsTest, AlarmMetrics_TracksHighestSeverities)
{
  auto instance1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source1"}, std::make_unique<AlarmConditionLogic>());
  auto instance2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"Source2"}, std::make_unique<AlarmConditionLogic>());

  instance1->enable_sync();
  instance2->enable_sync();

  instance1->activate_sync(300);
  instance2->activate_sync(800);

  auto metrics = mManager->compute_alarm_metrics_sync();

  EXPECT_EQ(metrics.active_count(), 2u);
  EXPECT_EQ(metrics.highest_active_severity(), 800u);
  EXPECT_EQ(metrics.highest_unack_severity(), 800u);
}

TEST_F(ConditionsTest, AlarmMetrics_DisabledConditionsExcluded)
{
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<AlarmConditionLogic>());

  // Don't enable - disabled conditions should not be counted
  auto metrics = mManager->compute_alarm_metrics_sync();

  EXPECT_EQ(metrics.active_count(), 0u);
  EXPECT_EQ(metrics.unacknowledged_count(), 0u);
}

// ===========================================================================
// Strand-component invariants (post-conversion)
//
// These tests verify the invariants added by the conditions strand-component
// conversion:
//   - try_emplace arbitration: duplicate-id register loses with BadAlreadyExists.
//   - close_async drains, sets mShuttingDown, prevents re-population.
//   - discover_existing_conditions_async is single-flight via mDiscoverInProgress.
//   - discover walks unbounded child counts without stack overflow.
// ===========================================================================

TEST_F(ConditionsTest, RegisterCondition_DuplicateId_LoserGetsBadAlreadyExists)
{
  // Build two instances with the same conditionId. Strand serialisation
  // gives a deterministic FIFO winner.
  auto instance1 = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 5000u},
    NodeId{1, 100u},
    String{"FirstWinner"},
    mSink);
  auto instance2 = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 5000u},
    NodeId{1, 101u},
    String{"SecondLoser"},
    mSink);

  std::promise<VoidResult> first;
  std::promise<VoidResult> second;
  mManager->register_condition_async(instance1, [&first](VoidResult r) { first.set_value(std::move(r)); });
  mManager->register_condition_async(instance2, [&second](VoidResult r) { second.set_value(std::move(r)); });

  auto firstResult = first.get_future().get();
  auto secondResult = second.get_future().get();

  EXPECT_TRUE(firstResult.is_good()) << "First post must succeed: status="
                                     << firstResult.status_code().as_uint32();
  EXPECT_EQ(secondResult.status_code(), StatusCode{Status::BadAlreadyExists})
    << "Second register_condition_async with duplicate id must report BadAlreadyExists; got "
    << secondResult.status_code().as_uint32();
  EXPECT_NE(secondResult.shared_detail(), nullptr)
    << "BadAlreadyExists must carry ErrorDetail per the ErrorDetail propagation rule";

  auto found = mManager->find_condition_sync(NodeId{1, 5000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found.get(), instance1.get())
    << "Winner of register_condition_async race must be the first poster (strand FIFO)";
}

TEST_F(ConditionsDiscoverTest, Discover_LargeBranch_DoesNotOverflowStack)
{
  // Regression: pre-conversion, inline-completing find_node_async callbacks
  // recursed unboundedly during BFS / hierarchy-walk, blowing the stack at
  // ~64 children (ConditionsDiscoverTest.Discover_FindsInstantiatedCondition
  // reproduced this). The on_strand-wrapped continuations now post per
  // iteration, so unbounded child counts are safe.
  constexpr int childCount = 80;
  std::vector<NodeId> ids;
  ids.reserve(childCount);
  for (int i = 0; i < childCount; ++i)
  {
    auto id = instantiate_bare_condition(plain_condition_type(), "DiscBulk");
    ASSERT_FALSE(id.is_null()) << "Failed to instantiate child #" << i;
    ids.push_back(id);
  }

  auto result = run_discover();
  ASSERT_TRUE(result.is_good()) << "Discover must complete without stack overflow; status="
                                << result.status_code().as_uint32();

  for (const auto& id : ids)
  {
    EXPECT_NE(mManager->find_condition_sync(id), nullptr)
      << "Bulk-instantiated condition not registered after discover (id namespace="
      << static_cast<unsigned>(id.namespace_index()) << ")";
  }
}

TEST_F(ConditionsDiscoverTest, Discover_Reentrant_ReturnsBadInvalidState)
{
  // discover_existing_conditions_async is single-flight via mDiscoverInProgress.
  // Two back-to-back posts: the first wins, the second sees the guard set
  // and reports BadInvalidState.
  std::promise<VoidResult> first;
  std::promise<VoidResult> second;
  mManager->discover_existing_conditions_async([&first](VoidResult r) { first.set_value(std::move(r)); });
  mManager->discover_existing_conditions_async([&second](VoidResult r) { second.set_value(std::move(r)); });

  auto firstResult = first.get_future().get();
  auto secondResult = second.get_future().get();

  EXPECT_TRUE(firstResult.is_good()) << "First discover must succeed; status="
                                     << firstResult.status_code().as_uint32();
  EXPECT_EQ(secondResult.status_code(), StatusCode{Status::BadInvalidState})
    << "Concurrent second discover must report BadInvalidState; got "
    << secondResult.status_code().as_uint32();
}

TEST_F(ConditionsTest, Discover_DeletedTargetAfterLookup_SkipsAndLogs)
{
  TestLogSink logs;
  auto addressSpace = AddressSpace::create("urn:test:discover-deleted", mPool.executor());
  addressSpace.set_logger(logs.logger());
  auto scripted = std::make_shared<ScriptedNamespace>();
  const auto namespaceIndex = addressSpace.add_namespace_sync(scripted);
  const NodeId targetId{namespaceIndex, 100u};
  auto target = std::make_shared<ScriptedNode>();
  target->answer_attribute(AttributeId::NodeId, Variant{targetId});
  target->answer_attribute(AttributeId::NodeClass, Variant{static_cast<int32_t>(NodeClass::Object)});
  scripted->hold(targetId, target);
  auto root = addressSpace.create_node_sync(NodeId{ObjectId::ObjectsFolder}, NodeClass::Object);
  root.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, targetId, true, ReferenceHalves::ThisHalfOnly);

  // A completed lookup can retain a Node that is deleted before discovery reads its description.
  target->mark_deleted();
  ASSERT_TRUE(addressSpace.try_find_node_sync(targetId).is_good());
  auto manager = ConditionsTestAccess::create(mPool.executor(), mSink, addressSpace);
  const auto result = manager->try_discover_existing_conditions_sync();
  ConditionsTestAccess::close_sync(*manager);

  EXPECT_TRUE(result.is_good()) << result.status_code().as_uint32();
  EXPECT_EQ(logs.count(LogLevel::Warning), 1u);
}

TEST_F(ConditionsTest, Discover_TargetDescriptionFailure_PreservesErrorDetail)
{
  auto addressSpace = AddressSpace::create("urn:test:discover-description-failure", mPool.executor());
  auto scripted = std::make_shared<ScriptedNamespace>();
  const auto namespaceIndex = addressSpace.add_namespace_sync(scripted);
  const NodeId targetId{namespaceIndex, 100u};
  auto target = std::make_shared<ScriptedNode>();
  target->answer_attribute(AttributeId::NodeId, Variant{targetId});
  target->answer_attribute(AttributeId::NodeClass, Variant{static_cast<int32_t>(NodeClass::Object)});
  scripted->hold(targetId, target);
  auto root = addressSpace.create_node_sync(NodeId{ObjectId::ObjectsFolder}, NodeClass::Object);
  root.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, targetId, true, ReferenceHalves::ThisHalfOnly);
  const StatusCode refusal{Status::BadOutOfMemory,
    ErrorDetail::build("DescriptionUnavailable", "The Node description could not be read", "test")};
  target->refuse_attribute(AttributeId::NodeClass, refusal);
  auto manager = ConditionsTestAccess::create(mPool.executor(), mSink, addressSpace);
  const auto result = manager->try_discover_existing_conditions_sync();
  ConditionsTestAccess::close_sync(*manager);

  EXPECT_EQ(result.status_code(), refusal);
  EXPECT_EQ(result.shared_detail(), refusal.shared_detail());
}

TEST_F(ConditionsDiscoverTest, Close_DuringDiscover_DrainsAndNoRepopulate)
{
  // Pre-populate AS with bare conditions, then race discover + close. After
  // close completes the registry must be empty regardless of which side
  // raced ahead - close sets mShuttingDown which discover's continuations
  // observe at each on_strand resume and bail with BadShutdown.
  for (int i = 0; i < 5; ++i)
  {
    auto id = instantiate_bare_condition(plain_condition_type(), "DiscDrain");
    ASSERT_FALSE(id.is_null());
  }

  std::promise<VoidResult> discoverDone;
  std::promise<VoidResult> closeDone;
  mManager->discover_existing_conditions_async(
    [&discoverDone](VoidResult r) { discoverDone.set_value(std::move(r)); });
  ConditionsTestAccess::close_async(
    *mManager, [&closeDone](VoidResult r) { closeDone.set_value(std::move(r)); });

  auto discoverResult = discoverDone.get_future().get();
  auto closeResult = closeDone.get_future().get();

  EXPECT_TRUE(closeResult.is_good()) << "close_async must complete OK";
  // discover either ran to completion before close set the flag, OR bailed
  // with BadShutdown mid-walk. Both are valid outcomes.
  (void)discoverResult;

  // After close, the strand is shut down, so try_retained_conditions_sync
  // returns Bad{Shutdown} - which is exactly the post-close invariant we
  // want (no further state queries are answered).
  auto retainedResult = mManager->try_retained_conditions_sync();
  EXPECT_FALSE(retainedResult.is_good())
    << "After close_async, retained_conditions queries must report Bad{Shutdown}";
  EXPECT_EQ(retainedResult.status_code(), StatusCode{Status::BadShutdown});

  // A second close is idempotent.
  std::promise<VoidResult> closeAgain;
  ConditionsTestAccess::close_async(
    *mManager, [&closeAgain](VoidResult r) { closeAgain.set_value(std::move(r)); });
  EXPECT_TRUE(closeAgain.get_future().get().is_good()) << "Second close_async must complete OK (idempotent)";
}

// ===========================================================================
// ConditionRefresh2 - wire method handler scoping (Part 9 section 5.5.8)
// ===========================================================================
//
// These tests drive the NS0 ConditionType_ConditionRefresh2 method node
// handler registered by register_refresh_methods. ConditionRefresh2 must
// refresh ONLY the conditions associated with the given MonitoredItem (its
// monitored NodeId), not the whole subscription, and must report
// Bad_MonitoredItemIdInvalid when the MonitoredItem cannot be resolved.

class ConditionRefresh2HandlerTest : public ConditionsDiscoverTest
{
protected:
  void SetUp() override
  {
    ConditionsDiscoverTest::SetUp();
    mEventBus = std::make_shared<server::EventBus>(as());
  }

  void TearDown() override
  {
    mEventBus.reset();
    ConditionsDiscoverTest::TearDown();
  }

  /// Create a retained alarm condition (logic-only, no AS instantiation) whose
  /// source node is `sourceNode`. Returns the created instance.
  std::shared_ptr<ConditionInstance> make_retained_alarm(const NodeId& conditionId, const NodeId& sourceNode)
  {
    auto instance = mManager->create_condition_sync(
      conditionId, sourceNode, String{"Source"}, std::make_unique<AlarmConditionLogic>());
    instance->enable_sync();
    instance->activate_sync(500);
    EXPECT_TRUE(instance->snapshot()->retained());
    return instance;
  }

  /// Invoke the registered ConditionType_ConditionRefresh2 method handler with
  /// the given (subscriptionId, monitoredItemId) and return the call result.
  CallResult call_refresh2(uint32_t subscriptionId, uint32_t monitoredItemId)
  {
    auto findResult = as().try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh2});
    EXPECT_TRUE(findResult.is_good());

    CallMethodRequest request;
    request.object_id() = NodeId{ObjectTypeId::ConditionType};
    request.method_id() = NodeId{MethodId::ConditionType_ConditionRefresh2};
    request.input_arguments().push_back(Variant{subscriptionId});
    request.input_arguments().push_back(Variant{monitoredItemId});

    auto context = std::make_shared<MethodCallContext>();

    std::promise<CallResult> promise;
    findResult.value().as<MethodAccessor>()->call_async(
      request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  std::shared_ptr<server::EventBus> mEventBus;
};

// Part 9 section 5.5.7: unlike instance-addressed Condition Methods, ConditionRefresh is available
// only on ConditionType and the Call's ObjectId shall be that well-known ObjectType NodeId. Drive
// the registered handler directly so the component owns this decision independently of the Call
// service's generic Method topology checks.
TEST_F(ConditionRefresh2HandlerTest, ConditionRefreshAcceptsConditionTypeAndRejectsAConditionInstanceObjectId)
{
  auto findResult = as().try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh});
  ASSERT_TRUE(findResult.is_good());

  mEventBus->register_event_item(NodeId{1, 100u}, 10, 17, [](IntegerId, std::shared_ptr<const BaseEvent>) {});
  mManager->register_refresh_methods(std::weak_ptr<server::EventBus>{mEventBus}, nullptr, nullptr);

  auto callRefresh = [&](NodeId objectId)
  {
    ensure_object(objectId);
    CallMethodRequest request;
    request.object_id() = std::move(objectId);
    request.method_id() = NodeId{MethodId::ConditionType_ConditionRefresh};
    request.input_arguments().push_back(Variant{uint32_t{17}});

    std::promise<CallResult> promise;
    findResult.value().as<MethodAccessor>()->call_async(request,
      std::make_shared<MethodCallContext>(),
      [&promise](CallResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  };

  auto accepted = callRefresh(NodeId{ObjectTypeId::ConditionType});
  ASSERT_TRUE(accepted.is_good());
  ASSERT_TRUE(accepted.value().status_code().is_good());

  auto refused = callRefresh(NodeId{1, uint32_t{7001}});
  ASSERT_TRUE(refused.is_good());
  EXPECT_EQ(refused.value().status_code(), StatusCode{Status::BadNodeIdInvalid});
}

// @relation(AC-SVR-AC-024-REFRESH-CODES, scope=function)
TEST_F(ConditionRefresh2HandlerTest, ConditionRefreshWithNoEventMonitoredItemReturnsRichBadNothingToDo)
{
  auto findResult = as().try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh});
  ASSERT_TRUE(findResult.is_good());

  mManager->register_refresh_methods(std::weak_ptr<server::EventBus>{mEventBus}, nullptr, nullptr);

  CallMethodRequest request;
  request.object_id() = NodeId{ObjectTypeId::ConditionType};
  request.method_id() = NodeId{MethodId::ConditionType_ConditionRefresh};
  request.input_arguments().push_back(Variant{uint32_t{17}});

  std::atomic<uint32_t> completionCount{0};
  std::promise<CallResult> promise;
  findResult.value().as<MethodAccessor>()->call_async(request,
    std::make_shared<MethodCallContext>(),
    [&completionCount, &promise](CallResult result)
    {
      ++completionCount;
      promise.set_value(std::move(result));
    });

  auto callResult = promise.get_future().get();
  ASSERT_TRUE(callResult.is_good()) << "the refusal belongs to the per-method CallMethodResult";
  const auto status = callResult.value().status_code();
  EXPECT_EQ(status, StatusCode{Status::BadNothingToDo});
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "ConditionRefreshNoEventMonitoredItems");
  EXPECT_EQ(status.shared_detail()->summary, "ConditionRefresh requires at least one event MonitoredItem");
  EXPECT_EQ(status.shared_detail()->source, "Conditions::register_refresh_methods");

  std::optional<std::string> subscriptionContext;
  for (const auto& fact : status.shared_detail()->context)
  {
    if (fact.key == ContextKeys::subscriptionId.value())
    {
      subscriptionContext = fact.value;
      break;
    }
  }
  ASSERT_TRUE(subscriptionContext.has_value());
  EXPECT_EQ(*subscriptionContext, "17");
  EXPECT_EQ(completionCount.load(), 1u);
}

TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2_ScopesToMonitoredItemNode)
{
  // Two retained alarms on different source nodes 100 and 200.
  const NodeId source100{1, 100u};
  const NodeId source200{1, 200u};
  make_retained_alarm(NodeId{1, 1000u}, source100);
  make_retained_alarm(NodeId{1, 2000u}, source200);

  // The refresh sink records what ConditionRefresh2 emits to the target item.
  auto refreshSink = std::make_shared<ManagerFakeEventSink>();

  // Resolver maps monitoredItemId 10 -> source node 100. The handler emits
  // retained-condition snapshots via emit_to_monitored_item, which we redirect
  // to refreshSink so we can inspect exactly what was re-emitted.
  Conditions::MonitoredItemNodeResolver resolver =
    [source100](
      uint32_t /*subscriptionId*/, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> done)
  {
    if (monitoredItemId == 10)
      done(source100);
    else
      done(std::nullopt);
  };

  // Register an event item on subscription 1 / monitored item 10 against the
  // source-100 node, with delivery into refreshSink, so emit_to_monitored_item
  // reaches our recorder.
  mEventBus->register_event_item(source100,
    10,
    1,
    [refreshSink](IntegerId, std::shared_ptr<const BaseEvent> ev)
    {
      if (ev)
      {
        auto clone = ev->clone();
        refreshSink->emit(*clone);
      }
    });

  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, nullptr, std::move(resolver));

  auto result = call_refresh2(1, 10);
  ASSERT_TRUE(result.is_good()) << "ConditionRefresh2 with a valid MonitoredItem must succeed";

  // Drain the EventBus dispatch by waiting for the expected count, delivered on
  // the EventBus worker thread: RefreshStart + exactly the source-100 condition
  // event + RefreshEnd = 3. Crucially the source-200 condition must NOT appear -
  // refresh is scoped to the MonitoredItem's node (100), not the whole
  // subscription.
  const size_t observed = refreshSink->wait_for_count(3, std::chrono::seconds(2));

  ASSERT_EQ(observed, 3u) << "Expected RefreshStart + one source-100 condition + RefreshEnd";

  // Exactly one AlarmConditionPayload, and it must be the source-100 condition.
  // Inspect under the sink's lock so we never race a late worker-thread emit.
  refreshSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      size_t alarmCount = 0;
      for (auto& ev : events)
      {
        if (auto* alarm = dynamic_cast<AlarmConditionPayload*>(ev.get()))
        {
          ++alarmCount;
          EXPECT_EQ(alarm->sourceNode, source100)
            << "ConditionRefresh2 must only re-emit conditions on the MonitoredItem's node";
        }
      }
      EXPECT_EQ(alarmCount, 1u) << "ConditionRefresh2 must scope to a single MonitoredItem's conditions";
    });
}

// Stage-3a F3: the refresh emit path captures the EventBus weakly, so it must be safe to invoke a
// ConditionRefresh AFTER the bus has been destroyed (e.g. ~ServerImpl tears the bus down while a refresh
// is in flight). Before the fix the emitter held a raw EventBus& and dereferenced freed memory (UAF);
// after it, each emit locks the weak_ptr and is skipped when the bus is gone, and the refresh still
// completes for the caller. This test destroys the bus before the call, so every emit hits the
// expired-weak_ptr branch.
TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2_AfterEventBusDestroyed_DoesNotUseAfterFree)
{
  make_retained_alarm(NodeId{1, 1000u}, NodeId{1, 100u});

  const NodeId source100{1, 100u};
  Conditions::MonitoredItemNodeResolver resolver =
    [source100](
      uint32_t /*subscriptionId*/, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> done)
  {
    if (monitoredItemId == 10)
      done(source100);
    else
      done(std::nullopt);
  };

  // Register the refresh handler with a WEAK handle to the bus, then destroy the bus - simulating
  // teardown while the handler's emitter survives (it is co-owned by the address-space method node).
  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, nullptr, std::move(resolver));
  mEventBus.reset();

  // The refresh runs, snapshots the retained alarm, and attempts to emit it - each emit must lock the
  // now-expired weak bus and skip, never touching freed memory. The call must return (no UAF, no hang).
  auto result = call_refresh2(1, 10);
  EXPECT_TRUE(result.is_good())
    << "ConditionRefresh2 must complete safely when the EventBus has been destroyed (emits skipped)";
}

TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2_UnknownMonitoredItem_ReturnsBadMonitoredItemIdInvalid)
{
  // One retained alarm so the whole-subscription path (the bug) would emit it.
  make_retained_alarm(NodeId{1, 1000u}, NodeId{1, 100u});

  auto refreshSink = std::make_shared<ManagerFakeEventSink>();
  mEventBus->register_event_item(NodeId{1, 100u},
    10,
    1,
    [refreshSink](IntegerId, std::shared_ptr<const BaseEvent> ev)
    {
      if (ev)
      {
        auto clone = ev->clone();
        refreshSink->emit(*clone);
      }
    });

  // Resolver returns nullopt for every item - the MonitoredItem is unknown.
  Conditions::MonitoredItemNodeResolver resolver =
    [](uint32_t, uint32_t, std::function<void(std::optional<NodeId>)> done)
  {
    done(std::nullopt);
  };

  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, nullptr, std::move(resolver));

  auto result = call_refresh2(1, 99);
  ASSERT_TRUE(result.is_good()) << "Call completed (status is on the CallMethodResult)";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "Unknown MonitoredItem must yield Bad_MonitoredItemIdInvalid";

  // No events should have been emitted, and the refresh guard must never have
  // been taken (otherwise a later refresh on this subscription would wrongly
  // report Bad_RefreshInProgress). Give any erroneous emit time to land.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(refreshSink->size(), 0u) << "An unknown MonitoredItem must not trigger any refresh emission";

  // A subsequent refresh on the same subscription via the whole-subscription
  // ConditionRefresh must still succeed - proving the guard was not wedged.
  ManagerFakeEventSink probeSink;
  EXPECT_TRUE(mManager->try_condition_refresh_sync(probeSink).is_good())
    << "The single-flight guard must not be left set after Bad_MonitoredItemIdInvalid";
}

// ===========================================================================
// Standard Condition methods on TYPE method nodes (Conditions::register_condition_methods)
//
// UACTT invokes Enable/Disable/AddComment/Acknowledge/Confirm using the *type*
// method-node ids (i=9027/9028/9029/9111/9113) with the condition *instance* as
// the object. These tests drive that exact wire shape through the real method
// service (node->call) and assert the per-operation status is Good (NOT
// BadNotSupported), that the operation took effect, and that an objectId which is
// not a live Condition instance yields Bad_NodeIdInvalid.
// ===========================================================================

class ConditionTypeMethodHandlerTest : public ConditionsDiscoverTest
{
protected:
  void SetUp() override
  {
    ConditionsDiscoverTest::SetUp();
    mManager->register_condition_methods();
  }

  /// Create a logic-only acknowledgeable condition registered in the manager under
  /// `conditionId`. The condition starts enabled (Part 9 restart default).
  std::shared_ptr<ConditionInstance> make_ack_condition(const NodeId& conditionId)
  {
    auto logic = std::make_unique<AcknowledgeableConditionLogic>();
    logic->set_supports_confirm(true);
    auto instance =
      mManager->create_condition_sync(conditionId, NodeId{1, 100u}, String{"Source"}, std::move(logic));
    return instance;
  }

  /// Invoke a type method node (`methodId`) against `objectId` with no input
  /// arguments and return the CallResult.
  CallResult call_argless(MethodId methodId, const NodeId& objectId)
  {
    auto findResult = as().try_find_node_sync(NodeId{methodId});
    EXPECT_TRUE(findResult.is_good());

    ensure_object(objectId);
    CallMethodRequest request;
    request.object_id() = objectId;
    request.method_id() = NodeId{methodId};

    auto context = std::make_shared<MethodCallContext>();

    std::promise<CallResult> promise;
    findResult.value().as<MethodAccessor>()->call_async(
      request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  /// Invoke a type method node (`methodId`) against `objectId` with (eventId,
  /// comment) input arguments and return the CallResult.
  CallResult call_event_comment(
    MethodId methodId, const NodeId& objectId, const ByteString& eventId, const LocalizedText& comment)
  {
    auto findResult = as().try_find_node_sync(NodeId{methodId});
    EXPECT_TRUE(findResult.is_good());

    ensure_object(objectId);
    CallMethodRequest request;
    request.object_id() = objectId;
    request.method_id() = NodeId{methodId};
    request.input_arguments().push_back(Variant{eventId});
    request.input_arguments().push_back(Variant{comment});

    auto context = std::make_shared<MethodCallContext>();

    std::promise<CallResult> promise;
    findResult.value().as<MethodAccessor>()->call_async(
      request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }
};

TEST_F(ConditionTypeMethodHandlerTest, AcknowledgeViaTypeNode_TakesEffect)
{
  const NodeId conditionId{1, 1000u};
  // Conditions start disabled (mEnabled=false); an alarm is acknowledgeable + activatable.
  // enable + activate so it is retained with a live, unacked EventId.
  auto instance = mManager->create_condition_sync(
    conditionId, NodeId{1, 100u}, String{"Source"}, std::make_unique<AlarmConditionLogic>());
  ASSERT_NE(instance, nullptr);
  instance->enable_sync();
  instance->activate_sync(500);

  // Live trunk EventId - the value a client would have received in the last condition event.
  ASSERT_FALSE(mSink->events.empty());
  auto eventId = mSink->events.back()->eventId;
  ASSERT_FALSE(eventId.empty());
  ASSERT_FALSE(instance->snapshot()->acked());

  // Invoke AcknowledgeableConditionType_Acknowledge (i=9111) with the instance as
  // the object - the exact wire shape UACTT uses.
  auto result = call_event_comment(
    MethodId::AcknowledgeableConditionType_Acknowledge, conditionId, eventId, LocalizedText{"", "Ack"});

  ASSERT_TRUE(result.is_good()) << "Outer CallResult must be Good (status rides on CallMethodResult)";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::Good})
    << "Acknowledge via type node must succeed, not BadNotSupported; got "
    << result.value().status_code().as_uint32();

  EXPECT_TRUE(instance->snapshot()->acked())
    << "Acknowledge via the type method node must move AckedState to acknowledged";
}

TEST_F(ConditionTypeMethodHandlerTest, ConfirmViaTypeNode_TakesEffect)
{
  const NodeId conditionId{1, 1001u};
  // A plain acknowledgeable condition with confirm support: enabling emits a trunk event whose
  // EventId is acknowledgeable, and acknowledging emits a fresh trunk event that is confirmable
  // (confirm matches eventId == last_event_id()). An alarm would branch on activate and desync the
  // trunk EventId. Conditions start disabled, so enable first.
  auto logic = std::make_unique<AcknowledgeableConditionLogic>();
  logic->set_supports_confirm(true);
  auto instance =
    mManager->create_condition_sync(conditionId, NodeId{1, 100u}, String{"Source"}, std::move(logic));
  ASSERT_NE(instance, nullptr);
  instance->enable_sync();

  // The trunk condition EventId comes from the snapshot - NOT sink->events.back(): a type-node
  // acknowledge/confirm emits the AuditCondition* event AFTER the condition event, so back() is
  // the audit event, whose EventId is not a condition EventId.
  ASSERT_FALSE(instance->snapshot()->event_id().empty());
  auto eventId = instance->snapshot()->event_id();
  auto ackResult = call_event_comment(
    MethodId::AcknowledgeableConditionType_Acknowledge, conditionId, eventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(ackResult.is_good());
  ASSERT_EQ(ackResult.value().status_code(), StatusCode{Status::Good});
  ASSERT_TRUE(instance->snapshot()->acked());
  ASSERT_FALSE(instance->snapshot()->confirmed());

  // Confirm via AcknowledgeableConditionType_Confirm (i=9113) using the post-ack live trunk
  // EventId (the acknowledge transition emitted a fresh trunk condition event).
  auto confirmEventId = instance->snapshot()->event_id();
  ASSERT_FALSE(confirmEventId.empty());
  auto confirmResult = call_event_comment(MethodId::AcknowledgeableConditionType_Confirm,
    conditionId,
    confirmEventId,
    LocalizedText{"", "Confirm"});

  ASSERT_TRUE(confirmResult.is_good());
  EXPECT_EQ(confirmResult.value().status_code(), StatusCode{Status::Good})
    << "Confirm via type node must succeed; got " << confirmResult.value().status_code().as_uint32();
  EXPECT_TRUE(instance->snapshot()->confirmed())
    << "Confirm via the type method node must move ConfirmedState to confirmed";
}

TEST_F(ConditionTypeMethodHandlerTest, EnableDisableViaTypeNode_TakesEffect)
{
  const NodeId conditionId{1, 1002u};
  // Conditions start disabled (mEnabled=false) - Enable is the explicit first operation.
  auto instance = mManager->create_condition_sync(
    conditionId, NodeId{1, 100u}, String{"Source"}, std::make_unique<AcknowledgeableConditionLogic>());
  ASSERT_NE(instance, nullptr);
  ASSERT_FALSE(instance->snapshot()->enabled());

  // Enable via ConditionType_Enable (i=9027).
  auto enableResult = call_argless(MethodId::ConditionType_Enable, conditionId);
  ASSERT_TRUE(enableResult.is_good());
  EXPECT_EQ(enableResult.value().status_code(), StatusCode{Status::Good})
    << "Enable via type node must succeed, not BadNotSupported; got "
    << enableResult.value().status_code().as_uint32();
  EXPECT_TRUE(instance->snapshot()->enabled()) << "Enable via type node must set EnabledState";

  // Disable via ConditionType_Disable (i=9028).
  auto disableResult = call_argless(MethodId::ConditionType_Disable, conditionId);
  ASSERT_TRUE(disableResult.is_good());
  EXPECT_EQ(disableResult.value().status_code(), StatusCode{Status::Good})
    << "Disable via type node must succeed; got " << disableResult.value().status_code().as_uint32();
  EXPECT_FALSE(instance->snapshot()->enabled()) << "Disable via type node must clear EnabledState";
}

TEST_F(ConditionTypeMethodHandlerTest, AddCommentViaTypeNode_Succeeds)
{
  const NodeId conditionId{1, 1003u};
  auto instance = make_ack_condition(conditionId);
  ASSERT_NE(instance, nullptr);
  instance->enable_sync();  // conditions start disabled; enabling emits the first event

  ASSERT_FALSE(mSink->events.empty());
  auto eventId = mSink->events.back()->eventId;
  ASSERT_FALSE(eventId.empty());

  // AddComment via ConditionType_AddComment (i=9029).
  auto result = call_event_comment(
    MethodId::ConditionType_AddComment, conditionId, eventId, LocalizedText{"", "Operator note"});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::Good})
    << "AddComment via type node must succeed, not BadNotSupported; got "
    << result.value().status_code().as_uint32();
  EXPECT_EQ(instance->snapshot()->comment().text(), String{"Operator note"})
    << "AddComment via the type method node must record the comment";
}

TEST_F(ConditionTypeMethodHandlerTest, ObjectIdNotACondition_ReturnsBadNodeIdInvalid)
{
  // Call the handler on an existing Object that is not a registered Condition. In production
  // the Call service's validate_object_id sub-flow runs first: a syntactically-valid-but-nonexistent
  // objectId fails its find_node and the service returns Bad_NodeIdUnknown without reaching this
  // handler. So any objectId that DOES reach the handler is an existing node that is not a live
  // Condition instance (e.g. a type node) -> the handler reports Bad_NodeIdInvalid (UACTT A&C Comment
  // Err_003 calls AddComment on ConditionType itself and expects exactly this).
  const NodeId notAConditionId{1, 7777u};

  auto result = call_argless(MethodId::ConditionType_Enable, notAConditionId);

  ASSERT_TRUE(result.is_good()) << "Outer CallResult must be Good (status rides on CallMethodResult)";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadNodeIdInvalid})
    << "An objectId that is not a live Condition instance must yield Bad_NodeIdInvalid; got "
    << result.value().status_code().as_uint32();
}

TEST_F(ConditionTypeMethodHandlerTest, AcknowledgeViaTypeNode_UnknownEventId_RidesOnCallMethodResult)
{
  const NodeId conditionId{1, 1004u};
  auto instance = make_ack_condition(conditionId);
  ASSERT_NE(instance, nullptr);

  ByteString bogusEventId{std::vector<uint8_t>{0xAA, 0xBB, 0xCC}};

  // Per-operation failure (BadEventIdUnknown) must ride INSIDE the CallMethodResult
  // (OPC 10000-4 section 5.11.2); the outer CallResult stays Good.
  auto result = call_event_comment(
    MethodId::AcknowledgeableConditionType_Acknowledge, conditionId, bogusEventId, LocalizedText{"", "Ack"});

  ASSERT_TRUE(result.is_good()) << "Outer CallResult must stay Good for a per-operation failure";
  EXPECT_EQ(result.value().status_code(), StatusCode{Status::BadEventIdUnknown})
    << "An unknown EventId must surface as Bad_EventIdUnknown on the CallMethodResult; got "
    << result.value().status_code().as_uint32();
  EXPECT_FALSE(instance->snapshot()->acked()) << "A failed acknowledge must not change AckedState";
}

// ===========================================================================
// Part 9 obligations driven end-to-end through the manager
// ===========================================================================

/// Resolve the direct child of `parent` reached over `refType` whose BrowseName is `browseName`,
/// or a null NodeId when there is none. This is the same navigation the attach flow performs
/// internally (find_child_id_by_browse_name_async), so a test can seed or inspect the very nodes
/// the production code reads.
static NodeId find_condition_child_id(
  AddressSpace& addressSpace, const NodeId& parent, const NodeId& refType, const std::string& browseName)
{
  auto nodeResult = addressSpace.try_find_node_sync(parent);
  if (nodeResult.is_bad())
  {
    return NodeId{};
  }
  auto refs = nodeResult.value().get_references_sync();
  for (const auto& ref : refs)
  {
    if (!ref.is_forward() || ref.is_remote() || ref.type_id() != refType)
    {
      continue;
    }
    auto childResult = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (childResult.is_good() && std::string{childResult.value().get_browse_name().name()} == browseName)
    {
      return ref.target_id().node_id();
    }
  }
  return NodeId{};
}

// Part 9 section 5.8.18: a configured alarm limit whose value the underlying system cannot supply
// remains a Property, but its AccessLevel omits CurrentRead. The supplied sibling is the control that
// proves ordinary configured-limit wiring remains readable.
// @relation(AC-SVR-AC-202-LIMIT-UNAVAILABLE-STATUS, scope=function)
TEST_F(ConditionsDiscoverTest, UnavailableLimitIsInstantiatedButNotReadable)
{
  auto logic = std::make_unique<LimitAlarmLogic>();
  LimitConfig limits;
  limits.highHighLimit = 90.0;
  limits.highLimit = ConfiguredLimit::unavailable();
  logic->set_limits(limits);

  const auto requestedId = sNextId++;
  auto created = mManager->try_create_condition_sync(NodeId{1, requestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("UnavailableLimit_{}", requestedId)},
    std::move(logic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(created.is_good());
  ASSERT_NE(created.value(), nullptr);
  const NodeId conditionId = created.value()->condition_id();

  const NodeId suppliedId =
    find_condition_child_id(as(), conditionId, NodeId{ReferenceTypeId::HasProperty}, "HighHighLimit");
  const NodeId unavailableId =
    find_condition_child_id(as(), conditionId, NodeId{ReferenceTypeId::HasProperty}, "HighLimit");
  ASSERT_FALSE(suppliedId.is_null()) << "the supplied control limit was omitted";
  ASSERT_FALSE(unavailableId.is_null()) << "the unavailable limit Property was omitted";

  auto suppliedResult = as().try_find_node_sync(suppliedId);
  auto unavailableResult = as().try_find_node_sync(unavailableId);
  ASSERT_TRUE(suppliedResult.is_good());
  ASSERT_TRUE(unavailableResult.is_good());
  auto supplied = suppliedResult.value().as<VariableAccessor>();
  auto unavailable = unavailableResult.value().as<VariableAccessor>();
  ASSERT_TRUE(supplied.has_value());
  ASSERT_TRUE(unavailable.has_value());
  EXPECT_TRUE(supplied->get_access_level().test(AccessLevelType::Bit::CurrentRead));
  EXPECT_FALSE(unavailable->get_access_level().test(AccessLevelType::Bit::CurrentRead));
}

// Part 9 section 5.8.22.1 requires every available low deviation limit to be negative and every
// available high deviation limit to be positive; zero is prohibited. Rejecting a mis-signed
// configuration is the negative arm, while the signed sibling proves ordinary creation remains live.
// @relation(AC-SVR-AC-209-DEVIATION-LIMIT-SIGNS, scope=function)
// @relation(AC-SVR-AC-217-DEVIATION-LIMIT-RULES, scope=function)
TEST_F(ConditionsDiscoverTest, DeviationAlarmCreationRejectsMisSignedOrZeroLimitsWithRichDetail)
{
  auto invalidLogic = std::make_unique<LimitAlarmLogic>();
  LimitConfig invalidLimits;
  invalidLimits.highLimit = 10.0;
  invalidLimits.lowLimit = 5.0;
  invalidLimits.lowLowLimit = 0.0;
  invalidLogic->set_limits(invalidLimits);

  const auto invalidId = sNextId++;
  auto rejected = mManager->try_create_condition_sync(NodeId{1, invalidId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("InvalidDeviation_{}", invalidId)},
    std::move(invalidLogic),
    NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
  ASSERT_TRUE(rejected.is_bad());
  EXPECT_EQ(rejected.status_code(), Status::BadOutOfRange);
  ASSERT_NE(rejected.shared_detail(), nullptr);
  EXPECT_EQ(rejected.shared_detail()->code, "DeviationLimitSignInvalid");
  EXPECT_EQ(rejected.shared_detail()->source, "Conditions");

  auto validLogic = std::make_unique<LimitAlarmLogic>();
  LimitConfig validLimits;
  validLimits.highLimit = 10.0;
  validLimits.lowLimit = -10.0;
  validLogic->set_limits(validLimits);
  const auto validId = sNextId++;
  auto accepted = mManager->try_create_condition_sync(NodeId{1, validId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("ValidDeviation_{}", validId)},
    std::move(validLogic),
    NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
  ASSERT_TRUE(accepted.is_good());
  ASSERT_NE(accepted.value(), nullptr);
}

// Part 9 section 5.5.2: on restart the manager restores each Condition's EnabledState from what the
// address space still holds, and where that state cannot be determined the Condition comes back
// **Enabled**. Defaulting the indeterminate case to Disabled is the plausible implementation - a
// freshly constructed logic object is disabled, so "no recovered value" and "not yet enabled" look
// alike - and it silently mutes an alarm nobody knows is muted.
// @verifies AC-SVR-AC-012-ENABLEDSTATE-RECOVERY
TEST_F(ConditionsDiscoverTest, RestartRestoresDisabledStateAndDefaultsIndeterminateStateToEnabled)
{
  // Two condition objects already present in the address space, as they would be after a restart.
  const auto persistedDisabledId = instantiate_bare_condition(plain_condition_type(), "RecoveryDisabled");
  ASSERT_FALSE(persistedDisabledId.is_null());
  const auto indeterminateId = instantiate_bare_condition(plain_condition_type(), "RecoveryUnknown");
  ASSERT_FALSE(indeterminateId.is_null());

  // The first carries a recoverable EnabledState of False.
  const auto disabledEnabledState =
    find_condition_child_id(as(), persistedDisabledId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(disabledEnabledState.is_null());
  const auto disabledEnabledStateIdProperty =
    find_condition_child_id(as(), disabledEnabledState, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(disabledEnabledStateIdProperty.is_null());
  auto disabledVar = as().try_find_sync<VariableAccessor>(disabledEnabledStateIdProperty);
  ASSERT_TRUE(disabledVar.is_good());
  ASSERT_TRUE(disabledVar.value().try_write_value_sync(DataValue{Variant{false}}).is_good())
    << "the persisted-Disabled precondition must actually reach the node the attach flow reads";

  // The second must genuinely hold no determinable Boolean, otherwise the default is never taken and
  // the second half of the obligation would pass vacuously.
  const auto indeterminateEnabledState =
    find_condition_child_id(as(), indeterminateId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(indeterminateEnabledState.is_null());
  const auto indeterminateIdProperty =
    find_condition_child_id(as(), indeterminateEnabledState, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(indeterminateIdProperty.is_null());
  auto indeterminateVar = as().try_find_sync<VariableAccessor>(indeterminateIdProperty);
  ASSERT_TRUE(indeterminateVar.is_good());
  auto indeterminateValue = indeterminateVar.value().try_read_value_sync();
  ASSERT_TRUE(indeterminateValue.is_bad() || indeterminateValue.value().value().try_as<bool>() == nullptr)
    << "the indeterminate condition must not carry a readable EnabledState/Id, or the recovery default "
       "is never exercised";

  // Restart: the manager scans the address space and re-attaches both conditions.
  ASSERT_TRUE(run_discover().is_good());

  auto recoveredDisabled = mManager->find_condition_sync(persistedDisabledId);
  ASSERT_NE(recoveredDisabled, nullptr) << "the previously Disabled condition must be recovered at all";
  auto recoveredIndeterminate = mManager->find_condition_sync(indeterminateId);
  ASSERT_NE(recoveredIndeterminate, nullptr) << "the indeterminate condition must be recovered at all";

  auto disabledSnapshot = recoveredDisabled->snapshot();
  ASSERT_NE(disabledSnapshot, nullptr);
  auto indeterminateSnapshot = recoveredIndeterminate->snapshot();
  ASSERT_NE(indeterminateSnapshot, nullptr);

  EXPECT_FALSE(disabledSnapshot->enabled())
    << "a Condition whose EnabledState was recoverable as False must come back Disabled";
  EXPECT_TRUE(indeterminateSnapshot->enabled())
    << "a Condition whose EnabledState cannot be determined must come back Enabled, so the operator "
       "still hears from it";
}

// Part 9 section 5.5.2: every Condition instance the server owns carries an identifier no other
// instance shares. The plausible economy is to key a Condition by (ConditionType, ConditionSource) -
// natural, and wrong: two instances then collapse onto one identifier and an Acknowledge lands on
// whichever the server finds first, leaving the other alarm unacknowledged with no explanation.
// @verifies AC-SVR-AC-036-CONDITION-UNIQUE-IDENTIFIER
TEST_F(ConditionsTest, NoTwoRegisteredConditionsShareAnIdentifier)
{
  // Same ConditionType, different ConditionSources.
  auto first = mManager->create_condition_sync(
    NodeId{1, 4100u}, NodeId{1, 100u}, String{"SourceA"}, std::make_unique<ConditionLogic>());
  ASSERT_NE(first, nullptr);
  auto second = mManager->create_condition_sync(
    NodeId{1, 4200u}, NodeId{1, 200u}, String{"SourceB"}, std::make_unique<ConditionLogic>());
  ASSERT_NE(second, nullptr);

  // A third instance of that same type, on the second source, claiming an identifier already in use:
  // the registry must refuse it rather than let two instances answer to one identifier.
  auto collision = mManager->try_create_condition_sync(
    NodeId{1, 4100u}, NodeId{1, 200u}, String{"SourceB"}, std::make_unique<ConditionLogic>());
  EXPECT_FALSE(collision.is_good()) << "a duplicate ConditionId must not produce a second live instance";
  EXPECT_EQ(collision.status_code(), StatusCode{Status::BadAlreadyExists})
    << "a duplicate ConditionId must be refused with BadAlreadyExists; got "
    << collision.status_code().as_uint32();

  // The identifier still resolves to the original instance, not to the late claimant.
  auto found = mManager->find_condition_sync(NodeId{1, 4100u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found.get(), first.get()) << "the identifier must keep resolving to the instance that owns it";

  // Enumerate the instances the manager owns and compare their identifiers pairwise.
  first->enable_sync();
  second->enable_sync();
  auto instances = mManager->retained_conditions_sync();
  ASSERT_EQ(instances.size(), 2u)
    << "exactly the two accepted instances must be enumerable - the refused one must not be registered";
  for (size_t i = 0; i < instances.size(); ++i)
  {
    ASSERT_NE(instances[i], nullptr);
    for (size_t j = i + 1; j < instances.size(); ++j)
    {
      ASSERT_NE(instances[j], nullptr);
      EXPECT_NE(instances[i]->condition_id(), instances[j]->condition_id())
        << "two enumerated Condition instances share an identifier";
    }
  }
}

// Part 9 section 5.5: on a server that supports auditing, EVERY Enable/Disable transition raises its
// AuditConditionEnableEventType. Auditing only the Enable direction is the plausible half-measure -
// enabling is the "interesting" operator action - and it loses the record of who muted a Condition,
// which is precisely the event an incident review needs.
// @verifies AC-SVR-AC-037-ENABLE-DISABLE-AUDIT-REQUIRED
TEST_F(ConditionTypeMethodHandlerTest, EnableAndDisableEachRaiseTheirAuditEvent)
{
  const NodeId conditionId{1, 1010u};
  auto instance = mManager->create_condition_sync(
    conditionId, NodeId{1, 100u}, String{"Source"}, std::make_unique<AcknowledgeableConditionLogic>());
  ASSERT_NE(instance, nullptr);
  ASSERT_FALSE(instance->snapshot()->enabled()) << "conditions start disabled; Enable is a real transition";

  // Count the audit events the manager's sink has recorded, under its lock. The sink keeps the
  // audit family in its own vector - the Condition Event stream is what every other test here
  // indexes, and folding audits into it renumbers all of them - so this reads that one.
  auto enableAuditCount = [this]()
  {
    return mSink->with_audit_events(
      [](const std::vector<std::unique_ptr<BaseEvent>>& events)
      {
        size_t count = 0;
        for (const auto& event : events)
        {
          if (dynamic_cast<const AuditConditionEnableEventPayload*>(event.get()) != nullptr)
          {
            ++count;
          }
        }
        return count;
      });
  };

  const size_t before = enableAuditCount();

  auto enableResult = call_argless(MethodId::ConditionType_Enable, conditionId);
  ASSERT_TRUE(enableResult.is_good());
  ASSERT_EQ(enableResult.value().status_code(), StatusCode{Status::Good})
    << "Enable must succeed, otherwise no transition happened and the audit assertion is meaningless";
  ASSERT_TRUE(instance->snapshot()->enabled()) << "Enable must have taken effect";
  const size_t afterEnable = enableAuditCount();
  EXPECT_EQ(afterEnable, before + 1) << "the Enable transition must raise an AuditConditionEnableEvent";

  auto disableResult = call_argless(MethodId::ConditionType_Disable, conditionId);
  ASSERT_TRUE(disableResult.is_good());
  ASSERT_EQ(disableResult.value().status_code(), StatusCode{Status::Good})
    << "Disable must succeed, otherwise no transition happened and the audit assertion is meaningless";
  ASSERT_FALSE(instance->snapshot()->enabled()) << "Disable must have taken effect";
  const size_t afterDisable = enableAuditCount();
  EXPECT_EQ(afterDisable, afterEnable + 1)
    << "the Disable transition must raise its own AuditConditionEnableEvent, not only Enable";
}

// @relation(AC-SVR-AC-041-METHOD-AUDIT-EVENTS, scope=function)
TEST_F(ConditionTypeMethodHandlerTest, RefusedEnableRaisesTheDeclaredAuditSubtypeWithFalseStatus)
{
  const NodeId conditionId{1, 1011u};
  auto instance = mManager->create_condition_sync(
    conditionId, NodeId{1, 100u}, String{"Source"}, std::make_unique<AcknowledgeableConditionLogic>());
  ASSERT_NE(instance, nullptr);

  auto accepted = call_argless(MethodId::ConditionType_Enable, conditionId);
  ASSERT_TRUE(accepted.is_good());
  ASSERT_EQ(accepted.value().status_code(), StatusCode{Status::Good});

  auto refused = call_argless(MethodId::ConditionType_Enable, conditionId);
  ASSERT_TRUE(refused.is_good()) << "the operation result belongs to CallMethodResult";
  ASSERT_EQ(refused.value().status_code(), StatusCode{Status::BadConditionAlreadyEnabled});

  mSink->with_audit_events(
    [](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      std::vector<bool> enableStatuses;
      for (const auto& event : events)
      {
        if (const auto* enable = dynamic_cast<const AuditConditionEnableEventPayload*>(event.get()))
        {
          enableStatuses.push_back(enable->status);
        }
      }

      ASSERT_EQ(enableStatuses.size(), 2u)
        << "both the accepted and refused invocation must raise the declared audit subtype";
      EXPECT_TRUE(enableStatuses[0]);
      EXPECT_FALSE(enableStatuses[1]);
    });
}

// Part 9 section 5.5.3 ("This is True even if..."): where a ConditionBranch is outstanding, the current
// Condition is still reported alongside it. Reporting only the branches is the plausible economy -
// the branch is the state awaiting an operator - and it hides the live alarm behind an old
// unacknowledged one, so the operator reads history while the process has already moved on.
// @verifies AC-SVR-AC-038-BRANCH-REPORTS-CURRENT
TEST_F(ConditionsTest, RefreshReportsTheCurrentConditionAlongsideAnOutstandingBranch)
{
  auto logic = std::make_unique<AlarmConditionLogic>();
  logic->set_supports_branches(true);
  auto instance = mManager->create_condition_sync(
    NodeId{1, 6000u}, NodeId{1, 600u}, String{"BranchSource"}, std::move(logic));
  ASSERT_NE(instance, nullptr);

  instance->enable_sync();
  instance->activate_sync(500);
  // The current Condition changes state while the prior, unacknowledged occurrence is outstanding:
  // that prior occurrence is forked onto a branch and the trunk takes the new severity.
  instance->activate_sync(700);
  ASSERT_TRUE(instance->snapshot()->retained());

  ManagerFakeEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  // RefreshStart + the current Condition + at least one branch + RefreshEnd.
  ASSERT_GE(refreshSink.events.size(), 4u)
    << "refresh must carry the current Condition and its branch between Start and End";
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(refreshSink.events.front().get()), nullptr);
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(refreshSink.events.back().get()), nullptr);

  size_t trunkCount = 0;
  size_t branchCount = 0;
  uint16_t trunkSeverity = 0;
  for (const auto& event : refreshSink.events)
  {
    auto* condition = dynamic_cast<ConditionPayload*>(event.get());
    if (condition == nullptr)
    {
      continue;
    }
    if (condition->branchId.is_null())
    {
      ++trunkCount;
      trunkSeverity = event->severity;
      EXPECT_TRUE(condition->retain) << "the reported current Condition must carry Retain=True";
    }
    else
    {
      ++branchCount;
      EXPECT_TRUE(condition->retain) << "an outstanding branch must be re-issued with Retain=True";
    }
  }

  ASSERT_GE(branchCount, 1u) << "no branch was outstanding - the obligation is not exercised without one";
  EXPECT_EQ(trunkCount, 1u)
    << "the current Condition must be reported exactly once, and the outstanding branch must not "
       "suppress it";
  EXPECT_EQ(trunkSeverity, 700)
    << "the event reported for the trunk must be the CURRENT state, not the branched prior one";
}

// Part 9 section 5.5.2: a Condition the server never named is still reported with a ConditionName -
// the BrowseName of its ConditionType. Leaving the field at its default is the plausible
// implementation (nothing in the create path assigns it and a fresh logic object starts with an
// empty name), and it hands the operator an unlabelled row in the alarm list with nothing to
// distinguish it from every other unnamed Condition.
// @verifies AC-SVR-AC-049-CONDITIONNAME-DEFAULT
TEST_F(ConditionsDiscoverTest, UnnamedSoleConditionTakesItsConditionTypeBrowseNameAsConditionName)
{
  auto typeNodeResult = as().try_find_node_sync(NodeId{ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(typeNodeResult.is_good()) << "AlarmConditionType must be present for this to mean anything";
  const String expectedConditionName{typeNodeResult.value().get_browse_name().name()};
  ASSERT_FALSE(expectedConditionName.empty())
    << "the expected name must be a real BrowseName, otherwise the comparison below passes vacuously";

  // Exactly one Condition of that type on the source, and the server assigns it no name: the
  // ConditionType fallback is the only thing that can populate ConditionName.
  const auto id = sNextId++;
  auto created = mManager->try_create_condition_sync(NodeId{1, id},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("UnnamedCond_{}", id)},
    std::make_unique<AlarmConditionLogic>(),
    NodeId{ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(created.is_good()) << "condition creation must succeed; status="
                                 << created.status_code().as_uint32();
  auto instance = created.value();
  ASSERT_NE(instance, nullptr);

  // The ConditionName a client reads resolves through the condition's state snapshot (the
  // ConditionName value source reads exactly this field).
  auto snapshot = instance->snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->condition_name(), expectedConditionName)
    << "a sole unnamed Condition must report its ConditionType's BrowseName as ConditionName, not an "
       "empty name";

  // The same field travels on every Condition Event, which is where a subscriber sees it.
  instance->enable_sync();

  size_t conditionEventCount = 0;
  String reportedConditionName;
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (const auto& event : events)
      {
        if (const auto* condition = dynamic_cast<const ConditionPayload*>(event.get()))
        {
          ++conditionEventCount;
          reportedConditionName = condition->conditionName;
        }
      }
    });
  ASSERT_GE(conditionEventCount, 1u)
    << "no Condition Event was emitted, so nothing carried a ConditionName to inspect";
  EXPECT_EQ(reportedConditionName, expectedConditionName)
    << "the ConditionName carried on the Condition Event must be the ConditionType's BrowseName";
}

/// Invoke the registered ConditionType_ConditionRefresh2 handler as a named Session and return the
/// call result. The fixture's own `call_refresh2` supplies a default (null) sessionId; the
/// Session-ownership check needs a caller identity it can compare against, so this shape carries one.
static CallResult call_refresh2_as_session(
  AddressSpace& addressSpace, uint32_t subscriptionId, uint32_t monitoredItemId, const NodeId& sessionId)
{
  auto findResult = addressSpace.try_find_node_sync(NodeId{MethodId::ConditionType_ConditionRefresh2});
  EXPECT_TRUE(findResult.is_good());

  CallMethodRequest request;
  request.object_id() = NodeId{ObjectTypeId::ConditionType};
  request.method_id() = NodeId{MethodId::ConditionType_ConditionRefresh2};
  request.input_arguments().push_back(Variant{subscriptionId});
  request.input_arguments().push_back(Variant{monitoredItemId});

  auto context = std::make_shared<MethodCallContext>();
  context->sessionId = sessionId;

  std::promise<CallResult> promise;
  findResult.value().as<MethodAccessor>()->call_async(
    request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
  return promise.get_future().get();
}

// Part 9 section 5.5.8: ConditionRefresh2 must confirm the named Subscription belongs to the calling
// Session before it refreshes anything. Trusting the SubscriptionId as supplied is the plausible
// implementation - the id is enough to route the events - and it lets any Session replay another
// Session's whole retained alarm set simply by guessing an id. The obligation is that the call is
// refused; the handler reports Bad_SubscriptionIdInvalid (SVR-AC-056 names Bad_UserAccessDenied),
// so this asserts the refusal itself rather than one particular Bad code.
// @verifies AC-SVR-AC-056-REFRESH2-SESSION-CHECK
TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2NamingAnotherSessionsSubscriptionIsRefused)
{
  const NodeId source100{1, 100u};
  make_retained_alarm(NodeId{1, 1000u}, source100);

  // Recorder for whatever the refresh delivers to the target MonitoredItem.
  auto refreshSink = std::make_shared<ManagerFakeEventSink>();
  mEventBus->register_event_item(source100,
    10,
    1,
    [refreshSink](IntegerId, std::shared_ptr<const BaseEvent> ev)
    {
      if (ev)
      {
        auto clone = ev->clone();
        refreshSink->emit(*clone);
      }
    });

  // Subscription 1 is owned by session 900 - the ownership table the server's validator reads out of
  // its subscription registry. The validator answers the ownership question; the refusal is the
  // handler's to make.
  const NodeId owningSession{1, 900u};
  const NodeId otherSession{1, 901u};
  Conditions::SubscriptionValidator validator = [owningSession](
                                                  uint32_t subscriptionId, const NodeId& callerSessionId)
  {
    return subscriptionId == 1u && callerSessionId == owningSession;
  };

  // Membership resolution is the live EventBus registry, as the server wires it.
  Conditions::MonitoredItemNodeResolver resolver =
    [weakBus = std::weak_ptr<server::EventBus>{mEventBus}](
      uint32_t subscriptionId, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> done)
  {
    auto bus = weakBus.lock();
    if (!bus)
    {
      done(std::nullopt);
      return;
    }
    bus->resolve_event_item_node_async(subscriptionId, monitoredItemId, std::move(done));
  };

  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, std::move(validator), std::move(resolver));

  auto refused = call_refresh2_as_session(as(), 1, 10, otherSession);
  ASSERT_TRUE(refused.is_good()) << "the Call completes; the refusal rides on the CallMethodResult";
  EXPECT_TRUE(refused.value().status_code().is_bad())
    << "ConditionRefresh2 naming a Subscription owned by another Session must be refused; got "
    << refused.value().status_code().as_uint32();

  // Refused means refused: nothing may be replayed to the Subscription's MonitoredItem. Give an
  // erroneous emission time to land before reading the (still un-drained) recorder.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(refreshSink->size(), 0u)
    << "a ConditionRefresh2 refused on Session ownership must not deliver any Condition Event";

  // Control: the identical call from the owning Session is accepted and does deliver the refresh, so
  // the refusal above is attributable to the Session check and not to the shape of the call.
  auto allowed = call_refresh2_as_session(as(), 1, 10, owningSession);
  ASSERT_TRUE(allowed.is_good());
  EXPECT_EQ(allowed.value().status_code(), StatusCode{Status::Good})
    << "the owning Session's ConditionRefresh2 must succeed; got "
    << allowed.value().status_code().as_uint32();
  EXPECT_GE(refreshSink->wait_for_count(3, std::chrono::seconds(2)), 3u)
    << "the owning Session must receive RefreshStart + the retained Condition + RefreshEnd";
}

// Part 9 section 5.5.8: ConditionRefresh2 takes both a SubscriptionId and a MonitoredItemId, and the
// MonitoredItem must belong to the named Subscription. Resolving the item by its id alone is the
// plausible implementation - MonitoredItem ids look unique enough - and it makes the narrower
// refresh a way to replay an item that lives in a Subscription the caller merely named.
// @verifies AC-SVR-AC-057-REFRESH2-ITEM-IN-SUBSCRIPTION
TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2WithAMonitoredItemFromAnotherSubscriptionIsRefused)
{
  const NodeId source100{1, 100u};
  make_retained_alarm(NodeId{1, 1000u}, source100);

  auto refreshSink = std::make_shared<ManagerFakeEventSink>();
  // MonitoredItem 10 exists on Subscription 1 and on no other Subscription.
  mEventBus->register_event_item(source100,
    10,
    1,
    [refreshSink](IntegerId, std::shared_ptr<const BaseEvent> ev)
    {
      if (ev)
      {
        auto clone = ev->clone();
        refreshSink->emit(*clone);
      }
    });

  // The caller owns every Subscription it names, so only the item-membership check can refuse this.
  const NodeId callerSession{1, 900u};
  Conditions::SubscriptionValidator validator = [](uint32_t, const NodeId&)
  {
    return true;
  };

  // Membership is answered by the live EventBus MonitoredItem registry - the same production lookup
  // the server installs - not by this test.
  Conditions::MonitoredItemNodeResolver resolver =
    [weakBus = std::weak_ptr<server::EventBus>{mEventBus}](
      uint32_t subscriptionId, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> done)
  {
    auto bus = weakBus.lock();
    if (!bus)
    {
      done(std::nullopt);
      return;
    }
    bus->resolve_event_item_node_async(subscriptionId, monitoredItemId, std::move(done));
  };

  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, std::move(validator), std::move(resolver));

  // Subscription 2 does not contain MonitoredItem 10.
  auto refused = call_refresh2_as_session(as(), 2, 10, callerSession);
  ASSERT_TRUE(refused.is_good()) << "the Call completes; the refusal rides on the CallMethodResult";
  EXPECT_EQ(refused.value().status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "a MonitoredItemId outside the named Subscription must be refused with "
       "Bad_MonitoredItemIdInvalid; got "
    << refused.value().status_code().as_uint32();

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(refreshSink->size(), 0u)
    << "a ConditionRefresh2 refused on MonitoredItem membership must not deliver any Condition Event";

  // Control: the same MonitoredItemId under the Subscription it does belong to is accepted, so the
  // refusal above is attributable to the membership check.
  auto accepted = call_refresh2_as_session(as(), 1, 10, callerSession);
  ASSERT_TRUE(accepted.is_good());
  EXPECT_EQ(accepted.value().status_code(), StatusCode{Status::Good})
    << "the MonitoredItem's own Subscription must be accepted; got "
    << accepted.value().status_code().as_uint32();
  EXPECT_GE(refreshSink->wait_for_count(3, std::chrono::seconds(2)), 3u)
    << "the accepted refresh must deliver RefreshStart + the retained Condition + RefreshEnd";
}

// Part 9 section 5.5.8: narrowing a refresh to one MonitoredItem changes which Conditions are
// refreshed, not what is issued for each of them - the prior states still awaiting acknowledgement
// come back alongside the current one. Reissuing only the current state is the plausible economy
// (that is the Condition's live state, and the branches are historical), and it leaves the operator
// who refreshed a single item with no record of the occurrences still owed an acknowledgement.
// @verifies AC-SVR-AC-059-REFRESH2-PRIOR-STATES
TEST_F(ConditionRefresh2HandlerTest, ConditionRefresh2ReissuesOutstandingPriorStatesAlongsideTheCurrentOne)
{
  const NodeId source100{1, 100u};

  auto logic = std::make_unique<AlarmConditionLogic>();
  logic->set_supports_branches(true);
  auto instance =
    mManager->create_condition_sync(NodeId{1, 7000u}, source100, String{"BranchSource"}, std::move(logic));
  ASSERT_NE(instance, nullptr);

  instance->enable_sync();
  instance->activate_sync(500);
  // The Condition changes state while the prior occurrence is still unacknowledged: that prior state
  // forks onto a ConditionBranch and the current Condition takes the new severity.
  instance->activate_sync(700);
  ASSERT_TRUE(instance->snapshot()->retained());

  auto refreshSink = std::make_shared<ManagerFakeEventSink>();
  mEventBus->register_event_item(source100,
    10,
    1,
    [refreshSink](IntegerId, std::shared_ptr<const BaseEvent> ev)
    {
      if (ev)
      {
        auto clone = ev->clone();
        refreshSink->emit(*clone);
      }
    });

  Conditions::SubscriptionValidator validator = [](uint32_t, const NodeId&)
  {
    return true;
  };
  Conditions::MonitoredItemNodeResolver resolver =
    [weakBus = std::weak_ptr<server::EventBus>{mEventBus}](
      uint32_t subscriptionId, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> done)
  {
    auto bus = weakBus.lock();
    if (!bus)
    {
      done(std::nullopt);
      return;
    }
    bus->resolve_event_item_node_async(subscriptionId, monitoredItemId, std::move(done));
  };

  mManager->register_refresh_methods(
    std::weak_ptr<server::EventBus>{mEventBus}, std::move(validator), std::move(resolver));

  auto result = call_refresh2_as_session(as(), 1, 10, NodeId{1, 900u});
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().status_code(), StatusCode{Status::Good})
    << "the refresh must run at all before its contents mean anything; got "
    << result.value().status_code().as_uint32();

  // The scoped refresh delivers RefreshStart, the current Condition, one event per outstanding
  // branch, and RefreshEnd - and delivery is asynchronous, through the EventBus dispatch strand.
  // How many branches are outstanding is the Condition's business, not this test's (enable +
  // activate + activate leaves two: the enabled-but-inactive state and the severity-500 state, both
  // unacknowledged), so wait on the closing bookend rather than on a guessed event count. Waiting
  // for a fixed four events returns as soon as the fourth arrives - a branch event, not RefreshEnd -
  // and reads the recorder while the RefreshEnd is still in flight.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  bool sawRefreshEnd = false;
  while (!sawRefreshEnd && std::chrono::steady_clock::now() < deadline)
  {
    sawRefreshEnd = refreshSink->with_events(
      [](const std::vector<std::unique_ptr<BaseEvent>>& events)
      {
        for (const auto& event : events)
        {
          if (dynamic_cast<RefreshEndEventPayload*>(event.get()) != nullptr)
          {
            return true;
          }
        }
        return false;
      });
    if (!sawRefreshEnd)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  ASSERT_TRUE(sawRefreshEnd) << "ConditionRefresh2 never closed its refresh window with a RefreshEnd";

  // RefreshEnd is emitted last, so every event of this refresh is now recorded:
  // RefreshStart + the current Condition + at least one prior state + RefreshEnd.
  const size_t observed = refreshSink->size();
  ASSERT_GE(observed, 4u)
    << "ConditionRefresh2 must deliver the current Condition AND its outstanding prior state between "
       "the Refresh bookends; observed "
    << observed << " events";

  size_t startCount = 0;
  size_t endCount = 0;
  size_t currentCount = 0;
  size_t priorCount = 0;
  uint16_t currentSeverity = 0;
  refreshSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (const auto& event : events)
      {
        if (dynamic_cast<RefreshStartEventPayload*>(event.get()) != nullptr)
        {
          ++startCount;
          continue;
        }
        if (dynamic_cast<RefreshEndEventPayload*>(event.get()) != nullptr)
        {
          ++endCount;
          continue;
        }
        auto* condition = dynamic_cast<ConditionPayload*>(event.get());
        if (condition == nullptr)
        {
          continue;
        }
        if (condition->branchId.is_null())
        {
          ++currentCount;
          currentSeverity = event->severity;
          EXPECT_TRUE(condition->retain) << "the reissued current Condition must carry Retain=True";
        }
        else
        {
          ++priorCount;
          EXPECT_TRUE(condition->retain) << "a reissued prior state must carry Retain=True";
        }
      }
    });

  EXPECT_EQ(startCount, 1u) << "the scoped refresh must be bracketed by exactly one RefreshStart";
  EXPECT_EQ(endCount, 1u) << "the scoped refresh must be bracketed by exactly one RefreshEnd";
  ASSERT_GE(priorCount, 1u)
    << "no prior state was reissued - a ConditionRefresh2 that drops the outstanding branches leaves "
       "the operator unaware of what is still owed an acknowledgement";
  EXPECT_EQ(currentCount, 1u)
    << "the current Condition must be reissued exactly once, alongside the prior states";
  EXPECT_EQ(currentSeverity, 700)
    << "the event reissued for the current Condition must be its CURRENT state, not the branched one";
}

// Part 9 section 5.11.4: when an Event queue overflows the server must track whether any of the events it
// threw away were Condition Events, because only that loss leaves the client's alarm list silently
// wrong. Counting the overflow without asking what was dropped is the plausible implementation - the
// queue code already maintains an overflow counter and every dropped notification looks alike at
// that point - and it either never prompts a recovery Refresh or prompts one after any overflow at
// all, so the flag stops carrying information.
// @verifies AC-SVR-AC-069-OVERFLOW-TRACKS-LOST-CONDITIONS
TEST_F(ConditionsTest, EventQueueOverflowRecordsWhetherConditionEventsWereLost)
{
  // Two queues overflowed the same way, differing only in what they were carrying. The queue holds
  // one notification, so the second enqueue is the overflow.
  server::MonitoredItem discardOldestWithConditions;
  discardOldestWithConditions.id = 1;
  discardOldestWithConditions.clientHandle = 42;
  discardOldestWithConditions.monitoringMode = MonitoringMode::Reporting;
  discardOldestWithConditions.isEventItem = true;
  discardOldestWithConditions.queueSize = 1;
  discardOldestWithConditions.discardOldest = true;
  discardOldestWithConditions.enqueue_event(EventFieldList{}, true);
  discardOldestWithConditions.enqueue_event(EventFieldList{}, true);

  server::MonitoredItem discardOldestWithoutConditions;
  discardOldestWithoutConditions.id = 2;
  discardOldestWithoutConditions.clientHandle = 43;
  discardOldestWithoutConditions.monitoringMode = MonitoringMode::Reporting;
  discardOldestWithoutConditions.isEventItem = true;
  discardOldestWithoutConditions.queueSize = 1;
  discardOldestWithoutConditions.discardOldest = true;
  discardOldestWithoutConditions.enqueue_event(EventFieldList{}, false);
  discardOldestWithoutConditions.enqueue_event(EventFieldList{}, false);

  // The same pair under the discard-newest policy, where it is the incoming notification that is
  // thrown away rather than the queued one.
  server::MonitoredItem discardNewestWithConditions;
  discardNewestWithConditions.id = 3;
  discardNewestWithConditions.clientHandle = 44;
  discardNewestWithConditions.monitoringMode = MonitoringMode::Reporting;
  discardNewestWithConditions.isEventItem = true;
  discardNewestWithConditions.queueSize = 1;
  discardNewestWithConditions.discardOldest = false;
  discardNewestWithConditions.enqueue_event(EventFieldList{}, true);
  discardNewestWithConditions.enqueue_event(EventFieldList{}, true);

  server::MonitoredItem discardNewestWithoutConditions;
  discardNewestWithoutConditions.id = 4;
  discardNewestWithoutConditions.clientHandle = 45;
  discardNewestWithoutConditions.monitoringMode = MonitoringMode::Reporting;
  discardNewestWithoutConditions.isEventItem = true;
  discardNewestWithoutConditions.queueSize = 1;
  discardNewestWithoutConditions.discardOldest = false;
  discardNewestWithoutConditions.enqueue_event(EventFieldList{}, false);
  discardNewestWithoutConditions.enqueue_event(EventFieldList{}, false);

  // Every queue must genuinely have overflowed, otherwise nothing was lost and the flags below say
  // nothing about the obligation.
  ASSERT_GT(discardOldestWithConditions.eventQueueOverflowCount, 0u)
    << "the Condition-bearing discard-oldest queue never overflowed";
  ASSERT_GT(discardOldestWithoutConditions.eventQueueOverflowCount, 0u)
    << "the Condition-free discard-oldest queue never overflowed";
  ASSERT_GT(discardNewestWithConditions.eventQueueOverflowCount, 0u)
    << "the Condition-bearing discard-newest queue never overflowed";
  ASSERT_GT(discardNewestWithoutConditions.eventQueueOverflowCount, 0u)
    << "the Condition-free discard-newest queue never overflowed";

  EXPECT_TRUE(discardOldestWithConditions.refreshRequired)
    << "an overflow that discarded a Condition Event must be recorded as a Condition-Event loss";
  EXPECT_FALSE(discardOldestWithoutConditions.refreshRequired)
    << "an overflow that discarded no Condition Event must not be recorded as a Condition-Event "
       "loss, or the record stops distinguishing anything";

  EXPECT_TRUE(discardNewestWithConditions.refreshRequired)
    << "discarding the incoming Condition Event is still a lost Condition Event and must be recorded";
  EXPECT_FALSE(discardNewestWithoutConditions.refreshRequired)
    << "discarding a non-Condition Event must not be recorded as a Condition-Event loss";
}

// Part 9 section 5.13: when a communication failure affects Conditions that are retained on a Subscription,
// those Conditions raise an Event so the subscriber learns the failure; Conditions the failure does
// not touch stay silent. Letting the failed reads fall on the floor is the plausible implementation
// - a read that failed has no new value to evaluate, so there is nothing obvious to report - and it
// leaves the affected alarms frozen in their last known state, indistinguishable from a quiet plant.
// The Condition whose underlying system is unreachable is bound to an input the address space cannot
// resolve, so every sampling cycle's read genuinely fails; the other Condition has no such link.
// @verifies AC-SVR-AC-077-COMMS-FAILURE-RETAINED-EVENTS
TEST_F(ConditionsDiscoverTest, CommunicationFailureRaisesEventsOnlyForTheAffectedRetainedConditions)
{
  const auto affectedId = create_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType}, "CommsAffected");
  ASSERT_FALSE(affectedId.is_null());
  const auto unaffectedId =
    create_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType}, "CommsUnaffected");
  ASSERT_FALSE(unaffectedId.is_null());

  auto affected = mManager->find_condition_sync(affectedId);
  ASSERT_NE(affected, nullptr);
  auto unaffected = mManager->find_condition_sync(unaffectedId);
  ASSERT_NE(unaffected, nullptr);

  // Both Conditions must be retained, otherwise the obligation ("if the Retain field is set to
  // True") does not apply and the assertions below mean nothing.
  affected->enable_sync();
  affected->activate_sync(500);
  unaffected->enable_sync();
  unaffected->activate_sync(500);
  ASSERT_TRUE(affected->snapshot()->retained()) << "the affected Condition must be retained";
  ASSERT_TRUE(unaffected->snapshot()->retained()) << "the unaffected Condition must be retained";

  // The underlying system behind the first Condition stops answering.
  const NodeId unreachableInput{1, 1900101u};
  ASSERT_TRUE(as().try_find_node_sync(unreachableInput).is_bad())
    << "the input node must genuinely be unresolvable, or no communication failure is provoked";
  ASSERT_TRUE(affected->try_bind_input_sync(unreachableInput, 25.0).is_good())
    << "binding the input is what puts this Condition behind an underlying system";

  // Whatever establishing the binding emitted is history. The obligation is about what the failure
  // itself raises, so only events recorded from here on are counted.
  const size_t mark = mSink->size();

  // Several sampling cycles run against the unreachable system. The affected
  // Condition's Event comes on one of them, later in a sanitized or loaded run, so the test waits for it
  // within a bound; the window for the Events that must not occur is then the original 300 ms.
  mSink->wait_until(std::chrono::seconds{10},
    [mark, affectedId](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        if (dynamic_cast<const ConditionPayload*>(events[index].get()) != nullptr &&
            events[index]->conditionNodeId == affectedId)
        {
          return true;
        }
      }
      return false;
    });
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  size_t affectedEvents = 0;
  size_t unaffectedEvents = 0;
  bool affectedCarriedRichCommunicationError = false;
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        const auto& event = events[index];
        if (dynamic_cast<const ConditionPayload*>(event.get()) == nullptr)
        {
          continue;
        }
        if (!event->conditionNodeId.has_value())
        {
          continue;
        }
        if (*event->conditionNodeId == affectedId)
        {
          ++affectedEvents;
          const auto* condition = dynamic_cast<const ConditionPayload*>(event.get());
          if (condition != nullptr)
          {
            if (const auto* quality = condition->quality.value.try_as<StatusCode>())
            {
              affectedCarriedRichCommunicationError =
                quality->as_status() == Status::BadCommunicationError && quality->shared_detail() != nullptr;
            }
          }
        }
        else if (*event->conditionNodeId == unaffectedId)
        {
          ++unaffectedEvents;
        }
      }
    });

  EXPECT_GE(affectedEvents, 1u)
    << "a retained Condition whose underlying system stopped answering must raise an Event; without "
       "one the subscriber's alarm list keeps showing the last known state forever";
  EXPECT_TRUE(affectedCarriedRichCommunicationError)
    << "the failed read must be normalized to Bad_CommunicationError while retaining the original "
       "lookup failure as ErrorDetail on that same StatusCode";
  EXPECT_EQ(unaffectedEvents, 0u)
    << "a Condition the communication failure does not touch must produce nothing";
}

// Part 9 section 5.13: the communication failure is itself reported to alarm clients as a Condition of
// SystemOffNormalAlarmType, whose NormalState names the Variable carrying the underlying system's
// status. Reporting the failure only through the affected Conditions' own fields is the plausible
// implementation - each of them already carries a Bad status - and it leaves the operator with a
// scatter of Bad values and no single Condition explaining why they all went Bad at once.
// @verifies AC-SVR-AC-078-SYSTEMOFFNORMAL-FOR-COMMS
TEST_F(ConditionsDiscoverTest, CommunicationFailureIsReportedAsAnActiveSystemOffNormalAlarm)
{
  const auto conditionId = create_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType}, "CommsOffNormal");
  ASSERT_FALSE(conditionId.is_null());
  auto instance = mManager->find_condition_sync(conditionId);
  ASSERT_NE(instance, nullptr);

  instance->enable_sync();
  instance->activate_sync(500);
  ASSERT_TRUE(instance->snapshot()->retained());

  // Break communication with the underlying system: the input Variable the Condition samples cannot
  // be resolved, so every sampling cycle's read fails.
  const NodeId unreachableInput{1, 1900201u};
  ASSERT_TRUE(as().try_find_node_sync(unreachableInput).is_bad())
    << "the input node must genuinely be unresolvable, or no communication failure is provoked";
  ASSERT_TRUE(instance->try_bind_input_sync(unreachableInput, 25.0).is_good());

  // Polled, not slept. The sampling cycle is 25ms, but how long the first failed read takes to
  // become an event is a property of the machine, not of the behaviour under test - an instrumented
  // build needs well over the 300ms this used to allow. Bounded, and it re-reads the whole event
  // list each time, so nothing below is weakened: a server that never reports the alarm, never
  // makes it active, or never names the status Variable still fails the assertions that follow.
  size_t offNormalCount = 0;
  bool anyActive = false;
  bool anyNamesAStatusVariable = false;
  const auto collect = [&]()
  {
    offNormalCount = 0;
    anyActive = false;
    anyNamesAStatusVariable = false;
    mSink->with_events(
      [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
      {
        for (const auto& event : events)
        {
          const auto* offNormal = dynamic_cast<const SystemOffNormalAlarmPayload*>(event.get());
          if (offNormal == nullptr)
          {
            continue;
          }
          ++offNormalCount;
          if (offNormal->activeState.id)
          {
            anyActive = true;
          }
          if (!offNormal->normalState.is_null())
          {
            anyNamesAStatusVariable = true;
          }
        }
      });
  };

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  do
  {
    collect();
    if (offNormalCount >= 1u && anyActive && anyNamesAStatusVariable)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  while (std::chrono::steady_clock::now() < deadline);

  ASSERT_GE(offNormalCount, 1u)
    << "a communication failure must be reported to alarm clients as a SystemOffNormalAlarmType "
       "Condition, not only through the affected Conditions' own field statuses";
  EXPECT_TRUE(anyActive) << "the SystemOffNormalAlarm reporting a live communication failure must be active";
  EXPECT_TRUE(anyNamesAStatusVariable)
    << "the SystemOffNormalAlarm must name the failure: NormalState carries the NodeId of the "
       "Variable indicating the underlying system's status";
}

// Part 9 section 5.13: an Event field whose value the underlying system has not yet supplied is reported
// with a StatusCode explaining the absence - Bad_WaitingForInitialData - rather than with a
// stand-in. Emitting the field's freshly constructed default is the plausible implementation
// (a newly built Condition's Quality reads Good before anything has been measured), and at start-up,
// when the most fields are unavailable at once, it fills the operator's first view of the plant with
// values nobody measured.
// @verifies AC-SVR-AC-079-STARTUP-UNAVAILABLE-FIELD
TEST_F(ConditionsDiscoverTest, StartupUnavailableFieldCarriesItsStatusRatherThanASubstituteValue)
{
  const auto conditionId =
    create_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType}, "StartupUnavailable");
  ASSERT_FALSE(conditionId.is_null());
  auto instance = mManager->find_condition_sync(conditionId);
  ASSERT_NE(instance, nullptr);

  // Start-up with the underlying system not yet reachable: the Condition is bound to its input, but
  // the address space cannot resolve it, so no sample ever arrives.
  const NodeId unreachableInput{1, 1900301u};
  ASSERT_TRUE(as().try_find_node_sync(unreachableInput).is_bad())
    << "the input node must genuinely be unresolvable, or a value does become available";
  ASSERT_TRUE(instance->try_bind_input_sync(unreachableInput, 25.0).is_good());
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // A Condition Event is now reported while the value is still unavailable.
  instance->enable_sync();
  instance->activate_sync(700);

  size_t conditionEventCount = 0;
  bool lastCarriedAStatus = false;
  StatusCode reportedQuality{};
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (const auto& event : events)
      {
        const auto* condition = dynamic_cast<const ConditionPayload*>(event.get());
        if (condition == nullptr)
        {
          continue;
        }
        ++conditionEventCount;
        if (const auto* code = condition->quality.value.try_as<StatusCode>())
        {
          lastCarriedAStatus = true;
          reportedQuality = *code;
        }
        else
        {
          lastCarriedAStatus = false;
        }
      }
    });

  ASSERT_GE(conditionEventCount, 1u) << "no Condition Event was reported, so no field was carried at all";
  ASSERT_TRUE(lastCarriedAStatus)
    << "the field for an unavailable value carried no StatusCode - a substitute value was reported "
       "in place of an explanation";
  EXPECT_EQ(reportedQuality, StatusCode{Status::BadWaitingForInitialData})
    << "a value the underlying system has not yet supplied must be reported as "
       "Bad_WaitingForInitialData, not as a measured value; got "
    << reportedQuality.as_uint32();
}

// Part 9 section 5.13: Time is the one Event field that is NOT left as a bare status when the underlying
// system cannot supply it - an Event without a time cannot be ordered against any other, so the
// server substitutes its own clock. Propagating the underlying system's absent timestamp is the
// plausible implementation, since the no-substitute rule of the preceding clause reads as applying
// to every field, and it hands the operator an alarm stamped at the epoch that sorts before the
// whole plant history.
// @verifies AC-SVR-AC-080-STARTUP-TIME-FALLBACK
TEST_F(ConditionsDiscoverTest, StartupUnavailableTimeFallsBackToTheServersOwnTime)
{
  const auto conditionId = create_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType}, "StartupTime");
  ASSERT_FALSE(conditionId.is_null());
  auto instance = mManager->find_condition_sync(conditionId);
  ASSERT_NE(instance, nullptr);

  // The underlying system that would stamp the Event is not reachable at start-up.
  const NodeId unreachableInput{1, 1900401u};
  ASSERT_TRUE(as().try_find_node_sync(unreachableInput).is_bad())
    << "the input node must genuinely be unresolvable, or the system does supply a time";
  ASSERT_TRUE(instance->try_bind_input_sync(unreachableInput, 25.0).is_good());
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  // Bracket the reporting window with the server's own clock: the fallback must land inside it.
  const DateTime beforeReport = DateTime::now();
  instance->enable_sync();
  instance->activate_sync(700);
  const DateTime afterReport = DateTime::now();

  size_t conditionEventCount = 0;
  DateTime reportedTime{};
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (const auto& event : events)
      {
        if (dynamic_cast<const ConditionPayload*>(event.get()) == nullptr)
        {
          continue;
        }
        ++conditionEventCount;
        reportedTime = event->time;
      }
    });

  ASSERT_GE(conditionEventCount, 1u) << "no Condition Event was reported, so nothing carried a Time";
  EXPECT_FALSE(reportedTime.is_null())
    << "an Event whose Time the underlying system cannot supply must still carry a time - a null "
       "Time cannot be ordered against any other Event";
  EXPECT_TRUE(reportedTime >= beforeReport && reportedTime <= afterReport)
    << "the substituted Time must be the server's own time at reporting, not a zero or stale stamp";
}

// Part 9 section 5.14.2: when communication with an underlying system fails, every retained Condition fed
// by that system must raise a fresh Event whose affected fields carry Bad_CommunicationError, while
// Conditions fed by systems that are still answering raise nothing. Discarding the failed sample is
// the plausible implementation - a read that returned no value has nothing to evaluate - and it
// leaves the affected alarms frozen in their last good state, which a subscriber cannot tell apart
// from a quiet plant. Here the link is proven live first (the alarm activates from a real reading
// taken through the address space) and only then broken, so a silent server cannot be excused as
// "no value has ever arrived": that is the separate start-up case of SVR-AC-079.
// @verifies AC-SVR-AC-077-COMMS-FAILURE-RETAINED-EVENTS
TEST_F(ConditionsDiscoverTest, CommunicationFailureOnALiveLinkIsReportedByEveryRetainedConditionItFeeds)
{
  // Two underlying systems, each publishing a reading above the alarm's HighHigh limit.
  const NodeId failingInput{1, 1900601u};
  const NodeId healthyInput{1, 1900602u};

  auto failingCreate = as().try_create_node_sync(failingInput, NodeClass::Variable);
  ASSERT_TRUE(failingCreate.is_good()) << "could not create the first underlying system's Variable";
  auto failingNode = failingCreate.value();
  auto failingVariable = failingNode.as<VariableAccessor>();
  ASSERT_TRUE(failingVariable.has_value());
  ASSERT_TRUE(failingVariable->try_write_value_sync(DataValue{Variant{95.0}}).is_good())
    << "the first system must publish a readable value, or communication never worked";

  auto healthyCreate = as().try_create_node_sync(healthyInput, NodeClass::Variable);
  ASSERT_TRUE(healthyCreate.is_good()) << "could not create the second underlying system's Variable";
  auto healthyNode = healthyCreate.value();
  auto healthyVariable = healthyNode.as<VariableAccessor>();
  ASSERT_TRUE(healthyVariable.has_value());
  ASSERT_TRUE(healthyVariable->try_write_value_sync(DataValue{Variant{95.0}}).is_good())
    << "the second system must publish a readable value, or there is no unaffected Condition";

  // One alarm per system, each driven by what its system actually reports.
  LimitConfig limits;
  limits.highHighLimit = 90.0;

  auto affectedLogic = std::make_unique<LimitAlarmLogic>();
  affectedLogic->set_exclusive(true);
  affectedLogic->set_limits(limits);
  const auto affectedRequestedId = sNextId++;
  auto affectedResult = mManager->try_create_condition_sync(NodeId{1, affectedRequestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("CommsLiveAffected_{}", affectedRequestedId)},
    std::move(affectedLogic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(affectedResult.is_good()) << "could not create the Condition fed by the failing system";
  auto affected = affectedResult.value();
  ASSERT_NE(affected, nullptr);
  const auto affectedId = affected->condition_id();

  auto unaffectedLogic = std::make_unique<LimitAlarmLogic>();
  unaffectedLogic->set_exclusive(true);
  unaffectedLogic->set_limits(limits);
  const auto unaffectedRequestedId = sNextId++;
  auto unaffectedResult = mManager->try_create_condition_sync(NodeId{1, unaffectedRequestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("CommsLiveUnaffected_{}", unaffectedRequestedId)},
    std::move(unaffectedLogic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(unaffectedResult.is_good()) << "could not create the Condition fed by the healthy system";
  auto unaffected = unaffectedResult.value();
  ASSERT_NE(unaffected, nullptr);
  const auto unaffectedId = unaffected->condition_id();

  affected->enable_sync();
  unaffected->enable_sync();
  ASSERT_TRUE(affected->try_bind_input_sync(failingInput, 25.0).is_good());
  ASSERT_TRUE(unaffected->try_bind_input_sync(healthyInput, 25.0).is_good());

  // Communication has to be working before it can break: both alarms must have activated off a real
  // sample read back out of the address space.
  bool bothSawTheirSystem = false;
  for (int attempt = 0; attempt < 100 && !bothSawTheirSystem; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bothSawTheirSystem = affected->snapshot()->active() && unaffected->snapshot()->active();
  }
  ASSERT_TRUE(bothSawTheirSystem)
    << "neither alarm evaluated a sample, so no communication was ever established and breaking it "
       "proves nothing";
  ASSERT_TRUE(affected->snapshot()->retained()) << "the affected Condition must be retained";
  ASSERT_TRUE(unaffected->snapshot()->retained()) << "the unaffected Condition must be retained";

  // Everything raised while the plant was healthy is history; only what the failure itself raises
  // counts.
  const size_t mark = mSink->size();

  // The first system's link drops: its readings now come back as a communication error, while the
  // second system keeps answering normally.
  ASSERT_TRUE(
    failingVariable->try_write_value_sync(DataValue{Variant{95.0}, StatusCode{Status::BadCommunicationError}})
      .is_good());

  // Several sampling cycles run against the broken link. The affected
  // Condition's Event comes on one of them, later in a sanitized or loaded run, so the test waits for it
  // within a bound; the window for the Events that must not occur is then the original 300 ms.
  mSink->wait_until(std::chrono::seconds{10},
    [mark, affectedId](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        if (dynamic_cast<const ConditionPayload*>(events[index].get()) != nullptr &&
            events[index]->conditionNodeId == affectedId)
        {
          return true;
        }
      }
      return false;
    });
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  size_t affectedEvents = 0;
  size_t unaffectedEvents = 0;
  bool affectedCarriedCommunicationError = false;
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        const auto& event = events[index];
        const auto* condition = dynamic_cast<const ConditionPayload*>(event.get());
        if (condition == nullptr || !event->conditionNodeId.has_value())
        {
          continue;
        }
        if (*event->conditionNodeId == affectedId)
        {
          ++affectedEvents;
          if (const auto* code = condition->quality.value.try_as<StatusCode>())
          {
            if (*code == StatusCode{Status::BadCommunicationError})
            {
              affectedCarriedCommunicationError = true;
            }
          }
        }
        else if (*event->conditionNodeId == unaffectedId)
        {
          ++unaffectedEvents;
        }
      }
    });

  EXPECT_EQ(affectedEvents, 1u)
    << "the retained Condition must raise exactly one Event on the communication-state transition; "
       "repeated bad samples must not create an Event storm";
  EXPECT_TRUE(affectedCarriedCommunicationError)
    << "the Event raised for the failure must carry Bad_CommunicationError on the affected field, "
       "otherwise the subscriber is told a value it cannot distinguish from a measured one";
  EXPECT_EQ(unaffectedEvents, 0u)
    << "the Condition fed by the system that is still answering must raise nothing";
}

// Part 9 section 5.14.2: the Variables exposing Event fields derived from an unreachable underlying
// system shall read a NULL Value with Bad_CommunicationError. The initial and recovered reads are
// controls proving the same production handlers still return typed values while communication works.
// @relation(AC-SVR-AC-076-COMMS-FAILURE-EVENT-FIELDS, scope=function)
TEST_F(ConditionsDiscoverTest, CommunicationFailureMakesInputDerivedVariablesNullAndBadUntilRecovery)
{
  const NodeId inputId{1, sNextId++};
  auto createdInput = as().try_create_node_sync(inputId, NodeClass::Variable);
  ASSERT_TRUE(createdInput.is_good());
  auto input = createdInput.value().as<VariableAccessor>();
  ASSERT_TRUE(input.has_value());
  ASSERT_TRUE(input->try_write_value_sync(DataValue{Variant{95.0}}).is_good());

  LimitConfig limits;
  limits.highHighLimit = 90.0;
  auto logic = std::make_unique<LimitAlarmLogic>();
  logic->set_exclusive(true);
  logic->set_limits(limits);

  const auto requestedId = sNextId++;
  auto created = mManager->try_create_condition_sync(NodeId{1, requestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("CommsFieldQuality_{}", requestedId)},
    std::move(logic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(created.is_good());
  auto condition = created.value();
  ASSERT_NE(condition, nullptr);
  condition->enable_sync();
  ASSERT_TRUE(condition->try_bind_input_sync(inputId, 25.0).is_good());

  for (int attempt = 0; attempt < 100 && !condition->snapshot()->active(); ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_TRUE(condition->snapshot()->active()) << "the live input must drive the alarm before it fails";

  const NodeId severityId = find_condition_child_id(
    as(), condition->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "Severity");
  const NodeId activeStateId = find_condition_child_id(
    as(), condition->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "ActiveState");
  const NodeId activeId =
    find_condition_child_id(as(), activeStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(severityId.is_null());
  ASSERT_FALSE(activeId.is_null());
  auto severity = as().try_find_sync<VariableAccessor>(severityId);
  auto active = as().try_find_sync<VariableAccessor>(activeId);
  ASSERT_TRUE(severity.is_good());
  ASSERT_TRUE(active.is_good());

  auto liveSeverity = severity.value().try_read_value_sync();
  auto liveActive = active.value().try_read_value_sync();
  ASSERT_TRUE(liveSeverity.is_good());
  ASSERT_TRUE(liveActive.is_good());
  ASSERT_NE(liveSeverity.value().value().try_as<uint16_t>(), nullptr);
  ASSERT_NE(liveActive.value().value().try_as<bool>(), nullptr);

  ASSERT_TRUE(input->try_write_value_sync(DataValue{Variant{95.0}, StatusCode{Status::BadCommunicationError}})
                .is_good());
  for (int attempt = 0;
       attempt < 100 && condition->snapshot()->quality().as_status() != Status::BadCommunicationError;
       ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_EQ(condition->snapshot()->quality().as_status(), Status::BadCommunicationError);

  auto failedSeverity = severity.value().try_read_value_sync();
  auto failedActive = active.value().try_read_value_sync();
  ASSERT_TRUE(failedSeverity.is_good());
  ASSERT_TRUE(failedActive.is_good());
  for (const auto* failed : {&failedSeverity.value(), &failedActive.value()})
  {
    ASSERT_TRUE(failed->status().has_value());
    EXPECT_EQ(failed->status()->as_status(), Status::BadCommunicationError);
    EXPECT_NE(failed->status()->shared_detail(), nullptr);
    EXPECT_TRUE(failed->value().empty());
  }

  ASSERT_TRUE(input->try_write_value_sync(DataValue{Variant{10.0}}).is_good());
  for (int attempt = 0; attempt < 100 && condition->snapshot()->quality().is_bad(); ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_TRUE(condition->snapshot()->quality().is_good());

  auto recoveredSeverity = severity.value().try_read_value_sync();
  auto recoveredActive = active.value().try_read_value_sync();
  ASSERT_TRUE(recoveredSeverity.is_good());
  ASSERT_TRUE(recoveredActive.is_good());
  EXPECT_NE(recoveredSeverity.value().value().try_as<uint16_t>(), nullptr);
  EXPECT_NE(recoveredActive.value().value().try_as<bool>(), nullptr);
}

// Part 9 sections 5.8.2, 5.8.4 and 5.4.6: any active referenced suppression group suppresses the
// Alarm, and only all referenced groups being inactive clears it. Both permitted member forms are
// driven; the unreferenced active group is the control against global or BrowseName-only coupling.
// @relation(AC-SVR-AC-107-SUPPRESSIONGROUP-DRIVES-SUPPRESSED, scope=function)
TEST_F(ConditionsDiscoverTest, SuppressionGroupsFollowAnyActiveAndAllInactiveMembers)
{
  auto targetLogic = std::make_unique<AlarmConditionLogic>();
  const auto targetRequestedId = sNextId++;
  auto targetResult = mManager->try_create_condition_sync(NodeId{1, targetRequestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("SuppressionTarget_{}", targetRequestedId)},
    std::move(targetLogic),
    NodeId{ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(targetResult.is_good());
  auto target = targetResult.value();
  ASSERT_NE(target, nullptr);
  target->enable_sync();
  target->activate_sync(700);

  auto memberLogic = std::make_unique<AlarmConditionLogic>();
  const auto memberRequestedId = sNextId++;
  auto memberResult = mManager->try_create_condition_sync(NodeId{1, memberRequestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("SuppressionAlarmMember_{}", memberRequestedId)},
    std::move(memberLogic),
    NodeId{ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(memberResult.is_good());
  auto alarmMember = memberResult.value();
  ASSERT_NE(alarmMember, nullptr);
  alarmMember->enable_sync();

  auto instantiateGroup = [this](std::string_view name)
  {
    InstantiationService instantiation{as()};
    InstantiationOptions options;
    std::promise<NodeSubtreeResult> promise;
    instantiation.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{1, name},
      NodeId{ObjectTypeId::AlarmSuppressionGroupType},
      options,
      [&promise](NodeSubtreeResult result) { promise.set_value(std::move(result)); });
    auto result = promise.get_future().get();
    EXPECT_TRUE(result.is_good());
    if (result.is_bad())
      return NodeId{};
    auto subtree = std::move(result).value();
    NodeId groupId = subtree.root();
    subtree.release();
    return groupId;
  };
  const NodeId booleanGroupId = instantiateGroup("BooleanSuppressionGroup");
  const NodeId alarmGroupId = instantiateGroup("AlarmSuppressionGroup");
  const NodeId unrelatedGroupId = instantiateGroup("UnrelatedSuppressionGroup");
  ASSERT_FALSE(booleanGroupId.is_null());
  ASSERT_FALSE(alarmGroupId.is_null());
  ASSERT_FALSE(unrelatedGroupId.is_null());

  auto createBooleanMember = [this](bool initialValue)
  {
    const NodeId memberId{1, sNextId++};
    auto created = as().try_create_node_sync(memberId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good());
    if (created.is_bad())
      return std::pair{NodeId{}, std::optional<VariableAccessor>{}};
    auto variable = created.value().as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    if (!variable)
      return std::pair{NodeId{}, std::optional<VariableAccessor>{}};
    variable->set_data_type(NodeId{DataTypeId::Boolean});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(initialValue);
    return std::pair{memberId, std::move(variable)};
  };
  auto [booleanMemberId, booleanMember] = createBooleanMember(false);
  auto [unrelatedMemberId, unrelatedMember] = createBooleanMember(false);
  ASSERT_TRUE(booleanMember.has_value());
  ASSERT_TRUE(unrelatedMember.has_value());

  auto booleanGroup = as().find_node_sync(booleanGroupId);
  auto alarmGroup = as().find_node_sync(alarmGroupId);
  auto unrelatedGroup = as().find_node_sync(unrelatedGroupId);
  ASSERT_TRUE(
    booleanGroup.try_add_reference_sync(NodeId{ReferenceTypeId::AlarmSuppressionGroupMember}, booleanMemberId)
      .is_good());
  ASSERT_TRUE(alarmGroup
                .try_add_reference_sync(
                  NodeId{ReferenceTypeId::AlarmSuppressionGroupMember}, alarmMember->condition_id())
                .is_good());
  ASSERT_TRUE(
    unrelatedGroup
      .try_add_reference_sync(NodeId{ReferenceTypeId::AlarmSuppressionGroupMember}, unrelatedMemberId)
      .is_good());

  auto targetNode = as().find_node_sync(target->condition_id());
  ASSERT_TRUE(
    targetNode.try_add_reference_sync(NodeId{ReferenceTypeId::HasAlarmSuppressionGroup}, booleanGroupId)
      .is_good());
  ASSERT_TRUE(
    targetNode.try_add_reference_sync(NodeId{ReferenceTypeId::HasAlarmSuppressionGroup}, alarmGroupId)
      .is_good());

  auto awaitSuppressed = [&target](bool expected)
  {
    for (int attempt = 0; attempt < 100; ++attempt)
    {
      if (target->snapshot()->suppressed().value_or(false) == expected)
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  };

  unrelatedMember->write_value_sync(true);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  EXPECT_FALSE(target->snapshot()->suppressed().value_or(false));

  booleanMember->write_value_sync(true);
  ASSERT_TRUE(awaitSuppressed(true));

  alarmMember->activate_sync(500);
  booleanMember->write_value_sync(false);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  EXPECT_TRUE(target->snapshot()->suppressed().value_or(false));

  alarmMember->deactivate_sync();
  ASSERT_TRUE(awaitSuppressed(false));

  // An inactive group is not a continuous Unsuppress command: manual suppression remains valid.
  target->suppress_sync();
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  EXPECT_TRUE(target->snapshot()->suppressed().value_or(false));
  target->unsuppress_sync();
  ASSERT_TRUE(awaitSuppressed(false));

  // Conversely, a group that remains active is authoritative even if another path clears the bit.
  booleanMember->write_value_sync(true);
  ASSERT_TRUE(awaitSuppressed(true));
  target->unsuppress_sync();
  ASSERT_TRUE(awaitSuppressed(true));
  booleanMember->write_value_sync(false);
  EXPECT_TRUE(awaitSuppressed(false));
}

// Part 9 section 5.14.2: the communication failure is itself reported to alarm clients as a Condition - a
// SystemOffNormalAlarmType instance that is active while the link is down and whose NormalState
// names the Variable carrying the underlying system's status. Reporting the failure only through the
// fields of the Conditions it feeds is the plausible implementation, since each of those already
// carries a Bad status, and it leaves the operator with a scatter of Bad values and nothing that
// says why they all went Bad at once. The link here is proven live before it is broken, so the
// absence of the alarm cannot be attributed to a system that was never reachable.
// @verifies AC-SVR-AC-078-SYSTEMOFFNORMAL-FOR-COMMS
TEST_F(ConditionsDiscoverTest, CommunicationFailureOnALiveLinkRaisesASystemOffNormalAlarmNamingTheSystem)
{
  const NodeId systemStatusInput{1, 1900701u};
  auto createdInput = as().try_create_node_sync(systemStatusInput, NodeClass::Variable);
  ASSERT_TRUE(createdInput.is_good()) << "could not create the underlying system's status Variable";
  auto inputNode = createdInput.value();
  auto inputVariable = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  ASSERT_TRUE(inputVariable->try_write_value_sync(DataValue{Variant{95.0}}).is_good())
    << "the system must publish a readable value, or communication never worked";

  LimitConfig limits;
  limits.highHighLimit = 90.0;
  auto logic = std::make_unique<LimitAlarmLogic>();
  logic->set_exclusive(true);
  logic->set_limits(limits);

  const auto requestedId = sNextId++;
  auto createdCondition = mManager->try_create_condition_sync(NodeId{1, requestedId},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("CommsLiveOffNormal_{}", requestedId)},
    std::move(logic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(createdCondition.is_good()) << "could not create the Condition fed by the system";
  auto instance = createdCondition.value();
  ASSERT_NE(instance, nullptr);

  instance->enable_sync();
  ASSERT_TRUE(instance->try_bind_input_sync(systemStatusInput, 25.0).is_good());

  bool sawTheSystem = false;
  for (int attempt = 0; attempt < 100 && !sawTheSystem; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    sawTheSystem = instance->snapshot()->active();
  }
  ASSERT_TRUE(sawTheSystem)
    << "the alarm never evaluated a sample, so communication was never established and breaking it "
       "proves nothing";

  const size_t mark = mSink->size();

  // The link to the underlying system drops: its status Variable now answers with a communication
  // error on every sampling cycle.
  ASSERT_TRUE(
    inputVariable->try_write_value_sync(DataValue{Variant{95.0}, StatusCode{Status::BadCommunicationError}})
      .is_good());
  // The alarm is raised on a later sampling cycle, later in a sanitized or loaded run than in an idle one, so
  // the test waits for it within a bound rather than for a fixed time.
  ASSERT_TRUE(mSink->wait_until(std::chrono::seconds{10},
    [mark, systemStatusInput](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        const auto* offNormal = dynamic_cast<const SystemOffNormalAlarmPayload*>(events[index].get());
        if (offNormal != nullptr && offNormal->activeState.id && offNormal->normalState == systemStatusInput)
        {
          return true;
        }
      }
      return false;
    }));

  size_t offNormalEvents = 0;
  bool anyActive = false;
  bool anyNamedTheStatusVariable = false;
  NodeId offNormalConditionId{};
  mSink->with_events(
    [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
    {
      for (size_t index = mark; index < events.size(); ++index)
      {
        const auto& event = events[index];
        const auto* offNormal = dynamic_cast<const SystemOffNormalAlarmPayload*>(event.get());
        if (offNormal == nullptr)
        {
          continue;
        }
        ++offNormalEvents;
        if (offNormal->activeState.id)
        {
          anyActive = true;
        }
        if (offNormal->normalState == systemStatusInput)
        {
          anyNamedTheStatusVariable = true;
        }
        if (offNormalConditionId.is_null() && event->conditionNodeId.has_value())
        {
          offNormalConditionId = *event->conditionNodeId;
        }
      }
    });

  ASSERT_GE(offNormalEvents, 1u)
    << "losing communication with an underlying system must be reported to alarm clients as a "
       "SystemOffNormalAlarmType Condition, not only through the fields of the Conditions it feeds";
  EXPECT_TRUE(anyActive)
    << "the SystemOffNormalAlarm must be active while the communication failure persists";
  EXPECT_TRUE(anyNamedTheStatusVariable)
    << "the SystemOffNormalAlarm must name the failure: NormalState carries the NodeId of the "
       "Variable indicating the underlying system's status";

  // It has to be a Condition, not a one-shot notification: a client must be able to find it and see
  // it standing in the active state for as long as the link is down.
  EXPECT_FALSE(offNormalConditionId.is_null())
    << "the SystemOffNormalAlarm Event carried no ConditionId, so no Condition is identified at all";
  auto offNormalCondition = mManager->find_condition_sync(offNormalConditionId);
  EXPECT_NE(offNormalCondition, nullptr)
    << "the communication failure must be reported by a registered Condition, not by an event with "
       "no Condition behind it";
  if (offNormalCondition != nullptr)
  {
    auto promise = std::make_shared<std::promise<std::vector<std::unique_ptr<BaseEvent>>>>();
    auto future = promise->get_future();
    offNormalCondition->build_refresh_events_async(
      [promise](std::vector<std::unique_ptr<BaseEvent>> events) { promise->set_value(std::move(events)); });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    const auto events = future.get();
    ASSERT_FALSE(events.empty());
    const auto* offNormal = dynamic_cast<const SystemOffNormalAlarmPayload*>(events.front().get());
    ASSERT_NE(offNormal, nullptr);
    EXPECT_TRUE(offNormal->activeState.id);
    EXPECT_EQ(offNormal->normalState, systemStatusInput);
    const auto& refreshedConditionId = offNormal->conditionNodeId;
    ASSERT_TRUE(refreshedConditionId.has_value());
    EXPECT_EQ(*refreshedConditionId, offNormalConditionId);
    EXPECT_TRUE(offNormalCondition->snapshot()->active())
      << "the Condition reporting the ongoing communication failure must stand active";
  }
}

// Part 9 section 5.14.2: one underlying system may feed several retained Conditions. Its
// SystemOffNormalAlarm remains active until the final dependent Condition recovers or unbinds; a
// per-Condition boolean or "last callback wins" implementation clears it too early.
// @verifies AC-SVR-AC-077-COMMS-FAILURE-RETAINED-EVENTS
// @verifies AC-SVR-AC-078-SYSTEMOFFNORMAL-FOR-COMMS
TEST_F(ConditionsDiscoverTest, SharedInputCommunicationAlarmClearsOnlyAfterTheLastDependentRecovers)
{
  const NodeId sharedInput{1, 1900801u};
  auto createdInput = as().try_create_node_sync(sharedInput, NodeClass::Variable);
  ASSERT_TRUE(createdInput.is_good());
  auto inputVariable = createdInput.value().as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  ASSERT_TRUE(inputVariable->try_write_value_sync(DataValue{Variant{95.0}}).is_good());

  auto createBoundAlarm = [&](std::string_view name)
  {
    LimitConfig limits;
    limits.highHighLimit = 90.0;
    auto logic = std::make_unique<LimitAlarmLogic>();
    logic->set_exclusive(true);
    logic->set_limits(limits);
    const auto requestedId = sNextId++;
    auto created = mManager->try_create_condition_sync(NodeId{1, requestedId},
      NodeId{ObjectId::ObjectsFolder},
      String{fmt::format("{}_{}", name, requestedId)},
      std::move(logic),
      NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
    EXPECT_TRUE(created.is_good());
    if (!created.is_good())
    {
      return std::shared_ptr<ConditionInstance>{};
    }
    auto condition = created.value();
    condition->enable_sync();
    EXPECT_TRUE(condition->try_bind_input_sync(sharedInput, 25.0).is_good());
    return condition;
  };

  auto first = createBoundAlarm("SharedCommsFirst");
  auto second = createBoundAlarm("SharedCommsSecond");
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);

  for (int attempt = 0; attempt < 100 && (!first->snapshot()->active() || !second->snapshot()->active());
       ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_TRUE(first->snapshot()->active());
  ASSERT_TRUE(second->snapshot()->active());

  ASSERT_TRUE(
    inputVariable->try_write_value_sync(DataValue{Variant{95.0}, StatusCode{Status::BadCommunicationError}})
      .is_good());
  for (int attempt = 0;
       attempt < 100 && (first->snapshot()->quality().as_status() != Status::BadCommunicationError ||
                          second->snapshot()->quality().as_status() != Status::BadCommunicationError);
       ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_EQ(first->snapshot()->quality().as_status(), Status::BadCommunicationError);
  ASSERT_EQ(second->snapshot()->quality().as_status(), Status::BadCommunicationError);

  NodeId communicationAlarmId;
  for (int attempt = 0; attempt < 100 && communicationAlarmId.is_null(); ++attempt)
  {
    mSink->with_events(
      [&](const std::vector<std::unique_ptr<BaseEvent>>& events)
      {
        for (const auto& event : events)
        {
          const auto* alarm = dynamic_cast<const SystemOffNormalAlarmPayload*>(event.get());
          if (alarm != nullptr && alarm->normalState == sharedInput && alarm->activeState.id &&
              event->conditionNodeId.has_value())
          {
            communicationAlarmId = *event->conditionNodeId;
          }
        }
      });
    if (communicationAlarmId.is_null())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
  ASSERT_FALSE(communicationAlarmId.is_null());
  auto communicationAlarm = mManager->find_condition_sync(communicationAlarmId);
  ASSERT_NE(communicationAlarm, nullptr);
  ASSERT_TRUE(communicationAlarm->snapshot()->active());

  std::promise<VoidResult> unbound;
  first->unbind_input_async([&unbound](VoidResult result) { unbound.set_value(std::move(result)); });
  ASSERT_TRUE(unbound.get_future().get().is_good());
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_TRUE(communicationAlarm->snapshot()->active())
    << "one dependent unbinding must not clear the shared system failure";

  ASSERT_TRUE(inputVariable->try_write_value_sync(DataValue{Variant{95.0}}).is_good());
  for (int attempt = 0; attempt < 100 && communicationAlarm->snapshot()->active(); ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  EXPECT_FALSE(communicationAlarm->snapshot()->active())
    << "the SystemOffNormalAlarm must clear after the final dependent Condition recovers";
}

// Closing the registry must close the instances it holds, not merely mark itself shut down. The
// fan-out reports completion once per instance, so a close that skipped the instances would still
// report success and leave their logic enabled and their timers armed.
TEST_F(ConditionsTest, ClosingTheRegistryDisablesTheConditionsItHolds)
{
  auto disabled = std::make_shared<std::atomic<bool>>(false);
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<DisableRecordingLogic>(disabled));
  ASSERT_NE(instance, nullptr);
  instance->enable_sync();

  ConditionsTestAccess::close_sync(*mManager);

  EXPECT_TRUE(disabled->load()) << "the registry close completed without disabling the instance it held";
}

}  // namespace ua::test
