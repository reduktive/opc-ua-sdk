// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "concrete_condition_type.h"
#include "ua_audit_event_payload.h"
#include "ua_condition_instance.h"

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_payload.h"
#include "ua_alarm_condition_logic.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_condition_payload.h"
#include "ua_condition_logic.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_dialog_condition_logic.h"
#include "ua_sinks.h"
#include "ua_file_stream.h"
#include "ua_limit_alarm_logic.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
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
#include <future>
#include <memory>
#include <stdexcept>
#include <mutex>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include <limits>

#include "posting_writes_namespace.h"
#include "test_utilities.h"

namespace ua::test
{

/// Read one context fact off an ErrorDetail, or "" when the key is absent. Returning the empty
/// string rather than asserting lets a test state the expected value directly, so a missing key
/// and a wrong value fail the same way.
std::string context_value(const ErrorDetail& detail, ContextKey key)
{
  for (const auto& entry : detail.context)
  {
    if (entry.key == key.value())
    {
      return entry.value;
    }
  }
  return {};
}

/// Simple fake EventSink that records emitted events.
/// Mimics the real EventBus's EventId assignment: ConditionInstance emits events
/// with an empty event_id; the EventBus assigns a unique ID during emit(), and
/// ConditionInstance then reads it back via set_last_event_id. This fake must
/// replicate that contract for downstream logic (e.g., Acknowledge) to work.
class FakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    // A Condition that samples an input emits on the sampling thread; a test then reads through observed().
    const std::lock_guard<std::mutex> lock(mMutex);
    // The Condition audit Events the server now raises alongside every transition reach this same
    // sink. They are not what these pins observe - a pin that says "one enable, one event" is
    // about the Condition Event - so the audit family is counted apart rather than folded in.
    if (dynamic_cast<ua::AuditEventPayload*>(&event) != nullptr)
    {
      ++auditEmitCount;
      return;
    }
    ++emitCount;

    // Auto-assign a unique EventId if not already set, mimicking EventBus behavior.
    if (event.eventId.empty())
    {
      auto id = static_cast<uint8_t>(emitCount);
      event.eventId = ByteString{std::vector<uint8_t>{id}};
    }

    lastEventId = event.eventId;
    lastTime = event.time;
    lastSourceNode = event.sourceNode;
    lastSourceName = event.sourceName;
  }

  /// The number of Condition Events emitted and the last one's Time, read under the lock emit() takes: for a
  /// test whose Events come from the sampling thread while it reads.
  std::pair<int, DateTime> observed() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return {emitCount, lastTime};
  }

  int emitCount{0};
  int auditEmitCount{0};
  ByteString lastEventId;
  DateTime lastTime;
  NodeId lastSourceNode;
  String lastSourceName;

private:
  mutable std::mutex mMutex;
};

/// Test fixture providing a thread pool, executor, and fake event sink.
class ConditionInstanceTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mSink = std::make_shared<FakeEventSink>();
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// Create a ConditionInstance with a base ConditionLogic.
  std::shared_ptr<ConditionInstance> create_basic_instance()
  {
    return ConditionInstance::create(mPool.get_executor(),
      std::make_unique<ConditionLogic>(),
      NodeId{1, 1000u},
      NodeId{1, 100u},
      String{"TestSource"},
      mSink);
  }

  /// Create a ConditionInstance with an AlarmConditionLogic.
  std::shared_ptr<ConditionInstance> create_alarm_instance()
  {
    return ConditionInstance::create(mPool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      NodeId{1, 2000u},
      NodeId{1, 200u},
      String{"AlarmSource"},
      mSink);
  }

  /// Create a ConditionInstance with an AlarmConditionLogic with all features.
  std::shared_ptr<ConditionInstance> create_full_alarm_instance()
  {
    auto logic = std::make_unique<AlarmConditionLogic>();
    logic->set_supports_confirm(true);
    logic->set_supports_suppressed(true);
    logic->set_supports_out_of_service(true);
    logic->set_supports_silence(true);
    logic->set_supports_latched(true);
    return ConditionInstance::create(mPool.get_executor(),
      std::move(logic),
      NodeId{1, 3000u},
      NodeId{1, 300u},
      String{"FullAlarmSource"},
      mSink);
  }

  /// Create a ConditionInstance with a DialogConditionLogic.
  std::shared_ptr<ConditionInstance> create_dialog_instance()
  {
    auto logic = std::make_unique<DialogConditionLogic>();
    logic->set_response_options(3);
    logic->set_default_response(0);
    return ConditionInstance::create(mPool.get_executor(),
      std::move(logic),
      NodeId{1, 4000u},
      NodeId{1, 400u},
      String{"DialogSource"},
      mSink);
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<FakeEventSink> mSink;
};

// --- Create ---

TEST_F(ConditionInstanceTest, Create_ConditionStartsDisabled)
{
  auto instance = create_basic_instance();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

TEST_F(ConditionInstanceTest, Create_ConditionIdMatchesConstructorArg)
{
  auto instance = create_basic_instance();
  EXPECT_EQ(instance->condition_id(), NodeId(1, 1000u));
}

// --- Enable ---

TEST_F(ConditionInstanceTest, EnableSync_Succeeds)
{
  auto instance = create_basic_instance();

  auto result = instance->try_enable_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, EnableSync_SnapshotShowsEnabled)
{
  auto instance = create_basic_instance();

  instance->enable_sync();

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->enabled());
  EXPECT_TRUE(snapshot->retained());
}

TEST_F(ConditionInstanceTest, EnableSync_EmitsEvent)
{
  auto instance = create_basic_instance();

  instance->enable_sync();

  EXPECT_EQ(mSink->emitCount, 1);
}

TEST_F(ConditionInstanceTest, EnableSync_AlreadyEnabled_ReturnsBadConditionAlreadyEnabled)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_enable_sync();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConditionAlreadyEnabled});
}

// --- Disable ---

TEST_F(ConditionInstanceTest, DisableSync_AfterEnable_Succeeds)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_disable_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, DisableSync_SnapshotShowsDisabled)
{
  auto instance = create_basic_instance();
  instance->enable_sync();
  instance->disable_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

TEST_F(ConditionInstanceTest, DisableSync_AlreadyDisabled_ReturnsBadConditionAlreadyDisabled)
{
  auto instance = create_basic_instance();

  auto result = instance->try_disable_sync();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConditionAlreadyDisabled});
}

namespace
{
// A Condition logic whose disable() reports @ref code, a Good code of its own, as the transition's status.
class QualifyingDisableLogic final : public ConditionLogic
{
public:
  explicit QualifyingDisableLogic(StatusCode code) : mCode(std::move(code))
  {}

protected:
  void on_disabled(ConditionStateTransition& transition) override
  {
    transition.status = mCode;
  }

private:
  StatusCode mCode;
};
}  // namespace

// The status a Condition's logic reports for a transition reaches the caller as it is, a Good subcode
// included, through the sync and the async forms.
// @relation(AC-COMP-SVR-STATUS-ROUTING-04-A-CONDITION-TRANSITION-PASSES-THE-LOGICS-CODE, scope=function)
TEST_F(ConditionInstanceTest, ATransitionPassesTheGoodCodeItsLogicReports)
{
  const StatusCode qualified{Status::GoodLocalOverride};
  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<QualifyingDisableLogic>(qualified),
    NodeId{1, 1100u},
    NodeId{1, 110u},
    String{"QualifyingSource"},
    mSink);
  instance->enable_sync();

  const auto disabled = instance->try_disable_sync();
  EXPECT_EQ(disabled.status_code().value(), qualified.value()) << to_string(disabled.status_code());
  EXPECT_FALSE(instance->snapshot()->enabled());

  instance->enable_sync();
  auto promise = std::make_shared<std::promise<VoidResult>>();
  auto future = promise->get_future();
  instance->disable_async([promise](VoidResult result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto disabledAsync = future.get();
  EXPECT_EQ(disabledAsync.status_code().value(), qualified.value()) << to_string(disabledAsync.status_code());
}

// --- Activate (alarm) ---

TEST_F(ConditionInstanceTest, ActivateSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();

  auto result = instance->try_activate_sync(500);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, ActivateSync_SnapshotShowsActive)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(600);

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->active());
  EXPECT_EQ(snapshot->severity(), 600);
}

TEST_F(ConditionInstanceTest, ActivateSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_activate_sync(500);
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNotSupported});
}

// --- Deactivate ---

TEST_F(ConditionInstanceTest, DeactivateSync_AfterActivate_Succeeds)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  auto result = instance->try_deactivate_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, DeactivateSync_SnapshotShowsInactive)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);
  instance->deactivate_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->active());
}

TEST_F(ConditionInstanceTest, DeactivateSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_deactivate_sync();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNotSupported});
}

// --- Acknowledge ---

TEST_F(ConditionInstanceTest, AcknowledgeSync_WithValidEventId_Succeeds)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  // After enable + activate, two events were emitted with assigned EventIds.
  ASSERT_EQ(mSink->emitCount, 2);
  auto lastEventId = mSink->lastEventId;
  ASSERT_FALSE(lastEventId.empty());

  auto result = instance->try_acknowledge_sync(lastEventId, LocalizedText{"", "Acknowledged"});
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, AcknowledgeSync_WithInvalidEventId_ReturnsBadEventIdUnknown)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  ByteString bogusId{std::vector<uint8_t>{0xFF, 0xFE, 0xFD}};

  auto result = instance->try_acknowledge_sync(bogusId, LocalizedText{"", "Ack"});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadEventIdUnknown});
}

// A stale Acknowledge is the condition model's characteristic failure, and the leaf status alone
// cannot be acted on: BadEventIdUnknown says a rule failed, not WHICH occurrence was rejected.
// Pin both facts the caller needs to correlate the reject with the event it actually held.
TEST_F(ConditionInstanceTest, AcknowledgeSync_WithInvalidEventId_DetailNamesConditionAndEventId)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  ByteString bogusId{std::vector<uint8_t>{0xFF, 0xFE, 0xFD}};

  auto result = instance->try_acknowledge_sync(bogusId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(result.is_bad());
  auto detail = result.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ConditionTransitionRejected");
  EXPECT_EQ(context_value(*detail, ContextKeys::nodeId), ua::to_string(instance->condition_id()));
  EXPECT_EQ(context_value(*detail, ContextKeys::eventId), ua::to_string(bogusId));
}

TEST_F(ConditionInstanceTest, AcknowledgeSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  ByteString someId{std::vector<uint8_t>{1}};
  auto result = instance->try_acknowledge_sync(someId, LocalizedText{"", "Ack"});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNotSupported});
}

TEST_F(ConditionInstanceTest, ConfirmSync_WithValidEventId_Succeeds)
{
  // Create an AcknowledgeableConditionLogic with confirm support
  auto confirmLogic = std::make_unique<AcknowledgeableConditionLogic>();
  confirmLogic->set_supports_confirm(true);

  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::move(confirmLogic),
    NodeId{1, 3000u},
    NodeId{1, 300u},
    String{"ConfirmSource"},
    mSink);

  instance->enable_sync();

  // Get the event id from the enable event
  ASSERT_GE(mSink->emitCount, 1);
  auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());

  // Acknowledge first
  auto ackResult = instance->try_acknowledge_sync(eventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(ackResult.is_good()) << "Acknowledge should succeed";

  // Get the new event id after acknowledge
  auto ackEventId = mSink->lastEventId;
  ASSERT_FALSE(ackEventId.empty());

  // Confirm
  auto confirmResult = instance->try_confirm_sync(ackEventId, LocalizedText{"", "Confirmed"});
  EXPECT_TRUE(confirmResult.is_good()) << "Confirm should succeed with valid event id";
}

// --- Event content ---

TEST_F(ConditionInstanceTest, EmittedEventContainsCorrectSourceInfo)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  ASSERT_EQ(mSink->emitCount, 1);
  EXPECT_EQ(mSink->lastSourceNode, NodeId(1, 100u));
  EXPECT_EQ(mSink->lastSourceName, String{"TestSource"});
}

// EventId is assigned by the EventSink (mimicking EventBus behavior in production).
// ConditionInstance emits with empty event_id; the EventBus/EventSink assigns a unique ID,
// then ConditionInstance reads it back via set_last_event_id.
TEST_F(ConditionInstanceTest, EmittedEventHasEventIdAssigned)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  ASSERT_EQ(mSink->emitCount, 1);
  EXPECT_FALSE(mSink->lastEventId.empty());
}

// --- Close ---

TEST_F(ConditionInstanceTest, CloseSync_Succeeds)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_close_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, CloseSync_DisablesCondition)
{
  auto instance = create_basic_instance();
  instance->enable_sync();
  instance->close_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
}

// ===========================================================================
// Shelving method tests (logic-only, no AS)
// ===========================================================================

TEST_F(ConditionInstanceTest, TimedShelveSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  auto result = instance->try_timed_shelve_sync(5000.0);
  EXPECT_TRUE(result.is_good());
}

// Clients pass the largest Double as ShelvingTime to mean "as long as the Server allows" (the CTT's
// A & C Shelving unit does). The shelve timer's duration cannot hold it; converting it with a checked cast
// threw inside the Method, which the Client saw as Bad_InternalError. The timer now saturates, so the
// shelve succeeds and the alarm stays shelved until it is unshelved.
TEST_F(ConditionInstanceTest, TimedShelveSync_WithTheLargestDuration_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  auto result = instance->try_timed_shelve_sync(std::numeric_limits<double>::max());
  EXPECT_TRUE(result.is_good()) << "a maximal ShelvingTime must shelve, not fault: "
                                << to_string(result.status_code());
  EXPECT_TRUE(instance->try_unshelve_sync().is_good()) << "the shelve must have taken effect";
}

TEST_F(ConditionInstanceTest, TimedShelveSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_timed_shelve_sync(5000.0);
  EXPECT_TRUE(result.is_bad());
}

TEST_F(ConditionInstanceTest, OneShotShelveSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  auto result = instance->try_one_shot_shelve_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, UnshelveSync_AfterTimedShelve_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);
  instance->timed_shelve_sync(5000.0);

  auto result = instance->try_unshelve_sync();
  EXPECT_TRUE(result.is_good());
}

// ===========================================================================
// Suppress / Out-of-service / Silence / Reset / Respond tests (logic-only)
// ===========================================================================

TEST_F(ConditionInstanceTest, SuppressSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();

  auto result = instance->try_suppress_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, SuppressSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_suppress_sync();
  EXPECT_TRUE(result.is_bad());
}

TEST_F(ConditionInstanceTest, UnsuppressSync_AfterSuppress_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->suppress_sync();

  auto result = instance->try_unsuppress_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, RemoveFromServiceSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();

  auto result = instance->try_remove_from_service_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, PlaceInServiceSync_AfterRemoveFromService_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->remove_from_service_sync();

  auto result = instance->try_place_in_service_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, SilenceSync_WithAlarmLogic_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  auto result = instance->try_silence_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, SilenceSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_silence_sync();
  EXPECT_TRUE(result.is_bad());
}

TEST_F(ConditionInstanceTest, ResetSync_AfterLatchedAlarm_Succeeds)
{
  auto instance = create_full_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);
  instance->deactivate_sync();
  auto eventId = mSink->lastEventId;
  instance->acknowledge_sync(eventId, LocalizedText{"", "ack"});

  auto result = instance->try_reset_sync();
  EXPECT_TRUE(result.is_good());
}

TEST_F(ConditionInstanceTest, ResetSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_reset_sync();
  EXPECT_TRUE(result.is_bad());
}

TEST_F(ConditionInstanceTest, RespondSync_WhenDialogNotActive_ReturnsBadDialogNotActive)
{
  auto instance = create_dialog_instance();
  instance->enable_sync();

  auto result = instance->try_respond_sync(0);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{Status::BadDialogNotActive}.as_uint32());
}

TEST_F(ConditionInstanceTest, RespondSync_WithBaseLogic_ReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  auto result = instance->try_respond_sync(0);
  EXPECT_TRUE(result.is_bad());
}

// ===========================================================================
// Address Space integration tests
// ===========================================================================

/// Test fixture for ConditionInstance address space integration.
/// Loads NS0 into a real AddressSpace, then creates and initializes
/// ConditionInstance objects with AS wiring.
class ConditionInstanceASTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);

    sAddressSpace.emplace(AddressSpace::create("uri:test:conditions", sPool.executor()));

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
    // Release the imported NS0 address space so it is reclaimed during the test
    // run rather than living in function-local static storage until process
    // exit - LeakSanitizer runs its check before such destructors and would
    // otherwise report the whole NS0 graph (~14.7k nodes) as leaked. This
    // teardown is inherited by the derived ConditionInstanceAttachTest suite,
    // whose SetUpTestSuite re-imports NS0.
    //
    // Do NOT join `sPool` here: it is static and shared with the derived suite,
    // and a joined thread_pool is terminal (cannot be revived), so joining
    // would strand the derived suite's posted handlers (and break
    // --gtest_repeat). The pool's destructor performs the final join at process
    // exit. Same convention as conditions_tests.cpp.
    sAddressSpace.reset();
  }

  /// A concrete ConditionType with ConditionType's members only: ConditionType itself is abstract.
  static NodeId plain_condition_type()
  {
    return ::ua::test_helpers::concrete_condition_type(as(), 1);
  }

  /// Create and initialize a ConditionInstance with address space integration.
  /// Each call uses a unique browse name/conditionId to avoid collisions.
  std::shared_ptr<ConditionInstance> create_and_init_condition(NodeId typeDefinition = plain_condition_type())
  {
    auto id = sNextId++;
    auto instance = ConditionInstance::create(sPool.executor(),
      make_logic(typeDefinition),
      NodeId{1, id},
      NodeId{ObjectId::ObjectsFolder},
      String{fmt::format("TestCond_{}", id)},
      mSink,
      as(),
      typeDefinition);

    auto result = instance->try_initialize_sync();
    EXPECT_TRUE(result.is_good()) << "Initialize failed";
    return instance;
  }

  /// Find a forward hierarchical child of parent with the given browse name.
  NodeId find_child(const NodeId& parent, const std::string& browseName)
  {
    auto nodeResult = as().try_find_node_sync(parent);
    if (nodeResult.is_bad())
    {
      return NodeId{};
    }
    auto refs = nodeResult.value().get_references_sync();
    for (const auto& ref : refs)
    {
      if (!ref.is_forward() || ref.is_remote())
      {
        continue;
      }
      auto childResult = as().try_find_node_sync(ref.target_id().node_id());
      if (childResult.is_good() && std::string{childResult.value().get_browse_name().name()} == browseName)
      {
        return ref.target_id().node_id();
      }
    }
    return NodeId{};
  }

  /// Find a forward child of parent linked via a specific reference type with given browse name.
  NodeId find_child_by_ref(const NodeId& parent, const NodeId& refType, const std::string& browseName)
  {
    auto nodeResult = as().try_find_node_sync(parent);
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
      auto childResult = as().try_find_node_sync(ref.target_id().node_id());
      if (childResult.is_good() && std::string{childResult.value().get_browse_name().name()} == browseName)
      {
        return ref.target_id().node_id();
      }
    }
    return NodeId{};
  }

  /// Check whether the source node has a HasCondition reference to the given target.
  bool has_condition_reference(const NodeId& sourceNode, const NodeId& conditionNode)
  {
    auto nodeResult = as().try_find_node_sync(sourceNode);
    if (nodeResult.is_bad())
    {
      return false;
    }
    auto refs = nodeResult.value().get_references_sync();
    for (const auto& ref : refs)
    {
      if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasCondition} && !ref.is_remote() &&
          ref.target_id().node_id() == conditionNode)
      {
        return true;
      }
    }
    return false;
  }

  static AddressSpace& as()
  {
    return *sAddressSpace;
  }

  static boost::asio::thread_pool sPool;
  static std::optional<AddressSpace> sAddressSpace;
  static EncodingLimits sLimits;
  static uint32_t sNextId;
  std::shared_ptr<FakeEventSink> mSink = std::make_shared<FakeEventSink>();

private:
  static std::unique_ptr<ConditionLogic> make_logic(const NodeId& typeDefinition)
  {
    if (typeDefinition == NodeId{ObjectTypeId::AlarmConditionType})
    {
      return std::make_unique<AlarmConditionLogic>();
    }
    if (typeDefinition == NodeId{ObjectTypeId::AcknowledgeableConditionType})
    {
      return std::make_unique<AcknowledgeableConditionLogic>();
    }
    if (typeDefinition == NodeId{ObjectTypeId::DialogConditionType})
    {
      return std::make_unique<DialogConditionLogic>();
    }
    if (typeDefinition == NodeId{ObjectTypeId::ExclusiveDeviationAlarmType} ||
        typeDefinition == NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType})
    {
      auto logic = std::make_unique<LimitAlarmLogic>();
      LimitConfig limits;
      limits.highLimit = 10.0;
      limits.lowLimit = -10.0;
      logic->set_limits(limits);
      logic->set_exclusive(typeDefinition == NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
      return logic;
    }
    return std::make_unique<ConditionLogic>();
  }
};

boost::asio::thread_pool ConditionInstanceASTest::sPool{2};
std::optional<AddressSpace> ConditionInstanceASTest::sAddressSpace{};
EncodingLimits ConditionInstanceASTest::sLimits{};
uint32_t ConditionInstanceASTest::sNextId{9000};

// --- AS Instantiation ---

TEST_F(ConditionInstanceASTest, Initialize_CreatesConditionNodeInAS)
{
  auto instance = create_and_init_condition();

  auto nodeResult = as().try_find_node_sync(instance->condition_id());
  EXPECT_TRUE(nodeResult.is_good()) << "ConditionPayload node should exist in the address space";
}

TEST_F(ConditionInstanceASTest, Initialize_ConditionNodeHasEnableMethod)
{
  auto instance = create_and_init_condition();

  auto enableId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Enable");
  EXPECT_FALSE(enableId.is_null()) << "Enable method should exist as a child of the condition node";
}

TEST_F(ConditionInstanceASTest, Initialize_ConditionNodeHasRetainProperty)
{
  auto instance = create_and_init_condition();

  auto retainId = find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "Retain");
  EXPECT_FALSE(retainId.is_null()) << "Retain property should exist as a child of the condition node";
}

TEST_F(ConditionInstanceASTest, Initialize_HasConditionReferenceExists)
{
  auto instance = create_and_init_condition();

  EXPECT_TRUE(has_condition_reference(NodeId{ObjectId::ObjectsFolder}, instance->condition_id()))
    << "ObjectsFolder should have a HasCondition reference to the condition node";
}

// --- ExternalValueSource reads ---

TEST_F(ConditionInstanceASTest, ReadRetain_AfterEnable_ReturnsTrue)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto retainId = find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "Retain");
  ASSERT_FALSE(retainId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(retainId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* retainValue = dvResult.value().value().try_as<bool>();
  ASSERT_NE(retainValue, nullptr);
  EXPECT_TRUE(*retainValue);
}

// F75: after AddComment the Comment ConditionVariable node must read back the operator comment from
// the address space. The snapshot holds it and events carry it; this pins that the wired node read
// reflects it too (UACTT reads the Comment node and got empty before this).
TEST_F(ConditionInstanceASTest, ReadComment_AfterAddComment_ReturnsComment)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AcknowledgeableConditionType});
  instance->enable_sync();

  auto eventId = instance->snapshot()->event_id();
  ASSERT_FALSE(eventId.empty());

  instance->add_comment_sync(eventId, LocalizedText{"", "Operator note"});
  // Sanity: the snapshot holds the comment.
  ASSERT_EQ(instance->snapshot()->comment().text(), String{"Operator note"});

  auto commentId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Comment");
  ASSERT_FALSE(commentId.is_null()) << "Comment ConditionVariable node must exist";

  auto varResult = as().try_find_sync<VariableAccessor>(commentId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* value = dvResult.value().value().try_as<LocalizedText>();
  ASSERT_NE(value, nullptr) << "Comment node Value must be a LocalizedText";
  EXPECT_EQ(value->text(), String{"Operator note"})
    << "Reading the Comment node must return the operator comment (F75)";
}

// A wired Condition Variable's Value changes only when the Condition pushes it, which reports every change,
// so its MinimumSamplingInterval is 0 and a MonitoredItem at interval 0 is fed by the pushes rather than
// sampled (OPC 10000-4 5.12.1.2). The Comment Variable is wired and has no interval of its own.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-WIRED-CONDITION-VARIABLE-HAS-AN-INTERVAL-OF-ZERO, scope=function)
TEST_F(ConditionInstanceASTest, AWiredConditionVariableHasAMinimumSamplingIntervalOfZero)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AcknowledgeableConditionType});
  auto commentId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Comment");
  ASSERT_FALSE(commentId.is_null()) << "Comment ConditionVariable node must exist";

  auto variable = as().try_find_sync<VariableAccessor>(commentId);
  ASSERT_TRUE(variable.is_good());
  const auto interval = variable.value().get_minimum_sampling_interval();
  ASSERT_TRUE(interval.has_value()) << "the wired Comment Variable has no MinimumSamplingInterval";
  EXPECT_EQ(*interval, Duration{0});
}

TEST_F(ConditionInstanceASTest, ReadConditionVariable_CarriesSourceTimestamp)
{
  // OPC 10000-4 section 7.7.3: a Read with TimestampsToReturn=Both must return a non-null SourceTimestamp.
  // The Condition variable value readers build a bare DataValue{Variant{...}}; the read-handler wrapper fills
  // a server-read SourceTimestamp/ServerTimestamp when the reader supplies none, so a client (the UACTT) does
  // not see an unset (0001-01-01) timestamp. (F83.)
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();

  auto qualityId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Quality");
  ASSERT_FALSE(qualityId.is_null()) << "Quality ConditionVariable node must exist";

  auto varResult = as().try_find_sync<VariableAccessor>(qualityId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  EXPECT_TRUE(
    dvResult.value().source_timestamp().has_value() && !dvResult.value().source_timestamp()->is_null())
    << "A Condition variable read must carry a non-null SourceTimestamp";
}

// Covers SVR-AC-042, SVR-AC-120 (coverage-audit retag).
TEST_F(ConditionInstanceASTest, ReadEnabledStateId_AfterEnable_ReturnsTrue)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto enabledStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  auto idPropertyId = find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(idPropertyId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* value = dvResult.value().value().try_as<bool>();
  ASSERT_NE(value, nullptr);
  EXPECT_TRUE(*value);
}

TEST_F(ConditionInstanceASTest, ReadSeverity_AfterActivate_ReturnsCorrectValue)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  auto severityId = find_child(instance->condition_id(), "Severity");
  ASSERT_FALSE(severityId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(severityId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* value = dvResult.value().value().try_as<uint16_t>();
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(*value, 500);
}

// F86 quality follow-up. BranchId is a materialised ConditionType property that the SDK leaves unwired
// for the main branch. Before wiring it read back BadAttributeIdInvalid (and after the F86 node-level
// fix, null+good but with NO SourceTimestamp). Wiring it to the snapshot makes the read carry a
// non-null SourceTimestamp (OPC 10000-4 section 7.7.3) - that timestamp is the proof the wired reader, not
// the unwired fallback, served the read. The value is a null NodeId because this is the current branch.
TEST_F(ConditionInstanceASTest, ReadBranchId_AfterEnable_IsGoodWithSourceTimestamp)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto branchId = find_child(instance->condition_id(), "BranchId");
  ASSERT_FALSE(branchId.is_null()) << "BranchId property node must exist on the condition";

  auto varResult = as().try_find_sync<VariableAccessor>(branchId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());
  EXPECT_FALSE(dvResult.value().status().has_value() && dvResult.value().status()->is_bad());
  EXPECT_TRUE(
    dvResult.value().source_timestamp().has_value() && !dvResult.value().source_timestamp()->is_null())
    << "A wired BranchId read must carry a non-null SourceTimestamp";

  // Main-branch BranchId is the null NodeId, but it is a typed NodeId value, not an empty read.
  auto* value = dvResult.value().value().try_as<NodeId>();
  ASSERT_NE(value, nullptr) << "BranchId Value must be a NodeId";
  EXPECT_TRUE(value->is_null());
}

// Part 9 sections 5.8.22.2 and 5.8.22.3 require a typed NULL NodeId when the deviation
// setpoint exists in the underlying system but is not represented by an AddressSpace Variable.
// @relation(AC-SVR-AC-218-SETPOINTNODE-NULL-WHEN-ABSENT, scope=function)
TEST_F(ConditionInstanceASTest, DeviationAlarmSetpointNodeReadsAsTypedNullNodeId)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});

  const auto setpointNode = find_child(instance->condition_id(), "SetpointNode");
  ASSERT_FALSE(setpointNode.is_null()) << "DeviationAlarm must materialise SetpointNode";
  auto variable = as().try_find_sync<VariableAccessor>(setpointNode);
  ASSERT_TRUE(variable.is_good());
  auto read = variable.value().try_read_value_sync();
  ASSERT_TRUE(read.is_good());
  ASSERT_FALSE(read.value().status().has_value() && read.value().status()->is_bad());
  const auto* setpoint = read.value().value().try_as<NodeId>();
  ASSERT_NE(setpoint, nullptr) << "SetpointNode must carry a NodeId-typed value";
  EXPECT_TRUE(setpoint->is_null());
}

// F86 quality follow-up. ClientUserId is wired to the snapshot; with no user-attributed operation yet it
// reads an (empty) String with a non-null SourceTimestamp - again the timestamp proves the wired reader
// served the read rather than the unwired null fallback.
TEST_F(ConditionInstanceASTest, ReadClientUserId_AfterEnable_IsGoodWithSourceTimestamp)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto clientUserId = find_child(instance->condition_id(), "ClientUserId");
  ASSERT_FALSE(clientUserId.is_null()) << "ClientUserId property node must exist on the condition";

  auto varResult = as().try_find_sync<VariableAccessor>(clientUserId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());
  EXPECT_FALSE(dvResult.value().status().has_value() && dvResult.value().status()->is_bad());
  EXPECT_TRUE(
    dvResult.value().source_timestamp().has_value() && !dvResult.value().source_timestamp()->is_null())
    << "A wired ClientUserId read must carry a non-null SourceTimestamp";
}

// F86 quality follow-up. ShelvingState.CurrentState is a ShelvedStateMachineType nested under the alarm
// node. It is not carried in any event payload, so the instance derives it from the alarm logic's
// ShelveState and mirrors it into the snapshot. A wired read must return the real current state name
// ("Unshelved" by default, "TimedShelved" after a timed shelve) plus the matching state NodeId on .../Id.
TEST_F(ConditionInstanceASTest, ReadShelvingStateCurrentState_TracksShelveState)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();

  auto shelvingStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "ShelvingState");
  ASSERT_FALSE(shelvingStateId.is_null()) << "ShelvingState object must exist on the alarm";
  auto currentStateId =
    find_child_by_ref(shelvingStateId, NodeId{ReferenceTypeId::HasComponent}, "CurrentState");
  ASSERT_FALSE(currentStateId.is_null()) << "ShelvingState/CurrentState must exist";

  const auto readCurrentState = [&]() -> DataValue
  {
    auto varResult = as().try_find_sync<VariableAccessor>(currentStateId);
    EXPECT_TRUE(varResult.is_good());
    auto dvResult = varResult.value().try_read_value_sync();
    EXPECT_TRUE(dvResult.is_good());
    return dvResult.value();
  };

  // Default: Unshelved.
  {
    auto dv = readCurrentState();
    auto* name = dv.value().try_as<LocalizedText>();
    ASSERT_NE(name, nullptr) << "CurrentState Value must be a LocalizedText";
    EXPECT_EQ(name->text(), "Unshelved");
  }

  // After a timed shelve the state machine reports TimedShelved.
  instance->activate_sync(500);
  ASSERT_TRUE(instance->try_timed_shelve_sync(5000.0).is_good());
  {
    auto dv = readCurrentState();
    auto* name = dv.value().try_as<LocalizedText>();
    ASSERT_NE(name, nullptr);
    EXPECT_EQ(name->text(), "TimedShelved");
  }

  // The CurrentState/Id property carries the matching ShelvedStateMachineType state NodeId.
  auto idPropertyId = find_child_by_ref(currentStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null()) << "ShelvingState/CurrentState/Id must exist";
  auto idVarResult = as().try_find_sync<VariableAccessor>(idPropertyId);
  ASSERT_TRUE(idVarResult.is_good());
  auto idDvResult = idVarResult.value().try_read_value_sync();
  ASSERT_TRUE(idDvResult.is_good());
  auto* stateId = idDvResult.value().value().try_as<NodeId>();
  ASSERT_NE(stateId, nullptr) << "CurrentState/Id Value must be a NodeId";
  EXPECT_EQ(*stateId, NodeId{ObjectId::ShelvedStateMachineType_TimedShelved});
}

TEST_F(ConditionInstanceASTest, ReadAckedStateId_AfterAcknowledge_ReturnsTrue)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  ASSERT_EQ(mSink->emitCount, 2);
  auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());

  instance->acknowledge_sync(eventId, LocalizedText{"", "Acknowledged"});

  auto ackedStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "AckedState");
  ASSERT_FALSE(ackedStateId.is_null());

  auto idPropertyId = find_child_by_ref(ackedStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(idPropertyId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* value = dvResult.value().value().try_as<bool>();
  ASSERT_NE(value, nullptr);
  EXPECT_TRUE(*value);
}

TEST_F(ConditionInstanceASTest, ConfirmSupport_MaterializesConfirmedStateWithIdAndConfirmMethod)
{
  // OPC 10000-9 section 5.7.2: ConfirmedState (TwoStateVariableType, with its Mandatory Id child) and the
  // Confirm Method are Optional on AcknowledgeableConditionType. When an instance supports Confirm, BOTH must
  // be materialised - the Method is meaningless without the state, and the UACTT Confirm CU browses
  // ConfirmedState/Id. (Regression for F80: the optional-child filter instantiated Confirm but not
  // ConfirmedState, so ConfirmedState/Id was missing.)
  auto id = sNextId++;
  auto logic = std::make_unique<AcknowledgeableConditionLogic>();
  logic->set_supports_confirm(true);
  auto instance = ConditionInstance::create(sPool.executor(),
    std::move(logic),
    NodeId{1, id},
    NodeId{ObjectId::ObjectsFolder},
    String{fmt::format("ConfirmCond_{}", id)},
    mSink,
    as(),
    NodeId{ObjectTypeId::AcknowledgeableConditionType});
  ASSERT_TRUE(instance->try_initialize_sync().is_good());

  auto confirmedStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "ConfirmedState");
  ASSERT_FALSE(confirmedStateId.is_null()) << "ConfirmedState must be materialised when Confirm is supported";

  auto idPropertyId = find_child_by_ref(confirmedStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  EXPECT_FALSE(idPropertyId.is_null()) << "ConfirmedState/Id must be materialised with ConfirmedState";

  auto confirmMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Confirm");
  EXPECT_FALSE(confirmMethodId.is_null()) << "Confirm method must be materialised when Confirm is supported";
}

// --- Method handler tests ---

TEST_F(ConditionInstanceASTest, CallEnableMethod_EnablesCondition)
{
  auto instance = create_and_init_condition();

  auto enableMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Enable");
  ASSERT_FALSE(enableMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(enableMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = enableMethodId;

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_TRUE(callResult.value().status_code().is_good());

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->enabled());
}

TEST_F(ConditionInstanceASTest, CallDisableMethod_DisablesCondition)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto disableMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Disable");
  ASSERT_FALSE(disableMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(disableMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = disableMethodId;

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_TRUE(callResult.value().status_code().is_good());

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
}

TEST_F(ConditionInstanceASTest, CallAcknowledgeMethod_ValidEventId_Succeeds)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  ASSERT_EQ(mSink->emitCount, 2);
  auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());

  auto ackMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Acknowledge");
  ASSERT_FALSE(ackMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(ackMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = ackMethodId;
  request.input_arguments() = Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack via method"}}};

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_TRUE(callResult.value().status_code().is_good());
}

TEST_F(ConditionInstanceASTest, CallAcknowledgeMethod_InvalidEventId_ReturnsBadEventIdUnknown)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  auto ackMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Acknowledge");
  ASSERT_FALSE(ackMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(ackMethodId);
  ASSERT_TRUE(methodResult.is_good());

  ByteString bogusId{std::vector<uint8_t>{0xFF, 0xFE, 0xFD}};

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = ackMethodId;
  request.input_arguments() = Array<Variant>{Variant{bogusId}, Variant{LocalizedText{"", "Bad ack"}}};

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadEventIdUnknown});
}

// The Method path is the one a REMOTE client drives, and Part 4 5.11.2 keeps the reject as a
// per-operation status inside CallMethodResult while the outer CallResult stays Good. The wire
// carries only that bare status, so the server-retained detail is the operator's only record of
// which EventId was presented - it must carry the same context the direct *_async API does.
TEST_F(ConditionInstanceASTest, CallAcknowledgeMethod_InvalidEventId_PerOperationDetailNamesEventId)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  auto ackMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "Acknowledge");
  ASSERT_FALSE(ackMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(ackMethodId);
  ASSERT_TRUE(methodResult.is_good());

  ByteString bogusId{std::vector<uint8_t>{0xAA, 0xBB}};

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = ackMethodId;
  request.input_arguments() = Array<Variant>{Variant{bogusId}, Variant{LocalizedText{"", "Bad ack"}}};

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  auto detail = callResult.value().status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ConditionTransitionRejected");
  EXPECT_EQ(context_value(*detail, ContextKeys::eventId), ua::to_string(bogusId));
  EXPECT_EQ(context_value(*detail, ContextKeys::nodeId), ua::to_string(instance->condition_id()));
}

TEST_F(ConditionInstanceASTest, CallAddCommentMethod_MissingArgs_ReturnsBadArgumentsMissing)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();

  auto addCommentMethodId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "AddComment");
  ASSERT_FALSE(addCommentMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(addCommentMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = instance->condition_id();
  request.method_id() = addCommentMethodId;
  // No input arguments - should fail

  auto callResult = methodResult.value().try_call_sync(request);
  EXPECT_TRUE(callResult.is_bad());
  EXPECT_EQ(callResult.status_code(), StatusCode{Status::BadArgumentsMissing});
}

// --- Cleanup ---

TEST_F(ConditionInstanceASTest, Close_RemovesNodesFromAS)
{
  auto instance = create_and_init_condition();
  auto conditionNodeId = instance->condition_id();

  // Verify node exists before close
  auto before = as().try_find_node_sync(conditionNodeId);
  ASSERT_TRUE(before.is_good());

  instance->close_sync();

  // Close removes the condition's subtree via an async fire-and-forget cascade.
  // Poll until the node is gone rather than draining sPool: the pool is static
  // and shared across the whole fixture (SetUpTestSuite), and drain_with_timeout
  // joins it permanently - that would terminate the pool for every subsequent
  // test (see the TearDownTestSuite note). try_find_node_sync round-trips the
  // still-live pool each iteration, so the deletion becomes visible without
  // touching the pool's lifetime. ~2s ceiling; the in-memory delete is immediate.
  bool removed = false;
  for (int attempt = 0; attempt < 200; ++attempt)
  {
    if (as().try_find_node_sync(conditionNodeId).is_bad())
    {
      removed = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  EXPECT_TRUE(removed) << "ConditionPayload node should be removed from AS after close";
}

// ===========================================================================
// Attach (wrap existing nodes) tests
// ===========================================================================

/// Test fixture for ConditionInstance attach path.
/// Reuses the same static AddressSpace from ConditionInstanceASTest.
class ConditionInstanceAttachTest : public ConditionInstanceASTest
{
protected:
  /// Instantiate a condition object in the AS by creating a temporary ConditionInstance
  /// with the "create" path, then leaking it (no close). The nodes remain in the AS.
  /// This simulates having pre-existing condition nodes (e.g. from NodeSet XML import).
  NodeId instantiate_condition_in_as(const NodeId& typeDefinition = plain_condition_type())
  {
    auto id = sNextId++;
    auto dummySink = std::make_shared<FakeEventSink>();
    auto tempInstance = ConditionInstance::create(sPool.executor(),
      make_logic_for_type(typeDefinition),
      NodeId{1, id},
      NodeId{ObjectId::ObjectsFolder},
      String{fmt::format("AttachCond_{}", id)},
      dummySink,
      as(),
      typeDefinition);

    auto result = tempInstance->try_initialize_sync();
    EXPECT_TRUE(result.is_good()) << "Failed to instantiate condition object in AS";

    auto rootId = tempInstance->condition_id();
    // Keep the instance alive (and its owned subtree) so nodes stay in the AS.
    mTempInstances.push_back(std::move(tempInstance));
    return rootId;
  }

  /// Create a ConditionInstance and attach it to an existing AS node.
  std::shared_ptr<ConditionInstance> create_and_attach_condition(
    const NodeId& existingNodeId, const NodeId& typeDefinition = plain_condition_type())
  {
    auto instance = ConditionInstance::create(sPool.executor(),
      make_logic_for_type(typeDefinition),
      existingNodeId,
      NodeId{ObjectId::ObjectsFolder},
      String{"AttachSource"},
      mSink,
      as(),
      typeDefinition);

    auto result = instance->try_attach_sync();
    EXPECT_TRUE(result.is_good()) << "Attach failed: " << result.status_code().as_uint32();
    return instance;
  }

  /// Gives a variable node the value `value`, as the node of an address space no ConditionInstance owns.
  ///
  /// The node was created by the temporary instance from instantiate_condition_in_as, which is kept alive
  /// for its subtree and still serves the node's reads from its own state; the view is cleared and the
  /// value written to the node's store, which the attaching instance then reads.
  void set_node_value(const NodeId& variableId, Variant value)
  {
    auto varResult = as().try_find_sync<VariableAccessor>(variableId);
    ASSERT_TRUE(varResult.is_good());
    // The temporary instance that created these nodes wired read-only views onto them; a node imported
    // from a NodeSet has no source. Clearing the view makes the node that imported node again, so the seed
    // lands in its value store instead of being refused as a write to a read-only source.
    auto* source = varResult.value()->external_value_source();
    ASSERT_NE(source, nullptr);
    ASSERT_TRUE(source->set_value_source(nullptr).is_good());
    auto writeResult = varResult.value().try_write_value_sync(DataValue{std::move(value)});
    EXPECT_TRUE(writeResult.is_good());
  }

  void write_bool_value(const NodeId& variableId, bool value)
  {
    set_node_value(variableId, Variant{value});
  }

  void write_uint16_value(const NodeId& variableId, uint16_t value)
  {
    set_node_value(variableId, Variant{value});
  }

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
    if (typeDefinition == NodeId{ObjectTypeId::DialogConditionType})
    {
      return std::make_unique<DialogConditionLogic>();
    }
    return std::make_unique<ConditionLogic>();
  }

  std::vector<std::shared_ptr<ConditionInstance>> mTempInstances;
};

// --- Basic attach ---

TEST_F(ConditionInstanceAttachTest, Attach_Succeeds)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);
  EXPECT_EQ(instance->condition_id(), conditionNodeId);
}

TEST_F(ConditionInstanceAttachTest, Attach_NodeNotFound_ReturnsError)
{
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 99999u},  // non-existent node
    NodeId{ObjectId::ObjectsFolder},
    String{"Missing"},
    mSink,
    as(),
    NodeId{ObjectTypeId::ConditionType});

  auto result = instance->try_attach_sync();
  EXPECT_TRUE(result.is_bad());
}

// The attach path owes the same notifier-source diagnostic contract as initialization.
// @relation(AC-SVR-AC-071-CONDITION-HIERARCHY, scope=function)
TEST_F(ConditionInstanceAttachTest, Attach_MissingSourcePreservesErrorDetail)
{
  const auto conditionNodeId = instantiate_condition_in_as();
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    conditionNodeId,
    NodeId{1, 999999u},
    String{"MissingAttachSource"},
    mSink,
    as(),
    NodeId{ObjectTypeId::ConditionType});

  const auto result = instance->try_attach_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{Status::BadNodeIdUnknown}.as_uint32());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NodeNotFound");
}

TEST_F(ConditionInstanceAttachTest, Attach_NoAddressSpace_IsNoOp)
{
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 50000u},
    NodeId{ObjectId::ObjectsFolder},
    String{"NoAS"},
    mSink);  // no address space

  auto result = instance->try_attach_sync();
  EXPECT_TRUE(result.is_good());
}

// --- HasCondition reference ---

TEST_F(ConditionInstanceAttachTest, Attach_CreatesHasConditionReference)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);

  EXPECT_TRUE(has_condition_reference(NodeId{ObjectId::ObjectsFolder}, conditionNodeId));
}

// --- Variable wiring ---

TEST_F(ConditionInstanceAttachTest, Attach_WiresRetainProperty)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);
  instance->enable_sync();

  auto retainId = find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasProperty}, "Retain");
  ASSERT_FALSE(retainId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(retainId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* retainValue = dvResult.value().value().try_as<bool>();
  ASSERT_NE(retainValue, nullptr);
  EXPECT_TRUE(*retainValue);
}

TEST_F(ConditionInstanceAttachTest, Attach_WiresEnabledStateId)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);
  instance->enable_sync();

  auto enabledStateId =
    find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  auto idPropertyId = find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(idPropertyId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* value = dvResult.value().value().try_as<bool>();
  ASSERT_NE(value, nullptr);
  EXPECT_TRUE(*value);
}

// --- Method handler wiring ---

TEST_F(ConditionInstanceAttachTest, Attach_EnableMethodWorks)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);

  auto enableMethodId = find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "Enable");
  ASSERT_FALSE(enableMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(enableMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = conditionNodeId;
  request.method_id() = enableMethodId;

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_TRUE(callResult.value().status_code().is_good());

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->enabled());
}

// --- Close does NOT remove nodes ---

TEST_F(ConditionInstanceAttachTest, Close_DoesNotRemoveNodesFromAS)
{
  auto conditionNodeId = instantiate_condition_in_as();
  auto instance = create_and_attach_condition(conditionNodeId);

  // Verify node exists before close
  auto before = as().try_find_node_sync(conditionNodeId);
  ASSERT_TRUE(before.is_good());

  instance->close_sync();

  // Node should STILL exist because attach does not own the subtree
  auto after = as().try_find_node_sync(conditionNodeId);
  EXPECT_TRUE(after.is_good())
    << "ConditionPayload node should NOT be removed after close on attached instance";
}

// --- Initial state reading ---

TEST_F(ConditionInstanceAttachTest, Attach_ReadsInitialEnabledState_True)
{
  auto conditionNodeId = instantiate_condition_in_as();

  // Write EnabledState/Id = true before attaching
  auto enabledStateId =
    find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());
  auto idPropertyId = find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());
  write_bool_value(idPropertyId, true);

  auto instance = create_and_attach_condition(conditionNodeId);

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->enabled());
}

TEST_F(ConditionInstanceAttachTest, Attach_ReadsInitialEnabledState_False)
{
  auto conditionNodeId = instantiate_condition_in_as();

  // Write EnabledState/Id = false before attaching
  auto enabledStateId =
    find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());
  auto idPropertyId = find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());
  write_bool_value(idPropertyId, false);

  auto instance = create_and_attach_condition(conditionNodeId);

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
}

TEST_F(ConditionInstanceAttachTest, Attach_ReadsInitialAckedState)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AcknowledgeableConditionType});

  // Write AckedState/Id = true before attaching
  auto ackedStateId = find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "AckedState");
  ASSERT_FALSE(ackedStateId.is_null());
  auto idPropertyId = find_child_by_ref(ackedStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());
  write_bool_value(idPropertyId, true);

  auto instance =
    create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AcknowledgeableConditionType});

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->acked());
}

TEST_F(ConditionInstanceAttachTest, Attach_ReadsInitialActiveState)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType});

  // Write ActiveState/Id = true and Severity = 750 before attaching
  auto activeStateId =
    find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "ActiveState");
  ASSERT_FALSE(activeStateId.is_null());
  auto idPropertyId = find_child_by_ref(activeStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());
  write_bool_value(idPropertyId, true);

  auto severityId = find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasProperty}, "Severity");
  ASSERT_FALSE(severityId.is_null());
  write_uint16_value(severityId, 750);

  auto instance = create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AlarmConditionType});

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->active());
  EXPECT_EQ(snapshot->severity(), 750);
}

// --- Alarm attach with method handlers ---

TEST_F(ConditionInstanceAttachTest, Attach_AlarmAcknowledgeMethodWorks)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType});
  auto instance = create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  instance->activate_sync(500);

  ASSERT_EQ(mSink->emitCount, 2);
  auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());

  auto ackMethodId = find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "Acknowledge");
  ASSERT_FALSE(ackMethodId.is_null());

  auto methodResult = as().try_find_sync<MethodAccessor>(ackMethodId);
  ASSERT_TRUE(methodResult.is_good());

  CallMethodRequest request;
  request.object_id() = conditionNodeId;
  request.method_id() = ackMethodId;
  request.input_arguments() = Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack via method"}}};

  auto callResult = methodResult.value().try_call_sync(request);
  ASSERT_TRUE(callResult.is_good());
  EXPECT_TRUE(callResult.value().status_code().is_good());

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->acked());
}

// ===========================================================================
// Phase D.1: Address Space Structure Tests
// ===========================================================================

// COND-001: All mandatory properties exist on a ConditionType instance
TEST_F(ConditionInstanceASTest, Initialize_HasAllMandatoryProperties)
{
  auto instance = create_and_init_condition();
  auto id = instance->condition_id();

  // Properties (HasProperty references)
  for (const auto& name : {"Retain",
         "ConditionClassId",
         "ConditionClassName",
         "ConditionName",
         "BranchId",
         "ClientUserId",
         "Severity"})
  {
    auto propId = find_child_by_ref(id, NodeId{ReferenceTypeId::HasProperty}, name);
    EXPECT_FALSE(propId.is_null()) << "Mandatory property '" << name << "' should exist";
  }

  // Components (HasComponent references): compound variables
  for (const auto& name : {"EnabledState", "Quality", "LastSeverity", "Comment"})
  {
    auto compId = find_child_by_ref(id, NodeId{ReferenceTypeId::HasComponent}, name);
    EXPECT_FALSE(compId.is_null()) << "Mandatory component '" << name << "' should exist";
  }
}

// COND-002: Enable, Disable, and AddComment methods exist
TEST_F(ConditionInstanceASTest, Initialize_HasAllMandatoryMethods)
{
  auto instance = create_and_init_condition();
  auto id = instance->condition_id();

  for (const auto& name : {"Enable", "Disable", "AddComment"})
  {
    auto methodId = find_child_by_ref(id, NodeId{ReferenceTypeId::HasComponent}, name);
    EXPECT_FALSE(methodId.is_null()) << "Mandatory method '" << name << "' should exist";
  }
}

// COND-011: Two condition instances have different ConditionIds
// Covers SVR-AC-036 (coverage-audit retag).
TEST_F(ConditionInstanceASTest, TwoInstances_HaveDifferentConditionIds)
{
  auto instance1 = create_and_init_condition();
  auto instance2 = create_and_init_condition();

  EXPECT_NE(instance1->condition_id(), instance2->condition_id());
}

// COND-020: ConditionName property exists on condition instance
TEST_F(ConditionInstanceASTest, ConditionName_PropertyExists)
{
  auto instance = create_and_init_condition();

  auto condNameId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "ConditionName");
  EXPECT_FALSE(condNameId.is_null()) << "ConditionName property should exist on instantiated condition";
}

// Part 9 section 5.5.2 permits a Server to stop providing selected evaluation outputs while a Condition is
// disabled, but requires every output it withdraws to read Bad_ConditionDisabled. This SDK withdraws
// the live evaluation fields while retaining the six fields the specification requires to remain
// valid. Drive the public address-space read path: a logic-only getter cannot prove the descriptor
// gate or its whitelist.
// @verifies AC-SVR-AC-011-DISABLED-VARIABLES-BAD
TEST_F(ConditionInstanceASTest, DisabledConditionDistinguishesWithdrawnFromRequiredVariables)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();
  instance->disable_sync();

  const auto read = [&](std::string_view browseName)
  {
    const NodeId variableId = find_child(instance->condition_id(), std::string{browseName});
    EXPECT_FALSE(variableId.is_null()) << "missing Variable " << browseName;
    if (variableId.is_null())
      return DataValue{};

    auto variable = as().try_find_sync<VariableAccessor>(variableId);
    EXPECT_TRUE(variable.is_good()) << "could not resolve Variable " << browseName;
    if (variable.is_bad())
      return DataValue{};

    auto value = variable.value().try_read_value_sync();
    EXPECT_TRUE(value.is_good()) << "read transport failed for " << browseName;
    return value.is_good() ? std::move(value).value() : DataValue{};
  };

  for (const auto name : {"Quality", "LastSeverity", "Comment", "Severity", "Message"})
  {
    SCOPED_TRACE(name);
    const DataValue value = read(name);
    ASSERT_TRUE(value.status().has_value());
    EXPECT_EQ(value.status()->as_status(), Status::BadConditionDisabled);
    EXPECT_TRUE(value.value().empty()) << "a withdrawn Variable must not leak its stale value";
  }

  for (const auto name : {"EventId", "EventType", "SourceNode", "SourceName", "Time", "EnabledState"})
  {
    SCOPED_TRACE(name);
    const DataValue value = read(name);
    EXPECT_TRUE(!value.status().has_value() || value.status()->is_good());
  }
}

// COND-053: After disable, EnabledState remains valid (not Bad_ConditionDisabled)
TEST_F(ConditionInstanceASTest, Disable_EnabledStateRemainsValid)
{
  auto instance = create_and_init_condition();
  instance->enable_sync();
  instance->disable_sync();

  auto enabledStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  auto idPropertyId = find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
  ASSERT_FALSE(idPropertyId.is_null());

  auto varResult = as().try_find_sync<VariableAccessor>(idPropertyId);
  ASSERT_TRUE(varResult.is_good());

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());
  EXPECT_TRUE(!dvResult.value().status().has_value() || dvResult.value().status().value().is_good())
    << "EnabledState/Id should remain readable after disable";

  auto* value = dvResult.value().value().try_as<bool>();
  ASSERT_NE(value, nullptr);
  EXPECT_FALSE(*value) << "EnabledState/Id should be false after disable";
}

// COND-151: TransitionTime sub-property is instantiated on EnabledState and wired
TEST_F(ConditionInstanceASTest, TransitionTime_ExistsAndWiredOnEnabledState)
{
  auto instance = create_and_init_condition();

  auto enabledStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  auto transTimeId =
    find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "TransitionTime");
  ASSERT_FALSE(transTimeId.is_null()) << "TransitionTime should be instantiated on EnabledState";

  auto varResult = as().try_find_sync<VariableAccessor>(transTimeId);
  ASSERT_TRUE(varResult.is_good());

  instance->enable_sync();

  auto dvResult = varResult.value().try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());

  auto* transTime = dvResult.value().value().try_as<DateTime>();
  ASSERT_NE(transTime, nullptr);
  EXPECT_NE(*transTime, DateTime{}) << "TransitionTime should be set after enable transition";
}

// COND-156: TrueState/FalseState exist on type declaration; check instance behavior
// Covers SVR-AC-044, SVR-AC-121 (coverage-audit retag).
// @verifies AC-SVR-AC-044-TRUESTATE-ON-INSTANCEDECLARATIONS
TEST_F(ConditionInstanceASTest, NS0Structure_TwoStateVariable_TrueStateFalseState)
{
  auto instance = create_and_init_condition();

  auto enabledStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  // Check whether TrueState/FalseState exist on the instance
  auto instanceTrueState =
    find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "TrueState");
  auto instanceFalseState =
    find_child_by_ref(enabledStateId, NodeId{ReferenceTypeId::HasProperty}, "FalseState");

  // Verify they exist on the type declaration (required by spec)
  auto condTypeEnabledState = find_child_by_ref(
    NodeId{ObjectTypeId::ConditionType}, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(condTypeEnabledState.is_null());

  auto typeTrueState =
    find_child_by_ref(condTypeEnabledState, NodeId{ReferenceTypeId::HasProperty}, "TrueState");
  auto typeFalseState =
    find_child_by_ref(condTypeEnabledState, NodeId{ReferenceTypeId::HasProperty}, "FalseState");
  EXPECT_FALSE(typeTrueState.is_null()) << "TrueState should exist on type declaration";
  EXPECT_FALSE(typeFalseState.is_null()) << "FalseState should exist on type declaration";

  // Per spec (COND-156), TrueState/FalseState should only be on the type declaration.
  // The instantiation engine does NOT copy them to instances (they are optional).
  // Documents current behavior.
  EXPECT_TRUE(instanceTrueState.is_null())
    << "Documents current behavior: TrueState is not copied to instances";
  EXPECT_TRUE(instanceFalseState.is_null())
    << "Documents current behavior: FalseState is not copied to instances";
}

// OPC 10000-9 section 6.2: the Server Object is the root of the notifier hierarchy. A ConditionSource
// that is an event-notifying Object is linked with HasNotifier, a subtype of HasEventSource. Both
// stored legs are required because Clients discover the source by browsing forward from Server.
// @relation(AC-SVR-AC-070-CONDITIONSOURCE-HASEVENTSOURCE-TARGET, scope=function)
// @relation(AC-SVR-AC-071-CONDITION-HIERARCHY, scope=function)
// @relation(AC-SVR-AC-085-AREAS-LINKED-BY-NOTIFIER, scope=function)
TEST_F(ConditionInstanceASTest, Initialize_CreatesReciprocalNotifierHierarchyLink)
{
  auto instance = create_and_init_condition();
  const NodeId sourceId{ObjectId::ObjectsFolder};
  const NodeId serverId{ObjectId::Server};

  auto sourceResult = as().try_find_node_sync(sourceId);
  ASSERT_TRUE(sourceResult.is_good());
  auto serverResult = as().try_find_node_sync(serverId);
  ASSERT_TRUE(serverResult.is_good());

  const auto sourceReferences = sourceResult.value().get_references_sync();
  const auto serverReferences = serverResult.value().get_references_sync();

  const bool hasCondition = std::any_of(sourceReferences.begin(),
    sourceReferences.end(),
    [&instance](const Reference& reference)
    {
      return reference.is_forward() && !reference.is_remote() &&
             reference.type_id() == NodeId{ReferenceTypeId::HasCondition} &&
             reference.target_id().node_id() == instance->condition_id();
    });
  const bool hasInverseNotifier = std::any_of(sourceReferences.begin(),
    sourceReferences.end(),
    [&serverId](const Reference& reference)
    {
      return !reference.is_forward() && !reference.is_remote() &&
             reference.type_id() == NodeId{ReferenceTypeId::HasNotifier} &&
             reference.target_id().node_id() == serverId;
    });
  const bool hasForwardNotifier = std::any_of(serverReferences.begin(),
    serverReferences.end(),
    [&sourceId](const Reference& reference)
    {
      return reference.is_forward() && !reference.is_remote() &&
             reference.type_id() == NodeId{ReferenceTypeId::HasNotifier} &&
             reference.target_id().node_id() == sourceId;
    });

  EXPECT_TRUE(hasCondition);
  EXPECT_TRUE(hasInverseNotifier);
  EXPECT_TRUE(hasForwardNotifier);
}

// A source that cannot be resolved cannot be placed in the mandatory notifier hierarchy. The
// initialization error must retain the address-space lookup detail for the caller.
// @relation(AC-SVR-AC-071-CONDITION-HIERARCHY, scope=function)
TEST_F(ConditionInstanceASTest, Initialize_MissingSourcePreservesErrorDetail)
{
  const auto id = sNextId++;
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, id},
    NodeId{1, 999999u},
    String{fmt::format("MissingSourceCond_{}", id)},
    mSink,
    as(),
    plain_condition_type());

  const auto result = instance->try_initialize_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{Status::BadNodeIdUnknown}.as_uint32());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NodeNotFound");
}

class ConditionNotifierLink : public ConditionInstanceASTest
{
protected:
  /// The types of the References @p holder holds to @p other in the direction @p forward that are
  /// HasEventSource or its subtype HasNotifier: a Browse for HasEventSource with subtypes.
  static std::vector<std::string> event_source_links(const NodeId& holder, const NodeId& other, bool forward)
  {
    std::vector<std::string> links;
    auto node = as().try_find_node_sync(holder);
    if (node.is_bad())
    {
      ADD_FAILURE() << ua::to_string(holder) << " not found";
      return links;
    }
    for (const auto& reference : node.value().get_references_sync())
    {
      if (reference.is_forward() != forward || reference.is_remote() ||
          reference.target_id().node_id() != other)
        continue;
      if (reference.type_id() == NodeId{ReferenceTypeId::HasEventSource})
        links.emplace_back("HasEventSource");
      else if (reference.type_id() == NodeId{ReferenceTypeId::HasNotifier})
        links.emplace_back("HasNotifier");
    }
    return links;
  }
};

// Part 9 section 5.12 with Clause 6: S is reachable from the Server Object by the HasEventSource it already
// holds, so that Reference links the source. The HasNotifier the Condition asks for is a subtype of the
// concrete HasEventSource and so, by Part 3 section 4.3.4, the Reference already held (DL-11 as amended): the
// initialization takes the refusal of a second one as the link being present, and the Server and S each hold
// one Reference between them, the HasEventSource.
// @relation(AC-SVR-AC-071-SERVER-ALREADY-HOLDING-HASEVENTSOURCE, scope=function)
TEST_F(ConditionNotifierLink, AServerHoldingHasEventSourceToTheSourceStillInitializesTheCondition)
{
  const NodeId serverId{ObjectId::Server};
  const NodeId sourceId{1, sNextId++};
  auto created = as().try_create_node_sync(sourceId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good()) << ua::to_string(created.status_code());
  auto source = std::move(created).value();
  source.set_browse_name(QualifiedName{1, "HeldEventSource"});
  auto sourceObject = source.as<ObjectAccessor>();
  ASSERT_TRUE(sourceObject.has_value());
  sourceObject->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto server = as().try_find_node_sync(serverId);
  ASSERT_TRUE(server.is_good());
  ASSERT_TRUE(
    server.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, sourceId).is_good());
  ASSERT_TRUE(
    source.try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, serverId, false).is_good());

  const auto id = sNextId++;
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, id},
    sourceId,
    String{fmt::format("HeldEventSourceCond_{}", id)},
    mSink,
    as(),
    plain_condition_type());
  const auto initialized = instance->try_initialize_sync();
  EXPECT_TRUE(initialized.is_good()) << "the initialization answered "
                                     << ua::to_string(initialized.status_code());

  EXPECT_EQ(event_source_links(serverId, sourceId, true), std::vector<std::string>{"HasEventSource"})
    << "the Server Object's forward References to S";
  EXPECT_EQ(event_source_links(sourceId, serverId, false), std::vector<std::string>{"HasEventSource"})
    << "S's inverse References to the Server Object";
}

// COND-1012: Check HasTrueSubState links on the AlarmConditionType declaration
// HasTrueSubState references are defined on the type, not necessarily on instances.
// Check the type declaration in the address space.
TEST_F(ConditionInstanceASTest, NS0Structure_HasTrueSubStateOnTypeDeclaration)
{
  // Check the AlarmConditionType's EnabledState declaration in NS0
  auto typeEnabledState = find_child_by_ref(
    NodeId{ObjectTypeId::AlarmConditionType}, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");

  if (typeEnabledState.is_null())
  {
    // AlarmConditionType may not have EnabledState directly - it inherits from ConditionType
    typeEnabledState = find_child_by_ref(
      NodeId{ObjectTypeId::ConditionType}, NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  }
  ASSERT_FALSE(typeEnabledState.is_null());

  auto nodeResult = as().try_find_node_sync(typeEnabledState);
  ASSERT_TRUE(nodeResult.is_good());

  auto refs = nodeResult.value().get_references_sync();
  bool hasAnyTrueSubState = false;
  for (const auto& ref : refs)
  {
    if (ref.type_id() == NodeId{ReferenceTypeId::HasTrueSubState} && ref.is_forward())
    {
      hasAnyTrueSubState = true;
      break;
    }
  }

  // HasTrueSubState references should be present on the type declaration
  EXPECT_TRUE(hasAnyTrueSubState)
    << "EnabledState on the type declaration should have HasTrueSubState references";
}

// COND-1013: No HasFalseSubState references from EnabledState
TEST_F(ConditionInstanceASTest, NS0Structure_NoHasFalseSubStateFromEnabledState)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});

  auto enabledStateId =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "EnabledState");
  ASSERT_FALSE(enabledStateId.is_null());

  auto nodeResult = as().try_find_node_sync(enabledStateId);
  ASSERT_TRUE(nodeResult.is_good());

  auto refs = nodeResult.value().get_references_sync();
  for (const auto& ref : refs)
  {
    EXPECT_NE(ref.type_id(), NodeId{ReferenceTypeId::HasFalseSubState})
      << "EnabledState should not have HasFalseSubState references (per spec section 5.5.2)";
  }
}

// COND-810: DialogConditionPayload has mandatory properties (Prompt, ResponseOptionSet, etc.)
TEST_F(ConditionInstanceASTest, DialogCondition_HasMandatoryProperties)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::DialogConditionType});
  auto id = instance->condition_id();

  // DialogConditionPayload-specific mandatory properties
  for (const auto& name :
    {"Prompt", "ResponseOptionSet", "DefaultResponse", "LastResponse", "OkResponse", "CancelResponse"})
  {
    auto propId = find_child_by_ref(id, NodeId{ReferenceTypeId::HasProperty}, name);
    EXPECT_FALSE(propId.is_null()) << "DialogConditionPayload mandatory property '" << name
                                   << "' should exist";
  }

  // DialogState component
  auto dialogStateId = find_child_by_ref(id, NodeId{ReferenceTypeId::HasComponent}, "DialogState");
  EXPECT_FALSE(dialogStateId.is_null()) << "DialogConditionPayload should have DialogState component";
}

// ===========================================================================
// Phase D.2: Restart Recovery Tests
// ===========================================================================

// COND-091: Attach to AcknowledgeableConditionPayload without modifying AckedState -
// defaults to unacknowledged (false) per Part 9
// Covers SVR-AC-060 (coverage-audit retag).
TEST_F(ConditionInstanceAttachTest, Attach_DefaultAckedState_IsFalse)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AcknowledgeableConditionType});
  // Do NOT write AckedState - rely on the default from the temp instance
  auto instance =
    create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AcknowledgeableConditionType});

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->acked()) << "Default AckedState should be false (unacknowledged)";
}

// COND-231: Attach reads ConfirmedState/Id from address space
TEST_F(ConditionInstanceAttachTest, Attach_ReadsInitialConfirmedState)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AcknowledgeableConditionType});

  // Write ConfirmedState/Id = true before attaching
  auto confirmedStateId =
    find_child_by_ref(conditionNodeId, NodeId{ReferenceTypeId::HasComponent}, "ConfirmedState");
  // ConfirmedState may not be instantiated if confirm support is not enabled on the type
  if (!confirmedStateId.is_null())
  {
    auto idPropertyId = find_child_by_ref(confirmedStateId, NodeId{ReferenceTypeId::HasProperty}, "Id");
    ASSERT_FALSE(idPropertyId.is_null());
    write_bool_value(idPropertyId, true);

    auto instance =
      create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AcknowledgeableConditionType});

    auto snapshot = instance->snapshot();
    EXPECT_TRUE(snapshot->confirmed()) << "Attached instance should read ConfirmedState=true from AS";
  }
}

// COND-232: Default ConfirmedState is false (unconfirmed) when not modified
TEST_F(ConditionInstanceAttachTest, Attach_DefaultConfirmedState_IsFalse)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AcknowledgeableConditionType});
  auto instance =
    create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AcknowledgeableConditionType});

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->confirmed()) << "Default ConfirmedState should be false (unconfirmed)";
}

// COND-550: Default ActiveState is false (inactive) when not modified
TEST_F(ConditionInstanceAttachTest, Attach_DefaultActiveState_IsFalse)
{
  auto conditionNodeId = instantiate_condition_in_as(NodeId{ObjectTypeId::AlarmConditionType});
  auto instance = create_and_attach_condition(conditionNodeId, NodeId{ObjectTypeId::AlarmConditionType});

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->active()) << "Default ActiveState should be false (inactive)";
  EXPECT_EQ(snapshot->severity(), 0) << "Default severity should be 0";
}

// Stage 3b #5/#6: a user CompleteCallback on a ConditionInstance *_async operation that throws must be
// contained inside the strand-posted Asio handler (invoke_user_callback) and delivered EXACTLY ONCE
// (the success fire runs through invoke_user_callback, which swallows the throw so the catch never
// re-fires; make_fire_once additionally guards the catch path). Pre-fix the throw escaped the strand
// handler -> std::terminate and the catch re-fired the callback (double delivery).
TEST_F(ConditionInstanceTest, EnableAsync_ThrowingCallbackIsContainedAndDeliveredOnce)
{
  auto instance = create_basic_instance();
  auto calls = std::make_shared<std::atomic<int>>(0);
  auto delivered = std::make_shared<std::promise<void>>();
  auto deliveredFuture = delivered->get_future();

  instance->enable_async(
    [calls, delivered](VoidResult) mutable
    {
      calls->fetch_add(1);
      delivered->set_value();  // signal delivery BEFORE throwing so the test can proceed
      throw std::runtime_error("application condition callback failed");  // must be contained, not terminate
    });

  ASSERT_EQ(deliveredFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready)
    << "the operation completion must be delivered";
  EXPECT_EQ(calls->load(), 1) << "a throwing condition callback must be delivered exactly once and contained";
  // Reaching here proves containment: pre-fix the throw escaped the Asio strand handler -> std::terminate.
}

// MaxTimeShelved is Optional on AlarmConditionType (OPC 10000-9 5.8.2). An alarm that configures a maximum
// exposes the Property, and a Read of it returns the same Duration the alarm's events carry; an alarm that
// imposes no maximum does not expose it.
TEST_F(ConditionInstanceASTest, MaxTimeShelvedIsExposedExactlyWhenConfigured)
{
  const auto create = [this](double maxTimeShelvedMs)
  {
    auto logic = std::make_unique<AlarmConditionLogic>();
    logic->set_max_time_shelved(maxTimeShelvedMs);
    const auto id = sNextId++;
    auto instance = ConditionInstance::create(sPool.executor(),
      std::move(logic),
      NodeId{1, id},
      NodeId{ObjectId::ObjectsFolder},
      String{fmt::format("MaxTimeShelved_{}", id)},
      mSink,
      as(),
      NodeId{ObjectTypeId::AlarmConditionType});
    EXPECT_TRUE(instance->try_initialize_sync().is_good());
    return instance;
  };

  auto configured = create(60'000.0);
  const auto propertyId =
    find_child_by_ref(configured->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "MaxTimeShelved");
  ASSERT_FALSE(propertyId.is_null()) << "a configured MaxTimeShelved must be exposed";
  auto property = as().try_find_sync<VariableAccessor>(propertyId);
  ASSERT_TRUE(property.is_good());
  auto value = property.value().try_read_value_sync();
  ASSERT_TRUE(value.is_good());
  const auto* duration = value.value().value().try_as<double>();
  ASSERT_NE(duration, nullptr) << "MaxTimeShelved is a Duration";
  EXPECT_EQ(*duration, 60'000.0);

  auto unconfigured = create(0.0);
  EXPECT_TRUE(
    find_child_by_ref(unconfigured->condition_id(), NodeId{ReferenceTypeId::HasProperty}, "MaxTimeShelved")
      .is_null())
    << "an alarm with no maximum must not expose MaxTimeShelved";
}

// ShelvingState.LastTransition (Optional, inherited from FiniteStateMachineType) is exposed on an alarm and
// reports the last shelving transition: its name, its ShelvedStateMachineType transition Id, and when it
// happened. An exclusive limit alarm's LimitState does not track transitions, so it gets no LastTransition.
TEST_F(ConditionInstanceASTest, ShelvingLastTransitionReportsEachShelvingTransition)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  const auto shelvingState =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "ShelvingState");
  ASSERT_FALSE(shelvingState.is_null());
  const auto lastTransition =
    find_child_by_ref(shelvingState, NodeId{ReferenceTypeId::HasComponent}, "LastTransition");
  ASSERT_FALSE(lastTransition.is_null()) << "ShelvingState must expose LastTransition";
  const auto idNode = find_child_by_ref(lastTransition, NodeId{ReferenceTypeId::HasProperty}, "Id");
  const auto timeNode =
    find_child_by_ref(lastTransition, NodeId{ReferenceTypeId::HasProperty}, "TransitionTime");
  ASSERT_FALSE(idNode.is_null());
  ASSERT_FALSE(timeNode.is_null());

  const auto read = [this](const NodeId& nodeId)
  {
    auto variable = as().try_find_sync<VariableAccessor>(nodeId);
    EXPECT_TRUE(variable.is_good());
    auto value = variable.value().try_read_value_sync();
    EXPECT_TRUE(value.is_good());
    return value.value().value();
  };
  const auto expectTransition = [&](std::string_view name, ObjectId transitionId)
  {
    const auto nameValue = read(lastTransition);
    const auto* text = nameValue.try_as<LocalizedText>();
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(std::string{text->text()}, name);
    const auto idValue = read(idNode);
    const auto* id = idValue.try_as<NodeId>();
    ASSERT_NE(id, nullptr);
    EXPECT_EQ(*id, NodeId{transitionId});
    const auto timeValue = read(timeNode);
    const auto* when = timeValue.try_as<DateTime>();
    ASSERT_NE(when, nullptr);
    EXPECT_NE(*when, DateTime{});
  };

  EXPECT_TRUE(read(lastTransition).empty()) << "no shelving transition has happened yet";

  instance->timed_shelve_sync(30'000.0);
  expectTransition("UnshelvedToTimedShelved", ObjectId::ShelvedStateMachineType_UnshelvedToTimedShelved);
  instance->unshelve_sync();
  expectTransition("TimedShelvedToUnshelved", ObjectId::ShelvedStateMachineType_TimedShelvedToUnshelved);
  instance->one_shot_shelve_sync();
  expectTransition("UnshelvedToOneShotShelved", ObjectId::ShelvedStateMachineType_UnshelvedToOneShotShelved);

  auto limitAlarm = create_and_init_condition(NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
  const auto limitState =
    find_child_by_ref(limitAlarm->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "LimitState");
  ASSERT_FALSE(limitState.is_null());
  EXPECT_TRUE(
    find_child_by_ref(limitState, NodeId{ReferenceTypeId::HasComponent}, "LastTransition").is_null())
    << "LimitState tracks no transitions, so it must not expose an unwired LastTransition";
}

// The Condition node's EventId, Time and ReceiveTime describe the last event it emitted. A re-evaluation
// that changes nothing and emits no event - a limit alarm's input sample inside the band it is already in -
// must not move Time and ReceiveTime to "now" while EventId still names the earlier event: a Client
// reading them together would see an event that never happened.
TEST_F(ConditionInstanceASTest, TimeAndReceiveTimeStayWithTheLastEmittedEvent)
{
  // A Double input the alarm samples; its limits (make_logic) are +-10, so 0..3 stays in the normal band.
  const NodeId inputId{1, sNextId++};
  auto input = as().try_create_node_sync(inputId, NodeClass::Variable, {});
  ASSERT_TRUE(input.is_good());
  auto inputVariable = input.value().as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  inputVariable->set_data_type(NodeId{DataTypeId::Double});
  ASSERT_TRUE(inputVariable->try_write_value_sync(DataValue{Variant{0.0}}).is_good());

  auto instance = create_and_init_condition(NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
  instance->enable_sync();
  ASSERT_TRUE(instance->try_bind_input_sync(inputId, 25.0).is_good());
  std::this_thread::sleep_for(std::chrono::milliseconds{150});
  const auto [emittedCount, emittedTime] = mSink->observed();
  ASSERT_NE(emittedTime, DateTime{});

  for (const double value : {1.0, 2.0, 3.0})
  {
    ASSERT_TRUE(inputVariable->try_write_value_sync(DataValue{Variant{value}}).is_good());
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
  }
  ASSERT_EQ(mSink->observed().first, emittedCount) << "precondition: in-band samples emit no event";

  for (const char* field : {"Time", "ReceiveTime"})
  {
    const auto nodeId =
      find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasProperty}, field);
    ASSERT_FALSE(nodeId.is_null()) << field;
    auto variable = as().try_find_sync<VariableAccessor>(nodeId);
    ASSERT_TRUE(variable.is_good());
    auto value = variable.value().try_read_value_sync();
    ASSERT_TRUE(value.is_good());
    const auto* time = value.value().value().try_as<DateTime>();
    ASSERT_NE(time, nullptr) << field;
    EXPECT_EQ(*time, emittedTime) << field << " must stay the last emitted event's Time";
  }
  std::promise<VoidResult> unbound;
  instance->unbind_input_async([&unbound](VoidResult result) { unbound.set_value(std::move(result)); });
  EXPECT_EQ(unbound.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// ShelvingState.UnshelveTime (Mandatory) is the time left until a TimedShelve ends (OPC 10000-9 5.8.17.1):
// a Read counts down between events, and reads 0 once the alarm is unshelved.
TEST_F(ConditionInstanceASTest, UnshelveTimeCountsDownWhileTimedShelved)
{
  auto instance = create_and_init_condition(NodeId{ObjectTypeId::AlarmConditionType});
  instance->enable_sync();
  const auto shelvingState =
    find_child_by_ref(instance->condition_id(), NodeId{ReferenceTypeId::HasComponent}, "ShelvingState");
  ASSERT_FALSE(shelvingState.is_null());
  const auto unshelveTimeId =
    find_child_by_ref(shelvingState, NodeId{ReferenceTypeId::HasProperty}, "UnshelveTime");
  ASSERT_FALSE(unshelveTimeId.is_null());
  const auto read = [this, &unshelveTimeId]()
  {
    auto variable = as().try_find_sync<VariableAccessor>(unshelveTimeId);
    EXPECT_TRUE(variable.is_good());
    auto value = variable.value().try_read_value_sync();
    EXPECT_TRUE(value.is_good());
    const auto* duration = value.value().value().try_as<double>();
    EXPECT_NE(duration, nullptr) << "UnshelveTime is a Duration";
    return duration ? *duration : -1.0;
  };

  EXPECT_EQ(read(), 0.0) << "an unshelved alarm has no time left";
  instance->timed_shelve_sync(30'000.0);
  const auto first = read();
  EXPECT_GT(first, 0.0);
  EXPECT_LE(first, 30'000.0);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  const auto second = read();
  EXPECT_LT(second, first) << "UnshelveTime must count down between events";
  EXPECT_GT(second, first - 5'000.0);
  instance->unshelve_sync();
  EXPECT_EQ(read(), 0.0);
}

/// Condition initialisation writes attributes on a node the application chose (the SourceNode's
/// EventNotifier) and on a node it instantiated (the AccessLevel of a limit whose value is unavailable).
/// Every one of those nodes may live in a namespace that answers by posting to the executor the Condition
/// runs on. On a one-thread executor a blocking write waits there for an answer that can only run there and
/// initialisation never completes; the awaited and asynchronous writes must let it complete.
class ConditionInstanceNonBlockingTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sExecutor = std::make_unique<OneThreadExecutor>();
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);
    sAddressSpace.emplace(AddressSpace::create("uri:test:conditions-posting", sExecutor->executor()));

    StructureFactory structureFactory;
    auto lookupFn = namespace_array_utils::get_index_lookup_function(*sAddressSpace);
    const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
    register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

    FileStream inputStream{"NodeSet2.xml"};
    inputStream.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(sLimits,
      inputStream,
      structureFactory,
      sAddressSpace->namespace_array(),
      sAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = xml::nodeset::ImportEngine::create(sLimits, *sAddressSpace, nodeSets, {});
    importer->import_all_sync({}, {});

    sPostingNamespace = PostingWritesNamespace::create("urn:test:posting-writes", sExecutor->executor());
    auto index = sAddressSpace->try_add_namespace_sync(sPostingNamespace);
    ASSERT_TRUE(index.is_good());
    sNamespaceIndex = index.value();
  }

  static void TearDownTestSuite()
  {
    sAddressSpace.reset();
    sPostingNamespace.reset();
    // Destroying the executor detaches its thread rather than joining it, so a test that left the
    // thread blocked fails instead of hanging the binary.
    sExecutor.reset();
  }

  static std::unique_ptr<OneThreadExecutor> sExecutor;
  static std::optional<AddressSpace> sAddressSpace;
  static std::shared_ptr<PostingWritesNamespace> sPostingNamespace;
  static uint16_t sNamespaceIndex;
  static EncodingLimits sLimits;
};

std::unique_ptr<OneThreadExecutor> ConditionInstanceNonBlockingTest::sExecutor{};
std::optional<AddressSpace> ConditionInstanceNonBlockingTest::sAddressSpace{};
std::shared_ptr<PostingWritesNamespace> ConditionInstanceNonBlockingTest::sPostingNamespace{};
uint16_t ConditionInstanceNonBlockingTest::sNamespaceIndex{0};
EncodingLimits ConditionInstanceNonBlockingTest::sLimits{};

TEST_F(ConditionInstanceNonBlockingTest, InitializeCompletesWhenTheNamespaceAnswersWritesByPosting)
{
  auto& addressSpace = *sAddressSpace;
  const NodeId sourceId{sNamespaceIndex, 100u};
  auto source = addressSpace.try_create_node_sync(sourceId, NodeClass::Object, {});
  ASSERT_TRUE(source.is_good());
  source.value().set_browse_name(QualifiedName{sNamespaceIndex, "PostingSource"});
  auto sourceObject = source.value().as<ObjectAccessor>();
  ASSERT_TRUE(sourceObject.has_value());
  ASSERT_FALSE(sourceObject->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents));

  auto logic = std::make_unique<LimitAlarmLogic>();
  LimitConfig limits;
  limits.highHighLimit = 90.0;
  limits.highLimit = ConfiguredLimit::unavailable();
  logic->set_limits(limits);
  auto instance = ConditionInstance::create(sExecutor->executor(),
    std::move(logic),
    NodeId{sNamespaceIndex, 1000u},
    sourceId,
    String{"PostingSource"},
    std::make_shared<FakeEventSink>(),
    addressSpace,
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});

  std::promise<VoidResult> initialized;
  auto future = initialized.get_future();
  instance->initialize_async([&initialized](VoidResult result) { initialized.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{30}), std::future_status::ready)
    << "initialisation blocked the thread its nodes' namespace answers on";
  const auto result = future.get();
  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());

  // Each write class reached the nodes through the posting namespace, so none of this passed vacuously.
  EXPECT_GT(sPostingNamespace->posted_writes(AttributeId::EventNotifier), 0u) << "SourceNode EventNotifier";
  EXPECT_GT(sPostingNamespace->posted_writes(AttributeId::AccessLevel), 0u) << "AccessLevel";

  // And each write took effect.
  EXPECT_TRUE(sourceObject->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents));
  const auto conditionResult = addressSpace.try_find_node_sync(instance->condition_id());
  ASSERT_TRUE(conditionResult.is_good());
  NodeId unavailableLimitId;
  for (const auto& reference : conditionResult.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasProperty})
      continue;
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child.is_good() && std::string{child.value().get_browse_name().name()} == "HighLimit")
      unavailableLimitId = reference.target_id().node_id();
  }
  ASSERT_FALSE(unavailableLimitId.is_null()) << "the unavailable limit Property was omitted";
  auto unavailableLimit = addressSpace.try_find_sync<VariableAccessor>(unavailableLimitId);
  ASSERT_TRUE(unavailableLimit.is_good());
  EXPECT_FALSE(unavailableLimit.value().get_access_level().test(AccessLevelType::Bit::CurrentRead))
    << "the unavailable limit's AccessLevel write did not complete";
}

}  // namespace ua::test
