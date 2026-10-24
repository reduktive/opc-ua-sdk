// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The model changes the address space raises for an operation (NR-36, NR-46, NR-55, NR-63; NR-70 C2): what a
// deleted Node's entry carries, and a namespace's own report through its context.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_address_space_change_events.h"
#include "ua_application_configuration.h"
#include "ua_data_type_registration.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_default_object_node.h"
#include "ua_default_variable_node.h"
#include "ua_encoding_limits.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_structure_factory.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace_context.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

uint8_t verb(ModelChangeStructureVerbMask mask)
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

// An in-memory namespace that reports its own changes through its context while it holds a lock of its own,
// and records whether any member the address space calls ran during that report.
class SelfReportingNamespace final : public default_ns::Namespace
{
public:
  SelfReportingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void report_under_own_lock(std::span<const ModelChangeReport> changes)
  {
    const std::lock_guard lock{mOwnLock};
    mReporting = true;
    context().model_changed(changes);
    mReporting = false;
  }

  /// Asks the context to advance ConfigurationVersion.
  VoidResult advance_configuration_version(std::function<void(VoidResult)> completion)
  {
    return context().constant_values_changed(std::move(completion));
  }

  /// Declares @p metadata as the Object that holds this namespace's NamespaceMetadata.
  void declare_metadata_object(const NodeId& metadata)
  {
    mMetadata = metadata;
  }

  std::optional<NodeId> metadata_object() const override
  {
    return mMetadata;
  }

  bool called_while_reporting() const
  {
    return mCalledWhileReporting.load();
  }

  /// From now on the namespace holds the answer of each write until @ref release_writes.
  void hold_writes()
  {
    mHeld->holding.store(true);
  }

  /// The writes whose answers are held.
  std::size_t held_writes() const
  {
    const std::lock_guard lock{mHeld->mutex};
    return mHeld->answers.size();
  }

  /// Answers the held writes on @p executor, as a namespace answers from its own work.
  void release_writes(const boost::asio::any_io_executor& executor)
  {
    boost::asio::post(executor, [held = mHeld] { held->release(); });
  }

  /// Whether the address space has called shutdown_async.
  bool shut_down() const
  {
    return mShutDown.load();
  }

  /// Whether shutdown_async was called while the answer of a write was still held.
  bool shut_down_while_a_write_was_held() const
  {
    return mShutDownWhileHeld.load();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (held_writes() != 0)
    {
      mShutDownWhileHeld.store(true);
    }
    mShutDown.store(true);
    default_ns::Namespace::shutdown_async(std::move(callback));
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    note_call();
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    note_call();
    default_ns::Namespace::read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    note_call();
    default_ns::Namespace::read_values_async(
      request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    note_call();
    if (mHeld->holding.load())
    {
      default_ns::Namespace::write_async(request,
        caller,
        items,
        [held = mHeld, complete = std::move(complete)](
          BatchResult<VoidResult> results, std::vector<VersionedNode> versioned) mutable
        {
          const std::lock_guard lock{held->mutex};
          held->answers.push_back(
            [complete = std::move(complete), results = std::move(results), versioned = std::move(versioned)]()
            { complete(results, versioned); });
        });
      return;
    }
    default_ns::Namespace::write_async(request, caller, items, std::move(complete));
  }

private:
  /// The answers of the writes held by @ref hold_writes; shared with each held completion.
  struct HeldWrites
  {
    std::atomic<bool> holding{false};
    mutable std::mutex mutex;
    std::vector<std::function<void()>> answers;

    void release()
    {
      std::vector<std::function<void()>> ready;
      {
        const std::lock_guard lock{mutex};
        ready.swap(answers);
      }
      for (auto& answer : ready)
      {
        answer();
      }
    }
  };

  void note_call()
  {
    if (mReporting.load())
    {
      mCalledWhileReporting.store(true);
    }
  }

  std::optional<NodeId> mMetadata;
  std::mutex mOwnLock;
  std::atomic<bool> mReporting{false};
  std::atomic<bool> mCalledWhileReporting{false};
  std::shared_ptr<HeldWrites> mHeld{std::make_shared<HeldWrites>()};
  std::atomic<bool> mShutDown{false};
  std::atomic<bool> mShutDownWhileHeld{false};
};

class ModelChangeReports : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:model-change-reports", mThreadPool.get_executor()));
    mNamespace = std::make_shared<SelfReportingNamespace>(
      "urn:test:model-change-reports:own", mThreadPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
    detail::AddressSpaceChangeEvents::set_handler(*mAddressSpace,
      [this](const detail::AddressSpaceChange& change)
      {
        {
          const std::lock_guard lock{mChangesMutex};
          mChanges.push_back(change);
        }
        mChangeArrived.notify_all();
      });
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor create_object(const std::string& name)
  {
    auto created = mAddressSpace->try_create_node_sync(NodeId{mIndex, String{name}}, NodeClass::Object, {});
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    auto object = std::move(created).value();
    object.set_browse_name(QualifiedName{mIndex, String{name}});
    EXPECT_TRUE(object
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                    ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}})
                  .is_good());
    return object;
  }

  // Gives @p node a NodeVersion Property.
  void version(NodeAccessor& node, const std::string& name)
  {
    const NodeId propertyId{mIndex, String{name + ".NodeVersion"}};
    auto created = mAddressSpace->try_create_node_sync(propertyId, NodeClass::Variable, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    auto property = std::move(created).value();
    property.set_browse_name(QualifiedName{0, "NodeVersion"});
    auto variable = property.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::String});
    ASSERT_TRUE(node.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{propertyId})
                  .is_good());
  }

  std::vector<detail::AddressSpaceChange> changes()
  {
    const std::lock_guard lock{mChangesMutex};
    return mChanges;
  }

  void clear_changes()
  {
    const std::lock_guard lock{mChangesMutex};
    mChanges.clear();
  }

  bool wait_for_change(std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mChangesMutex};
    return mChangeArrived.wait_for(lock, timeout, [this] { return !mChanges.empty(); });
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<SelfReportingNamespace> mNamespace;
  uint16_t mIndex{0};
  std::mutex mChangesMutex;
  std::condition_variable mChangeArrived;
  std::vector<detail::AddressSpaceChange> mChanges;
};

// Part 5 12.16 Table 240: "If the affected Node was an Object or Variable, affectedType contains the NodeId
// of the TypeDefinitionNode of the affected Node." A deleted versioned Object is listed with the
// TypeDefinition it had (NR-36 rule 2, NR-42 A-7), its NodeVersion not written.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-DELETED-NODE-CARRIES-ITS-TYPE, scope=function)
TEST_F(ModelChangeReports, ADeletedNodeCarriesTheTypeDefinitionItHad)
{
  auto object = create_object("Deleted");
  version(object, "Deleted");
  clear_changes();

  auto deleted =
    std::make_shared<std::promise<std::pair<VoidResult, std::vector<detail::AddressSpaceChange>>>>();
  auto deletedFuture = deleted->get_future();
  // The fixture owns this operation and drains its pool before destroying the recorded changes.
  mAddressSpace->delete_node_async(NodeId{mIndex, "Deleted"},
    false,
    ReferenceHalves::Both,
    [this, deleted](VoidResult result) { deleted->set_value({std::move(result), changes()}); });
  ASSERT_EQ(deletedFuture.wait_for(5s), std::future_status::ready);
  const auto [result, raised] = deletedFuture.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  // The snapshot is taken inside the delete completion (NR-46).
  ASSERT_EQ(raised.size(), 1u);
  EXPECT_EQ(raised[0].kind, detail::AddressSpaceChangeKind::Model);
  EXPECT_FALSE(raised[0].unspecified);
  ASSERT_EQ(raised[0].changes.size(), 1u);
  EXPECT_EQ(raised[0].changes[0].affected, (NodeId{mIndex, "Deleted"}));
  EXPECT_EQ(raised[0].changes[0].affectedType, NodeId{ObjectTypeId::BaseObjectType});
  EXPECT_EQ(raised[0].changes[0].verbs, verb(ModelChangeStructureVerbMask::NodeDeleted));
}

using NamespaceContextModelChanged = ModelChangeReports;

// NR-39 rule 6: a namespace may report from inside its own members, holding its own locks. The report
// advances the model generation at once, calls no namespace before it returns, and the event follows on the
// address space's executor (NR-36 rule 3).
// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-04-MODEL-CHANGED-CALLS-NO-NAMESPACE, scope=function)
TEST_F(NamespaceContextModelChanged, ACallUnderTheNamespacesOwnLockReturnsBeforeAnyNamespaceCall)
{
  const NodeId added{mIndex, "AddedByTheNamespace"};
  const ModelChangeReport reports[] = {
    ModelChangeReport{ModelChangeReport::Kind::NodeAdded, added, NodeId{ObjectTypeId::BaseObjectType}}};
  const auto before = mAddressSpace->model_generation();

  mNamespace->report_under_own_lock(reports);

  EXPECT_GT(mAddressSpace->model_generation(), before)
    << "the generation did not advance before the report returned";
  EXPECT_FALSE(mNamespace->called_while_reporting()) << "the report called the namespace before it returned";
  ASSERT_TRUE(wait_for_change(5s)) << "the reported change raised no event";
  const auto raised = changes();
  ASSERT_EQ(raised.size(), 1u);
  EXPECT_EQ(raised[0].kind, detail::AddressSpaceChangeKind::Model);
  ASSERT_EQ(raised[0].changes.size(), 1u);
  EXPECT_EQ(raised[0].changes[0].affected, added);
  EXPECT_EQ(raised[0].changes[0].affectedType, NodeId{ObjectTypeId::BaseObjectType});
  EXPECT_EQ(raised[0].changes[0].verbs, verb(ModelChangeStructureVerbMask::NodeAdded));
}

// A namespace that changed its model and cannot say how, or changed Nodes that have no NodeVersion, reports
// an empty list: the model generation advances and no event is raised.
// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-04-AN-EMPTY-REPORT-ADVANCES-THE-GENERATION-ONLY, scope=function)
TEST_F(NamespaceContextModelChanged, AnEmptyReportAdvancesTheGenerationAndRaisesNoEvent)
{
  const auto before = mAddressSpace->model_generation();

  mNamespace->report_under_own_lock({});

  EXPECT_GT(mAddressSpace->model_generation(), before) << "the empty report did not advance the generation";
  // The empty report posts nothing; a later report is the first and only event that arrives.
  const NodeId added{mIndex, "AddedAfterTheEmptyReport"};
  const ModelChangeReport reports[] = {
    ModelChangeReport{ModelChangeReport::Kind::NodeAdded, added, NodeId{ObjectTypeId::BaseObjectType}}};
  mNamespace->report_under_own_lock(reports);
  ASSERT_TRUE(wait_for_change(5s)) << "the later report raised no event";
  const auto raised = changes();
  ASSERT_EQ(raised.size(), 1u) << "the empty report raised an event";
  ASSERT_EQ(raised[0].changes.size(), 1u);
  EXPECT_EQ(raised[0].changes[0].affected, added);
}

// Part 3 9.32.2: only the Nodes that have a NodeVersion trigger a ModelChangeEvent. Operations through the
// address space on a Node without one (its creation, a BrowseName write, a Reference added and a DisplayName
// write) raise no event, so a later report is the first and only event that arrives.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-AN-OPERATION-THAT-LISTS-NO-NODE-RAISES-NO-EVENT, scope=function)
TEST_F(NamespaceContextModelChanged, AnOperationThatListsNoNodeRaisesNoEvent)
{
  auto object = create_object("Unversioned");
  object.set_display_name(LocalizedText{LocaleId{"en"}, String{"Renamed"}});

  const NodeId added{mIndex, "AddedAfterTheOperations"};
  const ModelChangeReport reports[] = {
    ModelChangeReport{ModelChangeReport::Kind::NodeAdded, added, NodeId{ObjectTypeId::BaseObjectType}}};
  mNamespace->report_under_own_lock(reports);
  ASSERT_TRUE(wait_for_change(5s)) << "the later report raised no event";
  const auto raised = changes();
  ASSERT_EQ(raised.size(), 1u) << "an operation that lists no Node raised an event";
  ASSERT_EQ(raised[0].changes.size(), 1u);
  EXPECT_EQ(raised[0].changes[0].affected, added);
}

// A Reference change made on a Node of the in-memory namespace directly, outside the address space's routes,
// is reported by the namespace: the model generation advances (NR-27 rule 2).
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-05-A-DIRECT-CHANGE-ADVANCES-THE-MODEL-GENERATION, scope=function)
TEST_F(NamespaceContextModelChanged, AReferenceChangeMadeOnANodeAdvancesTheGeneration)
{
  const auto node = mNamespace->create_node<default_ns::ObjectNode>(NodeId{mIndex, "ChangedDirectly"});
  ASSERT_NE(node, nullptr);
  const auto before = mAddressSpace->model_generation();

  std::optional<VoidResult> added;
  node->add_reference_async(NodeId{ReferenceTypeId::Organizes},
    ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
    false,
    [&added](VoidResult result) { added = std::move(result); });

  ASSERT_TRUE(added.has_value());
  ASSERT_TRUE(added->is_good()) << to_string(added->status_code());
  EXPECT_GT(mAddressSpace->model_generation(), before);
}

using ConstantValuesChanged = ModelChangeReports;

// A namespace that was never attached has a closed context: the request is answered Bad_Shutdown at once and
// the completion is never called.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-02-A-CLOSED-CONTEXT-ANSWERS-BAD-SHUTDOWN-AT-ONCE, scope=function)
TEST_F(ConstantValuesChanged, AClosedContextAnswersBadShutdownAtOnce)
{
  auto detached = std::make_shared<SelfReportingNamespace>(
    "urn:test:model-change-reports:detached", mThreadPool.get_executor());
  auto completed = std::make_shared<std::atomic<bool>>(false);

  const auto answer =
    detached->advance_configuration_version([completed](VoidResult) { completed->store(true); });

  EXPECT_EQ(answer.status_code(), StatusCode{Status::BadShutdown});
  EXPECT_FALSE(completed->load());
}

// The completion runs after the advance: when it runs, ConfigurationVersion already holds a greater value.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-02-THE-COMPLETION-RUNS-AFTER-THE-ADVANCE, scope=function)
TEST_F(ConstantValuesChanged, TheCompletionRunsAfterTheAdvance)
{
  auto metadata = create_object("Metadata");
  const NodeId versionId{mIndex, "Metadata.ConfigurationVersion"};
  auto created = mAddressSpace->try_create_node_sync(versionId, NodeClass::Variable, {});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  auto versionNode = std::move(created).value();
  versionNode.set_browse_name(QualifiedName{0, "ConfigurationVersion"});
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->set_data_type(NodeId{DataTypeId::UInt32});
  version->write_value_sync(Variant{uint32_t{5}});
  ASSERT_TRUE(metadata.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{versionId})
                .is_good());
  ASSERT_TRUE(versionNode
                .try_add_reference_sync(
                  NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{metadata.get_node_id()}, false)
                .is_good());
  mNamespace->declare_metadata_object(metadata.get_node_id());

  // The completion runs on the address space's executor, so whether it has already run when the call returns
  // depends on scheduling. What it must never do is run on the caller's thread inside the call, where it
  // could re-enter a lock the caller holds: the thread it ran on tells that apart exactly.
  const auto caller = std::this_thread::get_id();
  auto completionThread = std::make_shared<std::thread::id>();
  ASSERT_NE(dynamic_cast<const default_ns::VariableNode*>(&*versionNode), nullptr);
  auto answered = std::make_shared<std::promise<std::pair<VoidResult, DataValue>>>();
  auto answeredFuture = answered->get_future();
  const auto answer = mNamespace->advance_configuration_version(
    [completionThread, answered, versionNode](VoidResult result)
    {
      *completionThread = std::this_thread::get_id();
      // This synchronized default-source read posts no work and waits for no future or executor work.
      const auto& node = dynamic_cast<const default_ns::VariableNode&>(*versionNode);
      answered->set_value({std::move(result), node.read_default_source(0, false)});
    });

  ASSERT_TRUE(answer.is_good()) << to_string(answer.status_code());
  ASSERT_EQ(answeredFuture.wait_for(5s), std::future_status::ready) << "the completion did not run";
  EXPECT_NE(*completionThread, caller) << "the completion ran on the caller's thread";
  const auto [result, valueAtCompletion] = answeredFuture.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_TRUE(valueAtCompletion.value().is_uint32());
  EXPECT_GT(valueAtCompletion.value().as<uint32_t>(), 5u);
  // Retain the public read after completion as an additional value-transfer check.
  auto found = mAddressSpace->try_find_node_sync(versionId);
  ASSERT_TRUE(found.is_good()) << to_string(found.status_code());
  const auto read = found.value().as<VariableAccessor>()->try_read_value_sync();
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_TRUE(read.value().value().is_uint32());
  EXPECT_GT(read.value().value().as<uint32_t>(), 5u);
}

// NR-67 step 1: the address space's shutdown closes every context, so a report made after it is refused at
// once although the address space still exists: constant_values_changed answers Bad_Shutdown and never calls
// its completion, and model_changed leaves the model generation where it was. The control is the same
// context's report before the shutdown, which advances the generation.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-02-AFTER-SHUTDOWN-THE-CONTEXT-REFUSES-AT-ONCE, scope=function)
TEST_F(ConstantValuesChanged, AfterTheAddressSpaceShutDownTheContextRefusesAtOnce)
{
  const auto before = mAddressSpace->model_generation();
  mNamespace->report_under_own_lock({});
  ASSERT_GT(mAddressSpace->model_generation(), before) << "the control: the report before the shutdown";

  auto shutDown = std::make_shared<std::promise<VoidResult>>();
  auto shutDownFuture = shutDown->get_future();
  mAddressSpace->shutdown_async([shutDown](VoidResult result) { shutDown->set_value(std::move(result)); });
  ASSERT_EQ(shutDownFuture.wait_for(5s), std::future_status::ready) << "the shutdown did not complete";

  const auto after = mAddressSpace->model_generation();
  mNamespace->report_under_own_lock({});
  EXPECT_EQ(mAddressSpace->model_generation(), after)
    << "a report after the shutdown advanced the model generation";
  auto completed = std::make_shared<std::atomic<bool>>(false);
  const auto answer =
    mNamespace->advance_configuration_version([completed](VoidResult) { completed->store(true); });
  EXPECT_EQ(answer.status_code().as_status(), Status::BadShutdown)
    << "an advance asked for after the shutdown was queued";
  EXPECT_FALSE(completed->load());
}

// NR-67 step 2: the address space's shutdown waits for the ConfigurationVersion advances already queued
// before it shuts down the namespaces and completes. The namespace holds the answer of the advance's write of
// ConfigurationVersion. The address space runs on an io_context that this thread runs until no work is left,
// so that a shutdown that does not wait is observed as one that has completed, not raced. The control is the
// release of the write: the advance then completes, and after it the namespace is shut down and the shutdown
// completes.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-02-THE-SHUTDOWN-WAITS-FOR-A-QUEUED-ADVANCE, scope=function)
TEST(AddressSpaceShutdown, WaitsForAQueuedConfigurationVersionAdvance)
{
  boost::asio::io_context io;
  const auto runUntilNoWork = [&io]
  {
    io.restart();
    io.run_for(5s);
  };
  {
    std::optional<AddressSpace> addressSpace =
      AddressSpace::create("urn:test:shutdown-waits", io.get_executor());
    auto space = std::make_shared<SelfReportingNamespace>("urn:test:shutdown-waits:own", io.get_executor());

    // Set up through the synchronous members, with the io_context run by a thread of its own until it is
    // idle.
    const auto setUp = [&]
    {
      auto index = addressSpace->try_add_namespace_sync(space);
      ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
      const uint16_t namespaceIndex = index.value();
      const NodeId metadataId{namespaceIndex, "Metadata"};
      const NodeId versionId{namespaceIndex, "Metadata.ConfigurationVersion"};
      auto metadataCreated = addressSpace->try_create_node_sync(metadataId, NodeClass::Object, {});
      ASSERT_TRUE(metadataCreated.is_good()) << to_string(metadataCreated.status_code());
      auto metadata = std::move(metadataCreated).value();
      metadata.set_browse_name(QualifiedName{namespaceIndex, "Metadata"});
      auto versionCreated = addressSpace->try_create_node_sync(versionId, NodeClass::Variable, {});
      ASSERT_TRUE(versionCreated.is_good()) << to_string(versionCreated.status_code());
      auto versionNode = std::move(versionCreated).value();
      versionNode.set_browse_name(QualifiedName{0, "ConfigurationVersion"});
      auto version = versionNode.as<VariableAccessor>();
      ASSERT_TRUE(version.has_value());
      version->set_data_type(NodeId{DataTypeId::UInt32});
      version->write_value_sync(Variant{uint32_t{5}});
      ASSERT_TRUE(
        metadata.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{versionId})
          .is_good());
      space->declare_metadata_object(metadataId);
    };
    {
      auto work = boost::asio::make_work_guard(io);
      std::thread runner{[&io]
        {
          io.run_for(60s);
        }};
      setUp();
      work.reset();
      runner.join();
    }
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    runUntilNoWork();

    space->hold_writes();
    std::optional<VoidResult> advanced;
    const auto queued =
      space->advance_configuration_version([&advanced](VoidResult result) { advanced = std::move(result); });
    ASSERT_TRUE(queued.is_good()) << to_string(queued.status_code());
    runUntilNoWork();
    ASSERT_EQ(space->held_writes(), 1u) << "the advance did not reach its write of ConfigurationVersion";

    std::optional<VoidResult> shutDown;
    addressSpace->shutdown_async([&shutDown](VoidResult result) { shutDown = std::move(result); });
    runUntilNoWork();
    EXPECT_FALSE(space->shut_down()) << "the namespace was shut down while its advance was queued";
    EXPECT_FALSE(shutDown.has_value()) << "the shutdown completed while an advance was queued";

    space->release_writes(io.get_executor());
    runUntilNoWork();
    ASSERT_TRUE(advanced.has_value()) << "the advance did not complete once its write was answered";
    EXPECT_TRUE(advanced->is_good()) << to_string(advanced->status_code());
    ASSERT_TRUE(shutDown.has_value()) << "the shutdown did not complete once the advance had";
    EXPECT_TRUE(shutDown->is_good()) << to_string(shutDown->status_code());
    EXPECT_TRUE(space->shut_down());
    EXPECT_FALSE(space->shut_down_while_a_write_was_held());

    addressSpace.reset();
    space.reset();
  }
  runUntilNoWork();
}

// NR-36 rule 6, OPC 10000-3 9.32.2 ("every time the NodeVersion is changed, a ModelChangeEvent shall be
// generated"): a Value written to a Node's NodeVersion Property through its accessor raises one
// BaseModelChangeEvent, as a client's write through the Write service does. The control is a Value written to
// another Property of the same Node through its accessor, which raises no event.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-NODEVERSION-WRITTEN-THROUGH-AN-ACCESSOR-RAISES-AN-EVENT, scope=function)
TEST_F(ModelChangeReports, ANodeVersionWrittenThroughAnAccessorRaisesABaseModelChangeEvent)
{
  auto object = create_object("Written");
  version(object, "Written");
  const NodeId otherId{mIndex, "Written.Other"};
  auto createdOther = mAddressSpace->try_create_node_sync(otherId, NodeClass::Variable, {});
  ASSERT_TRUE(createdOther.is_good()) << to_string(createdOther.status_code());
  auto other = std::move(createdOther).value();
  other.set_browse_name(QualifiedName{mIndex, "Other"});
  ASSERT_TRUE(
    object.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{otherId}).is_good());
  clear_changes();

  auto otherVariable = other.as<VariableAccessor>();
  ASSERT_TRUE(otherVariable.has_value());
  const auto otherWritten = otherVariable->try_write_value_sync(DataValue{Variant{String{"7"}}});
  ASSERT_TRUE(otherWritten.is_good()) << to_string(otherWritten.status_code());
  EXPECT_TRUE(changes().empty()) << "a write of another Property raised an event";

  auto found = mAddressSpace->try_find_node_sync(NodeId{mIndex, "Written.NodeVersion"});
  ASSERT_TRUE(found.is_good()) << to_string(found.status_code());
  auto nodeVersion = found.value().as<VariableAccessor>();
  ASSERT_TRUE(nodeVersion.has_value());
  const auto written = nodeVersion->try_write_value_sync(DataValue{Variant{String{"client-set"}}});
  ASSERT_TRUE(written.is_good()) << to_string(written.status_code());

  // The write answers after its event was raised (NR-46).
  const auto raised = changes();
  ASSERT_EQ(raised.size(), 1u) << "the NodeVersion written through the accessor raised no event";
  EXPECT_EQ(raised[0].kind, detail::AddressSpaceChangeKind::Model);
  EXPECT_TRUE(raised[0].unspecified) << "the event is not a BaseModelChangeEvent";
}

// DL-115 (6), NR-36 rule 2, NR-63 rule 2: whether a Node an operation created is listed as added is decided
// once every Reference of the operation is in place. Within one operation, as a NodeSet import split by
// maxNodesPerNodeManagement sends them, Declared's HasProperty to a Property named NodeVersion reaches the
// namespace in one call and that Property's HasModellingRule in a later one, which makes it an
// InstanceDeclaration (OrderedListType's NodeVersion in namespace 0 is one); the operation's event does not
// list Declared. The control is Versioned, whose NodeVersion Property gets no HasModellingRule, listed as
// added.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-CREATED-NODE-IS-LISTED-ONLY-WITH-ITS-OWN-NODEVERSION, scope=function)
TEST_F(ModelChangeReports, AnOperationDoesNotListANodeWhoseNodeVersionBecomesADeclarationInALaterCall)
{
  const NodeId declared{mIndex, "Declared"};
  const NodeId versioned{mIndex, "Versioned"};
  const NodeId declaredVersion{mIndex, "Declared.NodeVersion"};
  const NodeId versionedVersion{mIndex, "Versioned.NodeVersion"};
  for (const auto& id : {declared, versioned})
  {
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::ObjectType, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    created.value().set_browse_name(QualifiedName{mIndex, id.identifier().get_string()});
  }
  for (const auto& id : {declaredVersion, versionedVersion})
  {
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::Variable, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    auto property = std::move(created).value();
    property.set_browse_name(QualifiedName{0, "NodeVersion"});
    auto variable = property.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::String});
  }
  clear_changes();

  const auto step = ::ua::detail::NodeAccessorRoute::model_change_step(mAddressSpace->weak());
  ASSERT_NE(step, nullptr);
  const auto send = [this, &step](std::vector<ReferenceChange> changes)
  {
    std::promise<std::vector<VoidResult>> answered;
    auto future = answered.get_future();
    ::ua::detail::NodeAccessorRoute::add_references(
      mAddressSpace->weak(),
      RequestInfo{},
      std::make_shared<const std::vector<ReferenceChange>>(std::move(changes)),
      [&answered](std::vector<VoidResult> answers) { answered.set_value(std::move(answers)); },
      /*addRequiredPairs=*/false,
      step);
    EXPECT_EQ(future.wait_for(10s), std::future_status::ready);
    for (const auto& answer : future.get())
    {
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
    }
  };
  const NodeId hasProperty{ReferenceTypeId::HasProperty};
  send({ReferenceChange{declared, hasProperty, ExpandedNodeId{declaredVersion}, true, true},
    ReferenceChange{versioned, hasProperty, ExpandedNodeId{versionedVersion}, true, true}});
  send({ReferenceChange{declaredVersion,
    NodeId{ReferenceTypeId::HasModellingRule},
    ExpandedNodeId{NodeId{ObjectId::ModellingRule_Optional}},
    true,
    true}});
  std::promise<void> closed;
  auto closedFuture = closed.get_future();
  step->close([&closed] { closed.set_value(); });
  ASSERT_EQ(closedFuture.wait_for(10s), std::future_status::ready);

  // The step's done runs after its event was raised.
  const auto raised = changes();
  ASSERT_EQ(raised.size(), 1u) << "the operation raised no event, or more than one";
  EXPECT_EQ(raised[0].kind, detail::AddressSpaceChangeKind::Model);
  EXPECT_FALSE(raised[0].unspecified);
  bool listsVersioned = false;
  for (const auto& entry : raised[0].changes)
  {
    EXPECT_NE(entry.affected, declared)
      << "the event lists a Node whose NodeVersion is an InstanceDeclaration";
    if (entry.affected == versioned)
    {
      listsVersioned = true;
      EXPECT_NE(entry.verbs & verb(ModelChangeStructureVerbMask::NodeAdded), 0)
        << "the Node with a NodeVersion of its own is not listed as added";
    }
  }
  EXPECT_TRUE(listsVersioned) << "the Node with a NodeVersion of its own is not listed";
}

// NR-63: loading namespace 0 creates OrderedListType and its NodeVersion InstanceDeclaration in one
// operation, so no version is advanced and the static declaration keeps the Value its NodeSet gives it, which
// is none.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-NAMESPACE-ZERO-LOAD-ADVANCES-NOTHING, scope=function)
TEST(NamespaceZeroLoad, LeavesTheStaticNodeVersionDeclarationUnchanged)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:namespace-zero-load", pool.get_executor());
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    StructureFactory structureFactory;
    const CodecNamespaceContext codec{
      namespace_array_utils::get_index_lookup_function(addressSpace), {}, {}, {}};
    register_ua_data_types_with_factory(codec, &structureFactory, &structureFactory);
    FileStream input{"NodeSet2.xml"};
    input.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(limits,
      input,
      structureFactory,
      addressSpace.namespace_array(),
      addressSpace.server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    xml::nodeset::ImportEngine::create(limits, addressSpace, nodeSets, {})->import_all_sync({}, {});

    auto node = addressSpace.try_find_node_sync(NodeId{VariableId::OrderedListType_NodeVersion});
    ASSERT_TRUE(node.is_good()) << to_string(node.status_code());
    auto variable = node.value().as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    const auto value = variable->try_read_value_sync();
    ASSERT_TRUE(value.is_good()) << to_string(value.status_code());
    EXPECT_TRUE(value.value().value().empty())
      << "the static NodeVersion declaration holds " << to_string(value.value().value());
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

}  // namespace
