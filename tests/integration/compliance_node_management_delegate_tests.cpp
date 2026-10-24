// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Runs the compliance_test_server's own NodeManagementDelegate against its own seeded address space - the
// CTT's Node Management Add Node unit exercises exactly this pair.

#include <gtest/gtest.h>

#include "address_space_seed.h"
#include "compliance_helpers.h"
#include "matchers.h"
#include "offloading_node_management_delegate.h"
#include "requests.h"
#include "ua_audit_delete_nodes_event_payload.h"
#include "ua_session_attribute_services.h"
#include "ua_session_node_management_services.h"
#include "node_management_delegate.h"
#include "scripted_referrer_namespace.h"
#include "ua_test_server.h"

#include "ua_add_nodes_item.h"
#include "ua_delete_nodes_item.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace_array.h"
#include "ua_node_class.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"
#include "ua_to_string.h"
#include "ua_base_event.h"
#include "ua_data_value.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_object_id.h"
#include "ua_range.h"
#include "ua_semantic_change_event_payload.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

namespace
{

using Delegate = ua::server::NodeManagementDelegate;

/// The seed writes its file-transfer fixtures into the working directory; keep them out of the build tree.
class ScopedWorkingDirectory
{
public:
  ScopedWorkingDirectory()
    : mPrevious{std::filesystem::current_path()},
      mDirectory{
        std::filesystem::temp_directory_path() / ("compliance_node_management_" + std::to_string(::getpid()))}
  {
    std::filesystem::create_directories(mDirectory);
    std::filesystem::current_path(mDirectory);
  }

  ~ScopedWorkingDirectory()
  {
    std::error_code ignored;
    std::filesystem::current_path(mPrevious, ignored);
    std::filesystem::remove_all(mDirectory, ignored);
  }

  ScopedWorkingDirectory(const ScopedWorkingDirectory&) = delete;
  ScopedWorkingDirectory& operator=(const ScopedWorkingDirectory&) = delete;

private:
  std::filesystem::path mPrevious;
  std::filesystem::path mDirectory;
};

class ComplianceServerNodeManagementDelegate : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();
    mSeed = std::make_unique<ua::compliance_test_server::AddressSpaceSeed>(
      mServer.server(), mSeedWorker.get_executor());
    mNamespaceIndex = mServer.server().address_space().namespace_array().get_namespace_index(
      std::string{ua::compliance_test_server::complianceNamespaceUri});
    mDelegate = std::make_shared<ua::compliance_test_server::ComplianceNodeManagementDelegate>();
  }

  void TearDown() override
  {
    mDelegate.reset();
    mSeed.reset();
    mSeedWorker.join();
  }

  /// A Variable under the seeded Surface folder, the CTT's NodeManagement RootNode.
  ua::AddNodesItem variable_item(const std::string& browseName, ua::NodeId requested = {}) const
  {
    ua::AddNodesItem item;
    item.parent_node_id() = ua::ExpandedNodeId{ua::NodeId{mNamespaceIndex, std::string{"Surface"}}};
    item.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
    item.requested_new_node_id() = ua::ExpandedNodeId{std::move(requested)};
    item.browse_name() = ua::QualifiedName{mNamespaceIndex, browseName};
    item.node_class() = ua::NodeClass::Variable;
    item.type_definition() = ua::ExpandedNodeId{ua::NodeId{ua::VariableTypeId::BaseDataVariableType}};
    return item;
  }

  ua::BatchResult<Delegate::PrepareAddNodesItemResult> prepare(std::vector<ua::AddNodesItem> items)
  {
    std::promise<ua::BatchResult<Delegate::PrepareAddNodesItemResult>> promise;
    mDelegate->prepare_add_nodes_async(std::make_shared<const Delegate::Context>(),
      mServer.server().address_space(),
      std::move(items),
      [&promise](auto result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  ua::BatchResult<Delegate::AddNodesItemResult> add(std::vector<ua::AddNodesItem> items)
  {
    std::vector<Delegate::AuthorizedAddNode> authorized;
    for (auto& item : items)
      authorized.push_back(
        Delegate::AuthorizedAddNode{std::move(item), Delegate::AddNodeDestination{mNamespaceIndex}});
    std::promise<ua::BatchResult<Delegate::AddNodesItemResult>> promise;
    mDelegate->add_nodes_async(std::make_shared<const Delegate::Context>(),
      mServer.server().address_space(),
      std::move(authorized),
      [&promise](auto result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  ScopedWorkingDirectory mWorkingDirectory;
  ua::test_helpers::TestServer mServer;
  boost::asio::thread_pool mSeedWorker{1};
  std::unique_ptr<ua::compliance_test_server::AddressSpaceSeed> mSeed;
  std::shared_ptr<ua::compliance_test_server::ComplianceNodeManagementDelegate> mDelegate;
  uint16_t mNamespaceIndex{0};
};

}  // namespace

// A node added without a requested NodeId gets one the server assigns, and it must not be one the namespace
// already holds. A private counter did exactly that against the seeded namespace: the CTT's Add Node 001
// failed Bad_NodeIdExists on an AddNodes that asked for no particular id.
TEST_F(ComplianceServerNodeManagementDelegate, ServerAssignedNodeIdsNeverCollideWithTheSeededNamespace)
{
  auto result = add({variable_item("Added1"), variable_item("Added2")});
  ASSERT_TRUE(result.batchStatus.is_good());
  ASSERT_EQ(result.items.size(), 2u);
  for (const auto& item : result.items)
  {
    ASSERT_TRUE(item.is_good()) << "0x" << std::hex << item.status_code().as_uint32();
    EXPECT_TRUE(item.value().status_code().is_good())
      << "0x" << std::hex << item.value().status_code().as_uint32();
  }
  EXPECT_NE(result.items[0].value().added_node_id(), result.items[1].value().added_node_id());
  EXPECT_EQ(result.items[0].value().added_node_id().namespace_index(), mNamespaceIndex);
}

namespace
{

/// Every Event the server emits, as its event listener receives it. The listener is removed on destruction.
///
/// The server may still deliver an Event to the listener after the capture is gone, because clearing the
/// listener is posted to the event bus's strand. The recorded state is therefore shared with the listener and
/// outlives the capture, and it is notified while its lock is held.
class EventCapture
{
public:
  explicit EventCapture(ua::server::Server& server) : mServer{server}, mState{std::make_shared<State>()}
  {
    mServer.set_event_listener(
      [state = mState](const ua::BaseEvent& event)
      {
        const std::lock_guard lock{state->mutex};
        state->events.push_back(std::shared_ptr<const ua::BaseEvent>{event.clone()});
        state->arrived.notify_all();
      });
  }

  ~EventCapture()
  {
    mServer.set_event_listener(nullptr);
  }

  EventCapture(const EventCapture&) = delete;
  EventCapture& operator=(const EventCapture&) = delete;

  /// The first Event of @p eventType for which @p wanted holds, waiting up to five seconds for it.
  std::shared_ptr<const ua::BaseEvent> wait_for(
    const ua::NodeId& eventType, const std::function<bool(const ua::BaseEvent&)>& wanted)
  {
    std::shared_ptr<const ua::BaseEvent> found;
    std::unique_lock lock{mState->mutex};
    mState->arrived.wait_for(lock,
      std::chrono::seconds{5},
      [&]
      {
        for (const auto& event : mState->events)
        {
          if (event->eventType == eventType && wanted(*event))
          {
            found = event;
            return true;
          }
        }
        return false;
      });
    return found;
  }

private:
  struct State
  {
    std::mutex mutex;
    std::condition_variable arrived;
    std::vector<std::shared_ptr<const ua::BaseEvent>> events;
  };

  ua::server::Server& mServer;
  std::shared_ptr<State> mState;
};

/// Whether @p changes, the Changes field of a model or semantic change Event, holds an entry of type @p Entry
/// whose Affected is @p node.
template<typename Entry>
bool changes_name(const ua::Variant& changes, const ua::NodeId& node)
{
  if (!changes.is_array())
    return false;
  for (const auto& element : changes.as<ua::Array<ua::RefStructure<ua::Structure>>>())
  {
    const auto* entry = dynamic_cast<const Entry*>(element.get());
    if (entry != nullptr && entry->affected() == node)
      return true;
  }
  return false;
}

}  // namespace

// Part 5 section 6.4.31: "The SourceName for Events of this type shall be the String part of the BrowseName
// of the View; for the whole AddressSpace it shall be "Server"." The compliance delegate reports the Nodes an
// AddNodes adds in a GeneralModelChangeEvent of the whole AddressSpace (NR-56 rules 1 and 2), so its
// SourceNode is the Server Object and its SourceName "Server". This fixture has no Session, so the Event is
// observed through the server's event listener; the Event is the one whose Changes name the added Node's
// parent, which the delegate versions (it gives the added Node no NodeVersion, so the Node is not listed).
// @relation(AC-SVR-EVT-TYP-014-SOURCENAME-SERVER, scope=function)
TEST_F(ComplianceServerNodeManagementDelegate, ItsModelChangeEventNamesTheServer)
{
  EventCapture capture{mServer.server()};
  auto result = add({variable_item("NamesTheServer")});
  ASSERT_TRUE(result.batchStatus.is_good());
  ASSERT_EQ(result.items.size(), 1u);
  ASSERT_TRUE(result.items[0].is_good()) << "0x" << std::hex << result.items[0].status_code().as_uint32();
  ASSERT_TRUE(result.items[0].value().status_code().is_good())
    << "0x" << std::hex << result.items[0].value().status_code().as_uint32();
  const ua::NodeId parent{mNamespaceIndex, std::string{"Surface"}};

  const auto reported = capture.wait_for(ua::NodeId{ua::ObjectTypeId::GeneralModelChangeEventType},
    [&parent](const ua::BaseEvent& event)
    {
      const auto* modelChange = dynamic_cast<const ua::GeneralModelChangeEventPayload*>(&event);
      return modelChange != nullptr &&
             changes_name<ua::ModelChangeStructureDataType>(modelChange->changes, parent);
    });
  ASSERT_NE(reported, nullptr) << "no GeneralModelChangeEvent names the added Node's parent";
  EXPECT_EQ(std::string{reported->sourceName}, "Server");
  EXPECT_EQ(reported->sourceNode, ua::NodeId{ua::ObjectId::Server});
}

// Part 5 section 6.4.33: the SourceName of a SemanticChangeEvent "shall be the String part of the BrowseName
// of the View, for the whole AddressSpace it shall be "Server"." The seed reports a write to the EURange
// Property of Surface.DataAccess.ProcessValue in a SemanticChangeEvent of the whole AddressSpace, whose
// SourceNode is the Server Object, so its SourceName is "Server". The write goes through the address space,
// as the Write service's does, and the Event is the one whose Changes name the AnalogItem.
// @relation(AC-SVR-EVT-TYP-017-SOURCENAME-SERVER, scope=function)
TEST_F(ComplianceServerNodeManagementDelegate, TheSeedsSemanticChangeEventNamesTheServer)
{
  const ua::NodeId analogItem{mNamespaceIndex, std::string{"Surface.DataAccess.ProcessValue"}};
  const ua::NodeId euRange{mNamespaceIndex, std::string{"Surface.DataAccess.ProcessValue.EURange"}};
  EventCapture capture{mServer.server()};

  ua::Range range;
  range.low() = 10.0;
  range.high() = 90.0;
  auto euRangeNode = mServer.server().address_space().try_find_node_sync(euRange);
  ASSERT_TRUE(euRangeNode.is_good())
    << "the seed holds no EURange Property at Surface.DataAccess.ProcessValue";
  auto euRangeVariable = euRangeNode.value().as<ua::VariableAccessor>();
  ASSERT_TRUE(euRangeVariable.has_value());
  const auto written = euRangeVariable->try_write_value_sync(ua::DataValue{ua::Variant{range}});
  ASSERT_TRUE(written.is_good()) << "0x" << std::hex << written.status_code().as_uint32();

  const auto reported = capture.wait_for(ua::NodeId{ua::ObjectTypeId::SemanticChangeEventType},
    [&analogItem](const ua::BaseEvent& event)
    {
      const auto* semanticChange = dynamic_cast<const ua::SemanticChangeEventPayload*>(&event);
      return semanticChange != nullptr &&
             changes_name<ua::SemanticChangeStructureDataType>(semanticChange->changes, analogItem);
    });
  ASSERT_NE(reported, nullptr) << "no SemanticChangeEvent names Surface.DataAccess.ProcessValue";
  EXPECT_EQ(std::string{reported->sourceName}, "Server");
  EXPECT_EQ(reported->sourceNode, ua::NodeId{ua::ObjectId::Server});
}

// Part 4 5.7.2: a requested NodeId the server cannot use is rejected with Bad_NodeIdRejected. Clients add
// nodes only to the compliance namespace, so an id in namespace 0 or the server's own namespace 1 is one it
// cannot use - whatever the user's rights - and a null or compliance-namespace id is routed as asked.
TEST_F(ComplianceServerNodeManagementDelegate, ARequestedNodeIdOutsideTheComplianceNamespaceIsRejected)
{
  auto prepared = prepare({variable_item("InNs0", ua::NodeId{0, uint32_t{900001}}),
    variable_item("InNs1", ua::NodeId{1, std::string{"string001"}}),
    variable_item("InCompliance", ua::NodeId{mNamespaceIndex, std::string{"string001"}}),
    variable_item("Unrequested")});
  ASSERT_TRUE(prepared.batchStatus.is_good());
  ASSERT_EQ(prepared.items.size(), 4u);
  EXPECT_EQ(prepared.items[0].status_code(), ua::StatusCode{ua::Status::BadNodeIdRejected});
  EXPECT_EQ(prepared.items[1].status_code(), ua::StatusCode{ua::Status::BadNodeIdRejected});
  ASSERT_TRUE(prepared.items[2].is_good());
  EXPECT_EQ(prepared.items[2].value().namespaceIndex, mNamespaceIndex);
  ASSERT_TRUE(prepared.items[3].is_good());
  EXPECT_EQ(prepared.items[3].value().namespaceIndex, mNamespaceIndex) << "the parent's namespace";
}

namespace
{

/// The compliance delegate installed as the server's NodeManagementDelegate over the seeded address space,
/// with a test namespace B registered beside the compliance namespace whose Nodes hold References to the
/// Nodes deleted, auditing enabled, and a Client Session through which DeleteNodes and the Reads are sent.
class ComplianceServerDeleteNodes : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithSession::configure_server_config(cfg);
    cfg.auditingEnabled = true;
  }

  // B is registered before the seed runs, so that the seeded Nodes it refers to are created after it.
  void configure_server() override
  {
    mNamespaceB = ua::test::ScriptedReferrerNamespace::create(
      "urn:test:delete-nodes:b", mServer.thread_pool().get_executor());
    auto index = mServer.server().address_space().try_add_namespace_sync(mNamespaceB);
    ASSERT_TRUE(index.is_good()) << ua::to_string(index.status_code()) << " "
                                 << (index.shared_detail() ? ua::to_string(*index.shared_detail())
                                                           : std::string{});
    mIndexB = index.value();
    mSeed = std::make_unique<ua::compliance_test_server::AddressSpaceSeed>(
      mServer.server(), mSeedWorker.get_executor());
    mNamespaceIndex = mServer.server().address_space().namespace_array().get_namespace_index(
      std::string{ua::compliance_test_server::complianceNamespaceUri});
    mDelegate = std::make_shared<ua::compliance_test_server::ComplianceNodeManagementDelegate>();
    mServer.server().set_node_management_delegate(ua::test::offloaded(mDelegate));
  }

  void TearDown() override
  {
    ComplianceWithSession::TearDown();
    if (mNamespaceB)
    {
      mNamespaceB->release_everything();
    }
    mDelegate.reset();
    mSeed.reset();
    mSeedWorker.join();
  }

  void create_object(const ua::NodeId& nodeId)
  {
    auto created = mServer.server().address_space().try_create_node_sync(nodeId, ua::NodeClass::Object, {});
    ASSERT_TRUE(created.is_good()) << ua::to_string(nodeId) << ": " << ua::to_string(created.status_code());
  }

  /// @p referrer holds an Organizes Reference to @p target, both halves added through the address space.
  void organizes(const ua::NodeId& referrer, const ua::NodeId& target)
  {
    auto addressSpace = mServer.server().address_space();
    auto referrerNode = addressSpace.try_find_node_sync(referrer);
    ASSERT_TRUE(referrerNode.is_good());
    auto targetNode = addressSpace.try_find_node_sync(target);
    ASSERT_TRUE(targetNode.is_good());
    const ua::NodeId organizesType{ua::ReferenceTypeId::Organizes};
    ASSERT_TRUE(
      referrerNode.value().try_add_reference_sync(organizesType, ua::ExpandedNodeId{target}, true).is_good());
    ASSERT_TRUE(targetNode.value()
                  .try_add_reference_sync(organizesType, ua::ExpandedNodeId{referrer}, false)
                  .is_good());
  }

  /// Sends one DeleteNodes request from the Session, each item with deleteTargetReferences TRUE, and answers
  /// the status of each item.
  std::vector<ua::Status> delete_through_session(std::initializer_list<ua::NodeId> nodeIds)
  {
    std::vector<ua::Status> statuses;
    auto deleted =
      mSession->node_management().try_delete_nodes_sync(ua::test_helpers::delete_nodes(nodeIds, true));
    EXPECT_THAT(deleted, Good());
    if (deleted.is_bad())
      return statuses;
    for (const auto& result : deleted.value().results())
      statuses.push_back(ua::StatusCode{result}.as_status());
    return statuses;
  }

  /// The status of a Read of @p nodeId's NodeClass from the Session.
  ua::Status read_node_class(const ua::NodeId& nodeId)
  {
    auto read =
      mSession->attributes().try_read_sync(ua::test_helpers::read_value(nodeId, ua::AttributeId::NodeClass));
    EXPECT_THAT(read, Good());
    if (read.is_bad() || read.value().results().size() != 1u)
      return ua::Status::BadInternalError;
    const auto& status = read.value().results()[0].status();
    return status ? status->as_status() : ua::Status::Good;
  }

  ScopedWorkingDirectory mWorkingDirectory;
  boost::asio::thread_pool mSeedWorker{1};
  std::unique_ptr<ua::compliance_test_server::AddressSpaceSeed> mSeed;
  std::shared_ptr<ua::compliance_test_server::ComplianceNodeManagementDelegate> mDelegate;
  uint16_t mNamespaceIndex{0};
  std::shared_ptr<ua::test::ScriptedReferrerNamespace> mNamespaceB;
  uint16_t mIndexB{0};
};

}  // namespace

// N and M have no forward hierarchical References: the compliance delegate passes deleteTargetReferences as
// the SDK's subtree flag, so a Node with children would be deleted with them. The request and the Reads go
// through a Client Session, so the DeleteNodes service puts the delegate's item results into the response.
// @relation(AC-SVR-NM-DN-024-SDK-DELETE-REPORTS-REFERENCE-LEFT-BEHIND, scope=function)
TEST_F(ComplianceServerDeleteNodes, AReferenceLeftInAnotherNamespaceAnswersUncertainReferenceNotDeleted)
{
  const ua::NodeId n{mNamespaceIndex, std::string{"DeleteNodesReferencedN"}};
  const ua::NodeId m{mNamespaceIndex, std::string{"DeleteNodesReferencedM"}};
  const ua::NodeId r{mIndexB, std::string{"R"}};
  const ua::NodeId referrerS{mIndexB, std::string{"S"}};
  for (const auto& nodeId : {n, m, r, referrerS})
  {
    create_object(nodeId);
  }
  organizes(r, n);
  organizes(referrerS, m);
  mNamespaceB->answer_removals(r, ua::StatusCode{ua::Status::BadInternalError});

  const auto items = delete_through_session({n, m});
  ASSERT_EQ(items.size(), 2u);
  EXPECT_EQ(items[0], ua::Status::UncertainReferenceNotDeleted)
    << "the item for N answered " << ua::to_string(ua::StatusCode{items[0]});
  EXPECT_EQ(items[1], ua::Status::Good)
    << "the item for M answered " << ua::to_string(ua::StatusCode{items[1]});

  EXPECT_EQ(read_node_class(n), ua::Status::BadNodeIdUnknown) << "N was not deleted";
  EXPECT_EQ(read_node_class(m), ua::Status::BadNodeIdUnknown) << "M was not deleted";
}

// Part 5 section 6.4.3: Status "identifies whether the requested action could be performed". A Node deleted
// with a Reference left behind was deleted, so a request with no Bad item is audited with Status TRUE; a
// request with a Bad item, alone or beside an Uncertain one, with Status FALSE (DL-48). Each request's Event
// is told apart by the NodeIds it deletes.
// @relation(AC-SVR-EVT-AUD-014-DELETENODES-REFERENCE-LEFT-BEHIND-AUDITED-AS-PERFORMED, scope=function)
TEST_F(ComplianceServerDeleteNodes, ADeleteThatLeavesAReferenceBehindIsAuditedAsPerformed)
{
  const ua::NodeId n{mNamespaceIndex, std::string{"DeleteNodesAuditN"}};
  const ua::NodeId m{mNamespaceIndex, std::string{"DeleteNodesAuditM"}};
  const ua::NodeId q{mNamespaceIndex, std::string{"DeleteNodesAuditQ"}};
  const ua::NodeId missing{mNamespaceIndex, std::string{"DeleteNodesAuditNoSuchNode"}};
  const ua::NodeId missingBesideQ{mNamespaceIndex, std::string{"DeleteNodesAuditNoSuchNodeBesideQ"}};
  const ua::NodeId r{mIndexB, std::string{"R"}};
  const ua::NodeId referrerS{mIndexB, std::string{"S"}};
  const ua::NodeId r2{mIndexB, std::string{"R2"}};
  for (const auto& nodeId : {n, m, q, r, referrerS, r2})
  {
    create_object(nodeId);
  }
  organizes(r, n);
  organizes(referrerS, m);
  organizes(r2, q);
  mNamespaceB->answer_removals(r, ua::StatusCode{ua::Status::BadInternalError});
  mNamespaceB->answer_removals(r2, ua::StatusCode{ua::Status::BadInternalError});
  EventCapture capture{mServer.server()};
  const ua::NodeId auditDeleteNodes{ua::ObjectTypeId::AuditDeleteNodesEventType};
  // The audit Event whose NodesToDelete names @p first.
  const auto auditFor = [&capture, &auditDeleteNodes](const ua::NodeId& first)
  {
    return std::dynamic_pointer_cast<const ua::AuditDeleteNodesEventPayload>(
      capture.wait_for(auditDeleteNodes,
        [&first](const ua::BaseEvent& event)
        {
          const auto* audit = dynamic_cast<const ua::AuditDeleteNodesEventPayload*>(&event);
          if (audit == nullptr || !audit->nodesToDelete.is_array())
            return false;
          for (const auto& element : audit->nodesToDelete.as<ua::Array<ua::RefStructure<ua::Structure>>>())
          {
            const auto* item = dynamic_cast<const ua::DeleteNodesItem*>(element.get());
            if (item != nullptr && item->node_id() == first)
              return true;
          }
          return false;
        }));
  };

  const auto performed = delete_through_session({n, m});
  ASSERT_EQ(performed.size(), 2u);
  EXPECT_EQ(performed[0], ua::Status::UncertainReferenceNotDeleted)
    << "the item for N answered " << ua::to_string(ua::StatusCode{performed[0]});
  EXPECT_EQ(performed[1], ua::Status::Good)
    << "the item for M answered " << ua::to_string(ua::StatusCode{performed[1]});
  const auto performedAudit = auditFor(n);
  ASSERT_NE(performedAudit, nullptr) << "no AuditDeleteNodesEvent names N";
  EXPECT_TRUE(performedAudit->status) << "a request with no Bad item was audited with Status FALSE";

  const auto refused = delete_through_session({missing});
  ASSERT_EQ(refused.size(), 1u);
  EXPECT_EQ(refused[0], ua::Status::BadNodeIdUnknown) << ua::to_string(ua::StatusCode{refused[0]});
  const auto refusedAudit = auditFor(missing);
  ASSERT_NE(refusedAudit, nullptr) << "no AuditDeleteNodesEvent names the NodeId no Node has";
  EXPECT_FALSE(refusedAudit->status) << "a request whose only item is Bad was audited with Status TRUE";

  const auto mixed = delete_through_session({q, missingBesideQ});
  ASSERT_EQ(mixed.size(), 2u);
  EXPECT_EQ(mixed[0], ua::Status::UncertainReferenceNotDeleted)
    << "the item for Q answered " << ua::to_string(ua::StatusCode{mixed[0]});
  EXPECT_EQ(mixed[1], ua::Status::BadNodeIdUnknown) << ua::to_string(ua::StatusCode{mixed[1]});
  const auto mixedAudit = auditFor(q);
  ASSERT_NE(mixedAudit, nullptr) << "no AuditDeleteNodesEvent names Q";
  EXPECT_FALSE(mixedAudit->status)
    << "a request with an Uncertain item and a Bad item was audited with Status TRUE";
}
