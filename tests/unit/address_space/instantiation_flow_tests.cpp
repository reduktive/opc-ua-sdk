// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// An instantiation plans its members first and then creates, links and fills them in one batch each (NR-31,
// NR-70 B7c), holds its address space weakly (COMP-SVR-NAMESPACE-CALLS-21), and refuses an Uncertain answer
// to the lookup that decides a member (COMP-SVR-STATUS-ROUTING-02).
//
// The parent lives in a namespace that records each call the instantiation makes and otherwise behaves as the
// in-memory namespace.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

#include "instantiation/ua_instantiation_service.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_attribute_wire.h"
#include "ua_data_type_registration.h"
#include "ua_datatype_id.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_namespace_route.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <tuple>
#include <vector>

using namespace ua;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

using namespace std::chrono_literals;

class InstantiationFlow : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mThreadPool.get_executor()));
    mA =
      std::make_shared<BatchRecordingNamespace>("urn:test:instantiation-flow:a", mThreadPool.get_executor());
    auto added = mAddressSpace->try_add_namespace_sync(mA);
    ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
    mIndexA = added.value();
    load_namespace_zero();
    auto parent = mAddressSpace->try_create_node_sync(parent_id(), NodeClass::Object, {});
    ASSERT_TRUE(parent.is_good()) << to_string(parent.status_code());
    mA->reset();
  }

  void TearDown() override
  {
    mA.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void load_namespace_zero()
  {
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    auto lookup = namespace_array_utils::get_index_lookup_function(*mAddressSpace);
    const CodecNamespaceContext context{std::move(lookup), {}, {}, {}};
    register_ua_data_types_with_factory(context, &mStructureFactory, &mStructureFactory);
    FileStream input{"NodeSet2.xml"};
    input.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(limits,
      input,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = xml::nodeset::ImportEngine::create(limits, *mAddressSpace, nodeSets, {});
    importer->import_all_sync({}, {});
  }

  NodeId parent_id() const
  {
    return NodeId{mIndexA, String{"P"}};
  }

  /// Starts an instantiation, and answers a future of its result.
  template<typename Start>
  static std::future<NodeSubtreeResult> started(Start&& start)
  {
    auto answered = std::make_shared<std::promise<NodeSubtreeResult>>();
    auto future = answered->get_future();
    start([answered](NodeSubtreeResult result) { answered->set_value(std::move(result)); });
    return future;
  }

  static NodeSubtreeResult answer_of(std::future<NodeSubtreeResult>& future)
  {
    if (future.wait_for(30s) != std::future_status::ready)
    {
      return NodeSubtreeResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }

  /// An AggregateConfigurationType instance under P: the root and its four Mandatory Properties.
  NodeSubtreeResult instantiate_aggregate_configuration()
  {
    const InstantiationService service{*mAddressSpace};
    auto future = started(
      [&](auto complete)
      {
        service.instantiate_object_async(parent_id(),
          QualifiedName{mIndexA, "Configuration"},
          NodeId{ObjectTypeId::AggregateConfigurationType},
          InstantiationOptions{},
          std::move(complete));
      });
    return answer_of(future);
  }

  static const Variant* attribute_of(const NodeCreation& creation, AttributeId attributeId)
  {
    const auto found = std::find_if(creation.attributes.begin(),
      creation.attributes.end(),
      [attributeId](const InitialAttribute& attribute) { return attribute.first == attributeId; });
    return found == creation.attributes.end() ? nullptr : &found->second;
  }

  boost::asio::thread_pool mThreadPool{2};
  StructureFactory mStructureFactory;
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<BatchRecordingNamespace> mA;
  uint16_t mIndexA{0};
};

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-05-THE-ROOT-IS-CREATED-WITH-ITS-ATTRIBUTES, scope=function)
TEST_F(InstantiationFlow, TheRootIsCreatedWithItsDataTypeValueRankAndAccessLevel)
{
  VariableInstantiationAttributes attributes;
  attributes.dataType = NodeId{DataTypeId::Double};
  attributes.valueRank = -1;
  attributes.accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead};
  const InstantiationService service{*mAddressSpace};
  auto future = started(
    [&](auto complete)
    {
      service.instantiate_variable_async(parent_id(),
        QualifiedName{mIndexA, "Level"},
        NodeId{VariableTypeId::BaseDataVariableType},
        InstantiationOptions{},
        attributes,
        std::move(complete));
    });
  auto instantiated = answer_of(future);
  ASSERT_TRUE(instantiated.is_good()) << to_string(instantiated.status_code());

  const auto creates = mA->calls(Member::CreateNodes);
  ASSERT_EQ(creates.size(), 1u);
  ASSERT_FALSE(creates.front().creations.empty());
  const NodeCreation& root = creates.front().creations.front();
  EXPECT_EQ(root.nodeId, instantiated.value().root());
  EXPECT_EQ(root.nodeClass, NodeClass::Variable);
  const Variant* dataType = attribute_of(root, AttributeId::DataType);
  const Variant* valueRank = attribute_of(root, AttributeId::ValueRank);
  const Variant* accessLevel = attribute_of(root, AttributeId::AccessLevel);
  ASSERT_NE(dataType, nullptr);
  ASSERT_NE(valueRank, nullptr);
  ASSERT_NE(accessLevel, nullptr);
  EXPECT_EQ(*dataType, attribute_wire::data_type(NodeId{DataTypeId::Double}));
  EXPECT_EQ(*valueRank, attribute_wire::value_rank(ValueRank{-1}));
  EXPECT_EQ(*accessLevel, attribute_wire::access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead}));
  for (const auto& write : mA->calls(Member::Write))
  {
    EXPECT_EQ(std::count(write.nodeIds.begin(), write.nodeIds.end(), root.nodeId), 0)
      << "an attribute of the root was written after its creation";
  }
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-05-ONE-CALL-PER-PHASE, scope=function)
TEST_F(InstantiationFlow, AnInstanceAndItsMembersAreOneCallPerPhase)
{
  auto instantiated = instantiate_aggregate_configuration();
  ASSERT_TRUE(instantiated.is_good()) << to_string(instantiated.status_code());

  const auto creates = mA->calls(Member::CreateNodes);
  ASSERT_EQ(creates.size(), 1u);
  EXPECT_EQ(creates.front().creations.size(), 5u) << "the root and its four Mandatory Properties";
  EXPECT_EQ(creates.front().nodeIds.front(), instantiated.value().root());
  EXPECT_EQ(mA->calls(Member::AddReferences).size(), 1u);
  EXPECT_LE(mA->calls(Member::Write).size(), 1u);
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-05-A-RELEASED-ADDRESS-SPACE-ANSWERS-ADDRESS-SPACE-GONE, scope=function)
TEST_F(InstantiationFlow, AnInstantiationWhoseAddressSpaceIsReleasedAnswersAddressSpaceGone)
{
  mA->hold_lookups_of({parent_id()});
  std::future<NodeSubtreeResult> future;
  {
    const InstantiationService service{*mAddressSpace};
    future = started(
      [&](auto complete)
      {
        service.instantiate_object_async(parent_id(),
          QualifiedName{mIndexA, "Configuration"},
          NodeId{ObjectTypeId::AggregateConfigurationType},
          InstantiationOptions{},
          std::move(complete));
      });
  }
  ASSERT_TRUE(mA->wait_for_held_lookups(1, 10s));
  // The turn that asked for the held lookup keeps the address space locked until find_node_async returns,
  // which can be after the hold is recorded. Release the lookup only once nothing holds the address space,
  // or the continuation finds it alive and rightly carries on.
  const WeakAddressSpace handle = mAddressSpace->weak();
  mAddressSpace.reset();
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (handle.lock() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_FALSE(handle.lock().has_value()) << "the held parent lookup keeps the address space";
  mA->release_held_lookups();

  const auto answered = answer_of(future);
  EXPECT_EQ(answered.status_code().as_status(), Status::BadShutdown) << to_string(answered.status_code());
  EXPECT_TRUE(::ua::detail::is_address_space_gone(answered.status_code()))
    << to_string(answered.status_code());
  EXPECT_TRUE(mA->calls(Member::CreateNodes).empty()) << "nothing is created once the address space is gone";
}

// CALLS-21 rule 1: a type's member reached through a ReferenceType of an application namespace is decided by
// walking that ReferenceType, and the walk keeps no address space while its namespace holds the lookup.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-05-A-HELD-MEMBER-REFERENCE-TYPE-LOOKUP-KEEPS-NO-ADDRESS-SPACE, scope=function)
TEST_F(InstantiationFlow, AHeldMemberReferenceTypeLookupKeepsNoAddressSpace)
{
  const NodeId type{mIndexA, String{"T"}};
  const NodeId component{mIndexA, String{"R"}};
  const NodeId member{mIndexA, String{"M"}};
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  auto created = mAddressSpace->try_create_node_sync(type, NodeClass::ObjectType, {});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  created.value().set_browse_name(QualifiedName{mIndexA, "T"});
  ASSERT_TRUE(
    created.value()
      .try_add_reference_sync(hasSubtype, ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}}, false)
      .is_good());
  auto reference = mAddressSpace->try_create_node_sync(component, NodeClass::ReferenceType, {});
  ASSERT_TRUE(reference.is_good()) << to_string(reference.status_code());
  reference.value().set_browse_name(QualifiedName{mIndexA, "R"});
  ASSERT_TRUE(
    reference.value()
      .try_add_reference_sync(hasSubtype, ExpandedNodeId{NodeId{ReferenceTypeId::HasComponent}}, false)
      .is_good());
  auto declared = mAddressSpace->try_create_node_sync(member, NodeClass::Object, {});
  ASSERT_TRUE(declared.is_good()) << to_string(declared.status_code());
  declared.value().set_browse_name(QualifiedName{mIndexA, "M"});
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}})
                .is_good());
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
                  ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}})
                .is_good());
  ASSERT_TRUE(created.value().try_add_reference_sync(component, ExpandedNodeId{member}).is_good());
  mA->hold_lookups_of({component});

  std::future<NodeSubtreeResult> future;
  {
    const InstantiationService service{*mAddressSpace};
    future = started(
      [&](auto complete)
      {
        service.instantiate_object_async(
          parent_id(), QualifiedName{mIndexA, "Instance"}, type, InstantiationOptions{}, std::move(complete));
      });
  }
  ASSERT_TRUE(mA->wait_for_held_lookups(1, 10s)) << "the instantiation did not look up the ReferenceType";
  const WeakAddressSpace handle = mAddressSpace->weak();
  mAddressSpace.reset();
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (handle.lock() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }
  EXPECT_FALSE(handle.lock().has_value()) << "the held ReferenceType lookup keeps the address space";
  mA->release_held_lookups();
  const auto answered = answer_of(future);
  EXPECT_TRUE(answered.is_bad()) << to_string(answered.status_code());
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-05-A-NODE-SUBTREE-DOES-NOT-KEEP-ITS-ADDRESS-SPACE, scope=function)
TEST_F(InstantiationFlow, ANodeSubtreeDoesNotKeepItsAddressSpace)
{
  std::optional<NodeSubtreeResult> instantiated{instantiate_aggregate_configuration()};
  ASSERT_TRUE(instantiated->is_good()) << to_string(instantiated->status_code());
  const WeakAddressSpace handle = mAddressSpace->weak();

  mAddressSpace.reset();
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (handle.lock() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }
  EXPECT_FALSE(handle.lock().has_value()) << "the NodeSubtree keeps its address space alive";
  // Releasing the subtree once its address space is gone removes nothing and does not fail.
  instantiated.reset();
}

// A type's member reached through a ReferenceType of an application namespace is decided by walking that
// ReferenceType. When the namespace answers the walk's lookup of it Uncertain, the instantiation is answered
// once, with the refusal, and creates nothing; answered Good, the same instantiation creates the member.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(InstantiationFlow, AnUncertainMemberReferenceTypeLookupRefusesTheInstantiationOnce)
{
  const NodeId type{mIndexA, String{"T"}};
  const NodeId component{mIndexA, String{"R"}};
  const NodeId member{mIndexA, String{"M"}};
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  auto created = mAddressSpace->try_create_node_sync(type, NodeClass::ObjectType, {});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  created.value().set_browse_name(QualifiedName{mIndexA, "T"});
  ASSERT_TRUE(
    created.value()
      .try_add_reference_sync(hasSubtype, ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}}, false)
      .is_good());
  auto reference = mAddressSpace->try_create_node_sync(component, NodeClass::ReferenceType, {});
  ASSERT_TRUE(reference.is_good()) << to_string(reference.status_code());
  reference.value().set_browse_name(QualifiedName{mIndexA, "R"});
  ASSERT_TRUE(
    reference.value()
      .try_add_reference_sync(hasSubtype, ExpandedNodeId{NodeId{ReferenceTypeId::HasComponent}}, false)
      .is_good());
  auto declared = mAddressSpace->try_create_node_sync(member, NodeClass::Object, {});
  ASSERT_TRUE(declared.is_good()) << to_string(declared.status_code());
  declared.value().set_browse_name(QualifiedName{mIndexA, "M"});
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
                  ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}})
                .is_good());
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
                  ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}})
                .is_good());
  ASSERT_TRUE(created.value().try_add_reference_sync(component, ExpandedNodeId{member}).is_good());

  const InstantiationService service{*mAddressSpace};

  // Control: the namespace answers the lookup of R Good, and the member is created.
  mA->reset();
  auto controlFuture = started(
    [&](auto complete)
    {
      service.instantiate_object_async(
        parent_id(), QualifiedName{mIndexA, "Control"}, type, InstantiationOptions{}, std::move(complete));
    });
  const auto control = answer_of(controlFuture);
  ASSERT_TRUE(control.is_good()) << to_string(control.status_code());
  const auto controlCreates = mA->calls(Member::CreateNodes);
  ASSERT_EQ(controlCreates.size(), 1u);
  EXPECT_EQ(controlCreates.front().creations.size(), 2u) << "the root and its Mandatory member M";

  // The namespace answers the walk's lookup of R Uncertain, without the Node.
  mA->reset();
  mA->answer_lookup_of(component, StatusCode{Status::UncertainLastUsableValue});
  auto answers = std::make_shared<std::atomic<int>>(0);
  auto answered = std::make_shared<std::promise<NodeSubtreeResult>>();
  auto refusedFuture = answered->get_future();
  service.instantiate_object_async(parent_id(),
    QualifiedName{mIndexA, "Refused"},
    type,
    InstantiationOptions{},
    [answers, answered](NodeSubtreeResult result)
    {
      if (answers->fetch_add(1) == 0)
      {
        answered->set_value(std::move(result));
      }
    });
  ASSERT_EQ(refusedFuture.wait_for(30s), std::future_status::ready) << "the instantiation was never answered";
  const auto refused = refusedFuture.get();

  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError) << to_string(refused.status_code());
  const auto detail = refused.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "the refusal carries no ErrorDetail";
  EXPECT_EQ(detail->code, "LookupAnswerUncertain");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
    << "the cause is " << to_string(StatusCode{detail->innerStatus});

  // Nothing of the refused instance was created or linked.
  EXPECT_TRUE(mA->calls(Member::CreateNodes).empty()) << "a partial instance was created";
  EXPECT_TRUE(mA->calls(Member::AddReferences).empty()) << "a partial instance was linked";

  // Answered once: a round trip through the address space after the answer saw no second one.
  EXPECT_TRUE(mAddressSpace->try_find_node_sync(parent_id()).is_good());
  EXPECT_EQ(answers->load(), 1) << "the instantiation was answered more than once";
}

// Whether a member's declared type is abstract decides OPC 10000-3 6.2.1's rule for it, so when the namespace
// answers the lookup of that type Uncertain, the instantiation is refused and creates nothing; answered Good,
// the same instantiation creates the member with that type.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(InstantiationFlow, AnUncertainDeclaredMemberTypeLookupRefusesTheInstantiation)
{
  const NodeId type{mIndexA, String{"T"}};
  const NodeId memberType{mIndexA, String{"D"}};
  const NodeId member{mIndexA, String{"M"}};
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  for (const auto& [typeId, name] : {std::pair{type, "T"}, std::pair{memberType, "D"}})
  {
    auto created = mAddressSpace->try_create_node_sync(typeId, NodeClass::ObjectType, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    created.value().set_browse_name(QualifiedName{mIndexA, name});
    ASSERT_TRUE(
      created.value()
        .try_add_reference_sync(hasSubtype, ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}}, false)
        .is_good());
  }
  auto declared = mAddressSpace->try_create_node_sync(member, NodeClass::Object, {});
  ASSERT_TRUE(declared.is_good()) << to_string(declared.status_code());
  declared.value().set_browse_name(QualifiedName{mIndexA, "M"});
  ASSERT_TRUE(
    declared.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, ExpandedNodeId{memberType})
      .is_good());
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
                  ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}})
                .is_good());
  auto owner = mAddressSpace->try_find_node_sync(type);
  ASSERT_TRUE(owner.is_good()) << to_string(owner.status_code());
  ASSERT_TRUE(owner.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{member})
                .is_good());

  const InstantiationService service{*mAddressSpace};

  // Control: the namespace answers the lookup of D Good, and the member is created.
  mA->reset();
  auto controlFuture = started(
    [&](auto complete)
    {
      service.instantiate_object_async(
        parent_id(), QualifiedName{mIndexA, "Control"}, type, InstantiationOptions{}, std::move(complete));
    });
  const auto control = answer_of(controlFuture);
  ASSERT_TRUE(control.is_good()) << to_string(control.status_code());
  const auto controlCreates = mA->calls(Member::CreateNodes);
  ASSERT_EQ(controlCreates.size(), 1u);
  EXPECT_EQ(controlCreates.front().creations.size(), 2u) << "the root and its Mandatory member M";

  // The namespace answers the lookup of D Uncertain, without the Node.
  mA->reset();
  mA->answer_lookup_of(memberType, StatusCode{Status::UncertainLastUsableValue});
  auto refusedFuture = started(
    [&](auto complete)
    {
      service.instantiate_object_async(
        parent_id(), QualifiedName{mIndexA, "Refused"}, type, InstantiationOptions{}, std::move(complete));
    });
  const auto refused = answer_of(refusedFuture);

  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError) << to_string(refused.status_code());
  const auto detail = refused.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "the refusal carries no ErrorDetail";
  EXPECT_EQ(detail->code, "LookupAnswerUncertain");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
    << "the cause is " << to_string(StatusCode{detail->innerStatus});
  EXPECT_TRUE(mA->calls(Member::CreateNodes).empty()) << "a member was created with a type not decided on";
}

// A required Reference half the namespace answers Uncertain is not stood on: the instantiation is refused
// with Bad_InternalError (AnswerUncertain) whose cause is the namespace's code, not answered Good with its
// member Values and links skipped, and what it created is removed again.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(InstantiationFlow, AnUncertainRequiredReferenceAdditionRefusesTheInstantiation)
{
  // The member's inverse half to the instance, held by the member, is a required half.
  const NodeId root{mIndexA, String{"Refused.Configuration"}};
  const NodeId member{mIndexA, String{"Refused.TreatUncertainAsBad"}};
  InstantiationOptions options;
  options.nodeIdAllocator = [root, member](uint16_t namespaceIndex, const QualifiedName& browseName) -> NodeId
  {
    if (browseName.name() == "Configuration")
      return root;
    if (browseName.name() == "TreatUncertainAsBad")
      return member;
    static std::atomic<uint32_t> counter{960000};
    return NodeId{namespaceIndex, counter.fetch_add(1)};
  };
  mA->fail_reference_changes_of(member, StatusCode{Status::UncertainLastUsableValue});

  const InstantiationService service{*mAddressSpace};
  auto future = started(
    [&](auto complete)
    {
      service.instantiate_object_async(parent_id(),
        QualifiedName{mIndexA, "Configuration"},
        NodeId{ObjectTypeId::AggregateConfigurationType},
        options,
        std::move(complete));
    });
  const auto refused = answer_of(future);

  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError) << to_string(refused.status_code());
  const auto detail = refused.status_code().shared_detail();
  ASSERT_NE(detail, nullptr) << "the refusal carries no ErrorDetail";
  EXPECT_EQ(detail->code, "AnswerUncertain");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
    << "the cause is " << to_string(StatusCode{detail->innerStatus});

  // What the instantiation created is removed again.
  ASSERT_TRUE(mA->wait_for_calls(Member::DeleteNodes, 1, 10s)) << "the created subtree was not removed";
  bool rootDeleted = false;
  for (const auto& call : mA->calls(Member::DeleteNodes))
  {
    rootDeleted = rootDeleted || std::count(call.nodeIds.begin(), call.nodeIds.end(), root) > 0;
  }
  EXPECT_TRUE(rootDeleted) << "the instance's root was not deleted";
}

// What a type is decides OPC 10000-3 6.2.1's rules for the instance and its members: the root's type must be
// concrete, and a member declared with an abstract type takes the concrete subtype memberTypeResolver names,
// checked to be one. When the namespace answers the lookup of the named type, or of the root's type,
// Uncertain, the instantiation is refused and creates nothing; answered Good, the member takes the named
// type.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(InstantiationFlow, AnUncertainLookupOfANamedOrRootTypeRefusesTheInstantiation)
{
  const NodeId type{mIndexA, String{"T"}};
  const NodeId abstractType{mIndexA, String{"D"}};
  const NodeId namedType{mIndexA, String{"E"}};
  const NodeId member{mIndexA, String{"M"}};
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  for (const auto& [typeId, name, supertype] : {std::tuple{type, "T", NodeId{ObjectTypeId::BaseObjectType}},
         std::tuple{abstractType, "D", NodeId{ObjectTypeId::BaseObjectType}},
         std::tuple{namedType, "E", abstractType}})
  {
    auto created = mAddressSpace->try_create_node_sync(typeId, NodeClass::ObjectType, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    created.value().set_browse_name(QualifiedName{mIndexA, name});
    ASSERT_TRUE(
      created.value().try_add_reference_sync(hasSubtype, ExpandedNodeId{supertype}, false).is_good());
  }
  auto abstractAccessor = mAddressSpace->try_find_sync<ObjectTypeAccessor>(abstractType);
  ASSERT_TRUE(abstractAccessor.is_good()) << to_string(abstractAccessor.status_code());
  abstractAccessor.value().set_is_abstract(true);
  auto declared = mAddressSpace->try_create_node_sync(member, NodeClass::Object, {});
  ASSERT_TRUE(declared.is_good()) << to_string(declared.status_code());
  declared.value().set_browse_name(QualifiedName{mIndexA, "M"});
  ASSERT_TRUE(
    declared.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, ExpandedNodeId{abstractType})
      .is_good());
  ASSERT_TRUE(declared.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
                  ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}})
                .is_good());
  auto owner = mAddressSpace->try_find_node_sync(type);
  ASSERT_TRUE(owner.is_good()) << to_string(owner.status_code());
  ASSERT_TRUE(owner.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{member})
                .is_good());

  InstantiationOptions options;
  options.memberTypeResolver = [namedType](const ChildFilterInfo&) -> std::optional<NodeId>
  {
    return namedType;
  };
  const InstantiationService service{*mAddressSpace};
  const auto instantiate = [&](const NodeId& typeDefinition, const char* name)
  {
    auto future = started(
      [&](auto complete)
      {
        service.instantiate_object_async(
          parent_id(), QualifiedName{mIndexA, name}, typeDefinition, options, std::move(complete));
      });
    return answer_of(future);
  };
  const auto expectRefusalOf = [](const NodeSubtreeResult& refused, const NodeId& nodeId)
  {
    EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError)
      << to_string(refused.status_code());
    const auto detail = refused.status_code().shared_detail();
    ASSERT_NE(detail, nullptr) << "the refusal carries no ErrorDetail";
    EXPECT_EQ(detail->code, "LookupAnswerUncertain");
    EXPECT_EQ(detail->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
      << "the cause is " << to_string(StatusCode{detail->innerStatus});
    const bool named = std::any_of(detail->context.begin(),
      detail->context.end(),
      [&](const auto& fact)
      { return fact.key == ContextKeys::nodeId.value() && fact.value == to_string(nodeId); });
    EXPECT_TRUE(named) << "the refusal does not name " << to_string(nodeId);
  };

  // Control: the namespace answers the lookups Good, and the member is created with the named type.
  mA->reset();
  const auto control = instantiate(type, "Control");
  ASSERT_TRUE(control.is_good()) << to_string(control.status_code());
  const auto controlCreates = mA->calls(Member::CreateNodes);
  ASSERT_EQ(controlCreates.size(), 1u);
  EXPECT_EQ(controlCreates.front().creations.size(), 2u) << "the root and its Mandatory member M";

  // The lookup of the type the resolver names is answered Uncertain, without the Node.
  mA->reset();
  mA->answer_lookup_of(namedType, StatusCode{Status::UncertainLastUsableValue});
  {
    SCOPED_TRACE("the named type");
    expectRefusalOf(instantiate(type, "NamedRefused"), namedType);
    EXPECT_TRUE(mA->calls(Member::CreateNodes).empty()) << "a member was created with a type not decided on";
  }

  // The lookup of the root's own type is answered Uncertain.
  mA->reset();
  {
    SCOPED_TRACE("the root's type");
    expectRefusalOf(instantiate(namedType, "RootRefused"), namedType);
    EXPECT_TRUE(mA->calls(Member::CreateNodes).empty()) << "an instance was created of a type not decided on";
  }
}

}  // namespace
