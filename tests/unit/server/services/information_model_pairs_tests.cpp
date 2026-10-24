// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"
#include "ua_access_level_type.h"
#include "ua_attribute_service_set.h"
#include "ua_datatype_id.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_status.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_information_model_pairs.h"
#include "ua_default_namespace.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_ref_structure.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;
using namespace ua;
using namespace ua::server;

namespace
{

class InformationModelWriteInterceptorTests : public ::testing::Test
{
protected:
  InformationModelWriteInterceptorTests()
    : mAddressSpace(AddressSpace::create("urn:test:information-model-write", mThreadPool.get_executor()))
  {
    auto owner = mAddressSpace.create_node_sync(mOwnerId, NodeClass::Variable);
    owner.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::SelectionListType});

    add_property(mOwnerId, mSelectionsId, "Selections", Array<int32_t>{1, 2, 3});
    add_property(mOwnerId,
      mDescriptionsId,
      "SelectionDescriptions",
      Array<LocalizedText>{LocalizedText{"", "One"}, LocalizedText{"", "Two"}, LocalizedText{"", "Three"}});

    auto dictionaryOwner = mAddressSpace.create_node_sync(mDictionaryOwnerId, NodeClass::Variable);
    dictionaryOwner.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
      NodeId{VariableTypeId::MultiStateDictionaryEntryDiscreteBaseType});
    add_property(mDictionaryOwnerId, mEnumValuesId, "EnumValues", make_enum_values(3));
    add_property(mDictionaryOwnerId,
      mEnumDictionaryEntriesId,
      "EnumDictionaryEntries",
      Array<NodeId>{Dimensions{3, 2},
        {NodeId{1, uint32_t{7100}},
          NodeId{1, uint32_t{7101}},
          NodeId{1, uint32_t{7102}},
          NodeId{1, uint32_t{7103}},
          NodeId{1, uint32_t{7104}},
          NodeId{1, uint32_t{7105}}}});
  }

  void TearDown() override
  {
    mSessionInfo.reset();
    mService.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  static Array<RefStructure<Structure>> make_enum_values(std::size_t count)
  {
    Array<RefStructure<Structure>> values;
    for (std::size_t index = 0; index < count; ++index)
    {
      auto value = std::make_unique<EnumValueType>();
      value->value() = static_cast<int64_t>(index + 1U);
      values.push_back(RefStructure<Structure>{std::move(value)});
    }
    return values;
  }

  template<typename ArrayValue>
  void add_property(
    const NodeId& ownerId, const NodeId& propertyId, std::string_view browseName, ArrayValue value)
  {
    auto property = mAddressSpace.create_node_sync(propertyId, NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, browseName});
    property.as<VariableAccessor>()->write_value_sync(std::move(value));
    mAddressSpace.find_node_sync(ownerId).add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, propertyId);
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{ownerId}, /*isForward=*/false);
  }

  // The result of checking a whole-array Value write of @p proposedSize elements to @p nodeId.
  VoidResult check(const NodeId& nodeId, std::size_t proposedSize)
  {
    std::promise<VoidResult> completion;
    auto result = completion.get_future();
    check_information_model_pair_async(mAddressSpace,
      mAddressSpace.find_node_sync(nodeId),
      proposedSize,
      [&completion](VoidResult outcome) mutable { completion.set_value(std::move(outcome)); });
    if (result.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"the information-model pair check did not complete"};
    return result.get();
  }

  // The status the Write service answers for a write of @p attributeId to the Selections Property of a
  // SelectionList, on a server with the Data Access setting unset: the Property holds {1, 2, 3}.
  StatusCode write_selections_through_the_service(
    AttributeId attributeId, Variant value, std::string indexRange = {})
  {
    ServerConfig serverConfig;
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto server = Server::create(mThreadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    mService = std::make_shared<ua::test::BatchRecordingNamespace>(
      "urn:test:pairs-service", mThreadPool.get_executor());
    const auto index = server.address_space().add_namespace_sync(mService);
    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(server), mThreadPool.get_executor());
    auto address = mSessionInfo->address_space();

    const NodeId ownerId{index, uint32_t{7400}};
    const NodeId selectionsId{index, uint32_t{7401}};
    address.create_node_sync(ownerId, NodeClass::Variable)
      .add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::SelectionListType});
    auto property = address.create_node_sync(selectionsId, NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, "Selections"});
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    property.as<VariableAccessor>()->set_access_level(accessLevel);
    property.as<VariableAccessor>()->set_data_type(NodeId{DataTypeId::Int32});
    // It holds an array; an unset ValueRank reads as Scalar.
    property.as<VariableAccessor>()->set_value_rank(ValueRank{1});
    property.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::Description});
    property.as<VariableAccessor>()->write_value_sync(Array<int32_t>{1, 2, 3});
    address.find_node_sync(ownerId).add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, selectionsId);
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{ownerId}, /*isForward=*/false);

    WriteValue item;
    item.node_id() = selectionsId;
    item.attribute_id() = utils::to_underlying(attributeId);
    item.index_range() = String{indexRange};
    item.value().value() = std::move(value);
    WriteRequest request;
    request.request_header().request_handle() = 1;
    request.nodes_to_write().payload().push_back(std::move(item));

    auto promise = std::make_shared<std::promise<StatusCode>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(mSessionInfo,
      1,
      std::move(request),
      mThreadPool.get_executor(),
      [promise](Response response)
      {
        if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
            writeResponse != nullptr && writeResponse->results().size() == 1)
        {
          promise->set_value(writeResponse->results()[0]);
        }
        else
        {
          promise->set_value(StatusCode{Status::BadInternalError});
        }
      });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the Write did not complete";
      return StatusCode{Status::BadTimeout};
    }
    return future.get();
  }

  boost::asio::thread_pool mThreadPool{2};
  AddressSpace mAddressSpace;
  std::shared_ptr<SessionInfoStub> mSessionInfo;
  std::shared_ptr<ua::test::BatchRecordingNamespace> mService;
  const NodeId mOwnerId{1, uint32_t{7000}};
  const NodeId mSelectionsId{1, uint32_t{7001}};
  const NodeId mDescriptionsId{1, uint32_t{7002}};
  const NodeId mDictionaryOwnerId{1, uint32_t{7050}};
  const NodeId mEnumValuesId{1, uint32_t{7051}};
  const NodeId mEnumDictionaryEntriesId{1, uint32_t{7052}};
};

// Part 5 section 7.18 requires SelectionDescriptions to remain the same array size as Selections.
// Rejecting a service Write that changes either array's length preserves that standing invariant.
// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, LengthChangingSelectionsWriteIsRejectedWithRichDetail)
{
  const auto outcome = check(mSelectionsId, 2);

  ASSERT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code(), Status::BadOutOfRange);
  const auto detail = outcome.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "SelectionListArraySizeMismatch");
  EXPECT_EQ(detail->source, "InformationModelPairs");
  EXPECT_EQ(
    ::ua::test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), ua::to_string(mSelectionsId));
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeActual.value()), "2");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeExpected.value()), "3");
}

// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, SameLengthSelectionsWriteIsAccepted)
{
  EXPECT_TRUE(check(mSelectionsId, 3).is_good());
}

// Part 19 section 7.1: the first EnumDictionaryEntries dimension shall remain the same size as
// EnumValues. Refusing a Write that would break the standing invariant is the negative discharge.
// @relation(AC-SVR-DA-036-ENUMDICTIONARYENTRIES-SHAPE, scope=function)
TEST_F(InformationModelWriteInterceptorTests, EnumValuesLengthDivergingFromDictionaryRowsIsRejected)
{
  const auto outcome = check(mEnumValuesId, 4);

  ASSERT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code(), Status::BadOutOfRange);
  const auto detail = outcome.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "EnumDictionaryEntriesRowCountMismatch");
  EXPECT_EQ(detail->source, "InformationModelPairs");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeActual.value()), "4");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::sizeExpected.value()), "3");
}

// @relation(AC-SVR-DA-036-ENUMDICTIONARYENTRIES-SHAPE, scope=function)
TEST_F(InformationModelWriteInterceptorTests, EnumValuesLengthMatchingDictionaryRowsIsAccepted)
{
  EXPECT_TRUE(check(mEnumValuesId, 3).is_good());
}

// A flat table has lost the required two-dimensional structure and cannot justify accepting a
// potentially divergent EnumValues write.
// @relation(AC-SVR-DA-036-ENUMDICTIONARYENTRIES-SHAPE, scope=function)
TEST_F(InformationModelWriteInterceptorTests, FlatEnumDictionaryEntriesTableFailsClosedWithRichDetail)
{
  mAddressSpace.find_node_sync(mEnumDictionaryEntriesId)
    .as<VariableAccessor>()
    ->write_value_sync(Array<NodeId>{NodeId{1, uint32_t{7100}}});

  const auto outcome = check(mEnumValuesId, 1);
  ASSERT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(outcome.shared_detail(), nullptr);
  EXPECT_EQ(outcome.shared_detail()->code, "EnumDictionaryEntriesShapeInvalid");
}

// The rule is bidirectional: a client cannot lengthen SelectionDescriptions independently either.
// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, LengthChangingSelectionDescriptionsWriteIsRejected)
{
  EXPECT_EQ(check(mDescriptionsId, 4).status_code(), Status::BadOutOfRange);
}

// An IndexRange replaces elements in place and cannot change the containing array's length; the Write
// service does not check the pair for it.
// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, IndexRangeWritePassesToTheNormalRangeMerge)
{
  const auto status =
    write_selections_through_the_service(AttributeId::Value, Variant{Array<int32_t>{9}}, "1");
  EXPECT_EQ(status.as_status(), Status::Good) << to_string(status);
}

// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, UnrelatedArrayPropertyPassesThrough)
{
  EXPECT_FALSE(is_information_model_pair(QualifiedName{0, "Values"}));
  EXPECT_FALSE(is_information_model_pair(QualifiedName{1, "Selections"}));
  EXPECT_TRUE(is_information_model_pair(QualifiedName{0, "Selections"}));
}

// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, NonValueAttributePassesThrough)
{
  const auto status =
    write_selections_through_the_service(AttributeId::Description, Variant{LocalizedText{"en", "Changed"}});
  EXPECT_EQ(status.as_status(), Status::Good) << to_string(status);
}

// The check answers on the address space's executor; a completion that throws there is contained and called
// once.
// @relation(AC-SVR-DIAG-007-CATCHALL-TO-STATUSCODE, scope=function)
TEST_F(InformationModelWriteInterceptorTests, ThrowingInlineCompletionIsContainedAndDeliveredOnce)
{
  auto calls = std::make_shared<std::atomic<std::size_t>>(0);
  auto answered = std::make_shared<std::promise<VoidResult>>();
  auto answer = answered->get_future();

  EXPECT_NO_THROW(check_information_model_pair_async(mAddressSpace,
    mAddressSpace.find_node_sync(mSelectionsId),
    3,
    [calls, answered](VoidResult outcome)
    {
      if (calls->fetch_add(1) == 0)
      {
        answered->set_value(outcome);
      }
      throw std::runtime_error{"injected completion failure"};
    }));

  ASSERT_EQ(answer.wait_for(5s), std::future_status::ready) << "the check did not answer";
  EXPECT_TRUE(answer.get().is_good());
  ::ua::test_utils::drain_with_timeout(mThreadPool);
  EXPECT_EQ(calls->load(), 1U);
}

// A topology lookup failure is not evidence that the owner is merely a different VariableType.
// It must fail closed and retain the address-space diagnostic instead of silently bypassing the rule.
// @relation(AC-SVR-BASE-080-SELECTIONDESCRIPTIONS-LENGTH, scope=function)
TEST_F(InformationModelWriteInterceptorTests, MissingOwnerResolutionPreservesFailureDetail)
{
  const NodeId propertyId{1, uint32_t{7011}};
  const NodeId missingOwnerId{1, uint32_t{7999}};
  auto property = mAddressSpace.create_node_sync(propertyId, NodeClass::Variable);
  property.set_browse_name(QualifiedName{0, "Selections"});
  property.as<VariableAccessor>()->write_value_sync(Array<int32_t>{1, 2, 3});
  property.add_reference_sync(
    NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{missingOwnerId}, /*isForward=*/false);

  const auto outcome = check(propertyId, 2);
  ASSERT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code(), StatusCode{Status::BadNodeIdUnknown});
  ASSERT_NE(outcome.shared_detail(), nullptr);
  EXPECT_EQ(outcome.shared_detail()->code, "NodeNotFound");
}

}  // namespace

// --- Owner decision 14 (SVC-16): the owner is found through the inverse edge only; no namespace walk -

namespace
{
/// Counts namespace enumerations: a write must never cause one.
class CountingNamespace final : public default_ns::Namespace
{
public:
  CountingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    ++enumerations;
    default_ns::Namespace::enumerate_nodes_async(request, std::move(complete));
  }

  std::atomic<size_t> enumerations{0};
};
}  // namespace

class OwnerByInverseEdgeTests : public InformationModelWriteInterceptorTests
{
protected:
  void SetUp() override
  {
    mCounting = std::make_shared<CountingNamespace>("urn:test:counting", mThreadPool.get_executor());
    mCountingIndex = mAddressSpace.add_namespace_sync(mCounting);
    mOwnerId = NodeId{mCountingIndex, 7200u};
    mEnumValuesId = NodeId{mCountingIndex, 7201u};
    mEntriesId = NodeId{mCountingIndex, 7202u};
    auto owner = mAddressSpace.create_node_sync(mOwnerId, NodeClass::Variable);
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
      NodeId{VariableTypeId::MultiStateDictionaryEntryDiscreteBaseType});
    add_property(mOwnerId, mEnumValuesId, "EnumValues", make_enum_values(3));
    std::vector<NodeId> cells;
    for (uint32_t cell = 0; cell < 6; ++cell)
      cells.push_back(NodeId{mCountingIndex, 7300u + cell});
    add_property(mOwnerId, mEntriesId, "EnumDictionaryEntries", Array<NodeId>{Dimensions{3, 2}, cells});
  }

  std::shared_ptr<CountingNamespace> mCounting;
  uint16_t mCountingIndex{0};
  NodeId mOwnerId;
  NodeId mEnumValuesId;
  NodeId mEntriesId;
};

// Owner decision 14 (security review SVC-16): the SDK never enumerates a namespace to find a
// Property's owner. With the inverse HasProperty edge the pair is checked (a 4-row EnumValues against a
// 3-row dictionary is refused); without it - a namespace that stores only the owner's forward edge - the
// pair is not checked and the write takes the normal Write path. Neither write enumerates the namespace.
// @verifies AC-SVR-DA-036-NO-NAMESPACE-WALK-TO-FIND-AN-OWNER
TEST_F(OwnerByInverseEdgeTests, TheOwnerIsFoundOnlyThroughTheInverseEdgeAndNoNamespaceIsWalked)
{
  const auto refused = check(mEnumValuesId, 4);
  EXPECT_EQ(refused.status_code(), Status::BadOutOfRange) << "the control: the inverse edge finds the owner";

  mAddressSpace.find_node_sync(mEnumValuesId)
    .remove_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{mOwnerId}, /*isForward=*/false);
  const auto unchecked = check(mEnumValuesId, 4);
  EXPECT_TRUE(unchecked.is_good()) << "a forward-only Property is not checked";

  EXPECT_EQ(mCounting->enumerations.load(), 0u) << "no write enumerates the namespace";
}
