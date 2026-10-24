// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The address space's route checks Part 3 6.2.7 on a HasSubtype between VariableTypes before either half is
// sent (NR-52; NR-70 B9a).
//
// The supertypes and the DataTypes live in namespace A, the subtypes in namespace B, so that every check
// reads a supertype the subtype's namespace does not hold.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ua;
using ua::test::BatchRecordingNamespace;

namespace
{

using namespace std::chrono_literals;

class VariableTypeSubtype : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mThreadPool.get_executor()));
    mA = std::make_shared<BatchRecordingNamespace>(
      "urn:test:variable-type-subtype:a", mThreadPool.get_executor());
    mB = std::make_shared<BatchRecordingNamespace>(
      "urn:test:variable-type-subtype:b", mThreadPool.get_executor());
    auto indexA = mAddressSpace->try_add_namespace_sync(mA);
    auto indexB = mAddressSpace->try_add_namespace_sync(mB);
    ASSERT_TRUE(indexA.is_good() && indexB.is_good());
    mIndexA = indexA.value();
    mIndexB = indexB.value();
    // Number, with its subtype Real; Text, which is neither.
    mNumber = data_type("Number");
    mReal = data_type("Real");
    mText = data_type("Text");
    ASSERT_TRUE(node(mNumber).try_add_reference_sync(mHasSubtype, ExpandedNodeId{mReal}).is_good());
  }

  void TearDown() override
  {
    mA.reset();
    mB.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor node(const NodeId& id)
  {
    auto found = mAddressSpace->try_find_node_sync(id);
    EXPECT_TRUE(found.is_good()) << to_string(id);
    return found.value();
  }

  NodeId data_type(const std::string& name)
  {
    const NodeId id{mIndexA, String{name}};
    EXPECT_TRUE(mAddressSpace->try_create_node_sync(id, NodeClass::DataType, {}).is_good()) << name;
    return id;
  }

  /// A VariableType of namespace @p index with the DataType, ValueRank and, when given, ArrayDimensions
  /// given.
  NodeId variable_type(uint16_t index, const std::string& name, const NodeId& dataType, int32_t valueRank,
    std::optional<std::vector<uint32_t>> dimensions = std::nullopt)
  {
    const NodeId id{index, String{name}};
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    auto variableType = created.value().as<VariableTypeAccessor>();
    EXPECT_TRUE(variableType.has_value());
    variableType->set_data_type(dataType);
    variableType->set_value_rank(ValueRank{valueRank});
    if (dimensions)
    {
      variableType->set_array_dimensions(std::move(*dimensions));
    }
    return id;
  }

  /// The subtype's inverse HasSubtype to @p supertype, as a NodeSet states it.
  VoidResult add_subtype(const NodeId& supertype, const NodeId& subtype)
  {
    return node(subtype).try_add_reference_sync(mHasSubtype, ExpandedNodeId{supertype}, false);
  }

  /// Whether either half of HasSubtype from @p supertype to @p subtype is held.
  bool either_half_held(const NodeId& supertype, const NodeId& subtype)
  {
    const auto holds = [this](const NodeId& holder, const NodeId& target, bool isForward)
    {
      auto references = node(holder).try_get_references_sync();
      EXPECT_TRUE(references.is_good());
      return std::ranges::any_of(references.value(),
        [this, &target, isForward](const Reference& reference)
        {
          return reference.type_id() == mHasSubtype && reference.is_forward() == isForward &&
                 reference.target_id() == ExpandedNodeId{target};
        });
    };
    return holds(supertype, subtype, true) || holds(subtype, supertype, false);
  }

  static void expect_refused(const VoidResult& added, std::string_view code)
  {
    EXPECT_EQ(added.status_code().as_status(), Status::BadReferenceNotAllowed)
      << to_string(added.status_code());
    ASSERT_NE(added.shared_detail(), nullptr);
    EXPECT_EQ(added.shared_detail()->code, code);
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<BatchRecordingNamespace> mA;
  shared_ptr<BatchRecordingNamespace> mB;
  uint16_t mIndexA{0};
  uint16_t mIndexB{0};
  NodeId mNumber;
  NodeId mReal;
  NodeId mText;
  const NodeId mHasSubtype{ReferenceTypeId::HasSubtype};
};

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-DATA-TYPE-NOT-A-SUBTYPE-IS-REFUSED, scope=function)
TEST_F(VariableTypeSubtype, ADataTypeThatIsNotASubtypeIsRefused)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::any);
  const auto narrowed = variable_type(mIndexB, "Narrowed", mReal, ValueRank::any);
  const auto unrelated = variable_type(mIndexB, "Unrelated", mText, ValueRank::any);

  const auto kept = add_subtype(supertype, narrowed);
  EXPECT_TRUE(kept.is_good()) << to_string(kept.status_code());
  const auto refused = add_subtype(supertype, unrelated);
  expect_refused(refused, "SubtypeDataTypeNotASubtype");
  EXPECT_FALSE(either_half_held(supertype, unrelated)) << "neither half is sent";
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-WIDER-VALUE-RANK-IS-REFUSED, scope=function)
TEST_F(VariableTypeSubtype, AWiderValueRankIsRefused)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::scalarOrOneDimension);
  const auto scalar = variable_type(mIndexB, "Scalar", mNumber, ValueRank::scalar);
  const auto oneOrMore = variable_type(mIndexB, "OneOrMore", mNumber, ValueRank::oneOrMore);
  const auto any = variable_type(mIndexB, "Any", mNumber, ValueRank::any);

  const auto kept = add_subtype(supertype, scalar);
  EXPECT_TRUE(kept.is_good()) << to_string(kept.status_code());
  expect_refused(add_subtype(supertype, oneOrMore), "SubtypeValueRankNotRestricted");
  expect_refused(add_subtype(supertype, any), "SubtypeValueRankNotRestricted");
  EXPECT_FALSE(either_half_held(supertype, any));
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-CHANGED-ARRAY-DIMENSION-IS-REFUSED, scope=function)
TEST_F(VariableTypeSubtype, AChangedArrayDimensionIsRefusedAcrossNamespaces)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, 2, std::vector<uint32_t>{4, 0});
  const auto fixed = variable_type(mIndexB, "Fixed", mNumber, 2, std::vector<uint32_t>{4, 7});
  const auto changed = variable_type(mIndexB, "Changed", mNumber, 2, std::vector<uint32_t>{9, 7});

  const auto kept = add_subtype(supertype, fixed);
  EXPECT_TRUE(kept.is_good()) << to_string(kept.status_code());
  expect_refused(add_subtype(supertype, changed), "SubtypeArrayDimensionChanged");
  EXPECT_FALSE(either_half_held(supertype, changed));
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-DATA-TYPE-HAS-SUBTYPE-IN-THE-SAME-CALL-IS-SEEN, scope=function)
TEST_F(VariableTypeSubtype, ADataTypesHasSubtypeInTheSameCallIsSeen)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::any);
  const auto integer = data_type("Integer");
  const auto counted = variable_type(mIndexB, "Counted", integer, ValueRank::any);

  // The VariableType's HasSubtype first, as a file may list it before the DataType's.
  auto changes = std::make_shared<const std::vector<ReferenceChange>>(std::vector<ReferenceChange>{
    ReferenceChange{counted, mHasSubtype, ExpandedNodeId{supertype}, false, false},
    ReferenceChange{mNumber, mHasSubtype, ExpandedNodeId{integer}, true, false}});
  std::promise<std::vector<VoidResult>> answered;
  auto future = answered.get_future();
  ::ua::detail::NodeAccessorRoute::add_references(mAddressSpace->weak(),
    RequestInfo{},
    changes,
    [&answered](std::vector<VoidResult> answers) { answered.set_value(std::move(answers)); });
  ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
  const auto answers = future.get();
  ASSERT_EQ(answers.size(), 2u);
  EXPECT_TRUE(answers[0].is_good()) << to_string(answers[0].status_code())
                                    << (answers[0].shared_detail() ? " " + answers[0].shared_detail()->code
                                                                   : "");
  EXPECT_TRUE(answers[1].is_good()) << to_string(answers[1].status_code());
}

}  // namespace

namespace
{

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-DATA-TYPE-WALK-THAT-FAILS-IS-ANSWERED-WITH-ITS-FAILURE, scope=function)
TEST_F(VariableTypeSubtype, ADataTypeWalkThatFailsIsAnsweredWithItsFailure)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::any);
  const auto real = variable_type(mIndexB, "Real", mReal, ValueRank::any);
  // A cannot answer for Real now: the walk cannot decide, which is not Real failing 6.2.7 a.
  mA->decline_single_lookups();
  mA->answer_lookup_of(mReal, StatusCode{Status::BadTimeout});

  const auto added = add_subtype(supertype, real);
  EXPECT_EQ(added.status_code().as_status(), Status::BadTimeout)
    << to_string(added.status_code()) << (added.shared_detail() ? " " + added.shared_detail()->code : "");
  EXPECT_FALSE(either_half_held(supertype, real));
}

// A lookup of the two VariableTypes that fails leaves Part 3 6.2.7 undecided, so the HasSubtype is refused
// with the failure rather than added unchecked (NR-52); here the subtype widens the
// supertype's ValueRank.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-FAILED-LOOKUP-REFUSES-THE-SUBTYPE, scope=function)
TEST_F(VariableTypeSubtype, ALookupThatFailsRefusesTheSubtype)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::scalar);
  const auto any = variable_type(mIndexB, "Any", mNumber, ValueRank::any);
  mA->decline_single_lookups();
  mA->answer_lookup_of(supertype, StatusCode{Status::BadTimeout});

  const auto added = add_subtype(supertype, any);
  EXPECT_EQ(added.status_code().as_status(), Status::BadTimeout) << to_string(added.status_code());
  auto references = node(any).try_get_references_sync();
  ASSERT_TRUE(references.is_good());
  EXPECT_FALSE(std::ranges::any_of(
    references.value(), [this](const Reference& reference) { return reference.type_id() == mHasSubtype; }))
    << "the subtype's half is not added";
}

// A supertype given by namespace URI is checked as its index form is.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-SUPERTYPE-GIVEN-BY-NAMESPACE-URI-IS-CHECKED, scope=function)
TEST_F(VariableTypeSubtype, ASupertypeGivenByNamespaceUriIsChecked)
{
  const auto supertype = variable_type(mIndexA, "Supertype", mNumber, ValueRank::scalar);
  const auto any = variable_type(mIndexB, "Any", mNumber, ValueRank::any);
  const ExpandedNodeId byUri{NodeId{0, String{"Supertype"}}, "urn:test:variable-type-subtype:a"};

  expect_refused(
    node(any).try_add_reference_sync(mHasSubtype, byUri, false), "SubtypeValueRankNotRestricted");
  EXPECT_FALSE(either_half_held(supertype, any));
}

}  // namespace
