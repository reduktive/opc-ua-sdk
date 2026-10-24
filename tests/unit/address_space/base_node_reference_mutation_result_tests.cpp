// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_default_base_node.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace
{

using namespace ua;

// The four Reference members of a Node of the in-memory namespace change the Node through the namespace that
// created it (NR-27). The namespace is not attached here, so nothing else answers for it.
class BaseNodeReferenceMutationResultTest : public ::testing::Test
{
protected:
  BaseNodeReferenceMutationResultTest()
    : mNamespace(default_ns::Namespace::create("urn:test:reference-mutation", mThreadPool.get_executor())),
      mNode(std::dynamic_pointer_cast<default_ns::BaseNode>(
        mNamespace->create_node(NodeId{0, "reference-mutation-holder"}, NodeClass::Object)))
  {}

  void TearDown() override
  {
    mNode.reset();
    mNamespace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::vector<Reference> held() const
  {
    std::vector<Reference> references;
    mNode->get_references_async(
      [&references](NodeAccessor::ReferencesResult result)
      {
        if (result.is_good())
        {
          const auto& held = result.value();
          references.assign(held.begin(), held.end());
        }
      });
    return references;
  }

  bool holds(const Reference& reference) const
  {
    const auto references = held();
    return std::ranges::find(references, reference) != references.end();
  }

  // The namespace is gone: each member is answered by the namespace layer, which the Node passes on
  // unchanged.
  static void expect_namespace_gone(const std::optional<VoidResult>& captured, int callbackCalls)
  {
    ASSERT_EQ(callbackCalls, 1);
    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->status_code(), Status::BadInvalidState);
    const auto detail = captured->status_code().shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "NamespaceUnavailable");
    EXPECT_EQ(detail->source, "DefaultNamespace");
  }

  static auto recorder(int& calls, std::optional<VoidResult>& captured)
  {
    return [&calls, &captured](VoidResult result)
    {
      ++calls;
      captured = std::move(result);
    };
  }

  boost::asio::thread_pool mThreadPool{1};
  shared_ptr<default_ns::Namespace> mNamespace;
  shared_ptr<default_ns::BaseNode> mNode;
};

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-01-EXACT-RICH-RESULT, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-02-ARGUMENT-SHAPE, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-03-EXACTLY-ONCE, scope=function)
TEST_F(BaseNodeReferenceMutationResultTest, SingleAddPreservesExactRichCoordinatorFailure)
{
  ASSERT_NE(mNode, nullptr);
  const NodeId referenceType{2, "single-add-type"};
  const ExpandedNodeId target{NodeId{7, "single-add-target"}};
  const auto before = held().size();
  int calls{0};
  std::optional<VoidResult> captured;

  mNode->add_reference_async(referenceType, target, false, recorder(calls, captured));

  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << to_string(captured->status_code());
  EXPECT_EQ(held().size(), before + 1);
  EXPECT_TRUE(holds(Reference{referenceType, target, false}));

  mNamespace.reset();
  calls = 0;
  captured.reset();
  mNode->add_reference_async(NodeId{2, "other-type"}, target, true, recorder(calls, captured));
  expect_namespace_gone(captured, calls);
}

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-01-EXACT-RICH-RESULT, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-02-ARGUMENT-SHAPE, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-03-EXACTLY-ONCE, scope=function)
TEST_F(BaseNodeReferenceMutationResultTest, BatchAddPreservesExactRichCoordinatorFailure)
{
  ASSERT_NE(mNode, nullptr);
  const Reference first{NodeId{2, "batch-type-a"}, ExpandedNodeId{NodeId{7, "batch-target-a"}}, true};
  const Reference second{NodeId{2, "batch-type-b"}, ExpandedNodeId{NodeId{8, "batch-target-b"}}, false};
  const auto before = held().size();
  int calls{0};
  std::optional<VoidResult> captured;

  mNode->add_references_async(std::vector<Reference>{first, second}, recorder(calls, captured));

  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << to_string(captured->status_code());
  const auto references = held();
  ASSERT_EQ(references.size(), before + 2);
  EXPECT_EQ(references[before], first);
  EXPECT_EQ(references[before + 1], second);

  mNamespace.reset();
  calls = 0;
  captured.reset();
  mNode->add_references_async(std::vector<Reference>{first}, recorder(calls, captured));
  expect_namespace_gone(captured, calls);
}

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-01-EXACT-RICH-RESULT, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-02-ARGUMENT-SHAPE, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-03-EXACTLY-ONCE, scope=function)
TEST_F(BaseNodeReferenceMutationResultTest, SingleRemovePreservesExactRichCoordinatorFailure)
{
  ASSERT_NE(mNode, nullptr);
  const NodeId referenceType{2, "single-remove-type"};
  const ExpandedNodeId target{NodeId{7, "single-remove-target"}};
  int calls{0};
  std::optional<VoidResult> captured;

  // A single removal reports the Reference it did not hold.
  mNode->remove_reference_async(referenceType, target, true, recorder(calls, captured));
  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), Status::UncertainReferenceNotDeleted);

  mNode->add_reference_async(referenceType, target, true, [](VoidResult) {});
  calls = 0;
  captured.reset();
  mNode->remove_reference_async(referenceType, target, true, recorder(calls, captured));
  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << to_string(captured->status_code());
  EXPECT_FALSE(holds(Reference{referenceType, target, true}));

  mNamespace.reset();
  calls = 0;
  captured.reset();
  mNode->remove_reference_async(referenceType, target, true, recorder(calls, captured));
  expect_namespace_gone(captured, calls);
}

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-01-EXACT-RICH-RESULT, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-02-ARGUMENT-SHAPE, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-03-EXACTLY-ONCE, scope=function)
TEST_F(BaseNodeReferenceMutationResultTest, BatchRemovePreservesExactRichCoordinatorFailure)
{
  ASSERT_NE(mNode, nullptr);
  const Reference first{
    NodeId{2, "batch-remove-a"}, ExpandedNodeId{NodeId{7, "batch-remove-target-a"}}, true};
  const Reference second{
    NodeId{2, "batch-remove-b"}, ExpandedNodeId{NodeId{8, "batch-remove-target-b"}}, false};
  int calls{0};
  std::optional<VoidResult> captured;

  // A batch removal does not report the References it did not hold.
  mNode->remove_references_async(std::vector<Reference>{first, second}, recorder(calls, captured));
  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << to_string(captured->status_code());

  mNode->add_references_async(std::vector<Reference>{first, second}, [](VoidResult) {});
  calls = 0;
  captured.reset();
  mNode->remove_references_async(std::vector<Reference>{first, second}, recorder(calls, captured));
  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << to_string(captured->status_code());
  EXPECT_FALSE(holds(first));
  EXPECT_FALSE(holds(second));

  mNamespace.reset();
  calls = 0;
  captured.reset();
  mNode->remove_references_async(std::vector<Reference>{first, second}, recorder(calls, captured));
  expect_namespace_gone(captured, calls);
}

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-REFMUT-04-THROWING-CALLBACK, scope=function)
TEST_F(BaseNodeReferenceMutationResultTest, ThrowingCallbacksAreContainedForEveryMutationSurface)
{
  ASSERT_NE(mNode, nullptr);
  int callbackCalls{0};
  const auto throwingCallback = [&callbackCalls](VoidResult)
  {
    ++callbackCalls;
    throw std::runtime_error("injected reference mutation callback failure");
  };
  const Reference first{NodeId{2, "throw-type-a"}, ExpandedNodeId{NodeId{7, "throw-target-a"}}, true};
  const Reference second{NodeId{2, "throw-type-b"}, ExpandedNodeId{NodeId{8, "throw-target-b"}}, false};

  EXPECT_NO_THROW(
    mNode->add_reference_async(first.type_id(), first.target_id(), first.is_forward(), throwingCallback));
  EXPECT_TRUE(holds(first));
  EXPECT_NO_THROW(mNode->add_references_async(std::vector<Reference>{second}, throwingCallback));
  EXPECT_TRUE(holds(second));
  EXPECT_NO_THROW(
    mNode->remove_reference_async(first.type_id(), first.target_id(), first.is_forward(), throwingCallback));
  EXPECT_FALSE(holds(first));
  EXPECT_NO_THROW(mNode->remove_references_async(std::vector<Reference>{second}, throwingCallback));
  EXPECT_FALSE(holds(second));

  EXPECT_EQ(callbackCalls, 4);
}

}  // namespace
