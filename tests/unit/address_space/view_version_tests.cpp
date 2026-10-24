// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_error_detail.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace ua;

namespace
{

class ViewVersionTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:view-version", mThreadPool.get_executor()));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  ViewAccessor create_versioned_view(
    const NodeId& viewId, const NodeId& versionId, Variant initialVersion = Variant{uint32_t{1}})
  {
    auto viewResult = mAddressSpace->try_create_sync<ViewAccessor>(viewId, NodeClass::View);
    EXPECT_TRUE(viewResult.is_good());

    auto versionResult = mAddressSpace->try_create_sync<VariableAccessor>(versionId, NodeClass::Variable);
    EXPECT_TRUE(versionResult.is_good());
    versionResult.value().set_browse_name(QualifiedName{0, "ViewVersion"});
    versionResult.value().write_value_sync(DataValue{std::move(initialVersion)});

    viewResult.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
    versionResult.value().add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{viewId}, false);
    return std::move(viewResult).value();
  }

  uint32_t read_version(const NodeId& versionId)
  {
    auto version = mAddressSpace->try_find_sync<VariableAccessor>(versionId);
    EXPECT_TRUE(version.is_good());
    auto value = version.value().try_read_value_sync();
    EXPECT_TRUE(value.is_good());
    return value.value().value().as<uint32_t>();
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
};

}  // namespace

// Part 3 section 5.4: when a Node is added to a View that publishes ViewVersion, the Property is
// updated so Clients can detect the composition change.
// @relation(AC-SVR-ADDRSP-248-VIEWVERSION-BUMPS-ON-CHANGE, scope=function)
TEST_F(ViewVersionTest, MembershipInsertionAdvancesPublishedViewVersion)
{
  const NodeId viewId{1, "versioned-view"};
  const NodeId versionId{1, "view-version"};
  auto view = create_versioned_view(viewId, versionId);

  ASSERT_TRUE(view.try_add_node_to_view_sync(NodeId{1, "member"}).is_good());
  EXPECT_EQ(read_version(versionId), 2u);
}

// Re-adding an existing member does not change the View's composition and therefore does not move
// ViewVersion a second time.
// @relation(AC-SVR-ADDRSP-248-VIEWVERSION-BUMPS-ON-CHANGE, scope=function)
TEST_F(ViewVersionTest, DuplicateMembershipLeavesPublishedViewVersionUnchanged)
{
  const NodeId viewId{1, "duplicate-view"};
  const NodeId versionId{1, "duplicate-version"};
  const NodeId memberId{1, "duplicate-member"};
  auto view = create_versioned_view(viewId, versionId);

  ASSERT_TRUE(view.try_add_node_to_view_sync(memberId).is_good());
  const auto afterFirst = read_version(versionId);
  ASSERT_TRUE(view.try_add_node_to_view_sync(memberId).is_good());
  EXPECT_EQ(read_version(versionId), afterFirst);
}

// ViewVersion is Optional. A View that does not publish it still accepts membership changes and does
// not manufacture a Property as a side effect.
// @relation(AC-SVR-ADDRSP-248-VIEWVERSION-BUMPS-ON-CHANGE, scope=function)
TEST_F(ViewVersionTest, ViewWithoutVersionAcceptsMembershipInsertion)
{
  const NodeId viewId{1, "unversioned-view"};
  auto viewResult = mAddressSpace->try_create_sync<ViewAccessor>(viewId, NodeClass::View);
  ASSERT_TRUE(viewResult.is_good());

  const NodeId memberId{1, "unversioned-member"};
  EXPECT_TRUE(viewResult.value().try_add_node_to_view_sync(memberId).is_good());
  EXPECT_TRUE(viewResult.value().try_is_node_in_view_sync(memberId).value());
}

// A malformed published ViewVersion is an implementation failure, not permission to commit an
// unversioned composition change. The membership insertion rolls back and reports its exact detail.
// @relation(AC-SVR-ADDRSP-248-VIEWVERSION-BUMPS-ON-CHANGE, scope=function)
TEST_F(ViewVersionTest, VersionTypeFailureRollsBackMembershipAndPreservesRichDetail)
{
  const NodeId viewId{1, "malformed-version-view"};
  const NodeId versionId{1, "malformed-version"};
  const NodeId memberId{1, "rolled-back-member"};
  auto view = create_versioned_view(viewId, versionId, Variant{String{"not-a-UInt32"}});

  const auto result = view.try_add_node_to_view_sync(memberId);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ViewVersionTypeMismatch");
  EXPECT_FALSE(view.try_is_node_in_view_sync(memberId).value());
}

// Every successful concurrent insertion is a separate composition change and consumes a distinct
// version step.
// @relation(AC-SVR-ADDRSP-248-VIEWVERSION-BUMPS-ON-CHANGE, scope=function)
TEST_F(ViewVersionTest, ConcurrentMembershipInsertionsEachAdvancePublishedVersion)
{
  const NodeId viewId{1, "concurrent-version-view"};
  const NodeId versionId{1, "concurrent-version"};
  auto view = create_versioned_view(viewId, versionId);
  const auto before = read_version(versionId);

  constexpr size_t writerCount = 8;
  std::atomic<size_t> successes{0};
  std::vector<std::thread> writers;
  writers.reserve(writerCount);
  for (size_t index = 0; index < writerCount; ++index)
  {
    writers.emplace_back(
      [&view, &successes, index]
      {
        if (view.try_add_node_to_view_sync(NodeId{1, static_cast<uint32_t>(8000U + index)}).is_good())
        {
          successes.fetch_add(1, std::memory_order_relaxed);
        }
      });
  }
  for (auto& writer : writers)
  {
    writer.join();
  }

  EXPECT_EQ(successes.load(std::memory_order_relaxed), writerCount);
  EXPECT_EQ(read_version(versionId), before + writerCount);
}

// @relation(AC-COMP-SVR-DEFAULT-VIEW-NODE-MEMBERSHIP-01-THROWING-CALLBACK, scope=function)
TEST_F(ViewVersionTest, ThrowingCompletionIsContainedAfterAsynchronousVersionAdvance)
{
  using namespace std::chrono_literals;
  const NodeId viewId{1, "throwing-completion-view"};
  const NodeId versionId{1, "throwing-completion-version"};
  auto view = create_versioned_view(viewId, versionId);
  std::promise<void> invoked;
  auto invocation = invoked.get_future();
  std::atomic<size_t> calls{0};

  view.add_node_to_view_async(NodeId{1, "throwing-completion-member"},
    [&invoked, &calls](VoidResult result)
    {
      EXPECT_TRUE(result.is_good());
      calls.fetch_add(1, std::memory_order_relaxed);
      invoked.set_value();
      throw std::runtime_error{"sentinel ViewVersion completion failure"};
    });

  ASSERT_EQ(invocation.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(calls.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(read_version(versionId), 2u);
}
