// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 3 section 5.4, Table 10, ViewVersion: "When Nodes are added to or removed from a View, the value of
// the ViewVersion Property is updated." A deleted Node is no longer one of the Nodes a View defines (Part 3
// section 9.32.3, Part 5 section 12.16), so deleting a member of an in-memory View removes it from the View
// and advances the View's ViewVersion once (SVR-ADDRSP-259, NR-57, DL-8). The namespace is driven through its
// own callback-form delete_node, the interface the AddressSpace's delete reaches.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_default_view_node.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Records every entry with its category, message and string fields.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::vector<std::pair<std::string, std::string>> fields;
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      const auto* text = std::get_if<std::string_view>(&field.value);
      copy.fields.emplace_back(std::string{field.key}, text != nullptr ? std::string{*text} : std::string{});
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  std::vector<Entry> entries() const
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// An in-memory namespace registered in an AddressSpace, so its Nodes are maintained by the AddressSpace's
/// version coordinator, as a server's are.
// A delete_nodes_async completion for one Node that sets @p answered to its item, or to the batch's status
// when the batch failed as a whole.
std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> answer_into(
  std::promise<DeleteNodeResult>& answered)
{
  return [&answered](BatchResult<DeleteNodeResult> result, std::vector<VersionedNode> /*versioned*/)
  {
    if (result.items.empty())
    {
      answered.set_value(DeleteNodeResult{result.batchStatus.status_code()});
      return;
    }
    answered.set_value(std::move(result.items.front()));
  };
}

class InMemoryView : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:in-memory-view-host", mThreadPool.get_executor()));
    mNamespace = default_ns::Namespace::create("urn:test:in-memory-view", mThreadPool.get_executor());
    mIndex = mAddressSpace->add_namespace_sync(mNamespace);
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeId id(uint32_t identifier) const
  {
    return NodeId{mIndex, identifier};
  }

  /// Gives @p viewId the ViewVersion Property @p versionId holding @p initialVersion.
  void add_view_version(
    const NodeId& viewId, const NodeId& versionId, Variant initialVersion = Variant{uint32_t{1}})
  {
    auto version = mAddressSpace->try_create_sync<VariableAccessor>(versionId, NodeClass::Variable);
    ASSERT_TRUE(version.is_good()) << to_string(version.status_code());
    version.value().set_browse_name(QualifiedName{0, "ViewVersion"});
    version.value().write_value_sync(DataValue{std::move(initialVersion)});
    auto view = mAddressSpace->try_find_sync<ViewAccessor>(viewId);
    ASSERT_TRUE(view.is_good()) << to_string(view.status_code());
    view.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
    version.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{viewId}, false);
  }

  /// A View created by NodeClass, with the ViewVersion Property.
  ViewAccessor create_view(const NodeId& viewId, const NodeId& versionId)
  {
    auto view = mAddressSpace->try_create_sync<ViewAccessor>(viewId, NodeClass::View);
    EXPECT_TRUE(view.is_good()) << to_string(view.status_code());
    add_view_version(viewId, versionId);
    return std::move(view).value();
  }

  void create_object(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  }

  std::optional<uint32_t> read_version(const NodeId& versionId)
  {
    auto version = mAddressSpace->try_find_sync<VariableAccessor>(versionId);
    if (version.is_bad())
    {
      ADD_FAILURE() << "the ViewVersion Property is gone: " << to_string(version.status_code());
      return std::nullopt;
    }
    auto value = version.value().try_read_value_sync();
    if (value.is_bad())
    {
      ADD_FAILURE() << "the ViewVersion could not be read: " << to_string(value.status_code());
      return std::nullopt;
    }
    const auto* number = value.value().value().try_as<uint32_t>();
    if (number == nullptr)
    {
      ADD_FAILURE() << "the ViewVersion is not a UInt32: " << to_string(value.value().value());
      return std::nullopt;
    }
    return *number;
  }

  /// Deletes @p nodeId through the namespace's delete_nodes_async and waits for its answer.
  DeleteNodeResult delete_node(const NodeId& nodeId)
  {
    std::promise<DeleteNodeResult> answered;
    auto answer = answered.get_future();
    mNamespace->delete_nodes_async(
      RequestInfo{}, std::span<const NodeId>{&nodeId, 1}, ReferenceHalves::Both, answer_into(answered));
    if (answer.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the delete of " << to_string(nodeId) << " never answered";
      return DeleteNodeResult{Status::BadTimeout};
    }
    return answer.get();
  }

  // One thread, so a test can hold back every posted step by blocking it.
  boost::asio::thread_pool mThreadPool{1};
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mIndex{0};
};

}  // namespace

// A and B are members; C is not. Deleting A removes it and advances the ViewVersion once, read as soon as the
// deletion answers; deleting C changes nothing. A Node created again with A's NodeId is not a member, and B
// still is.
// @relation(AC-SVR-ADDRSP-259-DELETED-MEMBER-LEAVES-VIEW, scope=function)
TEST_F(InMemoryView, DeletingAMemberRemovesItAndAdvancesViewVersion)
{
  const NodeId viewId = id(100);
  const NodeId versionId = id(101);
  const NodeId memberA = id(102);
  const NodeId memberB = id(103);
  const NodeId nonMemberC = id(104);
  auto view = create_view(viewId, versionId);
  for (const auto& nodeId : {memberA, memberB, nonMemberC})
    create_object(nodeId);
  ASSERT_TRUE(view.try_add_node_to_view_sync(memberA).is_good());
  ASSERT_TRUE(view.try_add_node_to_view_sync(memberB).is_good());
  const auto before = read_version(versionId);
  ASSERT_TRUE(before.has_value());

  ASSERT_TRUE(delete_node(memberA).is_good());
  EXPECT_EQ(read_version(versionId), *before + 1u)
    << "deleting a member did not advance the ViewVersion once by the time the deletion answered";

  ASSERT_TRUE(delete_node(nonMemberC).is_good());
  EXPECT_EQ(read_version(versionId), *before + 1u) << "deleting a Node that is not a member advanced it";

  create_object(memberA);
  auto again = view.try_is_node_in_view_sync(memberA);
  ASSERT_TRUE(again.is_good()) << to_string(again.status_code());
  EXPECT_FALSE(again.value()) << "the Node created again with a deleted member's NodeId is a member";
  auto other = view.try_is_node_in_view_sync(memberB);
  ASSERT_TRUE(other.is_good()) << to_string(other.status_code());
  EXPECT_TRUE(other.value()) << "the member that was not deleted left the View";
}

// The templated create_node<ViewNode> is the other route that creates an in-memory View; a View created
// through it drops a deleted member as one created by NodeClass does.
// Deleting a View itself answers Good: the View is removed from the namespace's list of Views without asking
// the already-deleted View for its NodeId. The other View keeps working.
// @relation(AC-SVR-ADDRSP-259-DELETING-A-VIEW-ANSWERS-GOOD, scope=function)
TEST_F(InMemoryView, DeletingAViewAnswersGoodAndLeavesTheOtherViewsWorking)
{
  const NodeId viewId = id(400);
  const NodeId otherViewId = id(402);
  const NodeId member = id(404);
  create_view(viewId, id(401));
  auto otherView = create_view(otherViewId, id(403));
  create_object(member);
  ASSERT_TRUE(otherView.try_add_node_to_view_sync(member).is_good());

  const auto deleted = delete_node(viewId);
  EXPECT_TRUE(deleted.is_good()) << "deleting a View answered " << to_string(deleted.status_code());
  EXPECT_TRUE(mAddressSpace->try_find_sync<ViewAccessor>(viewId).is_bad()) << "the deleted View is still found";

  ASSERT_TRUE(delete_node(member).is_good());
  const auto inView = otherView.try_is_node_in_view_sync(member);
  ASSERT_TRUE(inView.is_good());
  EXPECT_FALSE(inView.value()) << "the remaining View kept a deleted member";
}

// @relation(AC-SVR-ADDRSP-259-TEMPLATE-CREATED-VIEW-DROPS-DELETED-MEMBER, scope=function)
TEST_F(InMemoryView, AViewCreatedThroughTheTemplateDropsADeletedMember)
{
  const NodeId viewId = id(200);
  const NodeId versionId = id(201);
  const NodeId memberA = id(202);
  ASSERT_NE(mNamespace->create_node<default_ns::ViewNode>(viewId), nullptr);
  add_view_version(viewId, versionId);
  create_object(memberA);
  auto view = mAddressSpace->try_find_sync<ViewAccessor>(viewId);
  ASSERT_TRUE(view.is_good()) << to_string(view.status_code());
  ASSERT_TRUE(view.value().try_add_node_to_view_sync(memberA).is_good());
  const auto before = read_version(versionId);
  ASSERT_TRUE(before.has_value());

  ASSERT_TRUE(delete_node(memberA).is_good());

  EXPECT_EQ(read_version(versionId), *before + 1u)
    << "deleting a member of a View created through the template did not advance its ViewVersion";
  auto inView = view.value().try_is_node_in_view_sync(memberA);
  ASSERT_TRUE(inView.is_good()) << to_string(inView.status_code());
  EXPECT_FALSE(inView.value()) << "the deleted member is still in the View created through the template";
}

// The removal is made under the namespace's lock and the ViewVersion advanced afterwards (DL-8). With the
// advance held back - the executor's only thread is blocked, so the coordinator's version strand cannot run -
// A is created again and added to the View; the deletion must not then take out the new Node's membership.
// The ViewVersion is advanced once for the deletion and once for the add.
// @relation(AC-SVR-ADDRSP-259-NODE-CREATED-AGAIN-STAYS-A-MEMBER, scope=function)
TEST_F(InMemoryView, ANodeCreatedAgainAndAddedDuringTheDeleteStaysAMember)
{
  const NodeId viewId = id(300);
  const NodeId versionId = id(301);
  const NodeId memberA = id(302);
  auto view = create_view(viewId, versionId);
  create_object(memberA);
  ASSERT_TRUE(view.try_add_node_to_view_sync(memberA).is_good());
  const auto before = read_version(versionId);
  ASSERT_TRUE(before.has_value());

  // Hold back every posted step, the version strand's included: the executor's only thread waits.
  std::promise<void> started;
  std::promise<void> release;
  auto released = release.get_future().share();
  boost::asio::post(mThreadPool,
    [&started, released]
    {
      started.set_value();
      released.wait();
    });
  started.get_future().wait();

  std::promise<DeleteNodeResult> deleteAnswered;
  auto deleteAnswer = deleteAnswered.get_future();
  mNamespace->delete_nodes_async(
    RequestInfo{}, std::span<const NodeId>{&memberA, 1}, ReferenceHalves::Both, answer_into(deleteAnswered));
  const bool createdAgain = mNamespace->create_node(memberA, NodeClass::Object) != nullptr;
  std::promise<VoidResult> addAnswered;
  auto addAnswer = addAnswered.get_future();
  view.add_node_to_view_async(
    memberA, [&addAnswered](VoidResult result) mutable { addAnswered.set_value(std::move(result)); });
  release.set_value();

  ASSERT_TRUE(createdAgain) << "A could not be created again while its deletion completes";
  ASSERT_EQ(deleteAnswer.wait_for(5s), std::future_status::ready) << "the delete never answered";
  ASSERT_TRUE(deleteAnswer.get().is_good());
  ASSERT_EQ(addAnswer.wait_for(5s), std::future_status::ready) << "the add never answered";
  ASSERT_TRUE(addAnswer.get().is_good());

  auto inView = view.try_is_node_in_view_sync(memberA);
  ASSERT_TRUE(inView.is_good()) << to_string(inView.status_code());
  EXPECT_TRUE(inView.value()) << "the deletion removed the membership of the Node created again";
  EXPECT_EQ(read_version(versionId), *before + 2u)
    << "the ViewVersion was not advanced once for the deletion and once for the add";
}

// The Node is gone when the ViewVersion advance fails (here, a ViewVersion holding a String), so the
// deletion still answers Good, the member is removed, and the failure is logged (NR-57, DL-8).
// @relation(AC-SVR-ADDRSP-259-FAILED-ADVANCE-LOGGED-DELETE-SUCCEEDS, scope=function)
TEST_F(InMemoryView, AFailedViewVersionAdvanceIsLoggedAndTheDeleteSucceeds)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  const NodeId viewId = id(400);
  const NodeId versionId = id(401);
  const NodeId memberA = id(402);
  auto view = create_view(viewId, versionId);
  create_object(memberA);
  ASSERT_TRUE(view.try_add_node_to_view_sync(memberA).is_good());
  // Only now does the ViewVersion hold a value that cannot be advanced.
  auto version = mAddressSpace->try_find_sync<VariableAccessor>(versionId);
  ASSERT_TRUE(version.is_good());
  version.value().write_value_sync(DataValue{Variant{String{"not-a-UInt32"}}});

  const auto deleted = delete_node(memberA);
  EXPECT_TRUE(deleted.is_good()) << "a failed ViewVersion advance failed the deletion: "
                                 << to_string(deleted.status_code());
  auto inView = view.try_is_node_in_view_sync(memberA);
  ASSERT_TRUE(inView.is_good()) << to_string(inView.status_code());
  EXPECT_FALSE(inView.value()) << "the deleted member is still in the View";

  const std::string expected{"A View lost a member and its ViewVersion could not advance"};
  std::size_t warnings = 0;
  bool namesTheView = false;
  bool namesTheStatus = false;
  for (const auto& entry : sink->entries())
  {
    if (entry.level != LogLevel::Warning || entry.category != "address_space" ||
        entry.message.find(expected) == std::string::npos)
      continue;
    ++warnings;
    for (const auto& [key, value] : entry.fields)
    {
      namesTheView = namesTheView || value == to_string(viewId);
      namesTheStatus = namesTheStatus || value.find("BadTypeMismatch") != std::string::npos;
    }
  }
  EXPECT_EQ(warnings, 1u) << "the failed advance was not logged once as a warning in category address_space";
  EXPECT_TRUE(namesTheView) << "the warning does not name the View";
  EXPECT_TRUE(namesTheStatus) << "the warning does not name the status";
}
