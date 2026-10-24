// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// find_child_id_by_browse_name_async over a parent one of whose References' targets cannot be looked up
// (COMP-ADDRSP-FIND-CHILD-BY-BROWSE-NAME-01; DL-12).
//
// The namespace is a default namespace whose lookup of a given Node can be made to fail, as the lookup of a
// namespace that holds its Nodes elsewhere fails when it cannot reach them. The lookup is driven through the
// address space, as the SDK's own callers (the PercentDeadband's EURange lookup) drive it.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utility>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// A default namespace whose lookup of a given Node answers a failure the test chooses.
class FailingLookupNamespace final : public default_ns::Namespace
{
public:
  FailingLookupNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// Answers every later lookup of @p nodeId with @p status.
  void fail_lookups(const NodeId& nodeId, StatusCode status)
  {
    const std::lock_guard lock{mFailuresMutex};
    mFailures.insert_or_assign(nodeId, std::move(status));
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    {
      const std::lock_guard lock{mFailuresMutex};
      if (const auto found = mFailures.find(nodeId); found != mFailures.end())
      {
        return NodeResult{found->second};
      }
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  std::mutex mFailuresMutex;
  std::unordered_map<NodeId, StatusCode> mFailures;
};

class FindChildIdByBrowseName : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mPool.get_executor()));
    mNamespace = std::make_shared<FailingLookupNamespace>("urn:test:find-child", mPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mNsIndex = index.value();
  }

  void TearDown() override
  {
    mNodes.clear();
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeId id(uint32_t identifier) const
  {
    return NodeId{mNsIndex, identifier};
  }

  void create_parent(const NodeId& parent)
  {
    mNodes.insert_or_assign(parent, mAddressSpace->create_node_sync(parent, NodeClass::Object));
  }

  /// Gives @p parent a Property @p property with the BrowseName (0, @p browseName); the HasProperty
  /// References are listed in the order they are added.
  void add_property(const NodeId& parent, const NodeId& property, const char* browseName)
  {
    auto node = mAddressSpace->create_node_sync(property, NodeClass::Variable);
    node.set_browse_name(QualifiedName{0, browseName});
    mNodes.insert_or_assign(property, node);
    mNodes.at(parent).add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, property);
  }

  /// Looks up @p parent's HasProperty child with the BrowseName (0, "EURange").
  NodeIdResult find_eu_range(const NodeId& parent)
  {
    auto answered = std::make_shared<std::promise<NodeIdResult>>();
    auto future = answered->get_future();
    instance_utils::find_child_id_by_browse_name_async(*mAddressSpace,
      parent,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, "EURange"},
      [answered](NodeIdResult result) { answered->set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the lookup did not answer";
      return NodeIdResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }

  /// Looks up @p parent's HasProperty child (0, "EURange") through find_child_by_browse_name_async; counts
  /// the callback's calls in @p calls and waits at most 5 s for the first.
  NodeAccessorResult find_eu_range_accessor(
    const NodeId& parent, const std::shared_ptr<std::atomic<int>>& calls)
  {
    auto answered = std::make_shared<std::promise<NodeAccessorResult>>();
    auto future = answered->get_future();
    instance_utils::find_child_by_browse_name_async(*mAddressSpace,
      parent,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, "EURange"},
      [answered, calls](NodeAccessorResult result)
      {
        if (calls->fetch_add(1) == 0)
        {
          answered->set_value(std::move(result));
        }
      });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "find_child_by_browse_name_async did not complete";
      return NodeAccessorResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }

  boost::asio::thread_pool mPool{2};
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<FailingLookupNamespace> mNamespace;
  uint16_t mNsIndex{0};
  std::unordered_map<NodeId, NodeAccessor> mNodes;
};

}  // namespace

// DL-12: a target that could not be looked up may be the child asked for, so when no other target matches,
// the lookup answers that target's failure rather than Bad_NodeIdUnknown. A lookup that resolved every target
// still answers Bad_NodeIdUnknown (P2), and a match past a target that failed is found (P3): the controls.
// @relation(AC-COMP-ADDRSP-FIND-CHILD-BY-BROWSE-NAME-01-AN-UNRESOLVED-TARGET-IS-NOT-ABSENCE, scope=function)
TEST_F(FindChildIdByBrowseName, AnUnresolvedTargetWithNoMatchAnswersItsFailure)
{
  const StatusCode lookupFailed{Status::BadCommunicationError,
    ErrorDetail::build("LookupFailed", "The Node could not be looked up", "FindChildIdByBrowseNameTest")};
  const NodeId p1 = id(1);
  const NodeId t1 = id(2);
  const NodeId t2 = id(3);
  const NodeId p2 = id(10);
  const NodeId p3 = id(20);
  const NodeId t3 = id(21);
  const NodeId t4 = id(22);
  create_parent(p1);
  add_property(p1, t1, "Unreachable");
  add_property(p1, t2, "EngineeringUnits");
  create_parent(p2);
  add_property(p2, id(11), "EngineeringUnits");
  add_property(p2, id(12), "InstrumentRange");
  create_parent(p3);
  add_property(p3, t3, "Unreachable");
  add_property(p3, t4, "EURange");
  mNamespace->fail_lookups(t1, lookupFailed);
  mNamespace->fail_lookups(t3, lookupFailed);

  const auto onP1 = find_eu_range(p1);
  EXPECT_EQ(onP1.status_code().as_status(), Status::BadCommunicationError)
    << "P1: the lookup answered " << to_string(onP1.status_code()) << ", not T1's failure";
  EXPECT_TRUE(onP1.shared_detail() != nullptr && onP1.shared_detail()->code == "LookupFailed")
    << "P1: the lookup does not carry T1's ErrorDetail";

  const auto onP2 = find_eu_range(p2);
  EXPECT_EQ(onP2.status_code().as_status(), Status::BadNodeIdUnknown)
    << "P2: " << to_string(onP2.status_code());
  EXPECT_TRUE(onP2.shared_detail() != nullptr && onP2.shared_detail()->code == "BadNodeIdUnknown")
    << "P2: the lookup does not carry the ErrorDetail BadNodeIdUnknown";

  const auto onP3 = find_eu_range(p3);
  ASSERT_TRUE(onP3.is_good()) << "P3: " << to_string(onP3.status_code());
  EXPECT_EQ(onP3.value(), t4);

  // P5: one target whose lookup answers Uncertain with no Node.
  const NodeId p5 = id(50);
  const NodeId t5 = id(51);
  create_parent(p5);
  add_property(p5, t5, "Unreachable");
  mNamespace->fail_lookups(t5, StatusCode{Status::Uncertain});

  const auto onP5 = find_eu_range(p5);
  EXPECT_EQ(onP5.status_code().as_status(), Status::BadInternalError)
    << "P5: the lookup answered " << to_string(onP5.status_code());
  EXPECT_TRUE(onP5.shared_detail() != nullptr && onP5.shared_detail()->code == "LookupAnswerUncertain")
    << "P5: the lookup does not carry the ErrorDetail LookupAnswerUncertain";
  EXPECT_TRUE(onP5.shared_detail() != nullptr &&
              onP5.shared_detail()->innerStatus == StatusCode{Status::Uncertain}.value())
    << "P5: the ErrorDetail's cause is not T5's Uncertain answer";

  const auto calls = std::make_shared<std::atomic<int>>(0);
  const auto accessor = find_eu_range_accessor(p5, calls);
  EXPECT_EQ(accessor.status_code().as_status(), Status::BadInternalError)
    << "P5: find_child_by_browse_name_async answered " << to_string(accessor.status_code());
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(calls->load(), 1) << "P5: find_child_by_browse_name_async completed " << calls->load()
                              << " times";
}
