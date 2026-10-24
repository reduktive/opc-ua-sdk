// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Address-space defects the redesign fixes, at the namespace contract (address_space_1_0.md P0).
///
/// Each test was red until its fix landed (the address-space redesign defect record): the
/// namespace interface has no delete flag (SB-5), contains a namespace's exceptions (N1) and checks every
/// batch it receives (N13).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <memory>
#include <span>
#include <vector>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace.h"
#include "ua_node_accessor.h"
#include "ua_referencetype_id.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Forwards to a default namespace, with one misbehaviour switched on per test.
class ContractTestNamespace final : public Namespace
{
public:
  enum class Batch
  {
    AsAnswered,
    OneExtraItem,
    FailedBatchStatus,
  };

  ContractTestNamespace(std::shared_ptr<default_ns::Namespace> inner, Batch batch)
    : mInner(std::move(inner)), mBatch(batch)
  {}

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  String uri() const override
  {
    return mInner->uri();
  }

  // No immediate find_node: every lookup takes the batch path, which is the one under test.
  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->find_nodes_async(request,
      nodeIds,
      maxAge,
      [batch = mBatch, complete = std::move(complete)](BatchResult<NodeResult> result) mutable
      {
        switch (batch)
        {
        case Batch::AsAnswered:
          break;
        case Batch::OneExtraItem:
          if (!result.items.empty())
          {
            auto first = result.items[0];
            result.items.push_back(std::move(first));
          }
          break;
        case Batch::FailedBatchStatus:
          result.batchStatus = VoidResult{Status::BadInternalError,
            ErrorDetail::build(
              "InjectedBatchFailure", "The namespace failed the batch", "ContractTestNamespace")};
          break;
        }
        complete(std::move(result));
      });
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    for (const NodeId& nodeId : nodes)
    {
      deleted.push_back(nodeId);
    }
    mInner->delete_nodes_async(request, nodes, halves, std::move(complete));
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->add_references_async(request, changes, std::move(complete));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->remove_references_async(request, changes, std::move(complete));
  }

  // The NodeIds delete_nodes_async was asked to delete, in order.
  std::vector<NodeId> deleted;

private:
  std::shared_ptr<default_ns::Namespace> mInner;
  Batch mBatch;

  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }
};

struct Fixture
{
  explicit Fixture(ContractTestNamespace::Batch batch)
  {
    addressSpace.emplace(AddressSpace::create("urn:test:redesign-defects", pool.get_executor()));
    auto inner = default_ns::Namespace::create("urn:test:redesign-contract", pool.get_executor());
    space = std::make_shared<ContractTestNamespace>(inner, batch);
    index = addressSpace->add_namespace_sync(space);
  }

  ~Fixture()
  {
    addressSpace.reset();
    ::ua::test_utils::drain_with_timeout(pool);
  }

  BatchResult<NodeAccessorResult> find(std::vector<NodeId> ids)
  {
    std::promise<BatchResult<NodeAccessorResult>> answered;
    addressSpace->find_nodes_async(
      ids, [&answered](BatchResult<NodeAccessorResult> r) { answered.set_value(std::move(r)); });
    auto future = answered.get_future();
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready);
    return future.get();
  }

  boost::asio::thread_pool pool{2};
  std::optional<AddressSpace> addressSpace;
  std::shared_ptr<ContractTestNamespace> space;
  uint16_t index{0};
};

}  // namespace

// SB-5. A namespace deletes exactly the Nodes it is asked to delete (Namespace::delete_nodes_async, which
// takes no flag): a single-node delete asks for the Node alone, and its child stays. Part 4 section 5.7.4
// keeps deleteTargetReferences apart from child deletion, which is the Server's choice.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-02-A-SINGLE-NODE-DELETE-LEAVES-THE-CHILDREN, scope=function)
TEST(AddressSpaceRedesignDefects, ASingleNodeDeleteLeavesTheNodesChildren)
{
  Fixture fixture{ContractTestNamespace::Batch::AsAnswered};
  const NodeId parent{fixture.index, uint32_t{1}};
  const NodeId child{fixture.index, uint32_t{2}};
  auto parentNode = fixture.addressSpace->try_create_node_sync(parent, NodeClass::Object, {});
  ASSERT_TRUE(parentNode.is_good());
  ASSERT_TRUE(fixture.addressSpace->try_create_node_sync(child, NodeClass::Object, {}).is_good());
  parentNode.value().add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{child});

  ASSERT_TRUE(
    fixture.addressSpace->try_delete_node_sync(parent, /*deleteForwardHierarchicallyReferencedNodes=*/false)
      .is_good());

  EXPECT_EQ(fixture.space->deleted, std::vector<NodeId>{parent});
  EXPECT_TRUE(fixture.addressSpace->try_find_node_sync(child).is_good())
    << "a single-node delete must leave the Node's children";
}

// N13. A batch with more items than were asked for breaks the contract; the call's items are
// Bad_InternalError (address_space_1_0.md section 4.2, resolution rule 3).
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-WRONG-ITEM-COUNT-FAILS-THE-CALLS-ITEMS, scope=function)
TEST(AddressSpaceRedesignDefects, ABatchWithTheWrongItemCountFailsTheCallsItems)
{
  Fixture fixture{ContractTestNamespace::Batch::OneExtraItem};
  const NodeId only{fixture.index, uint32_t{20}};
  ASSERT_TRUE(fixture.addressSpace->try_create_node_sync(only, NodeClass::Object, {}).is_good());

  auto answer = fixture.find({only});
  ASSERT_EQ(answer.items.size(), 1u);
  EXPECT_EQ(answer.items[0].status_code().as_status(), Status::BadInternalError);
}

// N13. A batch the namespace failed as a whole fails the call's items, whatever items it carries.
// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-02-A-FAILED-BATCH-STATUS-FAILS-THE-CALLS-ITEMS, scope=function)
TEST(AddressSpaceRedesignDefects, AFailedBatchStatusFailsTheCallsItems)
{
  Fixture fixture{ContractTestNamespace::Batch::FailedBatchStatus};
  const NodeId only{fixture.index, uint32_t{30}};
  ASSERT_TRUE(fixture.addressSpace->try_create_node_sync(only, NodeClass::Object, {}).is_good());

  auto answer = fixture.find({only});
  ASSERT_EQ(answer.items.size(), 1u);
  EXPECT_TRUE(answer.items[0].is_bad()) << "the namespace failed this batch";
  const auto& status = answer.items[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadInternalError) << "the item is not the batch status answered";
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "InjectedBatchFailure");
}

// Control for N13: answered as asked, the same lookups resolve.
TEST(AddressSpaceRedesignDefects, AWellFormedBatchResolvesEachNode)
{
  Fixture fixture{ContractTestNamespace::Batch::AsAnswered};
  const NodeId first{fixture.index, uint32_t{40}};
  const NodeId second{fixture.index, uint32_t{41}};
  ASSERT_TRUE(fixture.addressSpace->try_create_node_sync(first, NodeClass::Object, {}).is_good());
  ASSERT_TRUE(fixture.addressSpace->try_create_node_sync(second, NodeClass::Object, {}).is_good());

  auto answer = fixture.find({first, second});
  ASSERT_EQ(answer.items.size(), 2u);
  ASSERT_TRUE(answer.items[0].is_good());
  ASSERT_TRUE(answer.items[1].is_good());
  EXPECT_EQ(answer.items[0].value().get_node_id(), first);
  EXPECT_EQ(answer.items[1].value().get_node_id(), second);
}

// N1. A write through an accessor whose Node has been deleted terminates the process: the exception
// "Node has been deleted" crosses a noexcept boundary (ua_node_accessor.cpp:521-528). The write must be
// answered with a Bad status instead. Run in a child process, so that a termination fails this test alone.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-01-A-WRITE-TO-A-DELETED-VARIABLE-IS-ANSWERED, scope=function)
TEST(AddressSpaceRedesignDefectsDeathTest, AWriteThroughAnAccessorToADeletedVariableIsAnswered)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto writeToTheDeletedVariable = []
  {
    boost::asio::thread_pool pool{2};
    auto addressSpace = AddressSpace::create("urn:test:redesign-n1", pool.get_executor());
    const NodeId id{1, "redesign-n1-variable"};
    auto created = addressSpace.try_create_node_sync(id, NodeClass::Variable, {});
    if (created.is_bad())
    {
      std::_Exit(2);
    }
    auto variable = created.value().as<VariableAccessor>();
    if (!variable.has_value())
    {
      std::_Exit(3);
    }
    if (addressSpace.try_delete_node_sync(id, false).is_bad())
    {
      std::_Exit(4);
    }
    auto answered = std::make_shared<std::promise<bool>>();
    variable->write_value_async(DataValue{Variant{int32_t{1}}},
      [answered](VoidResult result) { answered->set_value(result.is_bad()); });
    auto future = answered->get_future();
    if (future.wait_for(5s) != std::future_status::ready)
    {
      std::_Exit(5);
    }
    std::_Exit(future.get() ? 0 : 6);
  };
  EXPECT_EXIT(writeToTheDeletedVariable(), ::testing::ExitedWithCode(0), "");
}
