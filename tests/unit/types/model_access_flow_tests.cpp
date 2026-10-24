// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the address space's model access reads Values and browses: one lookup and one read_values_async call
// per namespace, as the server's own call (no CallerInfo); one lookup of the sources, rounds of one
// read_references_async per namespace and one lookup of the targets, with no permission call.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_address_space_model_access.h"
#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_result.h"
#include "ua_error_detail.h"
#include "ua_node_accessor.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

using namespace ua;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

NodeId create_variable(AddressSpace& addressSpace, uint16_t namespaceIndex, uint32_t numericId, int32_t value)
{
  const NodeId nodeId{namespaceIndex, numericId};
  auto created = addressSpace.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
  EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
  if (created.is_good())
  {
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    created.value().set_access_level(accessLevel);
    created.value().write_value_sync(DataValue{Variant{value}});
  }
  return nodeId;
}

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

void expect_one_lookup_and_one_value_read(
  const BatchRecordingNamespace& nameSpace, const std::vector<NodeId>& expected, const char* name)
{
  const auto lookups = nameSpace.calls(Member::BatchedLookup);
  EXPECT_EQ(lookups.size(), 1U) << name << ": batched lookups";
  if (lookups.size() == 1U)
  {
    EXPECT_EQ(sorted(lookups.front().nodeIds), sorted(expected))
      << name << ": the lookup names its Variables";
  }
  const auto reads = nameSpace.calls(Member::ReadValues);
  EXPECT_EQ(reads.size(), 1U) << name << ": read_values_async calls";
  if (reads.size() == 1U)
  {
    EXPECT_EQ(sorted(reads.front().nodeIds), sorted(expected)) << name << ": the call holds its Value items";
  }
  for (const auto& read : reads)
  {
    EXPECT_FALSE(read.hasCaller) << name << ": the model access's Value read carries a CallerInfo";
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-05-ONE-LOOKUP-AND-ONE-VALUE-READ-PER-NAMESPACE, scope=function)
TEST(ModelAccessFlow, OneLookupAndOneValueReadPerNamespace)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("urn:test:model-access-flow", threadPool.get_executor());
  auto r1 =
    std::make_shared<BatchRecordingNamespace>("urn:test:model-access-flow:r1", threadPool.get_executor());
  auto r2 =
    std::make_shared<BatchRecordingNamespace>("urn:test:model-access-flow:r2", threadPool.get_executor());
  const uint16_t index1 = addressSpace.add_namespace_sync(r1);
  const uint16_t index2 = addressSpace.add_namespace_sync(r2);

  // R1's three and R2's two, interleaved; each Variable's Value is 1000 plus its position in the request.
  const std::vector<std::pair<uint16_t, uint32_t>> layout{
    {index1, 100}, {index2, 200}, {index1, 101}, {index2, 201}, {index1, 102}};
  std::vector<NodeId> order;
  for (const auto& [namespaceIndex, numericId] : layout)
  {
    order.push_back(
      create_variable(addressSpace, namespaceIndex, numericId, static_cast<int32_t>(1000 + order.size())));
  }
  for (const auto& nameSpace : {r1, r2})
  {
    nameSpace->decline_single_lookups();
    nameSpace->reset();
  }

  std::vector<ReadValueId> reads;
  for (const auto& nodeId : order)
  {
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::Value);
    reads.push_back(std::move(item));
  }
  auto promise = std::make_shared<std::promise<Result<std::vector<DataValue>>>>();
  auto future = promise->get_future();
  dynamic_types::AddressSpaceModelAccess access{addressSpace};
  access.read_async(std::move(reads),
    [promise](Result<std::vector<DataValue>> result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(3s), std::future_status::ready) << "read_async did not complete";
  const auto result = future.get();

  expect_one_lookup_and_one_value_read(*r1, {order[0], order[2], order[4]}, "R1");
  expect_one_lookup_and_one_value_read(*r2, {order[1], order[3]}, "R2");

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), order.size());
  for (std::size_t i = 0; i < order.size(); ++i)
  {
    const auto& value = result.value()[i];
    EXPECT_TRUE(!value.status().has_value() || value.status()->is_good()) << "item " << i;
    ASSERT_TRUE(value.value().is_int32()) << "item " << i;
    EXPECT_EQ(value.value().as<int32_t>(), static_cast<int32_t>(1000 + i)) << "item " << i;
  }

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-11-THE-MODEL-ACCESS-BROWSES-WITH-ONE-CALL-OF-EACH-KIND-PER-NAMESPACE, scope=function)
TEST(ModelAccessFlow, BrowseMakesOneReferenceReadPerNamespace)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("urn:test:model-access-browse", threadPool.get_executor());
  auto r1 =
    std::make_shared<BatchRecordingNamespace>("urn:test:model-access-browse:r1", threadPool.get_executor());
  auto r2 =
    std::make_shared<BatchRecordingNamespace>("urn:test:model-access-browse:r2", threadPool.get_executor());
  const uint16_t index1 = addressSpace.add_namespace_sync(r1);
  const uint16_t index2 = addressSpace.add_namespace_sync(r2);

  // Each namespace holds two sources, each with forward HasComponent References to two Objects of its own
  // namespace; each target holds the inverse half.
  struct Source
  {
    NodeId nodeId;
    std::vector<NodeId> targets;
  };

  std::vector<Source> sources;
  for (const uint16_t namespaceIndex : {index1, index2})
  {
    for (uint32_t s = 1; s <= 2; ++s)
    {
      Source source{NodeId{namespaceIndex, 100u + s}, {}};
      auto created = addressSpace.try_create_sync<ObjectAccessor>(source.nodeId, NodeClass::Object);
      ASSERT_TRUE(created.is_good()) << "creating " << source.nodeId.as_definition();
      for (uint32_t t = 1; t <= 2; ++t)
      {
        const NodeId target{namespaceIndex, 100u * (s + 1) + t};
        auto targetNode = addressSpace.try_create_sync<ObjectAccessor>(target, NodeClass::Object);
        ASSERT_TRUE(targetNode.is_good()) << "creating " << target.as_definition();
        ASSERT_TRUE(
          created.value()
            .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{target}, true)
            .is_good());
        ASSERT_TRUE(targetNode.value()
                      .try_add_reference_sync(
                        NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{source.nodeId}, false)
                      .is_good());
        source.targets.push_back(target);
      }
      sources.push_back(std::move(source));
    }
  }
  for (const auto& nameSpace : {r1, r2})
  {
    nameSpace->decline_single_lookups();
    nameSpace->decline_immediate_permissions();
    nameSpace->reset();
  }

  std::vector<BrowseDescription> descriptions;
  for (const auto& source : sources)
  {
    BrowseDescription description;
    description.node_id() = source.nodeId;
    description.browse_direction() = BrowseDirection::Forward;
    description.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    description.include_subtypes() = true;
    description.result_mask() = 0x3f;
    descriptions.push_back(std::move(description));
  }
  auto promise = std::make_shared<std::promise<Result<std::vector<BrowseResult>>>>();
  auto future = promise->get_future();
  dynamic_types::AddressSpaceModelAccess access{addressSpace};
  access.browse_async(std::move(descriptions),
    [promise](Result<std::vector<BrowseResult>> result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(3s), std::future_status::ready) << "browse_async did not complete";
  const auto result = future.get();

  const std::vector<std::pair<const char*, const BatchRecordingNamespace*>> named{
    {"R1", r1.get()}, {"R2", r2.get()}};
  for (std::size_t n = 0; n < named.size(); ++n)
  {
    const auto& [name, nameSpace] = named[n];
    const std::vector<NodeId> own{sources[2 * n].nodeId, sources[2 * n + 1].nodeId};
    const auto reads = nameSpace->calls(Member::ReadReferences);
    EXPECT_EQ(reads.size(), 1U) << name << ": read_references_async calls";
    if (reads.size() == 1U)
    {
      EXPECT_EQ(sorted(reads.front().nodeIds), sorted(own)) << name << ": the call names its two sources";
      for (const auto& query : reads.front().referenceQueries)
      {
        EXPECT_EQ(query.maxReferences, 0U) << name << ": the query naming " << query.nodeId.as_definition();
      }
    }
    EXPECT_LE(nameSpace->count(Member::BatchedLookup), 2U) << name << ": batched lookups";
    for (const auto member : {Member::ImmediatePermissionsOfNode, Member::PermissionsAsyncForRequest})
    {
      EXPECT_EQ(nameSpace->count(member), 0U)
        << name << ": permissions calls of kind " << static_cast<int>(member);
    }
  }

  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), sources.size());
  for (std::size_t i = 0; i < sources.size(); ++i)
  {
    const auto& browsed = result.value()[i];
    EXPECT_TRUE(browsed.status_code().is_good())
      << "source " << i << ": " << to_string(browsed.status_code());
    std::vector<NodeId> targets;
    for (const auto& reference : browsed.references())
    {
      targets.push_back(reference.node_id().node_id());
    }
    EXPECT_EQ(sorted(targets), sorted(sources[i].targets)) << "source " << i;
  }

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-11-A-MODEL-ACCESS-BROWSE-KEEPS-ITS-LOOKUPS-STATUS-AND-DETAIL, scope=function)
TEST(ModelAccessFlow, ABrowseKeepsItsLookupsStatusAndDetail)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("urn:test:model-access-lookup-status", threadPool.get_executor());
  auto r = std::make_shared<BatchRecordingNamespace>(
    "urn:test:model-access-lookup-status:r", threadPool.get_executor());
  const uint16_t index = addressSpace.add_namespace_sync(r);
  const NodeId s1{index, 101u};
  const NodeId s2{index, 102u};
  for (const auto& [source, target] :
    {std::pair{s1, NodeId{index, 201u}}, std::pair{s2, NodeId{index, 202u}}})
  {
    auto sourceNode = addressSpace.try_create_sync<ObjectAccessor>(source, NodeClass::Object);
    ASSERT_TRUE(sourceNode.is_good()) << "creating " << source.as_definition();
    auto targetNode = addressSpace.try_create_sync<ObjectAccessor>(target, NodeClass::Object);
    ASSERT_TRUE(targetNode.is_good()) << "creating " << target.as_definition();
    ASSERT_TRUE(sourceNode.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{target}, true)
                  .is_good());
  }
  r->answer_lookup_of(s1,
    StatusCode{Status::BadResourceUnavailable,
      ErrorDetail::build(
        "LookupFailedSentinel", "The test's namespace cannot look this Node up", "TestNamespace")});
  r->answer_lookup_of(s2,
    StatusCode{Status::Uncertain,
      ErrorDetail::build(
        "UncertainLookupSentinel", "The test's namespace cannot say what this Node is", "TestNamespace")});
  r->reset();

  std::vector<BrowseDescription> descriptions;
  for (const auto& source : {s1, s2})
  {
    BrowseDescription description;
    description.node_id() = source;
    description.browse_direction() = BrowseDirection::Forward;
    description.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    description.include_subtypes() = true;
    description.result_mask() = 0x3f;
    descriptions.push_back(std::move(description));
  }
  auto promise = std::make_shared<std::promise<Result<std::vector<BrowseResult>>>>();
  auto future = promise->get_future();
  dynamic_types::AddressSpaceModelAccess access{addressSpace};
  access.browse_async(std::move(descriptions),
    [promise](Result<std::vector<BrowseResult>> result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(3s), std::future_status::ready) << "browse_async did not complete";
  const auto result = future.get();

  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().size(), 2U);
  const auto detailOf = [](const StatusCode& status)
  {
    return status.shared_detail() ? status.shared_detail()->code : std::string{};
  };
  const auto& first = result.value()[0];
  EXPECT_EQ(first.status_code().as_status(), Status::BadResourceUnavailable)
    << "S1 answered " << to_string(first.status_code());
  EXPECT_EQ(detailOf(first.status_code()), "LookupFailedSentinel");
  EXPECT_TRUE(first.references().empty()) << "S1 returned " << first.references().size() << " References";
  const auto& second = result.value()[1];
  EXPECT_EQ(second.status_code().as_status(), Status::Uncertain)
    << "S2 answered " << to_string(second.status_code());
  EXPECT_EQ(detailOf(second.status_code()), "UncertainLookupSentinel");
  EXPECT_TRUE(second.references().empty()) << "S2 returned " << second.references().size() << " References";

  ::ua::test_utils::drain_with_timeout(threadPool);
}
