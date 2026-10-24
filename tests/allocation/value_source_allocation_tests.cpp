// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// NR-13a's proof: the heap allocations the in-memory namespace makes for one Variable's Value read through a
// ValueSource. The binary replaces the global operator new to count them, which is why it is a binary of its
// own.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_to_string.h"
#include "ua_value_source.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

#include <cstdlib>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <span>

namespace
{

// Counted only on the thread that measures, between the two marks.
thread_local bool gCounting = false;
thread_local std::size_t gAllocations = 0;

}  // namespace

void* operator new(std::size_t size)
{
  if (gCounting)
  {
    ++gAllocations;
  }
  if (void* allocated = std::malloc(size == 0 ? 1 : size))
  {
    return allocated;
  }
  throw std::bad_alloc{};
}

void operator delete(void* allocated) noexcept
{
  std::free(allocated);
}

void operator delete(void* allocated, std::size_t) noexcept
{
  std::free(allocated);
}

using namespace ua;

namespace
{

// A source that answers each read inline with the Int32 7, allocating nothing.
class InlineSource final : public ValueSource
{
public:
  void read_async(const ReadContext&, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    ++calls;
    BatchResult<DataValueResult> answer;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answer.items.emplace_back(DataValue{Variant{int32_t{7}}});
    }
    complete(std::move(answer));
  }

  // Answers each write inline as applied, allocating nothing.
  void write_async(const WriteContext&, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    ++writeCalls;
    BatchResult<WriteResult> answer;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answer.items.emplace_back(Written{});
    }
    complete(std::move(answer));
  }

  int calls{0};
  int writeCalls{0};
};

// NR-13a rule 1: one item goes to its source with the completion passed through: no grouping state, no join,
// no reassembly and no heap allocation by the namespace.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-02-A-SINGLE-ITEM-READ-ALLOCATES-NOTHING, scope=function)
TEST(ValueSourceAllocation, ASingleItemReadAllocatesNothingInTheNamespace)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:value-source-allocation", pool.get_executor());
    auto nameSpace =
      default_ns::Namespace::create("urn:test:value-source-allocation:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    ASSERT_TRUE(addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {}).is_good());
    auto found = nameSpace->find_node(variableId, std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good());
    std::shared_ptr<Node> node = found->value();
    auto source = std::make_shared<InlineSource>();
    ASSERT_TRUE(node->external_value_source()->set_value_source(source).is_good());

    ReadValueId read;
    read.node_id() = variableId;
    read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    const ValueReadItem item{*node, read};
    const RequestInfo request;
    DataValueResult answered{StatusCode{Status::BadInternalError}};
    const std::function<void(BatchResult<DataValueResult>)> complete = [&answered](
                                                                         BatchResult<DataValueResult> read)
    {
      answered = std::move(read.items.front());
    };
    // Once before counting, so that nothing created on first use is counted.
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, complete);
    std::function<void(BatchResult<DataValueResult>)> measured = complete;

    gAllocations = 0;
    gCounting = true;
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, std::move(measured));
    gCounting = false;

    EXPECT_EQ(gAllocations, 0U) << "the namespace allocated for a single-item read through a source";
    EXPECT_EQ(source->calls, 2);
    ASSERT_TRUE(answered.is_good()) << to_string(answered.status_code());
    EXPECT_EQ(answered.value().value(), Variant{int32_t{7}});
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// A single-item write goes to its source with one block allocated by the namespace: its completion wrapper.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-03-A-SINGLE-ITEM-WRITE-ALLOCATES-ONE-BLOCK, scope=function)
TEST(ValueSourceAllocation, ASingleItemWriteAllocatesOneBlock)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:value-source-allocation-write", pool.get_executor());
    auto nameSpace =
      default_ns::Namespace::create("urn:test:value-source-allocation-write:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    auto created = addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {});
    ASSERT_TRUE(created.is_good());
    auto accessor = created.value().as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_data_type(NodeId{DataTypeId::Int32});
    accessor->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto found = nameSpace->find_node(variableId, std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good());
    std::shared_ptr<Node> node = found->value();
    auto source = std::make_shared<InlineSource>();
    ASSERT_TRUE(node->external_value_source()->set_value_source(source).is_good());

    WriteValue write;
    write.node_id() = variableId;
    write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    write.value() = DataValue{Variant{int32_t{9}}};
    const ValueWriteItem item{*node, write};
    const RequestInfo request;
    StatusCode answered{Status::BadInternalError};
    const std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete =
      [&answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
    {
      answered = written.items.front().status_code();
    };
    // Once before counting, so that nothing created on first use is counted.
    nameSpace->write_async(request, nullptr, std::span<const ValueWriteItem>{&item, 1}, complete);
    answered = StatusCode{Status::BadInternalError};
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> measured = complete;

    gAllocations = 0;
    gCounting = true;
    nameSpace->write_async(request, nullptr, std::span<const ValueWriteItem>{&item, 1}, std::move(measured));
    gCounting = false;

    EXPECT_EQ(gAllocations, 1U) << "the namespace did not allocate exactly its completion wrapper";
    EXPECT_EQ(source->writeCalls, 2);
    EXPECT_EQ(answered, StatusCode{Status::Good}) << to_string(answered);
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// An Int32 Variable of a fresh in-memory namespace that reads and writes, with no application source.
std::shared_ptr<Node> create_int32_variable(
  AddressSpace& addressSpace, default_ns::Namespace& nameSpace, const NodeId& variableId)
{
  auto created = addressSpace.try_create_node_sync(variableId, NodeClass::Variable, {});
  if (created.is_bad())
  {
    return nullptr;
  }
  auto accessor = created.value().as<VariableAccessor>();
  if (!accessor.has_value())
  {
    return nullptr;
  }
  accessor->set_data_type(NodeId{DataTypeId::Int32});
  accessor->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  auto found = nameSpace.find_node(variableId, std::nullopt);
  return found.has_value() && found->is_good() ? found->value() : nullptr;
}

WriteValue int32_write(const NodeId& variableId, int32_t value)
{
  WriteValue write;
  write.node_id() = variableId;
  write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write.value() = DataValue{Variant{value}};
  return write;
}

// DL-115 (2): a Variable with no application source keeps NR-13a rule 1's cost. The namespace reads its
// default source through the source's synchronous member, so a single-item Int32 read allocates nothing.
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-06-A-SINGLE-ITEM-DEFAULT-SOURCE-READ-ALLOCATES-NOTHING, scope=function)
TEST(ValueSourceAllocation, ASingleItemReadOfAVariableOnItsDefaultSourceAllocatesNothing)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:default-source-allocation-read", pool.get_executor());
    auto nameSpace =
      default_ns::Namespace::create("urn:test:default-source-allocation-read:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    std::shared_ptr<Node> node = create_int32_variable(addressSpace, *nameSpace, variableId);
    ASSERT_NE(node, nullptr);
    const RequestInfo request;
    const WriteValue seed = int32_write(variableId, 5);
    const ValueWriteItem seedItem{*node, seed};
    StatusCode seeded{Status::BadInternalError};
    nameSpace->write_async(request,
      nullptr,
      std::span<const ValueWriteItem>{&seedItem, 1},
      [&seeded](BatchResult<VoidResult> written, std::vector<VersionedNode>)
      { seeded = written.items.front().status_code(); });
    ASSERT_EQ(seeded, StatusCode{Status::Good}) << to_string(seeded);

    ReadValueId read;
    read.node_id() = variableId;
    read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    const ValueReadItem item{*node, read};
    DataValueResult answered{StatusCode{Status::BadInternalError}};
    const std::function<void(BatchResult<DataValueResult>)> complete = [&answered](
                                                                         BatchResult<DataValueResult> read)
    {
      answered = std::move(read.items.front());
    };
    // Once before counting, so that nothing created on first use is counted.
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, complete);
    std::function<void(BatchResult<DataValueResult>)> measured = complete;

    gAllocations = 0;
    gCounting = true;
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, std::move(measured));
    gCounting = false;

    EXPECT_EQ(gAllocations, 0U) << "the namespace allocated for a single-item read of its default source";
    ASSERT_TRUE(answered.is_good()) << to_string(answered.status_code());
    EXPECT_EQ(answered.value().value(), Variant{int32_t{5}});
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// A Variable never written has no source at all; its read takes the same direct path and answers a null Value
// without allocating (NR-13a rule 1).
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-06-A-SINGLE-ITEM-READ-OF-A-NEVER-WRITTEN-VARIABLE-ALLOCATES-NOTHING, scope=function)
TEST(ValueSourceAllocation, ASingleItemReadOfAVariableNeverWrittenAllocatesNothing)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:unwritten-allocation-read", pool.get_executor());
    auto nameSpace =
      default_ns::Namespace::create("urn:test:unwritten-allocation-read:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    std::shared_ptr<Node> node = create_int32_variable(addressSpace, *nameSpace, variableId);
    ASSERT_NE(node, nullptr);
    const RequestInfo request;
    ReadValueId read;
    read.node_id() = variableId;
    read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    const ValueReadItem item{*node, read};
    DataValueResult answered{StatusCode{Status::BadInternalError}};
    const std::function<void(BatchResult<DataValueResult>)> complete = [&answered](
                                                                         BatchResult<DataValueResult> read)
    {
      answered = std::move(read.items.front());
    };
    // Once before counting, so that nothing created on first use is counted.
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, complete);
    std::function<void(BatchResult<DataValueResult>)> measured = complete;

    gAllocations = 0;
    gCounting = true;
    nameSpace->read_values_async(
      request, nullptr, std::span<const ValueReadItem>{&item, 1}, 0.0, false, std::move(measured));
    gCounting = false;

    EXPECT_EQ(gAllocations, 0U)
      << "the namespace allocated for a single-item read of a Variable never written";
    ASSERT_TRUE(answered.is_good()) << to_string(answered.status_code());
    EXPECT_TRUE(answered.value().value().empty());
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// DL-115 (2): the namespace writes a Variable's default source through the source's synchronous member, with
// no completion wrapper, so a single-item Int32 write allocates nothing.
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-06-A-SINGLE-ITEM-DEFAULT-SOURCE-WRITE-ALLOCATES-NOTHING, scope=function)
TEST(ValueSourceAllocation, ASingleItemWriteToAVariableOnItsDefaultSourceAllocatesNothing)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:default-source-allocation-write", pool.get_executor());
    auto nameSpace =
      default_ns::Namespace::create("urn:test:default-source-allocation-write:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    std::shared_ptr<Node> node = create_int32_variable(addressSpace, *nameSpace, variableId);
    ASSERT_NE(node, nullptr);

    const WriteValue write = int32_write(variableId, 9);
    const ValueWriteItem item{*node, write};
    const RequestInfo request;
    StatusCode answered{Status::BadInternalError};
    const std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete =
      [&answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
    {
      answered = written.items.front().status_code();
    };
    // Once before counting, so that nothing created on first use - the default source itself - is counted.
    nameSpace->write_async(request, nullptr, std::span<const ValueWriteItem>{&item, 1}, complete);
    ASSERT_EQ(answered, StatusCode{Status::Good}) << to_string(answered);
    answered = StatusCode{Status::BadInternalError};
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> measured = complete;

    gAllocations = 0;
    gCounting = true;
    nameSpace->write_async(request, nullptr, std::span<const ValueWriteItem>{&item, 1}, std::move(measured));
    gCounting = false;

    EXPECT_EQ(gAllocations, 0U) << "the namespace allocated for a single-item write to its default source";
    EXPECT_EQ(answered, StatusCode{Status::Good}) << to_string(answered);
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// What the route allocates for an accessor's one-item Value read and write (NR-2 rule 4): their completion
// state and std::function's heap copy of the function object that holds it.
constexpr std::size_t oneItemValueReadBlocks = 2;
constexpr std::size_t oneItemValueWriteBlocks = 2;

// NR-2 rule 4: a one-item accessor call adds no batch state. On an in-memory Variable, which the namespace
// reads and writes on the caller's stack without allocating, a lookup the namespace answers through find_node
// allocates nothing, and a Value read or write allocates only its completion's state. Each call is counted
// alone, after one uncounted call of each.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-06-A-ONE-ITEM-ACCESSOR-CALL-ALLOCATES-ONLY-ITS-COMPLETION-STATE, scope=function)
TEST(RouteAllocation, AOneItemAccessorCallAllocatesOnlyItsCompletionState)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:route-allocation", pool.get_executor());
    auto nameSpace = default_ns::Namespace::create("urn:test:route-allocation:own", pool.get_executor());
    auto index = addressSpace.try_add_namespace_sync(nameSpace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const NodeId variableId{index.value(), "V"};
    ASSERT_NE(create_int32_variable(addressSpace, *nameSpace, variableId), nullptr);
    auto found = addressSpace.try_find_node_sync(variableId);
    ASSERT_TRUE(found.is_good());
    auto variable = found.value().as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    ASSERT_TRUE(variable->try_write_value_sync(int32_write(variableId, 5)).is_good());

    ReadValueId read;
    read.node_id() = variableId;
    read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    const WriteValue write = int32_write(variableId, 6);
    StatusCode lookedUp{Status::BadInternalError};
    StatusCode readStatus{Status::BadInternalError};
    StatusCode written{Status::BadInternalError};
    const AddressSpace::FindNodeCompleteCallback onFound = [&lookedUp](NodeAccessorResult result)
    {
      lookedUp = result.status_code();
    };
    const NodeAccessor::ReadValueCompleteCallback onRead = [&readStatus](DataValueResult result)
    {
      readStatus = result.status_code();
    };
    const NodeAccessor::WriteValueCompleteCallback onWritten = [&written](VoidResult result)
    {
      written = result.status_code();
    };

    const auto count = [](const std::function<void()>& call)
    {
      gAllocations = 0;
      gCounting = true;
      call();
      gCounting = false;
      return gAllocations;
    };
    // Each once before counting, so that nothing created on first use is counted.
    addressSpace.find_node_async(variableId, onFound);
    variable->read_value_async(0.0, false, read, nullptr, onRead);
    variable->write_value_async(write, nullptr, onWritten);

    auto findCallback = onFound;
    auto readCallback = onRead;
    auto writeCallback = onWritten;
    const std::function<void()> find = [&]
    {
      addressSpace.find_node_async(variableId, std::move(findCallback));
    };
    const std::function<void()> readValue = [&]
    {
      variable->read_value_async(0.0, false, read, nullptr, std::move(readCallback));
    };
    const std::function<void()> writeValue = [&]
    {
      variable->write_value_async(write, nullptr, std::move(writeCallback));
    };
    EXPECT_EQ(count(find), 0U) << "find_node_async allocated";
    EXPECT_EQ(count(readValue), oneItemValueReadBlocks)
      << "read_value_async allocated more than its completion";
    EXPECT_EQ(count(writeValue), oneItemValueWriteBlocks)
      << "write_value_async allocated more than its completion";
    EXPECT_EQ(lookedUp, StatusCode{Status::Good}) << to_string(lookedUp);
    EXPECT_EQ(readStatus, StatusCode{Status::Good}) << to_string(readStatus);
    EXPECT_EQ(written, StatusCode{Status::Good}) << to_string(written);
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

}  // namespace

namespace
{

}  // namespace
