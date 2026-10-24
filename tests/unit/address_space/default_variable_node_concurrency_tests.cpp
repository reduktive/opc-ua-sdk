// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// TSan regression test for the default in-memory VariableNode value store.
//
// default_ns::VariableNode::set_default_handlers() installs a read handler and a
// write handler that share a single optional<DataValue> "value store". The node's
// read_value() / write_value_async() copy the handler out under mMutex but invoke it
// OUTSIDE the lock (the callback-safety rule forbids running a callback while
// holding a lock). The two handlers can therefore execute concurrently on
// different threads, so the shared value store must carry its own
// synchronization. Without it, a concurrent read_value/write_value pair races on
// the stored DataValue (the gcc-tsan failure this test pins).
//
// The handlers are synchronous, so driving read_value/write_value from separate
// threads runs the handler bodies genuinely concurrently - under TSan this fails
// loudly if the store is unsynchronized, and under any build it verifies that
// concurrent access stays functionally correct (every op completes good).

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_default_variable_node.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_node_accessor.h"
#include "ua_error_detail.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_value_source.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <atomic>
#include <functional>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace ua;

namespace
{

WriteValue make_value_write(const NodeId& nodeId, int32_t payload)
{
  WriteValue wv;
  wv.node_id() = nodeId;
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value() = DataValue{Variant{payload}};
  return wv;
}

}  // namespace

// OPC 10000-3 section 5.6.2: Value is a mandatory attribute of every Variable. A freshly created Variable
// that has never been written and has no value source must still return its (null) Value with a good
// status on a Read - not BadAttributeIdInvalid (which is reserved for node classes that lack the
// attribute). This backs materialised-but-unwired condition property nodes (BranchId, ClientUserId,
// ShelvingState.CurrentState) whose SourceTimestamp would otherwise be dropped (F86).
TEST(DefaultVariableNode, UnwrittenVariableValueReadIsGoodNotBadAttributeIdInvalid)
{
  const NodeId nodeId{1, "never-written"};
  auto node = default_ns::VariableNode::create(nodeId);

  std::optional<DataValueResult> captured;
  ReadValueId toRead;
  node->read_value(
    0.0, true, toRead, nullptr, [&captured](DataValueResult result) { captured = std::move(result); });

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  const auto& dv = captured->value();
  EXPECT_FALSE(dv.status().has_value() && dv.status()->is_bad());
  EXPECT_TRUE(dv.value().empty());
}

TEST(DefaultVariableNode, FreshVariableHasMandatoryScalarValueRank)
{
  boost::asio::thread_pool pool{1};
  auto addressSpace = AddressSpace::create("urn:test:default-value-rank", pool.get_executor());
  auto variable =
    addressSpace.create_sync<VariableAccessor>(NodeId{1, "default-value-rank"}, NodeClass::Variable);

  EXPECT_TRUE(variable.get_value_rank().is_scalar());

  variable.set_value_rank(ValueRank{2});
  EXPECT_EQ(variable.get_value_rank().as_int32(), 2);
}

// Regression (use-after-move-in-catch -> process abort): a value handler that THROWS before invoking
// its completion callback must still complete the callback with a converted error status, NOT abort.
// read_value/write_value used to pass the callback into the handler by std::move, leaving the outer
// std::function EMPTY; a pre-completion throw then drove the catch to invoke that empty std::function
// -> std::bad_function_call escaping the noexcept VariableAccessor::read_value_async -> std::terminate.
// The fix passes the callback by COPY so the error path can complete it. Before the fix these tests
// abort the test process; after, they observe a single bad-status completion.
TEST(DefaultVariableNode, ReadValueHandlerThrowingBeforeCompletionDeliversErrorNotTerminate)
{
  const NodeId nodeId{1, "read-handler-throws"};
  auto node = default_ns::VariableNode::create(nodeId);
  node->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)> /*callback*/)
    { throw std::runtime_error("read handler failed before completing the callback"); },
    [](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)>
        callback) { callback(ValueSource::Written{}); }));

  std::optional<DataValueResult> captured;
  int calls = 0;
  ReadValueId toRead;
  EXPECT_NO_THROW(node->read_value(0.0,
    true,
    toRead,
    nullptr,
    [&calls, &captured](DataValueResult result)
    {
      ++calls;
      captured = std::move(result);
    }));
  ASSERT_EQ(calls, 1) << "the throwing handler's error must be delivered to the callback exactly once";
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
}

TEST(DefaultVariableNode, WriteValueHandlerThrowingBeforeCompletionDeliversErrorNotTerminate)
{
  const NodeId nodeId{1, "write-handler-throws"};
  auto node = default_ns::VariableNode::create(nodeId);
  node->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               callback) { callback(DataValue{}); },
    [](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)> /*callback*/)
    { throw std::runtime_error("write handler failed before completing the callback"); }));

  std::optional<VoidResult> captured;
  int calls = 0;
  EXPECT_NO_THROW(node->write_value_async(make_value_write(nodeId, 7),
    nullptr,
    [&calls, &captured](VoidResult result)
    {
      ++calls;
      captured = result;
    }));
  ASSERT_EQ(calls, 1) << "the throwing handler's error must be delivered to the callback exactly once";
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
}

// @relation(AC-COMP-SVR-VARIABLE-WRITE-RESULT-01-SENTINEL, scope=function)
TEST(DefaultVariableNode, WriteValueHandlerFailurePreservesExactSentinelResult)
{
  const NodeId nodeId{1, "write-handler-sentinel"};
  auto node = default_ns::VariableNode::create(nodeId);
  shared_ptr<const ErrorDetail> stagedDetail =
    make_error_detail("WriteHandlerSentinel", "injected write-handler failure", "DefaultVariableNodeTest");
  node->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               callback) { callback(DataValue{}); },
    [stagedDetail](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)>
        callback) { callback(ValueSource::WriteResult{Status::BadResourceUnavailable, stagedDetail}); }));

  std::optional<VoidResult> captured;
  int calls = 0;
  node->write_value_async(make_value_write(nodeId, 19),
    nullptr,
    [&calls, &captured](VoidResult result)
    {
      ++calls;
      captured = std::move(result);
    });

  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), Status::BadResourceUnavailable);
  EXPECT_EQ(captured->shared_detail(), stagedDetail);
}

// Regression (double-fire -> std::future_error -> std::terminate): a value handler that FIRES its
// completion callback and THEN throws (fire-then-throw) must deliver exactly ONE completion. The
// callback was passed by copy into the handler inside a try whose catch re-fired the SAME callback on
// the throw, so a fire-then-throw handler delivered twice; on the sync path the second
// std::promise::set_value raised std::future_error, which escaped the noexcept
// VariableAccessor::read_value_async -> std::terminate. The fix wraps the completion in
// detail::make_fire_once (mirroring default_ns::MethodNode::call), so the catch's second fire is a
// no-op CAS and the first (success) delivery wins.
TEST(DefaultVariableNode, ReadValueHandlerFiringThenThrowingDeliversExactlyOnce)
{
  const NodeId nodeId{1, "read-handler-fires-then-throws"};
  auto node = default_ns::VariableNode::create(nodeId);
  node->set_value_source(make_value_source(
    [](const ValueSource::ReadContext&,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        callback)
    {
      callback(DataValue{});  // signal success first...
      throw std::runtime_error("read handler threw AFTER completing the callback");  // ...then throw
    },
    [](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)>
        callback) { callback(ValueSource::Written{}); }));

  std::optional<DataValueResult> captured;
  int calls = 0;
  ReadValueId toRead;
  EXPECT_NO_THROW(node->read_value(0.0,
    true,
    toRead,
    nullptr,
    [&calls, &captured](DataValueResult result)
    {
      ++calls;
      captured = std::move(result);
    }));
  EXPECT_EQ(calls, 1) << "a fire-then-throw handler must deliver the completion exactly once";
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good()) << "the first (success) delivery wins; the catch's re-fire is suppressed";
}

TEST(DefaultVariableNode, WriteValueHandlerFiringThenThrowingDeliversExactlyOnce)
{
  const NodeId nodeId{1, "write-handler-fires-then-throws"};
  auto node = default_ns::VariableNode::create(nodeId);
  node->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               callback) { callback(DataValue{}); },
    [](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)>
        callback)
    {
      callback(ValueSource::Written{});  // signal success first...
      throw std::runtime_error("write handler threw AFTER completing the callback");  // ...then throw
    }));

  std::optional<VoidResult> captured;
  int calls = 0;
  EXPECT_NO_THROW(node->write_value_async(make_value_write(nodeId, 11),
    nullptr,
    [&calls, &captured](VoidResult result)
    {
      ++calls;
      captured = result;
    }));
  EXPECT_EQ(calls, 1) << "a fire-then-throw handler must deliver the completion exactly once";
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good()) << "the first (success) delivery wins; the catch's re-fire is suppressed";
}

// Concurrent read_value / write_value against the same default VariableNode must
// be race-free. Surfaces under TSan; correctness-relevant under any model (an
// unsynchronized DataValue read torn against a concurrent write is UB).
TEST(DefaultVariableNodeConcurrency, ConcurrentReadWriteValueIsRaceFree)
{
  const NodeId nodeId{1, "concurrent-value"};
  auto node = default_ns::VariableNode::create(nodeId);

  // Seed once so the default handlers are installed (write_value installs them on
  // first call) and the shared store is engaged before the concurrent phase.
  {
    std::atomic<bool> seeded{false};
    node->write_value_async(make_value_write(nodeId, 0), nullptr, [&seeded](VoidResult) { seeded = true; });
    ASSERT_TRUE(seeded.load());
  }

  constexpr int iterations = 2000;
  constexpr int writers = 2;
  constexpr int readers = 2;

  std::atomic<int> writesOk{0};
  std::atomic<int> readsOk{0};

  std::vector<std::thread> threads;
  threads.reserve(writers + readers);

  for (int w = 0; w < writers; ++w)
  {
    threads.emplace_back(
      [&, w]()
      {
        for (int i = 0; i < iterations; ++i)
        {
          node->write_value_async(make_value_write(nodeId, w * iterations + i),
            nullptr,
            [&writesOk](VoidResult result)
            {
              if (result.is_good())
                writesOk.fetch_add(1, std::memory_order_relaxed);
            });
        }
      });
  }

  for (int r = 0; r < readers; ++r)
  {
    threads.emplace_back(
      [&]()
      {
        ReadValueId toRead;
        for (int i = 0; i < iterations; ++i)
        {
          node->read_value(0.0,
            true,
            toRead,
            nullptr,
            [&readsOk](DataValueResult result)
            {
              if (result.is_good())
                readsOk.fetch_add(1, std::memory_order_relaxed);
            });
        }
      });
  }

  for (auto& thread : threads)
    thread.join();

  EXPECT_EQ(writesOk.load(), writers * iterations);
  EXPECT_EQ(readsOk.load(), readers * iterations);
}

// The default in-memory store and an application's value source. A Variable with no source holds its value
// in the default store, installed by its first write. An application source replaces the store as a whole,
// and a source with no write handler refuses writes: neither rule may let a write silently disconnect a
// source or be accepted into a store no read returns.
namespace
{

std::optional<DataValueResult> read_now(default_ns::VariableNode& node)
{
  std::optional<DataValueResult> captured;
  ReadValueId toRead;
  toRead.attribute_id() = utils::to_underlying(AttributeId::Value);
  node.read_value(
    0.0, true, toRead, nullptr, [&captured](DataValueResult result) { captured = std::move(result); });
  return captured;
}

std::optional<VoidResult> write_now(default_ns::VariableNode& node, const NodeId& nodeId, int32_t payload)
{
  std::optional<VoidResult> captured;
  node.write_value_async(make_value_write(nodeId, payload),
    nullptr,
    [&captured](VoidResult result) { captured = std::move(result); });
  return captured;
}

ValueSource::ReadValueHandler answering(int32_t value)
{
  return [value](const ValueSource::ReadContext&,
           const Node&,
           const ReadValueId&,
           std::function<void(DataValueResult)>
             callback)
  {
    callback(DataValue{Variant{value}});
  };
}

}  // namespace

// Control: a Variable with no source holds what is written to it.
// @verifies AC-COMP-DEFAULT-NODE-ATTR-STORAGE-03-DEFAULT-STORE-ONLY-WITHOUT-A-SOURCE
TEST(DefaultVariableNode, AVariableWithNoSourceHoldsTheValueWrittenToIt)
{
  const NodeId nodeId{1, "plain-value"};
  auto node = default_ns::VariableNode::create(nodeId);
  const auto written = write_now(*node, nodeId, 41);
  ASSERT_TRUE(written.has_value());
  ASSERT_TRUE(written->is_good());
  const auto read = read_now(*node);
  ASSERT_TRUE(read.has_value() && read->is_good());
  EXPECT_EQ(read->value().value().as<int32_t>(), 41);
}

// A read-only source (read handler, no write handler) refuses a write with Bad_NotWritable, and the write
// does not replace it: the next read still comes from the source.
// @verifies AC-COMP-DEFAULT-NODE-ATTR-STORAGE-03-DEFAULT-STORE-ONLY-WITHOUT-A-SOURCE
TEST(DefaultVariableNode, AWriteToAReadOnlySourceIsRefusedAndDoesNotDisconnectIt)
{
  const NodeId nodeId{1, "read-only-source"};
  auto node = default_ns::VariableNode::create(nodeId);
  ASSERT_TRUE(node->set_value_source(make_value_source(answering(7))).is_good());

  const auto written = write_now(*node, nodeId, 99);
  ASSERT_TRUE(written.has_value());
  EXPECT_EQ(written->status_code().as_status(), Status::BadNotWritable);

  const auto read = read_now(*node);
  ASSERT_TRUE(read.has_value() && read->is_good());
  EXPECT_EQ(read->value().value().as<int32_t>(), 7) << "the write replaced the application's read handler";
}

// A source attached after an initial value (a NodeSet value or a seed write) replaces the default store as
// a whole: reads come from the source, and with no write handler a write is refused rather than accepted
// into the store no read returns.
// @verifies AC-COMP-DEFAULT-NODE-ATTR-STORAGE-03-DEFAULT-STORE-ONLY-WITHOUT-A-SOURCE
TEST(DefaultVariableNode, AReadSourceAttachedAfterASeedValueDetachesTheStore)
{
  const NodeId nodeId{1, "seeded-then-sourced"};
  auto node = default_ns::VariableNode::create(nodeId);
  ASSERT_TRUE(write_now(*node, nodeId, 5).value().is_good()) << "precondition: the seed lands in the store";
  ASSERT_TRUE(node->set_value_source(make_value_source(answering(8))).is_good());

  const auto read = read_now(*node);
  ASSERT_TRUE(read.has_value() && read->is_good());
  EXPECT_EQ(read->value().value().as<int32_t>(), 8);

  const auto written = write_now(*node, nodeId, 9);
  ASSERT_TRUE(written.has_value());
  EXPECT_EQ(written->status_code().as_status(), Status::BadNotWritable)
    << "the store's write handler stayed behind and accepted a write no read returns";
}

// The write-side counterpart: a source attached after a seed takes the writes, and the store's read
// handler does not stay behind to return a value the source never produced (this source's read answers an
// empty Value).
// @verifies AC-COMP-DEFAULT-NODE-ATTR-STORAGE-03-DEFAULT-STORE-ONLY-WITHOUT-A-SOURCE
TEST(DefaultVariableNode, AWriteSourceAttachedAfterASeedValueDetachesTheStore)
{
  const NodeId nodeId{1, "seeded-then-write-sourced"};
  auto node = default_ns::VariableNode::create(nodeId);
  ASSERT_TRUE(write_now(*node, nodeId, 5).value().is_good());
  std::optional<int32_t> received;
  ASSERT_TRUE(node
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         callback) { callback(DataValue{}); },
                  [&received](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue& write,
                    std::function<void(ValueSource::WriteResult)>
                      callback)
                  {
                    received = write.value().value().as<int32_t>();
                    callback(ValueSource::Written{});
                  }))
                .is_good());

  ASSERT_TRUE(write_now(*node, nodeId, 12).value().is_good());
  EXPECT_EQ(received, 12);

  const auto read = read_now(*node);
  ASSERT_TRUE(read.has_value() && read->is_good());
  EXPECT_TRUE(read->value().value().empty()) << "the store's read handler returned the seed after detaching";
}

// A Property whose AccessLevelEx has the SemanticChange bit is written while other Nodes of its namespace are
// created and deleted. After each write that is not the first, the namespace looks the Property's owner up to
// name it in the SemanticChangeEvent (NR-38 rule 2); that lookup reads the namespace's Node table, which the
// creates and deletes change, so it must be ordered with them.
// @relation(AC-COMP-ADDRSP-SEMANTICS-02-THE-OWNER-LOOKUP-IS-ORDERED-WITH-CREATES-AND-DELETES, scope=function)
TEST(DefaultVariableNodeConcurrency, ASemanticChangeOwnerLookupIsRaceFreeWithCreatesAndDeletes)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:semantic-owner-lookup", pool.get_executor());
    const NodeId ownerId{1, "semantic-owner"};
    const NodeId propertyId{1, "semantic-property"};
    auto owner = addressSpace.try_create_node_sync(ownerId, NodeClass::Object, {});
    ASSERT_TRUE(owner.is_good()) << to_string(owner.status_code());
    auto created = addressSpace.try_create_node_sync(propertyId, NodeClass::Variable, {});
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    auto property = addressSpace.try_find_sync<VariableAccessor>(propertyId);
    ASSERT_TRUE(property.is_good()) << to_string(property.status_code());
    property.value().set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
      AccessLevelExType::Bit::CurrentWrite,
      AccessLevelExType::Bit::SemanticChange});
    owner.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId, true);
    property.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerId, false);
    // The first Value is not a semantic change (NR-38 rule 1); every write after it is.
    ASSERT_TRUE(property.value().try_write_value_sync(DataValue{Variant{0.0}}).is_good());

    constexpr int iterations = 500;
    std::atomic<int> writesOk{0};
    std::atomic<int> createsAndDeletesOk{0};
    std::thread writer(
      [&]
      {
        for (int i = 1; i <= iterations; ++i)
        {
          if (property.value().try_write_value_sync(DataValue{Variant{static_cast<double>(i)}}).is_good())
          {
            ++writesOk;
          }
        }
      });
    std::thread creator(
      [&]
      {
        for (int i = 0; i < iterations; ++i)
        {
          const NodeId transient{1, static_cast<uint32_t>(10000 + i)};
          if (addressSpace.try_create_node_sync(transient, NodeClass::Object, {}).is_good() &&
              !addressSpace.try_delete_node_sync(transient, false).is_bad())
          {
            ++createsAndDeletesOk;
          }
        }
      });
    writer.join();
    creator.join();
    EXPECT_EQ(writesOk.load(), iterations);
    EXPECT_EQ(createsAndDeletesOk.load(), iterations);
  }
  pool.join();
}

// The default source a first write installs is an ordinary ValueSource (DL-115 (2)): through that interface a
// read applies its IndexRange, and a ranged write is merged into the Value the source holds.
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-06-THE-DEFAULT-SOURCE-APPLIES-RANGES, scope=function)
TEST(DefaultValueSource, ItAppliesReadAndWriteIndexRangesToTheValueItHolds)
{
  const NodeId nodeId{1, "default-source-ranges"};
  auto node = default_ns::VariableNode::create(nodeId);
  default_ns::DefaultValueSource source;
  const RequestInfo request;
  const ValueSource::WriteContext writeContext{request, nullptr};
  const ValueSource::ReadContext readContext{request, nullptr, 0.0, false};

  const auto write = [&](Variant value, const char* range)
  {
    WriteValue item = make_value_write(nodeId, 0);
    item.value().value() = std::move(value);
    item.index_range() = String{range};
    const ValueSource::WriteItem writeItem{*node, item};
    std::optional<BatchResult<ValueSource::WriteResult>> answered;
    source.write_async(writeContext,
      std::span<const ValueSource::WriteItem>{&writeItem, 1},
      [&answered](BatchResult<ValueSource::WriteResult> result) { answered = std::move(result); });
    return answered;
  };
  const auto read = [&](const char* range)
  {
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = utils::to_underlying(AttributeId::Value);
    item.index_range() = String{range};
    const ValueSource::ReadItem readItem{*node, item};
    std::optional<BatchResult<DataValueResult>> answered;
    source.read_async(readContext,
      std::span<const ValueSource::ReadItem>{&readItem, 1},
      [&answered](BatchResult<DataValueResult> result) { answered = std::move(result); });
    return answered;
  };

  const auto first = write(Variant{Array<int32_t>{10, 20, 30, 40, 50}}, "");
  ASSERT_TRUE(first.has_value() && first->batchStatus.is_good() && first->items.size() == 1);
  ASSERT_TRUE(first->items[0].is_good());
  EXPECT_TRUE(first->items[0].value().initial) << "the first write gave the Variable its first Value";

  const auto ranged = read("1:2");
  ASSERT_TRUE(ranged.has_value() && ranged->items.size() == 1 && ranged->items[0].is_good());
  EXPECT_EQ(ranged->items[0].value().value(), (Variant{Array<int32_t>{20, 30}}));

  const auto merged = write(Variant{Array<int32_t>{7, 8}}, "1:2");
  ASSERT_TRUE(merged.has_value() && merged->items.size() == 1);
  ASSERT_TRUE(merged->items[0].is_good()) << to_string(merged->items[0].status_code());
  EXPECT_FALSE(merged->items[0].value().initial);

  const auto whole = read("");
  ASSERT_TRUE(whole.has_value() && whole->items.size() == 1 && whole->items[0].is_good());
  EXPECT_EQ(whole->items[0].value().value(), (Variant{Array<int32_t>{10, 7, 8, 40, 50}}));
}

// A ranged write applies to the Value the default store holds only when that Value is present: one whose
// DataValue status is Bad is null (OPC 10000-4 7.11.1, Table 135) and the write answers Bad_IndexRangeNoData,
// leaving it unchanged; one whose status is Uncertain has its range replaced.
// @relation(AC-SVR-ATTR-WRITE-021-A-RANGED-WRITE-ONTO-A-BAD-VALUE-IS-INDEXRANGENODATA, scope=function)
TEST(DefaultVariableNode, ARangedWriteOntoABadValueIsIndexRangeNoDataAndOntoAnUncertainOneMerges)
{
  for (const Status stored : {Status::BadSensorFailure, Status::UncertainLastUsableValue})
  {
    SCOPED_TRACE(to_string(StatusCode{stored}));
    const NodeId nodeId{1, "ranged-onto-quality"};
    auto node = default_ns::VariableNode::create(nodeId);

    WriteValue whole;
    whole.node_id() = nodeId;
    whole.attribute_id() = utils::to_underlying(AttributeId::Value);
    whole.value() = DataValue{Variant{Array<int32_t>{1, 2, 3, 4}}};
    whole.value().status() = StatusCode{stored};
    std::optional<VoidResult> seeded;
    node->write_value_async(whole, nullptr, [&seeded](VoidResult result) { seeded = std::move(result); });
    ASSERT_TRUE(seeded.has_value() && seeded->is_good())
      << (seeded ? to_string(seeded->status_code()) : "none");

    WriteValue ranged;
    ranged.node_id() = nodeId;
    ranged.attribute_id() = utils::to_underlying(AttributeId::Value);
    ranged.index_range() = String{"1:2"};
    ranged.value() = DataValue{Variant{Array<int32_t>{20, 30}}};
    std::optional<VoidResult> written;
    node->write_value_async(ranged, nullptr, [&written](VoidResult result) { written = std::move(result); });
    ASSERT_TRUE(written.has_value());

    const auto read = read_now(*node);
    ASSERT_TRUE(read.has_value() && read->is_good());
    const auto* held = read->value().value().try_as<Array<int32_t>>();
    ASSERT_NE(held, nullptr);
    const std::vector<int32_t> elements(held->payload().begin(), held->payload().end());
    if (StatusCode{stored}.is_bad())
    {
      EXPECT_EQ(written->status_code().as_status(), Status::BadIndexRangeNoData);
      EXPECT_EQ(elements, (std::vector<int32_t>{1, 2, 3, 4})) << "the Bad Value was merged into";
    }
    else
    {
      EXPECT_TRUE(written->is_good()) << to_string(written->status_code());
      EXPECT_EQ(elements, (std::vector<int32_t>{1, 20, 30, 4}));
    }
  }
}
