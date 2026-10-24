// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief An accessor's one-item Value read and write on a namespace that is not the in-memory one: the call
/// keeps the guards the route gives every namespace call (NR-2 rule 4, NR-23 rule 4) and the change events of
/// NR-36.
///
/// The scripted namespace holds an in-memory namespace for its Nodes and forwards every member to it, except
/// `read_values_async` and `write_async` while a test has scripted them.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_address_space_change_events.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_read_value_id.h"
#include "ua_request_info.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

using ReadCompletion = std::function<void(BatchResult<DataValueResult>)>;
using WriteCompletion = std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>;

/// Forwards every member to an in-memory namespace, except the Value read and the write while scripted.
class ScriptedValueNamespace final : public Namespace
{
public:
  using Namespace::find_node;

  using ReadScript = std::function<void(ScriptedValueNamespace&, ReadCompletion)>;
  using WriteScript = std::function<void(ScriptedValueNamespace&, WriteCompletion)>;

  explicit ScriptedValueNamespace(std::shared_ptr<default_ns::Namespace> inner) : mInner(std::move(inner))
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    return mInner->find_node(nodeId, maxAge);
  }

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> callback) override
  {
    mInner->enumerate_nodes_async(request, std::move(callback));
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
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

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    ReadCompletion complete) override
  {
    mReadCalls.fetch_add(1);
    if (mReadScript)
    {
      mReadScript(*this, std::move(complete));
      return;
    }
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items, WriteCompletion complete) override
  {
    mWriteCalls.fetch_add(1);
    if (mWriteScript)
    {
      mWriteScript(*this, std::move(complete));
      return;
    }
    mInner->write_async(request, caller, items, std::move(complete));
  }

  void script_reads(ReadScript script)
  {
    mReadScript = std::move(script);
  }

  void script_writes(WriteScript script)
  {
    mWriteScript = std::move(script);
  }

  /// Keeps a completion in this namespace, unanswered, until @ref take_held.
  void hold(ReadCompletion complete)
  {
    const std::lock_guard lock{mMutex};
    mHeldRead = std::move(complete);
  }

  void hold(WriteCompletion complete)
  {
    const std::lock_guard lock{mMutex};
    mHeldWrite = std::move(complete);
  }

  ReadCompletion take_held_read()
  {
    const std::lock_guard lock{mMutex};
    return std::exchange(mHeldRead, nullptr);
  }

  WriteCompletion take_held_write()
  {
    const std::lock_guard lock{mMutex};
    return std::exchange(mHeldWrite, nullptr);
  }

  int read_calls() const
  {
    return mReadCalls.load();
  }

  int write_calls() const
  {
    return mWriteCalls.load();
  }

private:
  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }

  std::shared_ptr<default_ns::Namespace> mInner;
  ReadScript mReadScript;
  WriteScript mWriteScript;
  std::mutex mMutex;
  ReadCompletion mHeldRead;
  WriteCompletion mHeldWrite;
  std::atomic<int> mReadCalls{0};
  std::atomic<int> mWriteCalls{0};
};

struct OneItemFixture
{
  OneItemFixture()
  {
    addressSpace.emplace(AddressSpace::create("urn:test:one-item-route", pool.get_executor()));
    space = std::make_shared<ScriptedValueNamespace>(
      default_ns::Namespace::create("urn:test:one-item-route:own", pool.get_executor()));
    index = addressSpace->add_namespace_sync(space);
  }

  ~OneItemFixture()
  {
    addressSpace.reset();
    space.reset();
    ::ua::test_utils::drain_with_timeout(pool);
  }

  OneItemFixture(const OneItemFixture&) = delete;
  OneItemFixture& operator=(const OneItemFixture&) = delete;

  /// Creates a Variable through the address space; nullopt when that fails.
  std::optional<VariableAccessor> variable(const std::string& name)
  {
    auto created = addressSpace->try_create_node_sync(NodeId{index, String{name}}, NodeClass::Variable, {});
    if (created.is_bad())
    {
      return std::nullopt;
    }
    return created.value().as<VariableAccessor>();
  }

  boost::asio::thread_pool pool{2};
  std::optional<AddressSpace> addressSpace;
  std::shared_ptr<ScriptedValueNamespace> space;
  uint16_t index{0};
};

/// Every answer a caller's completion received, in order.
template<typename T>
struct Answers
{
  std::function<void(T)> callback()
  {
    return [this](T answer)
    {
      const std::lock_guard lock{mutex};
      received.push_back(std::move(answer));
    };
  }

  std::vector<T> all()
  {
    const std::lock_guard lock{mutex};
    return received;
  }

  std::mutex mutex;
  std::vector<T> received;
};

ReadValueId value_of(const NodeId& nodeId)
{
  ReadValueId read;
  read.node_id() = nodeId;
  read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  return read;
}

WriteValue int32_write(const NodeId& nodeId, int32_t value)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write.value() = DataValue{Variant{value}};
  return write;
}

BatchResult<DataValueResult> int32_values(std::initializer_list<int32_t> values)
{
  BatchResult<DataValueResult> answer;
  for (const int32_t value : values)
  {
    answer.items.emplace_back(DataValue{Variant{value}});
  }
  return answer;
}

BatchResult<VoidResult> good_writes(std::size_t count)
{
  BatchResult<VoidResult> answer;
  for (std::size_t i = 0; i < count; ++i)
  {
    answer.items.emplace_back(VoidResult{});
  }
  return answer;
}

/// The code of the ErrorDetail @p status carries, or empty.
std::string detail_code(const StatusCode& status)
{
  const auto& detail = status.shared_detail();
  return detail ? std::string{detail->code} : std::string{};
}

}  // namespace

// NR-23 rule 4, kept by NR-2 rule 4's one-item call: a namespace that completes a one-item Value read or
// write twice reaches the caller once, with its first answer. Control on the unchanged code: the general
// route ignores a second completion too.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-07-A-SECOND-COMPLETION-IS-IGNORED, scope=function)
TEST(NodeAccessorOneItemRoute, ASecondCompletionReachesTheCallerOnce)
{
  OneItemFixture fixture;
  auto variable = fixture.variable("V");
  ASSERT_TRUE(variable.has_value());
  const NodeId variableId{fixture.index, "V"};
  fixture.space->script_reads(
    [](ScriptedValueNamespace&, ReadCompletion complete)
    {
      complete(int32_values({1}));
      complete(int32_values({2}));
    });
  fixture.space->script_writes(
    [](ScriptedValueNamespace&, WriteCompletion complete)
    {
      complete(good_writes(1), {});
      BatchResult<VoidResult> refused;
      refused.batchStatus = VoidResult{StatusCode{Status::BadNotWritable}};
      complete(std::move(refused), {});
    });

  Answers<DataValueResult> read;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, read.callback());
  Answers<VoidResult> written;
  variable->write_value_async(int32_write(variableId, 3), nullptr, written.callback());

  const auto reads = read.all();
  ASSERT_EQ(reads.size(), 1U) << "the read's caller was answered " << reads.size() << " times";
  ASSERT_TRUE(reads[0].is_good()) << to_string(reads[0].status_code());
  EXPECT_EQ(reads[0].value().value(), Variant{int32_t{1}});
  const auto writes = written.all();
  ASSERT_EQ(writes.size(), 1U) << "the write's caller was answered " << writes.size() << " times";
  EXPECT_EQ(writes[0].status_code(), StatusCode{Status::Good}) << to_string(writes[0].status_code());
}

// NR-23 rule 4: an answer with another number of items than the one the call had answers Bad_InternalError
// with the route's NamespaceItemCountMismatch detail; the read is answered two items, the write none. Control
// on the unchanged code: the general route checks the count too.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-07-A-WRONG-ITEM-COUNT-ANSWERS-BAD-INTERNAL-ERROR, scope=function)
TEST(NodeAccessorOneItemRoute, AnAnswerWithAnotherItemCountAnswersBadInternalError)
{
  OneItemFixture fixture;
  auto variable = fixture.variable("V");
  ASSERT_TRUE(variable.has_value());
  const NodeId variableId{fixture.index, "V"};
  fixture.space->script_reads(
    [](ScriptedValueNamespace&, ReadCompletion complete) { complete(int32_values({1, 2})); });
  fixture.space->script_writes(
    [](ScriptedValueNamespace&, WriteCompletion complete) { complete(good_writes(0), {}); });

  Answers<DataValueResult> read;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, read.callback());
  Answers<VoidResult> written;
  variable->write_value_async(int32_write(variableId, 3), nullptr, written.callback());

  const auto reads = read.all();
  ASSERT_EQ(reads.size(), 1U);
  EXPECT_EQ(reads[0].status_code(), StatusCode{Status::BadInternalError})
    << to_string(reads[0].status_code());
  EXPECT_EQ(detail_code(reads[0].status_code()), "NamespaceItemCountMismatch");
  const auto writes = written.all();
  ASSERT_EQ(writes.size(), 1U);
  EXPECT_EQ(writes[0].status_code(), StatusCode{Status::BadInternalError})
    << to_string(writes[0].status_code());
  EXPECT_EQ(detail_code(writes[0].status_code()), "NamespaceItemCountMismatch");
}

// NR-23 rule 4: a member that throws without answering answers Bad_InternalError (NamespaceCallThrew); one
// that throws after answering leaves its answer, which reaches the caller once. Control on the unchanged
// code: the general route converts the throw too.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-07-A-THROWING-MEMBER-ANSWERS-BAD-INTERNAL-ERROR, scope=function)
TEST(NodeAccessorOneItemRoute, AThrowingMemberAnswersBadInternalError)
{
  OneItemFixture fixture;
  auto variable = fixture.variable("V");
  ASSERT_TRUE(variable.has_value());
  const NodeId variableId{fixture.index, "V"};
  fixture.space->script_reads(
    [](ScriptedValueNamespace&, ReadCompletion) { throw std::runtime_error{"read refused by throwing"}; });
  fixture.space->script_writes(
    [](ScriptedValueNamespace&, WriteCompletion) { throw std::runtime_error{"write refused by throwing"}; });

  Answers<DataValueResult> read;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, read.callback());
  Answers<VoidResult> written;
  variable->write_value_async(int32_write(variableId, 3), nullptr, written.callback());

  const auto reads = read.all();
  ASSERT_EQ(reads.size(), 1U);
  EXPECT_EQ(reads[0].status_code(), StatusCode{Status::BadInternalError})
    << to_string(reads[0].status_code());
  EXPECT_EQ(detail_code(reads[0].status_code()), "NamespaceCallThrew");
  const auto writes = written.all();
  ASSERT_EQ(writes.size(), 1U);
  EXPECT_EQ(writes[0].status_code(), StatusCode{Status::BadInternalError})
    << to_string(writes[0].status_code());
  EXPECT_EQ(detail_code(writes[0].status_code()), "NamespaceCallThrew");

  // Answered, then thrown: the answer stands.
  fixture.space->script_reads(
    [](ScriptedValueNamespace&, ReadCompletion complete)
    {
      complete(int32_values({4}));
      throw std::runtime_error{"thrown after answering"};
    });
  fixture.space->script_writes(
    [](ScriptedValueNamespace&, WriteCompletion complete)
    {
      complete(good_writes(1), {});
      throw std::runtime_error{"thrown after answering"};
    });
  Answers<DataValueResult> readThenThrown;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, readThenThrown.callback());
  Answers<VoidResult> writtenThenThrown;
  variable->write_value_async(int32_write(variableId, 3), nullptr, writtenThenThrown.callback());

  const auto answeredReads = readThenThrown.all();
  ASSERT_EQ(answeredReads.size(), 1U);
  ASSERT_TRUE(answeredReads[0].is_good()) << to_string(answeredReads[0].status_code());
  EXPECT_EQ(answeredReads[0].value().value(), Variant{int32_t{4}});
  const auto answeredWrites = writtenThenThrown.all();
  ASSERT_EQ(answeredWrites.size(), 1U);
  EXPECT_EQ(answeredWrites[0].status_code(), StatusCode{Status::Good})
    << to_string(answeredWrites[0].status_code());
}

// NR-2 rule 4 keeps no item past the member's return, yet a namespace may answer later (Namespace,
// "Lifetime"): an answer given after the call returned reaches the caller. Control on the unchanged code.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-07-AN-ANSWER-AFTER-THE-CALL-RETURNED-REACHES-THE-CALLER, scope=function)
TEST(NodeAccessorOneItemRoute, AnAnswerGivenAfterTheCallReturnedReachesTheCaller)
{
  OneItemFixture fixture;
  auto variable = fixture.variable("V");
  ASSERT_TRUE(variable.has_value());
  const NodeId variableId{fixture.index, "V"};
  fixture.space->script_reads(
    [](ScriptedValueNamespace& self, ReadCompletion complete) { self.hold(std::move(complete)); });
  fixture.space->script_writes(
    [](ScriptedValueNamespace& self, WriteCompletion complete) { self.hold(std::move(complete)); });

  Answers<DataValueResult> read;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, read.callback());
  Answers<VoidResult> written;
  variable->write_value_async(int32_write(variableId, 3), nullptr, written.callback());
  EXPECT_TRUE(read.all().empty()) << "the read was answered before the namespace answered";
  EXPECT_TRUE(written.all().empty()) << "the write was answered before the namespace answered";

  auto heldRead = fixture.space->take_held_read();
  auto heldWrite = fixture.space->take_held_write();
  ASSERT_TRUE(heldRead);
  ASSERT_TRUE(heldWrite);
  std::thread later(
    [&]
    {
      heldRead(int32_values({8}));
      heldWrite(good_writes(1), {});
    });
  later.join();

  const auto reads = read.all();
  ASSERT_EQ(reads.size(), 1U);
  ASSERT_TRUE(reads[0].is_good()) << to_string(reads[0].status_code());
  EXPECT_EQ(reads[0].value().value(), Variant{int32_t{8}});
  const auto writes = written.all();
  ASSERT_EQ(writes.size(), 1U);
  EXPECT_EQ(writes[0].status_code(), StatusCode{Status::Good}) << to_string(writes[0].status_code());
}

// NR-23 rule 4 and the Namespace "Ownership" rule: the completion a one-item call gives the namespace does
// not hold the namespace. The namespace keeps the completions of a read and a write it has not answered; once
// the address space and the test let it go, it is destroyed, which a completion holding it would prevent
// (each would hold the other). Control on the unchanged code: the general route holds a namespace weakly.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-07-THE-COMPLETION-DOES-NOT-KEEP-THE-NAMESPACE-ALIVE, scope=function)
TEST(NodeAccessorOneItemRoute, TheCompletionDoesNotKeepTheNamespaceAlive)
{
  OneItemFixture fixture;
  auto variable = fixture.variable("V");
  ASSERT_TRUE(variable.has_value());
  const NodeId variableId{fixture.index, "V"};
  fixture.space->script_reads(
    [](ScriptedValueNamespace& self, ReadCompletion complete) { self.hold(std::move(complete)); });
  fixture.space->script_writes(
    [](ScriptedValueNamespace& self, WriteCompletion complete) { self.hold(std::move(complete)); });

  Answers<DataValueResult> read;
  variable->read_value_async(0.0, false, value_of(variableId), nullptr, read.callback());
  Answers<VoidResult> written;
  variable->write_value_async(int32_write(variableId, 3), nullptr, written.callback());
  ASSERT_EQ(fixture.space->read_calls(), 1);
  ASSERT_EQ(fixture.space->write_calls(), 1);

  const std::weak_ptr<ScriptedValueNamespace> observed = fixture.space;
  variable.reset();
  fixture.addressSpace.reset();
  fixture.space.reset();
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!observed.expired() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(1ms);
  }
  EXPECT_TRUE(observed.expired()) << "a held completion keeps the namespace alive";
}

// NR-36 rule 6 with NR-2 rule 4: a one-item Value write to a plain Variable raises no ModelChangeEvent, while
// a Value written to a NodeVersion Property still raises a BaseModelChangeEvent before the caller is
// answered. Control on the unchanged code, which raised the same events.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-ONE-ITEM-VALUE-WRITE-RAISES-AN-EVENT-ONLY-FOR-A-NODEVERSION, scope=function)
TEST(NodeAccessorOneItemRoute, OnlyAValueWrittenToANodeVersionRaisesAModelChangeEvent)
{
  OneItemFixture fixture;
  std::mutex changesMutex;
  std::vector<detail::AddressSpaceChange> changes;
  detail::AddressSpaceChangeEvents::set_handler(*fixture.addressSpace,
    [&](const detail::AddressSpaceChange& change)
    {
      const std::lock_guard lock{changesMutex};
      changes.push_back(change);
    });
  const auto raised = [&]
  {
    const std::lock_guard lock{changesMutex};
    return changes;
  };
  auto plain = fixture.variable("Plain");
  ASSERT_TRUE(plain.has_value());
  plain->set_data_type(NodeId{DataTypeId::Int32});
  auto nodeVersion = fixture.variable("Plain.NodeVersion");
  ASSERT_TRUE(nodeVersion.has_value());
  nodeVersion->set_browse_name(QualifiedName{0, "NodeVersion"});
  nodeVersion->set_data_type(NodeId{DataTypeId::String});
  {
    const std::lock_guard lock{changesMutex};
    changes.clear();
  }

  const auto plainWritten = plain->try_write_value_sync(DataValue{Variant{int32_t{7}}});
  ASSERT_TRUE(plainWritten.is_good()) << to_string(plainWritten.status_code());
  EXPECT_TRUE(raised().empty()) << "a Value write to a plain Variable raised an event";

  const auto versionWritten = nodeVersion->try_write_value_sync(DataValue{Variant{String{"client-set"}}});
  ASSERT_TRUE(versionWritten.is_good()) << to_string(versionWritten.status_code());
  // The write answers after its event was raised (NR-36 rule 4).
  const auto events = raised();
  ASSERT_EQ(events.size(), 1U) << "the NodeVersion written through the accessor raised no event";
  EXPECT_EQ(events[0].kind, detail::AddressSpaceChangeKind::Model);
  EXPECT_TRUE(events[0].unspecified) << "the event is not a BaseModelChangeEvent";
}
