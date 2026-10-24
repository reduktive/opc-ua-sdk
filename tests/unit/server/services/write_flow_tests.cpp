// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the Write service calls the namespaces that own its Nodes: one write_async call per namespace per
// request, carrying the Nodes the lookup returned; no lookup of a built-in declared DataType and one lookup
// per request of any other; the ranged and OptionSet merges, which apply in request order, answer the Good
// subcode the Node answered, and apply to an accessor's ranged write as they do to the service's.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_option_set.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_option_set.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_variabletype_id.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include "ua_value_source.h"
#include "ua_numeric_range_parser.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

struct WriteOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::optional<WriteResponse> response;
};

// A server with the given namespaces registered, and a Session on it allowed every permission.
struct FlowHarness
{
  ~FlowHarness()
  {
    variables.clear();
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  // Destroyed after the pool is drained, so that no Write still running can reach a destroyed sink.
  shared_ptr<EventBus> eventBus;
  shared_ptr<SessionInfoStub> sessionInfo;
  std::map<NodeId, VariableAccessor> variables;

  std::vector<uint16_t> setup(
    const std::vector<shared_ptr<ua::Namespace>>& namespaces, ServerConfig serverConfig = ServerConfig{})
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    std::vector<uint16_t> indexes;
    for (const auto& nameSpace : namespaces)
    {
      indexes.push_back(server.address_space().add_namespace_sync(nameSpace));
    }
    sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
    return indexes;
  }

  AddressSpace address_space() const
  {
    return sessionInfo->address_space();
  }

  // Makes @p bus the Session's event sink, with a listener, so that the audit gate sees an interest.
  void attach_event_bus(shared_ptr<EventBus> bus)
  {
    bus->set_event_listener([](const BaseEvent&) {});
    sessionInfo->eventSink = bus.get();
    eventBus = std::move(bus);
  }

  // A readable and writable Variable of @p dataType holding @p initial, its DisplayName its NodeId.
  NodeId create_variable(uint16_t namespaceIndex, uint32_t numericId, NodeId dataType, Variant initial)
  {
    const NodeId nodeId{namespaceIndex, numericId};
    auto created = address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      AccessLevelType accessLevel;
      accessLevel.set(AccessLevelType::Bit::CurrentRead);
      accessLevel.set(AccessLevelType::Bit::CurrentWrite);
      created.value().set_access_level(accessLevel);
      created.value().set_display_name(LocalizedText{"", nodeId.as_definition()});
      created.value().set_data_type(std::move(dataType));
      if (!initial.empty())
      {
        created.value().write_value_sync(DataValue{std::move(initial)});
      }
      variables.insert_or_assign(nodeId, created.value());
    }
    return nodeId;
  }

  Variant value_of(const NodeId& nodeId)
  {
    const auto found = variables.find(nodeId);
    if (found == variables.end())
    {
      ADD_FAILURE() << "no Variable " << nodeId.as_definition();
      return {};
    }
    auto read = found->second.try_read_value_sync();
    EXPECT_TRUE(read.is_good()) << "reading " << nodeId.as_definition() << ": "
                                << to_string(read.status_code());
    return read.is_good() ? read.value().value() : Variant{};
  }

  WriteOutcome write(WriteRequest request, std::function<void()> observeResponse = {})
  {
    auto promise = std::make_shared<std::promise<WriteOutcome>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise, observeResponse = std::move(observeResponse)](Response response)
      {
        if (observeResponse)
        {
          observeResponse();
        }
        WriteOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        {
          outcome.serviceResult = writeResponse->response_header().service_result();
          outcome.response = std::move(*writeResponse);
        }
        promise->set_value(std::move(outcome));
      });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Write did not complete";
      return {};
    }
    return future.get();
  }
};

WriteValue value_write(const NodeId& nodeId, Variant value, std::string indexRange = {})
{
  WriteValue item;
  item.node_id() = nodeId;
  item.attribute_id() = utils::to_underlying(AttributeId::Value);
  item.index_range() = String{indexRange};
  item.value().value() = std::move(value);
  return item;
}

WriteRequest request_of(std::vector<WriteValue> items)
{
  WriteRequest request;
  request.request_header().request_handle() = 1;
  for (auto& item : items)
  {
    request.nodes_to_write().payload().push_back(std::move(item));
  }
  return request;
}

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

std::vector<NodeId> of_namespace(const std::vector<NodeId>& all, uint16_t index)
{
  std::vector<NodeId> selected;
  for (const auto& nodeId : all)
  {
    if (nodeId.namespace_index() == index)
    {
      selected.push_back(nodeId);
    }
  }
  return selected;
}

bool is_lookup(const BatchRecordingNamespace::Call& call)
{
  return call.member == Member::BatchedLookup || call.member == Member::SingleLookup;
}

std::string describe(const std::vector<BatchRecordingNamespace::Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    switch (call.member)
    {
    case Member::BatchedLookup:
      text += "\n  batched lookup";
      break;
    case Member::SingleLookup:
      text += "\n  single lookup";
      break;
    case Member::Write:
      text += "\n  write_async";
      break;
    default:
      continue;
    }
    for (const auto& nodeId : call.nodeIds)
    {
      text += " " + nodeId.as_definition();
    }
  }
  return text;
}

// @p nameSpace received one lookup and one write_async call during the Write; the write holds @p expected,
// and each item's Node is the Node the namespace's own lookup answers for that NodeId.
void expect_one_lookup_and_one_write_of(
  BatchRecordingNamespace& nameSpace, const std::vector<NodeId>& expected, const char* name)
{
  const auto calls = nameSpace.calls();
  const auto lookups = nameSpace.calls(Member::BatchedLookup).size();
  EXPECT_EQ(lookups, 1U) << name << ": lookup calls" << describe(calls);

  const auto writes = nameSpace.calls(Member::Write);
  EXPECT_EQ(writes.size(), 1U) << name << ": write_async calls" << describe(calls);
  if (writes.size() != 1U)
  {
    return;
  }
  const auto& write = writes.front();
  EXPECT_EQ(sorted(write.nodeIds), sorted(expected)) << name << ": the call holds its namespace's items";
  ASSERT_EQ(write.itemNodes.size(), write.nodeIds.size()) << name;
  // The calls are counted; the test's own lookups below must be answered.
  nameSpace.decline_single_lookups(false);
  for (std::size_t k = 0; k < write.nodeIds.size(); ++k)
  {
    const auto found = nameSpace.find_node(write.nodeIds[k], std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good()) << name << ": " << write.nodeIds[k].as_definition();
    EXPECT_EQ(write.itemNodes[k], found->value().get())
      << name << ": the item's Node is not the Node the lookup returned for "
      << write.nodeIds[k].as_definition();
  }
}

std::vector<int32_t> elements_of(const Array<int32_t>& array)
{
  return std::vector<int32_t>(array.payload().begin(), array.payload().end());
}

std::shared_ptr<EnumDefinition> enum_definition_of_one_field(int64_t value)
{
  auto definition = std::make_shared<EnumDefinition>();
  EnumField field;
  field.name() = String{"Only"};
  field.value() = value;
  definition->fields().payload().push_back(std::move(field));
  return definition;
}

// The value a Variable's handlers keep in place of the in-memory store.
struct HeldValue
{
  mutable std::mutex mutex;
  DataValue value;
};

// Makes @p variable's value its handlers': the read handler answers the held value, the write handler stores
// what it is given and answers @p answer.
void hold_value_with_handlers(VariableAccessor& variable, std::shared_ptr<HeldValue> held, StatusCode answer)
{
  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  ASSERT_TRUE(
    source
      ->set_value_source(make_value_source(
        [held](const ValueSource::ReadContext&,
          const Node&,
          const ReadValueId& read,
          std::function<void(DataValueResult)>
            complete)
        {
          DataValue current;
          {
            const std::lock_guard lock{held->mutex};
            current = held->value;
          }
          ua::index_range_utils::apply_to_value(current, read.index_range());
          complete(DataValueResult{std::move(current)});
        },
        [held, answer](const ValueSource::WriteContext&,
          const Node&,
          const WriteValue& write,
          std::function<void(ValueSource::WriteResult)>
            complete)
        {
          {
            const std::lock_guard lock{held->mutex};
            const auto range = ua::parse_numeric_range(write.index_range());
            if (range.is_good() && !write.index_range().empty())
            {
              auto merged =
                ua::index_range_utils::apply_write(held->value.value(), write.value().value(), range.value());
              if (merged.is_good())
                held->value.value() = std::move(merged.value());
            }
            else
            {
              held->value = write.value();
            }
          }
          const VoidResult result{answer};
          complete(result.is_bad() ? ValueSource::WriteResult{result.status_code(), result.shared_detail()}
                                   : ValueSource::WriteResult{ValueSource::Written{}, result.status_code()});
        }))
      .is_good());
}

// Keeps the SourceNode and Status of every AuditWriteUpdateEvent, recorded in `emit` itself on the emitter's
// thread: what it holds when a response arrives is what had been emitted by then.
class AuditWriteCapture : public EventBus
{
public:
  explicit AuditWriteCapture(AddressSpace addressSpace) : EventBus(std::move(addressSpace))
  {}

  void emit(BaseEvent& event) override
  {
    const auto* audit = dynamic_cast<const AuditWriteUpdateEventPayload*>(&event);
    if (audit == nullptr)
    {
      return;
    }
    const std::lock_guard lock{mMutex};
    mEmitted.emplace_back(audit->sourceNode, audit->status);
  }

  std::vector<std::pair<NodeId, bool>> emitted() const
  {
    const std::lock_guard lock{mMutex};
    return mEmitted;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<NodeId, bool>> mEmitted;
};

std::string describe(const std::vector<std::pair<NodeId, bool>>& audits)
{
  std::string text;
  for (const auto& [source, status] : audits)
  {
    text += "\n  " + source.as_definition() + (status ? " true" : " false");
  }
  return text.empty() ? std::string{" none"} : text;
}

// Lets the namespace's held writes go when the test leaves, however it leaves, so that none is still held
// when the harness drains its pool.
class ReleaseHeldWritesOnExit
{
public:
  explicit ReleaseHeldWritesOnExit(shared_ptr<BatchRecordingNamespace> nameSpace)
    : mNamespace(std::move(nameSpace))
  {}

  ~ReleaseHeldWritesOnExit()
  {
    mNamespace->release_held_writes();
  }

  ReleaseHeldWritesOnExit(const ReleaseHeldWritesOnExit&) = delete;
  ReleaseHeldWritesOnExit& operator=(const ReleaseHeldWritesOnExit&) = delete;

private:
  shared_ptr<BatchRecordingNamespace> mNamespace;
};

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-ONE-WRITE-PER-NAMESPACE-PER-REQUEST, scope=function)
TEST(WriteFlow, OneWritePerNamespacePerRequest)
{
  FlowHarness harness;
  auto r1 = make_shared<BatchRecordingNamespace>("urn:test:write-flow:r1", harness.threadPool.get_executor());
  auto r2 = make_shared<BatchRecordingNamespace>("urn:test:write-flow:r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  const NodeId int32Type{DataTypeId::Int32};
  // R1's and R2's Variables interleaved: R1, R2, R1, R2, R1.
  std::vector<NodeId> order;
  for (uint32_t i = 0; i < 5; ++i)
  {
    const uint16_t index = indexes.at(i % 2);
    order.push_back(harness.create_variable(index, 100 + i, int32Type, Variant{int32_t{0}}));
  }
  std::vector<WriteValue> items;
  for (std::size_t i = 0; i < order.size(); ++i)
  {
    items.push_back(value_write(order[i], Variant{static_cast<int32_t>(2000 + i)}));
  }
  // Every lookup reaches the batched member, so the one lookup call per namespace is counted there.
  r1->decline_single_lookups();
  r2->decline_single_lookups();
  r1->reset();
  r2->reset();

  const auto outcome = harness.write(request_of(std::move(items)));

  expect_one_lookup_and_one_write_of(*r1, of_namespace(order, indexes.at(0)), "R1");
  expect_one_lookup_and_one_write_of(*r2, of_namespace(order, indexes.at(1)), "R2");

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), order.size());
  for (std::size_t i = 0; i < order.size(); ++i)
  {
    EXPECT_EQ(outcome.response->results()[i].as_status(), Status::Good)
      << "item " << i << ": " << to_string(outcome.response->results()[i]);
    const auto value = harness.value_of(order[i]);
    ASSERT_TRUE(value.is_int32()) << "item " << i;
    EXPECT_EQ(value.as<int32_t>(), static_cast<int32_t>(2000 + i)) << "item " << i;
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-A-BUILT-IN-DECLARED-TYPE-CAUSES-NO-LOOKUP, scope=function)
TEST(WriteFlow, ABuiltInDeclaredTypeCausesNoLookup)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:built-in", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId int32Type{DataTypeId::Int32};

  // Namespace 0's Int32 DataType Node is given an EnumDefinition that 5 is not a member of.
  auto int32Node = harness.address_space().try_find_sync<DataTypeAccessor>(int32Type);
  ASSERT_TRUE(int32Node.is_good()) << to_string(int32Node.status_code());
  int32Node.value().set_data_type_definition(enum_definition_of_one_field(1));

  // E: an Enumeration subtype in R whose only member is 1.
  const NodeId e{index, 50u};
  auto eNode = harness.address_space().try_create_sync<DataTypeAccessor>(e, NodeClass::DataType);
  ASSERT_TRUE(eNode.is_good()) << to_string(eNode.status_code());
  eNode.value().set_data_type_definition(enum_definition_of_one_field(1));
  ASSERT_TRUE(eNode.value()
                .try_add_reference_sync(
                  NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{DataTypeId::Enumeration}}, false)
                .is_good());

  const NodeId a = harness.create_variable(index, 100, int32Type, Variant{int32_t{0}});
  const NodeId b1 = harness.create_variable(index, 101, e, Variant{int32_t{1}});
  const NodeId b2 = harness.create_variable(index, 102, e, Variant{int32_t{1}});
  const NodeId b3 = harness.create_variable(index, 103, e, Variant{int32_t{1}});
  r->reset();

  const auto outcome = harness.write(request_of({value_write(a, Variant{int32_t{5}}),
    value_write(b1, Variant{int32_t{5}}),
    value_write(b2, Variant{int32_t{5}}),
    value_write(b3, Variant{int32_t{5}})}));

  const auto calls = r->calls();
  std::size_t lookupsOfE = 0;
  for (const auto& call : calls)
  {
    if (is_lookup(call))
    {
      lookupsOfE += static_cast<std::size_t>(std::count(call.nodeIds.begin(), call.nodeIds.end(), e));
    }
  }

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::Good)
    << "A, of the built-in Int32, was checked against the EnumDefinition on i=6: "
    << to_string(outcome.response->results()[0]);
  const auto aValue = harness.value_of(a);
  ASSERT_TRUE(aValue.is_int32());
  EXPECT_EQ(aValue.as<int32_t>(), 5);
  for (std::size_t i = 1; i < 4; ++i)
  {
    EXPECT_EQ(outcome.response->results()[i].as_status(), Status::BadOutOfRange)
      << "B" << i << ": " << to_string(outcome.response->results()[i]);
  }
  EXPECT_EQ(lookupsOfE, 1U) << "R's lookups during the Write:" << describe(calls);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-REPEATED-RANGED-WRITES-IN-ONE-REQUEST-BOTH-APPLY, scope=function)
TEST(WriteFlow, RepeatedRangedWritesInOneRequestBothApply)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:ranged", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId a =
    harness.create_variable(index, 100, NodeId{DataTypeId::Int32}, Variant{Array<int32_t>{0, 0, 0, 0, 0}});
  harness.variables.at(a).set_value_rank(ValueRank{1});  // it holds an array; unset reads as Scalar (F3)

  const auto outcome = harness.write(request_of(
    {value_write(a, Variant{Array<int32_t>{7}}, "1"), value_write(a, Variant{Array<int32_t>{9}}, "3")}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::Good)
    << to_string(outcome.response->results()[0]);
  EXPECT_EQ(outcome.response->results()[1].as_status(), Status::Good)
    << to_string(outcome.response->results()[1]);
  const auto value = harness.value_of(a);
  const auto* array = value.try_as<Array<int32_t>>();
  ASSERT_NE(array, nullptr);
  EXPECT_EQ(elements_of(*array), (std::vector<int32_t>{0, 7, 0, 9, 0}));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-A-GOOD-SUBCODE-FROM-A-WRITE-HANDLER-IS-ANSWERED, scope=function)
TEST(WriteFlow, AGoodSubcodeFromAWriteHandlerIsAnswered)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:write-flow:good-subcode", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);

  // A: an Int32 array whose handlers hold its value and answer Good_Clamped.
  const NodeId a = harness.create_variable(index, 100, NodeId{DataTypeId::Int32}, Variant{});
  harness.variables.at(a).set_value_rank(ValueRank{1});
  auto heldArray = std::make_shared<HeldValue>();
  heldArray->value = DataValue{Variant{Array<int32_t>{0, 0, 0, 0, 0}}};
  hold_value_with_handlers(harness.variables.at(a), heldArray, StatusCode{Status::GoodClamped});

  // O: an OptionSet of an eight-bit OptionSet DataType in R, likewise.
  const NodeId optionSetType{index, 60u};
  EnumDefinition bits;
  for (int64_t bit = 0; bit < 8; ++bit)
  {
    EnumField field;
    field.name() = String{"Bit" + std::to_string(bit)};
    field.value() = bit;
    bits.fields().payload().push_back(std::move(field));
  }
  auto typeNode =
    harness.address_space().try_create_sync<DataTypeAccessor>(optionSetType, NodeClass::DataType);
  ASSERT_TRUE(typeNode.is_good()) << to_string(typeNode.status_code());
  typeNode.value().set_data_type_definition(std::make_shared<EnumDefinition>(bits));
  auto descriptor = std::make_shared<DynamicEnumTypeDescriptor>(
    String{"WriteFlowFlags"}, ExpandedNodeId{optionSetType}, true, bits);
  const NodeId o = harness.create_variable(index, 101, optionSetType, Variant{});
  auto heldOptionSet = std::make_shared<HeldValue>();
  {
    DynamicOptionSet current{descriptor};
    current.value() = ByteString({0x00});
    heldOptionSet->value = DataValue{Variant{std::move(current)}};
  }
  hold_value_with_handlers(harness.variables.at(o), heldOptionSet, StatusCode{Status::GoodClamped});

  // P: an Int32 scalar, likewise, written whole.
  const NodeId p = harness.create_variable(index, 102, NodeId{DataTypeId::Int32}, Variant{});
  auto heldScalar = std::make_shared<HeldValue>();
  heldScalar->value = DataValue{Variant{int32_t{0}}};
  hold_value_with_handlers(harness.variables.at(p), heldScalar, StatusCode{Status::GoodClamped});

  DynamicOptionSet written{descriptor};
  written.value() = ByteString({0x01});
  written.valid_bits() = ByteString({0x01});

  const auto outcome = harness.write(request_of({value_write(p, Variant{int32_t{5}}),
    value_write(a, Variant{Array<int32_t>{7}}, "1"),
    value_write(o, Variant{std::move(written)})}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 3U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::GoodClamped)
    << "the plain write: " << to_string(outcome.response->results()[0]);
  EXPECT_EQ(outcome.response->results()[1].as_status(), Status::GoodClamped)
    << "the ranged write: " << to_string(outcome.response->results()[1]);
  EXPECT_EQ(outcome.response->results()[2].as_status(), Status::GoodClamped)
    << "the OptionSet write: " << to_string(outcome.response->results()[2]);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-AN-ACCESSORS-RANGED-WRITE-CHANGES-ONLY-ITS-RANGE, scope=function)
TEST(WriteFlow, AnAccessorsRangedWriteChangesOnlyItsRange)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:write-flow:accessor-range", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId a =
    harness.create_variable(index, 100, NodeId{DataTypeId::Int32}, Variant{Array<int32_t>{0, 0, 0, 0, 0}});

  const WriteValue ranged = value_write(a, Variant{Array<int32_t>{7}}, "1");
  std::promise<VoidResult> written;
  auto completion = written.get_future();
  harness.variables.at(a).write_value_async(
    ranged, nullptr, [&written](VoidResult result) { written.set_value(std::move(result)); });
  ASSERT_EQ(completion.wait_for(3s), std::future_status::ready) << "the accessor's write did not complete";
  const auto result = completion.get();

  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
  const auto value = harness.value_of(a);
  const auto* array = value.try_as<Array<int32_t>>();
  ASSERT_NE(array, nullptr) << "A's Value is no longer an Int32 array";
  EXPECT_EQ(elements_of(*array), (std::vector<int32_t>{0, 7, 0, 0, 0}));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-A-FINISHED-WRITE-KEEPS-ITS-RESULT-AND-ITS-AUDIT-EVENT-AT-THE-TIMEOUTHINT, scope=function)
TEST(WriteFlow, AFinishedWriteKeepsItsResultAndItsAuditEventAtTheTimeoutHint)
{
  FlowHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:answers", harness.threadPool.get_executor());
  auto b =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:holds", harness.threadPool.get_executor());
  ServerConfig audited;
  audited.auditingEnabled = true;
  const auto indexes = harness.setup({a, b}, std::move(audited));
  auto audits = make_shared<AuditWriteCapture>(harness.address_space());
  harness.attach_event_bus(audits);

  const NodeId int32Type{DataTypeId::Int32};
  const NodeId x = harness.create_variable(indexes.at(0), 100, int32Type, Variant{int32_t{0}});
  const NodeId z = harness.create_variable(indexes.at(0), 101, int32Type, Variant{int32_t{0}});
  AccessLevelType readOnly;
  readOnly.set(AccessLevelType::Bit::CurrentRead);
  harness.variables.at(z).set_access_level(readOnly);
  const NodeId y = harness.create_variable(indexes.at(1), 100, int32Type, Variant{int32_t{0}});

  // B answers every call at once except write_async, which it holds until released.
  b->hold_writes();
  const ReleaseHeldWritesOnExit releaseOnExit{b};

  auto request = request_of({value_write(x, Variant{int32_t{5}}),
    value_write(y, Variant{int32_t{6}}),
    value_write(z, Variant{int32_t{7}})});
  request.request_header().timeout_hint() = 1000;
  auto emittedByTheResponse = make_shared<std::vector<std::pair<NodeId, bool>>>();
  const auto started = std::chrono::steady_clock::now();
  const auto outcome = harness.write(
    std::move(request), [audits, emittedByTheResponse] { *emittedByTheResponse = audits->emitted(); });
  const auto elapsed = std::chrono::steady_clock::now() - started;
  const auto xValue = harness.value_of(x);
  const auto released = b->release_held_writes();

  ASSERT_TRUE(outcome.answered) << "no response within 3 s";
  EXPECT_EQ(released, 1U) << "B did not hold one write_async call: the stimulus did not occur";
  EXPECT_GE(elapsed, 900ms) << "the response came before the timeoutHint";

  ASSERT_TRUE(xValue.is_int32()) << "X's Value is no longer an Int32";
  EXPECT_EQ(xValue.as<int32_t>(), 5) << "X was not stored";

  const bool xAudited = std::any_of(emittedByTheResponse->begin(),
    emittedByTheResponse->end(),
    [&x](const std::pair<NodeId, bool>& audit) { return audit.first == x && audit.second; });
  EXPECT_TRUE(xAudited) << "no AuditWriteUpdateEvent naming X with Status true had been emitted by the time "
                           "the response arrived; emitted:"
                        << describe(*emittedByTheResponse);

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  const auto& results = outcome.response->results();
  ASSERT_EQ(results.size(), 3U);
  EXPECT_EQ(results[0].as_status(), Status::Good) << "X, which A wrote at once: " << to_string(results[0]);
  EXPECT_EQ(results[1].as_status(), Status::BadTimeout) << "Y, whose write B held: " << to_string(results[1]);
  EXPECT_EQ(results[2].as_status(), Status::BadNotWritable)
    << "Z, whose AccessLevel lacks CurrentWrite: " << to_string(results[2]);
}

// At the timeoutHint the Write answers the items of a write still running Bad_Timeout and tells the namespace
// running it to stop: the cancellation flag of the held call's RequestInfo is set by the time the response
// arrives.
// @relation(AC-SVR-PARTIAL-RESULTS-003-A-NAMESPACE-STILL-RUNNING-AT-THE-HINT-IS-TOLD-TO-STOP, scope=function)
TEST(WriteFlow, ANamespaceStillRunningAtTheHintIsToldToStop)
{
  FlowHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:hint-a", harness.threadPool.get_executor());
  auto b =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:hint-b", harness.threadPool.get_executor());
  const auto indexes = harness.setup({a, b});
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId x = harness.create_variable(indexes.at(0), 100, int32Type, Variant{int32_t{0}});
  const NodeId y = harness.create_variable(indexes.at(1), 100, int32Type, Variant{int32_t{0}});
  b->hold_writes();
  const ReleaseHeldWritesOnExit releaseOnExit{b};

  auto request = request_of({value_write(x, Variant{int32_t{5}}), value_write(y, Variant{int32_t{6}})});
  request.request_header().timeout_hint() = 300;
  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.write(std::move(request));
  const auto arrived = std::chrono::steady_clock::now();

  // What B was given, taken before it is released.
  const RequestInfo heldRequest = b->held_write_request(0);
  const bool cancelledAtResponse = heldRequest.cancelled && heldRequest.cancelled->load();
  const auto released = b->release_held_writes();

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(released, 1U) << "B did not hold one write_async call: the stimulus did not occur";
  EXPECT_GE(arrived, sent + 300ms) << "the response arrived before the timeoutHint";
  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  const auto& results = outcome.response->results();
  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].as_status(), Status::Good) << "X, which A wrote at once: " << to_string(results[0]);
  EXPECT_EQ(results[1].as_status(), Status::BadTimeout) << "Y, whose write B held: " << to_string(results[1]);
  EXPECT_GE(heldRequest.deadline, sent + 300ms) << "the deadline of B's write_async";
  EXPECT_LE(heldRequest.deadline, sent + 350ms) << "the deadline of B's write_async";
  EXPECT_FALSE(heldRequest.answerBy.has_value()) << "a Write carries no partial-results deadline";
  EXPECT_TRUE(cancelledAtResponse)
    << "the cancellation flag of B's RequestInfo is not set after the response";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-02-A-FAILED-ALLOWNULLS-READ-ANSWERS-THE-NULL-WRITE-WITH-ITS-STATUS-AND-DETAIL, scope=function)
TEST(WriteFlow, AFailedAllowNullsReadAnswersTheNullWriteWithItsStatusAndDetail)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:write-flow:allow-nulls-read", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId int32Type{DataTypeId::Int32};

  // V: an Int32 Variable holding 1 whose AllowNulls Property, reached by a forward HasProperty Reference,
  // holds true.
  const NodeId v = harness.create_variable(index, 100, int32Type, Variant{int32_t{1}});
  const NodeId allowNulls =
    harness.create_variable(index, 101, NodeId{DataTypeId::Boolean}, Variant{bool{true}});
  harness.variables.at(allowNulls).set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
  ASSERT_TRUE(harness.variables.at(v)
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, allowNulls, true)
                .is_good());

  // C: an Int32 Variable holding 1 with no AllowNulls Property.
  const NodeId c = harness.create_variable(index, 102, int32Type, Variant{int32_t{1}});

  // R fails the read of V's AllowNulls Property's Value; every other call is the in-memory namespace's.
  r->fail_value_reads_of(allowNulls,
    StatusCode{Status::BadDeviceFailure,
      ErrorDetail::build("AllowNullsReadSentinel",
        "The test namespace fails the read of the AllowNulls Property's Value",
        "WriteFlow")});

  const auto outcome = harness.write(request_of({value_write(v, Variant{}), value_write(c, Variant{})}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  const auto& results = outcome.response->results();
  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].as_status(), Status::BadDeviceFailure)
    << "V, whose AllowNulls Property could not be read: " << to_string(results[0]);
  EXPECT_EQ(results[1].as_status(), Status::Good)
    << "C, which has no AllowNulls Property: " << to_string(results[1]);
  const auto vValue = harness.value_of(v);
  EXPECT_TRUE(vValue.is_int32() && vValue.as<int32_t>() == 1) << "V no longer reads 1: the null was written";
  ASSERT_NE(results[0].shared_detail(), nullptr) << "V's result carries no ErrorDetail";
  EXPECT_EQ(results[0].shared_detail()->code, "AllowNullsReadSentinel");
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-24-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-OPERATION, scope=function)
TEST(WriteFlow, AnUncertainLookupAnswerRefusesOnlyItsOperation)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:uncertain", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId a = harness.create_variable(index, 100, int32Type, Variant{int32_t{0}});
  const NodeId b = harness.create_variable(index, 101, int32Type, Variant{int32_t{0}});
  r->decline_single_lookups();
  r->answer_lookup_of(b, StatusCode{Status::UncertainNoCommunicationLastUsableValue});
  r->reset();

  const auto outcome =
    harness.write(request_of({value_write(a, Variant{int32_t{41}}), value_write(b, Variant{int32_t{42}})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::Good)
    << to_string(outcome.response->results()[0]);
  const auto& refused = outcome.response->results()[1];
  EXPECT_EQ(refused.as_status(), Status::BadInternalError) << to_string(refused);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "LookupAnswerUncertain");
  EXPECT_EQ(refused.shared_detail()->innerStatus,
    StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value());
  EXPECT_EQ(harness.value_of(a).as<int32_t>(), 41);
}

namespace
{

// Makes @p variable an analog item: a HasTypeDefinition to @p type and an EURange Property {low, high}.
void make_analog(FlowHarness& harness, const NodeId& variable, const NodeId& type, uint32_t euRangeId,
  double low, double high)
{
  ASSERT_TRUE(harness.variables.at(variable)
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, type, true)
                .is_good());
  auto range = std::make_unique<Range>();
  range->low() = low;
  range->high() = high;
  const NodeId euRange = harness.create_variable(variable.namespace_index(),
    euRangeId,
    NodeId{DataTypeId::Range},
    Variant{RefStructure<Structure>{std::move(range)}});
  harness.variables.at(euRange).set_browse_name(QualifiedName{uint16_t{0}, "EURange"});
  ASSERT_TRUE(harness.variables.at(variable)
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRange, true)
                .is_good());
}

ServerConfig with_data_access_policy(DataAccessOutOfRangePolicy policy)
{
  ServerConfig config;
  config.dataAccessWritePolicy = policy;
  return config;
}

// The read_references_async queries @p nameSpace received that walk up a type: inverse HasSubtype.
std::size_t supertype_queries(const BatchRecordingNamespace& nameSpace)
{
  std::size_t count = 0;
  for (const auto& call : nameSpace.calls(Member::ReadReferences))
  {
    for (const auto& query : call.referenceQueries)
    {
      if (query.direction == BrowseDirection::Inverse &&
          std::find(query.referenceTypeHint.begin(),
            query.referenceTypeHint.end(),
            NodeId{ReferenceTypeId::HasSubtype}) != query.referenceTypeHint.end())
      {
        ++count;
      }
    }
  }
  return count;
}

}  // namespace

// NR-58: a Variable whose TypeDefinition is in namespace 0 is decided from the namespace-0 table: its type is
// not looked up and not walked. The control is the write inside the range.
// @relation(AC-COMP-SVR-WRITE-DATA-ACCESS-01-A-NAMESPACE-ZERO-TYPE-IS-DECIDED-WITHOUT-A-WALK, scope=function)
TEST(WriteFlowDataAccess, ANamespaceZeroTypeIsDecidedWithoutAWalk)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:da-ns0", harness.threadPool.get_executor());
  const auto index = harness.setup({r}, with_data_access_policy(DataAccessOutOfRangePolicy::Reject)).at(0);
  const NodeId v = harness.create_variable(index, 100, NodeId{DataTypeId::Double}, Variant{50.0});
  make_analog(harness, v, NodeId{VariableTypeId::AnalogItemType}, 101, 0.0, 100.0);
  r->reset();

  const auto outcome = harness.write(request_of({value_write(v, Variant{150.0})}));

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::BadOutOfRange)
    << to_string(outcome.response->results()[0]);
  EXPECT_EQ(supertype_queries(*r), 0U) << "a namespace-0 TypeDefinition was walked:" << describe(r->calls());
  const auto value = harness.value_of(v);
  EXPECT_TRUE(value.is_double() && value.as<double>() == 50.0) << "the refused write was stored";

  const auto inside = harness.write(request_of({value_write(v, Variant{75.0})}));
  ASSERT_TRUE(inside.response.has_value());
  EXPECT_EQ(inside.response->results()[0].as_status(), Status::Good)
    << to_string(inside.response->results()[0]);
}

// NR-58: a TypeDefinition outside namespace 0 is walked up by inverse HasSubtype until a namespace-0 type
// decides it.
// @relation(AC-COMP-SVR-WRITE-DATA-ACCESS-01-AN-APPLICATION-SUBTYPE-IS-WALKED-TO-NAMESPACE-ZERO, scope=function)
TEST(WriteFlowDataAccess, AnApplicationSubtypeIsWalkedToNamespaceZero)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:da-subtype", harness.threadPool.get_executor());
  const auto index = harness.setup({r}, with_data_access_policy(DataAccessOutOfRangePolicy::Reject)).at(0);
  // T: a VariableType of R, a subtype of AnalogItemType.
  const NodeId t{index, 90U};
  auto type = harness.address_space().try_create_sync<VariableTypeAccessor>(t, NodeClass::VariableType);
  ASSERT_TRUE(type.is_good()) << to_string(type.status_code());
  // A subtype's DataType is its supertype's (Number) or a subtype of it (OPC 10000-3 6.2.7).
  type.value().set_data_type(NodeId{DataTypeId::Double});
  const auto linked = type.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{VariableTypeId::AnalogItemType}, false);
  ASSERT_TRUE(linked.is_good()) << to_string(linked.status_code()) << " "
                                << (linked.status_code().shared_detail()
                                       ? linked.status_code().shared_detail()->code
                                       : std::string{});
  const NodeId v = harness.create_variable(index, 100, NodeId{DataTypeId::Double}, Variant{50.0});
  make_analog(harness, v, t, 101, 0.0, 100.0);
  r->reset();

  const auto outcome = harness.write(request_of({value_write(v, Variant{150.0})}));

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::BadOutOfRange)
    << "the subtype of AnalogItemType was not range-checked: " << to_string(outcome.response->results()[0]);
  EXPECT_GE(supertype_queries(*r), 1U) << "T was not walked:" << describe(r->calls());
}

// NR-58: with `dataAccessWritePolicy` unset the Write service makes no call for the Data Access rules, and an
// analog value outside its range is stored.
// @relation(AC-COMP-SVR-WRITE-DATA-ACCESS-01-THE-SETTING-UNSET-MAKES-NO-CALL, scope=function)
TEST(WriteFlowDataAccess, TheSettingUnsetMakesNoCall)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:da-unset", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId v = harness.create_variable(index, 100, NodeId{DataTypeId::Double}, Variant{50.0});
  make_analog(harness, v, NodeId{VariableTypeId::AnalogItemType}, 101, 0.0, 100.0);
  r->reset();

  const auto outcome = harness.write(request_of({value_write(v, Variant{150.0})}));

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::Good)
    << to_string(outcome.response->results()[0]);
  EXPECT_TRUE(r->calls(Member::ReadReferences).empty()) << "References were read:" << describe(r->calls());
  const auto value = harness.value_of(v);
  EXPECT_TRUE(value.is_double() && value.as<double>() == 150.0) << "the write was not stored as written";
}

// OPC 10000-4 7.39.2 and DL-18: a value the Data Access step clamps, stored with plain Good, answers
// Good_Clamped.
// @relation(AC-COMP-SVR-WRITE-ITEM-STATUS-02-LAST-INTERCEPTOR-SUBCODE-ANSWERED, scope=function)
TEST(WriteFlowDataAccess, AClampedValueStoredWithPlainGoodAnswersGoodClamped)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:da-clamp", harness.threadPool.get_executor());
  const auto index = harness.setup({r}, with_data_access_policy(DataAccessOutOfRangePolicy::Clamp)).at(0);
  const NodeId v = harness.create_variable(index, 100, NodeId{DataTypeId::Double}, Variant{50.0});
  make_analog(harness, v, NodeId{VariableTypeId::AnalogItemType}, 101, 0.0, 100.0);

  const auto outcome =
    harness.write(request_of({value_write(v, Variant{150.0}), value_write(v, Variant{25.0})}));

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::GoodClamped)
    << to_string(outcome.response->results()[0]);
  EXPECT_EQ(outcome.response->results()[1].as_status(), Status::Good)
    << "a write inside the range: " << to_string(outcome.response->results()[1]);
}

// DL-18: the Good subcode the storage step answers outranks the clamp's.
// @relation(AC-COMP-SVR-WRITE-ITEM-STATUS-02-LAST-INTERCEPTOR-SUBCODE-ANSWERED, scope=function)
TEST(WriteFlowDataAccess, AStorageGoodSubcodeOutranksTheClamp)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:write-flow:da-storage", harness.threadPool.get_executor());
  const auto index = harness.setup({r}, with_data_access_policy(DataAccessOutOfRangePolicy::Clamp)).at(0);
  const NodeId v = harness.create_variable(index, 100, NodeId{DataTypeId::Double}, Variant{});
  make_analog(harness, v, NodeId{VariableTypeId::AnalogItemType}, 101, 0.0, 100.0);
  auto held = std::make_shared<HeldValue>();
  held->value = DataValue{Variant{50.0}};
  hold_value_with_handlers(harness.variables.at(v), held, StatusCode{Status::GoodCompletesAsynchronously});

  const auto outcome = harness.write(request_of({value_write(v, Variant{150.0})}));

  ASSERT_TRUE(outcome.response.has_value()) << "service result " << to_string(outcome.serviceResult);
  EXPECT_EQ(outcome.response->results()[0].as_status(), Status::GoodCompletesAsynchronously)
    << to_string(outcome.response->results()[0]);
}
