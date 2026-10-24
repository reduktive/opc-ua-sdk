// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// A Variable's Value owned by a ValueSource (NR-11, NR-12, NR-13; NR-70 C3): the source receives each item as
// the request gives it, applies IndexRanges and ValidBits itself, and is called once per request for all its
// items.
//
// The calls are the in-memory namespace's read_values_async and write_async, the members the services call.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_option_set.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_option_set.h"
#include "ua_request_info.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_value_source.h"
#include <boost/asio/thread_pool.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace ua;

namespace
{

/// The NodeId of @p node, copied out of the description it reads.
NodeId node_id_of(const Node& node)
{
  const NodeDescription description = node.attributes();
  return description.node_id();
}

// A source that records what it was given and answers each read with its Value and each write Good.
class RecordingSource final : public ValueSource
{
public:
  struct ReadCall
  {
    std::vector<NodeId> nodes;
    std::vector<String> ranges;
  };

  struct WriteCall
  {
    std::vector<NodeId> nodes;
    std::vector<WriteValue> writes;
  };

  explicit RecordingSource(Variant value) : mValue(std::move(value))
  {}

  void read_async(const ReadContext&, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    {
      const std::lock_guard lock{mMutex};
      ReadCall call;
      for (const auto& item : items)
      {
        call.nodes.push_back(node_id_of(item.node));
        call.ranges.push_back(item.value.index_range());
        answer.items.emplace_back(DataValue{mValue});
      }
      mReads.push_back(std::move(call));
    }
    complete(std::move(answer));
  }

  void write_async(const WriteContext&, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    BatchResult<WriteResult> answer;
    {
      const std::lock_guard lock{mMutex};
      WriteCall call;
      for (const auto& item : items)
      {
        call.nodes.push_back(node_id_of(item.node));
        call.writes.push_back(item.value);
        answer.items.emplace_back(Written{});
      }
      mWrites.push_back(std::move(call));
    }
    complete(std::move(answer));
  }

  std::vector<ReadCall> reads() const
  {
    const std::lock_guard lock{mMutex};
    return mReads;
  }

  std::vector<WriteCall> writes() const
  {
    const std::lock_guard lock{mMutex};
    return mWrites;
  }

private:
  mutable std::mutex mMutex;
  Variant mValue;
  std::vector<ReadCall> mReads;
  std::vector<WriteCall> mWrites;
};

// A source that records the Value each write gives it and keeps the write's completion until the test runs
// it.
class ParkingSource final : public ValueSource
{
public:
  void read_async(const ReadContext&, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    answer.items.resize(items.size(), DataValueResult{DataValue{Variant{int32_t{0}}}});
    complete(std::move(answer));
  }

  void write_async(const WriteContext&, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    const std::lock_guard lock{mMutex};
    for (const auto& item : items)
    {
      mReceived.push_back(item.value.value().value());
    }
    mParked = [count = items.size(), complete = std::move(complete)]
    {
      BatchResult<WriteResult> answer;
      answer.items.resize(count, WriteResult{Written{}});
      complete(std::move(answer));
    };
  }

  /// Runs the parked completion. @return false when no write is parked.
  bool answer_parked()
  {
    std::function<void()> parked;
    {
      const std::lock_guard lock{mMutex};
      parked = std::move(mParked);
      mParked = nullptr;
    }
    if (!parked)
    {
      return false;
    }
    parked();
    return true;
  }

  std::vector<Variant> received() const
  {
    const std::lock_guard lock{mMutex};
    return mReceived;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Variant> mReceived;
  std::function<void()> mParked;
};

class ValueSourceTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:value-source", mThreadPool.get_executor()));
    mNamespace = default_ns::Namespace::create("urn:test:value-source:own", mThreadPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// A Variable of @p dataType and @p valueRank whose Value @p source owns.
  std::shared_ptr<Node> variable(
    const std::string& name, const NodeId& dataType, ValueRank valueRank, std::shared_ptr<ValueSource> source)
  {
    const NodeId id{mIndex, String{name}};
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::Variable, {});
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    auto accessor = created.value().as<VariableAccessor>();
    EXPECT_TRUE(accessor.has_value());
    accessor->set_data_type(dataType);
    accessor->set_value_rank(valueRank);
    auto found = mNamespace->find_node(id, std::nullopt);
    EXPECT_TRUE(found.has_value() && found->is_good());
    std::shared_ptr<Node> node = found->value();
    EXPECT_TRUE(node->external_value_source()->set_value_source(std::move(source)).is_good());
    return node;
  }

  static ReadValueId value_of(const Node& node, String range = {})
  {
    ReadValueId read;
    read.node_id() = node_id_of(node);
    read.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    read.index_range() = std::move(range);
    return read;
  }

  BatchResult<DataValueResult> read(std::span<const ValueReadItem> items)
  {
    std::optional<BatchResult<DataValueResult>> answered;
    mNamespace->read_values_async(RequestInfo{},
      nullptr,
      items,
      0.0,
      false,
      [&answered](BatchResult<DataValueResult> read) { answered = std::move(read); });
    EXPECT_TRUE(answered.has_value()) << "the read was not answered inline";
    return answered.value_or(BatchResult<DataValueResult>{});
  }

  BatchResult<VoidResult> write(std::span<const ValueWriteItem> items)
  {
    std::optional<BatchResult<VoidResult>> answered;
    mNamespace->write_async(RequestInfo{},
      nullptr,
      items,
      [&answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
      { answered = std::move(written); });
    // The committed-write steps may post: wait for the answer.
    for (int i = 0; i < 500 && !answered; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    EXPECT_TRUE(answered.has_value()) << "the write was not answered";
    return answered.value_or(BatchResult<VoidResult>{});
  }

  BatchResult<VoidResult> write_item(const ValueWriteItem& item)
  {
    return write(std::span<const ValueWriteItem>{&item, 1});
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mIndex{0};
};

using ValueSourceRead = ValueSourceTest;
using ValueSourceWrite = ValueSourceTest;
using ValueSourceBatching = ValueSourceTest;
using ValueSourceScalar = ValueSourceTest;

// NR-11 rule 3: the source applies a read's IndexRange. It receives the range, and its answer is returned as
// it gave it, not narrowed again.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-SOURCE-RECEIVES-EACH-ITEM-AS-GIVEN, scope=function)
TEST_F(ValueSourceRead, ASourceReceivesTheIndexRange)
{
  // The source's answer for "1:2" of {1, 2, 3, 4}: the two elements, already selected.
  auto source = std::make_shared<RecordingSource>(Variant{Array<int32_t>{2, 3}});
  auto node = variable("Array", NodeId{DataTypeId::Int32}, ValueRank{1}, source);
  const auto ranged = value_of(*node, "1:2");
  const ValueReadItem item{*node, ranged};

  const auto answered = read(std::span<const ValueReadItem>{&item, 1});

  ASSERT_EQ(source->reads().size(), 1U);
  ASSERT_EQ(source->reads()[0].ranges.size(), 1U);
  EXPECT_EQ(source->reads()[0].ranges[0], String{"1:2"});
  ASSERT_EQ(answered.items.size(), 1U);
  ASSERT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  EXPECT_EQ(answered.items[0].value().value(), (Variant{Array<int32_t>{2, 3}}));
}

// NR-11 rule 3: a ranged write reaches the source as the client sent it, the partial Value with its range;
// the SDK does not merge it.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-SOURCE-RECEIVES-EACH-ITEM-AS-GIVEN, scope=function)
TEST_F(ValueSourceWrite, ASourceReceivesThePartialValueAndItsRange)
{
  auto source = std::make_shared<RecordingSource>(Variant{Array<int32_t>{1, 2, 3, 4}});
  auto node = variable("Array", NodeId{DataTypeId::Int32}, ValueRank{1}, source);
  WriteValue partial;
  partial.node_id() = node_id_of(*node);
  partial.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  partial.index_range() = String{"1"};
  partial.value().value() = Variant{Array<int32_t>{9}};
  const ValueWriteItem item{*node, partial};

  const auto answered = write(std::span<const ValueWriteItem>{&item, 1});

  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  ASSERT_EQ(source->writes().size(), 1U);
  ASSERT_EQ(source->writes()[0].writes.size(), 1U);
  EXPECT_EQ(source->writes()[0].writes[0].index_range(), String{"1"});
  EXPECT_EQ(source->writes()[0].writes[0].value().value(), (Variant{Array<int32_t>{9}}));
}

// Part 3 OptionSet and NR-11 rule 3: an OptionSet write with ValidBits reaches the source with its ValidBits;
// the SDK does not merge it into the current Value.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-SOURCE-RECEIVES-EACH-ITEM-AS-GIVEN, scope=function)
TEST_F(ValueSourceWrite, AnOptionSetWriteReceivesTheValidBits)
{
  EnumDefinition definition;
  for (const int64_t bit : {0, 1, 2, 3})
  {
    EnumField field;
    field.name() = String{"Bit" + std::to_string(bit)};
    field.value() = bit;
    definition.fields().payload().push_back(std::move(field));
  }
  const auto descriptor = std::make_shared<DynamicEnumTypeDescriptor>(
    String{"TestFlags"}, ExpandedNodeId{NodeId{mIndex, 5000U}}, true, std::move(definition));
  DynamicOptionSet current{descriptor};
  current.value() = ByteString{0x0F};
  auto source = std::make_shared<RecordingSource>(Variant{current});
  auto node = variable("Options", NodeId{mIndex, 5000U}, ValueRank{-1}, source);
  DynamicOptionSet written{descriptor};
  written.value() = ByteString{0x01};
  written.valid_bits() = ByteString{0x03};
  WriteValue write;
  write.node_id() = node_id_of(*node);
  write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write.value().value() = Variant{written};
  const ValueWriteItem item{*node, write};

  const auto answered = write_item(item);

  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  const auto writes = source->writes();
  ASSERT_EQ(writes.size(), 1U);
  const auto* received = writes[0].writes[0].value().value().try_as<OptionSet>();
  ASSERT_NE(received, nullptr) << "the source did not receive an OptionSet";
  EXPECT_EQ(received->value(), ByteString{0x01});
  EXPECT_EQ(received->valid_bits(), ByteString{0x03});
}

// NR-12: writing has a default, which answers Bad_NotWritable, so a source made from a read handler alone is
// read-only.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-THE-DEFAULT-WRITE-ANSWERS-BAD-NOT-WRITABLE, scope=function)
TEST_F(ValueSourceWrite, TheDefaultAnswersBadNotWritable)
{
  auto source = make_value_source([](const ValueSource::ReadContext&,
                                    const Node&,
                                    const ReadValueId&,
                                    std::function<void(DataValueResult)>
                                      done) { done(DataValue{Variant{int32_t{1}}}); });
  auto node = variable("ReadOnly", NodeId{DataTypeId::Int32}, ValueRank{-1}, source);
  WriteValue write;
  write.node_id() = node_id_of(*node);
  write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write.value().value() = Variant{int32_t{2}};
  const ValueWriteItem item{*node, write};

  const auto answered = write_item(item);

  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_EQ(answered.items[0].status_code().as_status(), Status::BadNotWritable);
}

// NR-13 rules 3 and 4: one source serving two Variables is called once for a read of both, with both items in
// order.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-ONE-CALL-PER-SOURCE-PER-REQUEST, scope=function)
TEST_F(ValueSourceBatching, OneSourceServingTwoVariablesIsCalledOncePerRead)
{
  auto source = std::make_shared<RecordingSource>(Variant{int32_t{5}});
  auto first = variable("First", NodeId{DataTypeId::Int32}, ValueRank{-1}, source);
  auto second = variable("Second", NodeId{DataTypeId::Int32}, ValueRank{-1}, source);
  // The control: a Variable with its own source between them.
  auto other = std::make_shared<RecordingSource>(Variant{int32_t{6}});
  auto between = variable("Between", NodeId{DataTypeId::Int32}, ValueRank{-1}, other);
  const auto firstRead = value_of(*first);
  const auto betweenRead = value_of(*between);
  const auto secondRead = value_of(*second);
  const ValueReadItem items[] = {{*first, firstRead}, {*between, betweenRead}, {*second, secondRead}};

  const auto answered = read(items);

  ASSERT_EQ(source->reads().size(), 1U) << "the shared source was not called once";
  EXPECT_EQ(source->reads()[0].nodes, (std::vector<NodeId>{node_id_of(*first), node_id_of(*second)}));
  EXPECT_EQ(other->reads().size(), 1U);
  ASSERT_EQ(answered.items.size(), 3U);
  EXPECT_EQ(answered.items[0].value().value(), Variant{int32_t{5}});
  EXPECT_EQ(answered.items[1].value().value(), Variant{int32_t{6}});
  EXPECT_EQ(answered.items[2].value().value(), Variant{int32_t{5}});
}

// NR-11 rule 3.2: a ranged read of a Scalar Variable whose DataType holds neither a String nor a ByteString
// is refused with Bad_IndexRangeNoData before the source is called. The control is the same read without a
// range.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-RANGED-READ-OF-A-NUMERIC-SCALAR-IS-SCREENED, scope=function)
TEST_F(ValueSourceScalar, ARangedReadOfANumericScalarIsBadIndexRangeNoData)
{
  auto source = std::make_shared<RecordingSource>(Variant{int32_t{5}});
  auto node = variable("Scalar", NodeId{DataTypeId::Int32}, ValueRank{-1}, source);
  const auto ranged = value_of(*node, "0");
  const ValueReadItem rangedItem{*node, ranged};

  const auto refused = read(std::span<const ValueReadItem>{&rangedItem, 1});

  ASSERT_EQ(refused.items.size(), 1U);
  EXPECT_EQ(refused.items[0].status_code().as_status(), Status::BadIndexRangeNoData);
  EXPECT_TRUE(source->reads().empty()) << "the source was called for a screened read";

  const auto whole = value_of(*node);
  const ValueReadItem wholeItem{*node, whole};
  const auto answered = read(std::span<const ValueReadItem>{&wholeItem, 1});
  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_TRUE(answered.items[0].is_good());
  EXPECT_EQ(source->reads().size(), 1U);
}

// NR-11 rule 3.2 covers every DataType that can hold neither a String nor a ByteString, subtypes included: a
// ranged read of a Scalar Variable whose DataType is an Enumeration subtype (ServerState) or a subtype of
// UInt32 (Counter) is refused with Bad_IndexRangeNoData, and its source is not called. The control is a
// Scalar Variable whose DataType is a subtype of String (LocaleId): its ranged read reaches the source.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-RANGED-ACCESS-TO-A-SUBTYPE-SCALAR-IS-SCREENED, scope=function)
TEST_F(ValueSourceScalar, ARangedReadOfAnEnumerationOrCounterScalarIsBadIndexRangeNoData)
{
  for (const auto& [name, dataType] : {std::pair{std::string{"ServerState"}, NodeId{DataTypeId::ServerState}},
         std::pair{std::string{"Counter"}, NodeId{DataTypeId::Counter}}})
  {
    SCOPED_TRACE(name);
    auto source = std::make_shared<RecordingSource>(Variant{uint32_t{5}});
    auto node = variable(name, dataType, ValueRank{-1}, source);
    const auto ranged = value_of(*node, "0");
    const ValueReadItem rangedItem{*node, ranged};

    const auto refused = read(std::span<const ValueReadItem>{&rangedItem, 1});

    ASSERT_EQ(refused.items.size(), 1U);
    EXPECT_EQ(refused.items[0].status_code().as_status(), Status::BadIndexRangeNoData)
      << to_string(refused.items[0].status_code());
    EXPECT_TRUE(source->reads().empty()) << "the source was called for a screened read";
  }

  auto source = std::make_shared<RecordingSource>(Variant{String{"en-NZ"}});
  auto node = variable("Locale", NodeId{DataTypeId::LocaleId}, ValueRank{-1}, source);
  const auto ranged = value_of(*node, "0:1");
  const ValueReadItem rangedItem{*node, ranged};
  const auto answered = read(std::span<const ValueReadItem>{&rangedItem, 1});
  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  ASSERT_EQ(source->reads().size(), 1U) << "a ranged read of a String subtype was screened";
  EXPECT_EQ(source->reads()[0].ranges, std::vector<String>{String{"0:1"}});
}

// As above for a ranged write: a Scalar Variable whose DataType is ServerState or Counter refuses it with
// Bad_IndexRangeNoData without calling its source. The control is the same ranged write to a Scalar LocaleId
// Variable, which reaches its source.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-RANGED-ACCESS-TO-A-SUBTYPE-SCALAR-IS-SCREENED, scope=function)
TEST_F(ValueSourceScalar, ARangedWriteOfAnEnumerationOrCounterScalarIsBadIndexRangeNoData)
{
  const auto rangedWrite = [](const Node& node, Variant value)
  {
    WriteValue write;
    write.node_id() = node_id_of(node);
    write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    write.index_range() = String{"0"};
    write.value().value() = std::move(value);
    return write;
  };
  for (const auto& [name, dataType] : {std::pair{std::string{"ServerState"}, NodeId{DataTypeId::ServerState}},
         std::pair{std::string{"Counter"}, NodeId{DataTypeId::Counter}}})
  {
    SCOPED_TRACE(name);
    auto source = std::make_shared<RecordingSource>(Variant{uint32_t{5}});
    auto node = variable(name, dataType, ValueRank{-1}, source);
    const WriteValue write = rangedWrite(*node, Variant{Array<uint32_t>{1}});

    const auto refused = write_item(ValueWriteItem{*node, write});

    ASSERT_EQ(refused.items.size(), 1U);
    EXPECT_EQ(refused.items[0].status_code().as_status(), Status::BadIndexRangeNoData)
      << to_string(refused.items[0].status_code());
    EXPECT_TRUE(source->writes().empty()) << "the source was called for a screened write";
  }

  auto source = std::make_shared<RecordingSource>(Variant{String{"en-NZ"}});
  auto node = variable("Locale", NodeId{DataTypeId::LocaleId}, ValueRank{-1}, source);
  const WriteValue write = rangedWrite(*node, Variant{String{"d"}});
  const auto answered = write_item(ValueWriteItem{*node, write});
  ASSERT_EQ(answered.items.size(), 1U);
  EXPECT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  EXPECT_EQ(source->writes().size(), 1U) << "a ranged write of a String subtype was screened";
}

// NR-13 rule 4: the namespace keeps the source of a call until that source has answered, so replacing a
// Variable's source does not affect a write already made. The source parks a whole-value write; the test
// holds it only weakly and replaces it on the Variable. The old source is still alive, and its answer
// completes the write Good. The control is the write's answer itself, which arrives only through that source.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-REPLACED-SOURCE-LIVES-UNTIL-IT-ANSWERS, scope=function)
TEST_F(ValueSourceWrite, ASourceReplacedWhileAWriteIsOutstandingLivesUntilItAnswers)
{
  auto parking = std::make_shared<ParkingSource>();
  const std::weak_ptr<ParkingSource> held = parking;
  auto node = variable("Replaced", NodeId{DataTypeId::Int32}, ValueRank{-1}, std::move(parking));
  WriteValue write;
  write.node_id() = node_id_of(*node);
  write.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write.value().value() = Variant{int32_t{5}};
  const ValueWriteItem item{*node, write};

  struct Answered
  {
    std::mutex mutex;
    std::optional<BatchResult<VoidResult>> answer;
  };

  const auto answered = std::make_shared<Answered>();
  mNamespace->write_async(RequestInfo{},
    nullptr,
    std::span<const ValueWriteItem>{&item, 1},
    [answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
    {
      const std::lock_guard lock{answered->mutex};
      answered->answer = std::move(written);
    });

  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(std::make_shared<RecordingSource>(Variant{int32_t{0}}))
                .is_good());
  const auto old = held.lock();
  ASSERT_TRUE(old) << "the source was destroyed with the write outstanding";
  ASSERT_TRUE(old->answer_parked()) << "the write did not reach the source";
  EXPECT_EQ(old->received(), std::vector<Variant>{Variant{int32_t{5}}});

  // The committed-write steps may post: wait for the answer.
  bool arrived = false;
  for (int i = 0; i < 500 && !arrived; ++i)
  {
    {
      const std::lock_guard lock{answered->mutex};
      arrived = answered->answer.has_value();
    }
    if (!arrived)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
  }
  ASSERT_TRUE(arrived) << "the write was not answered";
  const std::lock_guard lock{answered->mutex};
  ASSERT_EQ(answered->answer->items.size(), 1U) << to_string(answered->answer->batchStatus.status_code());
  EXPECT_TRUE(answered->answer->items[0].is_good()) << to_string(answered->answer->items[0].status_code());
}

}  // namespace

// NR-66 and NR-2 rule 4: what a write item refers to is valid until write_async returns, as is the
// CallerInfo. A source that answers after the return is answered correctly when the WriteValue, the items and
// the CallerInfo are gone; the address-sanitizer job reports a read of them.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-09-A-WRITE-ANSWERED-AFTER-THE-RETURN-USES-NO-ITEM-FIELD, scope=function)
TEST_F(ValueSourceWrite, ASourceAnsweringAfterTheReturnUsesNoItemField)
{
  auto source = std::make_shared<ParkingSource>();
  auto node = variable("Parked", NodeId{DataTypeId::Int32}, ValueRank{-1}, source);
  auto write = std::make_unique<WriteValue>();
  write->node_id() = node_id_of(*node);
  write->attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  write->value().value() = Variant{int32_t{5}};
  auto caller = std::make_unique<CallerInfo>();
  auto items = std::make_unique<std::vector<ValueWriteItem>>();
  items->push_back(ValueWriteItem{*node, *write});

  struct Answered
  {
    std::mutex mutex;
    int count{0};
    std::optional<BatchResult<VoidResult>> answer;
  };

  const auto answered = std::make_shared<Answered>();
  mNamespace->write_async(RequestInfo{},
    caller.get(),
    *items,
    [answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
    {
      const std::lock_guard lock{answered->mutex};
      ++answered->count;
      answered->answer = std::move(written);
    });

  write->value().value() = Variant{int32_t{9}};
  write.reset();
  items.reset();
  caller.reset();
  ASSERT_TRUE(source->answer_parked()) << "the source was not called";

  // The committed-write steps may post: wait for the answer.
  bool arrived = false;
  for (int i = 0; i < 500 && !arrived; ++i)
  {
    {
      const std::lock_guard lock{answered->mutex};
      arrived = answered->answer.has_value();
    }
    if (!arrived)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
  }
  ASSERT_TRUE(arrived) << "the write was not answered";
  EXPECT_EQ(source->received(), std::vector<Variant>{Variant{int32_t{5}}});
  const std::lock_guard lock{answered->mutex};
  EXPECT_EQ(answered->count, 1);
  ASSERT_EQ(answered->answer->items.size(), 1U) << to_string(answered->answer->batchStatus.status_code());
  EXPECT_TRUE(answered->answer->items[0].is_good()) << to_string(answered->answer->items[0].status_code());
}

// A source built by make_value_source answers one call once, after every item has answered, with each item's
// own answer. A handler that answers an item a second time does not complete the call in its place, and is
// not taken for another item's answer.
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-SECOND-ANSWER-IS-DROPPED, scope=function)
TEST(ValueSourceFactory, ASecondAnswerToOneItemNeitherCompletesTheCallNorStandsForAnotherItem)
{
  const NodeId firstId{1, "factory-first"};
  const NodeId secondId{1, "factory-second"};
  const auto first = default_ns::VariableNode::create(firstId);
  const auto second = default_ns::VariableNode::create(secondId);
  std::function<void(DataValueResult)> secondAnswer;
  auto source = make_value_source(
    [&firstId, &secondAnswer](const ValueSource::ReadContext&,
      const Node& node,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        complete)
    {
      if (node_id_of(node) == firstId)
      {
        complete(DataValueResult{DataValue{Variant{int32_t{1}}}});
        complete(DataValueResult{DataValue{Variant{int32_t{11}}}});
        return;
      }
      secondAnswer = std::move(complete);
    });

  const RequestInfo request{};
  const ValueSource::ReadContext context{request, nullptr, 0.0, false};
  ReadValueId firstRead;
  firstRead.node_id() = firstId;
  ReadValueId secondRead;
  secondRead.node_id() = secondId;
  const std::array items{
    ValueSource::ReadItem{*first, firstRead}, ValueSource::ReadItem{*second, secondRead}};
  int completions = 0;
  BatchResult<DataValueResult> answered;
  source->read_async(context,
    items,
    [&completions, &answered](BatchResult<DataValueResult> batch)
    {
      ++completions;
      answered = std::move(batch);
    });
  EXPECT_EQ(completions, 0) << "the call completed before its second item answered";
  ASSERT_TRUE(secondAnswer) << "the second item was not read";

  secondAnswer(DataValueResult{DataValue{Variant{int32_t{2}}}});
  ASSERT_EQ(completions, 1);
  ASSERT_EQ(answered.items.size(), 2U);
  ASSERT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  ASSERT_TRUE(answered.items[1].is_good()) << to_string(answered.items[1].status_code());
  const auto* firstValue = answered.items[0].value().value().try_as<int32_t>();
  const auto* secondValue = answered.items[1].value().value().try_as<int32_t>();
  ASSERT_NE(firstValue, nullptr);
  ASSERT_NE(secondValue, nullptr);
  EXPECT_EQ(*firstValue, 1);
  EXPECT_EQ(*secondValue, 2);
}
