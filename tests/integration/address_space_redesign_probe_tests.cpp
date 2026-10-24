// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The suspected defects of address_space_1_0.md section 10.1, probed over the wire (P0, section 8.4
///        item 4).
///
/// Each probe states the conformant behaviour, from its criterion in
/// the server redesign probe record. A probe that fails confirms its suspicion and carries
/// `@pending` against the DEFECT that records it, which P6 fixes; one that passes refutes it. Controls show
/// each fixture works.

#include <gtest/gtest.h>

#include <chrono>
#include <limits>
#include <string>

#include "compliance_helpers.h"
#include "requests.h"
#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_element_operand.h"
#include "ua_eu_information.h"
#include "ua_literal_operand.h"
#include "ua_node_accessor.h"
#include "ua_range.h"
#include "ua_read_response.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_session_attribute_services.h"
#include "ua_unknown_structure.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

using namespace ua;
using namespace std::chrono_literals;

namespace
{

class AddressSpaceRedesignProbes : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    using Bit = AccessLevelType::Bit;
    mBaseDataType = make_variable(97000,
      NodeId{DataTypeId::BaseDataType},
      ValueRank{ValueRank::any},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{int32_t{1}});
    Range range;
    range.low() = 0.0;
    range.high() = 10.0;
    mRangeTyped = make_variable(97001,
      NodeId{DataTypeId::Range},
      ValueRank{ValueRank::scalar},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{range});
    mScalar = make_variable(97002,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::scalar},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{int32_t{1}});
    mOneDimension = make_variable(97003,
      NodeId{DataTypeId::Int32},
      ValueRank{1},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{Array<int32_t>{1, 2, 3, 4}});
    mTimestampWritable = make_variable(97004,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::scalar},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite, Bit::TimestampWrite},
      Variant{int32_t{1}});
    mPlain = make_variable(97005,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::scalar},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{int32_t{1}});
    mFilterOperandTyped = make_variable(97007,
      NodeId{DataTypeId::FilterOperand},
      ValueRank{ValueRank::scalar},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{LiteralOperand{}});
    mRangeArrayTyped = make_variable(97008,
      NodeId{DataTypeId::Range},
      ValueRank{1},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      ranges(2));
    mAnyRank = make_variable(97009,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::any},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{int32_t{1}});
    mScalarOrOneDimension = make_variable(97010,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::scalarOrOneDimension},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{int32_t{1}});
    mOneOrMore = make_variable(97011,
      NodeId{DataTypeId::Int32},
      ValueRank{ValueRank::oneOrMore},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{Array<int32_t>{1}});
    mMatrix = make_variable(97012,
      NodeId{DataTypeId::Int32},
      ValueRank{2},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      matrix());
    mByteArray = make_variable(97013,
      NodeId{DataTypeId::Byte},
      ValueRank{1},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{Array<uint8_t>{1, 2}});
    // A simple DataType derived from Byte: on the wire a Byte, so its array takes a ByteString too.
    const NodeId tinyByte{mTestNamespaceIndex, uint32_t{97100}};
    {
      auto addressSpace = mServer.server().address_space();
      auto dataType = addressSpace.create_node_sync(tinyByte, NodeClass::DataType);
      dataType.set_browse_name(QualifiedName{mTestNamespaceIndex, "TinyByte"});
      // The address space adds the inverse half on TinyByte (NR-70 B8).
      addressSpace.find_node_sync(NodeId{DataTypeId::Byte})
        .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{tinyByte});
    }
    mTinyByteArray = make_variable(97014,
      tinyByte,
      ValueRank{1},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite},
      Variant{Array<uint8_t>{1, 2}});
    mSliceable = make_variable(97006,
      NodeId{DataTypeId::Int32},
      ValueRank{1},
      AccessLevelType{Bit::CurrentRead, Bit::CurrentWrite, Bit::StatusWrite, Bit::TimestampWrite},
      Variant{Array<int32_t>{1, 2, 3, 4}});
  }

  /// A two-by-two Int32 matrix.
  static Variant matrix()
  {
    return Variant{Array<int32_t>{Dimensions{2, 2}, std::vector<int32_t>{1, 2, 3, 4}}};
  }

  /// An array of @p count Range structures, the form a Variant holds a Structure array in.
  static Variant ranges(std::size_t count)
  {
    Array<RefStructure<Structure>> array;
    for (std::size_t index = 0; index < count; ++index)
    {
      array.payload().emplace_back(unique_ptr<Structure>{std::make_unique<Range>()});
    }
    return Variant{std::move(array)};
  }

  NodeId make_variable(
    uint32_t id, const NodeId& dataType, ValueRank valueRank, AccessLevelType accessLevel, Variant initial)
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId nodeId{mTestNamespaceIndex, id};
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
      ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{nodeId});
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    const std::string name = "Probe" + std::to_string(id);
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    variable->set_display_name(LocalizedText{"", name});
    variable->set_data_type(dataType);
    variable->set_value_rank(valueRank);
    variable->write_value_sync(std::move(initial));
    variable->set_access_level(accessLevel);
    return nodeId;
  }

  StatusCode write(const NodeId& node, DataValue value, const char* indexRange = nullptr)
  {
    WriteRequestBuilder builder;
    builder.write(node, std::move(value));
    if (indexRange != nullptr)
    {
      builder.index_range(String{indexRange});
    }
    auto response = mSession->attributes().try_write_sync(builder.build());
    EXPECT_TRUE(response.is_good()) << to_string(response.status_code());
    if (!response.is_good() || response.value().results().empty())
    {
      return StatusCode{Status::BadUnexpectedError};
    }
    return response.value().results()[0];
  }

  StatusCode write(const NodeId& node, Variant value)
  {
    return write(node, DataValue{std::move(value)});
  }

  DataValue read(const NodeId& node)
  {
    auto response = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                           .read(node)
                                                           .attribute(AttributeId::Value)
                                                           .timestamps(TimestampsToReturn::Both)
                                                           .build());
    EXPECT_TRUE(response.is_good());
    if (!response.is_good() || response.value().results().empty())
    {
      return DataValue{};
    }
    return response.value().results()[0];
  }

  NodeId mBaseDataType;
  NodeId mRangeTyped;
  NodeId mScalar;
  NodeId mOneDimension;
  NodeId mTimestampWritable;
  NodeId mPlain;
  NodeId mSliceable;
  NodeId mFilterOperandTyped;
  NodeId mRangeArrayTyped;
  NodeId mAnyRank;
  NodeId mScalarOrOneDimension;
  NodeId mOneOrMore;
  NodeId mMatrix;
  NodeId mByteArray;
  NodeId mTinyByteArray;
};

}  // namespace

// F1, fixed in P6. BaseDataType is the root of the DataType hierarchy: every value's type is a subtype of
// it, and "subtypes of the Attribute DataType shall be accepted" (Part 4 section 5.10.4.2). The synchronous
// check mapped namespace-0 id 24 to built-in type 24, Variant, and compared a scalar's type with it.
// @relation(AC-SVR-PROBE-F1-BASEDATATYPE-ACCEPTS-ANY-VALUE, scope=function)
TEST_F(AddressSpaceRedesignProbes, ABaseDataTypeVariableAcceptsAScalarOfAnyBuiltInType)
{
  EXPECT_EQ(write(mBaseDataType, Variant{int32_t{5}}).as_status(), Status::Good);
  EXPECT_EQ(write(mBaseDataType, Variant{String{"text"}}).as_status(), Status::Good);
}

// F2, fixed in P6. A Variable declared with a Structure DataType holds that Structure or a subtype (Part 4
// section 5.10.4.2). Neither a built-in scalar nor another Structure is a subtype of Range.
// @relation(AC-SVR-PROBE-F2-STRUCTURE-ACCEPTS-ONLY-ITS-TYPE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AStructureTypedVariableRefusesAValueThatIsNotThatStructure)
{
  EXPECT_EQ(write(mRangeTyped, Variant{int32_t{5}}).as_status(), Status::BadTypeMismatch);
  EUInformation units;
  units.unit_id() = 4408652;
  EXPECT_EQ(write(mRangeTyped, Variant{units}).as_status(), Status::BadTypeMismatch);
}

// Control for F2: the Variable accepts a Range.
TEST_F(AddressSpaceRedesignProbes, AStructureTypedVariableAcceptsItsOwnStructure)
{
  Range range;
  range.low() = 1.0;
  range.high() = 2.0;
  EXPECT_EQ(write(mRangeTyped, Variant{range}).as_status(), Status::Good);
}

// F2: a Variable declared with an abstract Structure accepts every subtype of it (Part 4 section
// 5.10.4.2) and nothing outside it.
// @relation(AC-SVR-PROBE-F2-STRUCTURE-ACCEPTS-ONLY-ITS-TYPE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AStructureTypedVariableAcceptsTheSubtypesOfItsStructureOnly)
{
  EXPECT_EQ(write(mFilterOperandTyped, Variant{LiteralOperand{}}).as_status(), Status::Good);
  EXPECT_EQ(write(mFilterOperandTyped, Variant{ElementOperand{}}).as_status(), Status::Good);
  EXPECT_EQ(write(mFilterOperandTyped, Variant{Range{}}).as_status(), Status::BadTypeMismatch);
}

// F2: every element of an array is checked, not the first; a null element carries no type.
// @relation(AC-SVR-PROBE-F2-STRUCTURE-ACCEPTS-ONLY-ITS-TYPE, scope=function)
TEST_F(AddressSpaceRedesignProbes, EveryStructureInAnArrayIsOfTheDeclaredType)
{
  EXPECT_EQ(write(mRangeArrayTyped, ranges(3)).as_status(), Status::Good) << "control";
  Array<RefStructure<Structure>> mixed;
  mixed.payload().emplace_back(unique_ptr<Structure>{std::make_unique<Range>()});
  mixed.payload().emplace_back(unique_ptr<Structure>{std::make_unique<EUInformation>()});
  EXPECT_EQ(write(mRangeArrayTyped, Variant{std::move(mixed)}).as_status(), Status::BadTypeMismatch);
}

// F2: a Structure the server cannot decode, whose encoding no DataType in the address space owns, cannot be
// shown to be the declared type and is refused.
// @relation(AC-SVR-PROBE-F2-STRUCTURE-ACCEPTS-ONLY-ITS-TYPE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AStructureOfAnUnknownEncodingIsRefused)
{
  // A body, so the ExtensionObject is not the null one an empty body encodes.
  UnknownStructure unknown{NodeId{mTestNamespaceIndex, uint32_t{979797}},
    UnknownStructure::BodyEncoding::Binary,
    ByteString{0x01, 0x02, 0x03, 0x04}};
  EXPECT_EQ(write(mRangeTyped, Variant{std::move(unknown)}).as_status(), Status::BadTypeMismatch);
}

// F3, fixed in P6. A value whose rank the Variable's ValueRank forbids is not "the same type" as the
// Attribute (Part 4 section 5.10.4.2; Part 3 section 5.6.2 ValueRank): an array written to a Scalar
// Variable, or a scalar to a OneDimension one.
// @relation(AC-SVR-PROBE-F3-VALUERANK-CHECKED-ON-WRITE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AValueOfTheWrongRankIsRefused)
{
  EXPECT_EQ(write(mScalar, Variant{Array<int32_t>{1, 2}}).as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(write(mOneDimension, Variant{int32_t{9}}).as_status(), Status::BadTypeMismatch);
}

// Control for F3: values of the declared rank are written.
TEST_F(AddressSpaceRedesignProbes, AValueOfTheDeclaredRankIsWritten)
{
  EXPECT_EQ(write(mScalar, Variant{int32_t{9}}).as_status(), Status::Good);
  EXPECT_EQ(write(mOneDimension, Variant{Array<int32_t>{9, 8}}).as_status(), Status::Good);
}

// F3: the open ValueRanks (Part 3 section 5.6.2). Any takes a scalar and an array of any rank;
// ScalarOrOneDimension a scalar or a one-dimensional array but not a matrix; OneOrMoreDimensions an array
// of any rank but not a scalar.
// @relation(AC-SVR-PROBE-F3-VALUERANK-CHECKED-ON-WRITE, scope=function)
TEST_F(AddressSpaceRedesignProbes, TheOpenValueRanksTakeWhatTheyName)
{
  EXPECT_EQ(write(mAnyRank, Variant{int32_t{3}}).as_status(), Status::Good);
  EXPECT_EQ(write(mAnyRank, matrix()).as_status(), Status::Good);
  EXPECT_EQ(write(mScalarOrOneDimension, Variant{int32_t{3}}).as_status(), Status::Good);
  EXPECT_EQ(write(mScalarOrOneDimension, Variant{Array<int32_t>{3, 4}}).as_status(), Status::Good);
  EXPECT_EQ(write(mScalarOrOneDimension, matrix()).as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(write(mOneOrMore, Variant{Array<int32_t>{3, 4}}).as_status(), Status::Good);
  EXPECT_EQ(write(mOneOrMore, matrix()).as_status(), Status::Good);
  EXPECT_EQ(write(mOneOrMore, Variant{int32_t{3}}).as_status(), Status::BadTypeMismatch);
}

// F3: a fixed rank above one is the number of dimensions (Part 3 section 5.6.2): a two-dimensional
// Variable takes a matrix and refuses a one-dimensional array and a scalar.
// @relation(AC-SVR-PROBE-F3-VALUERANK-CHECKED-ON-WRITE, scope=function)
TEST_F(AddressSpaceRedesignProbes, ATwoDimensionalVariableTakesAMatrixOnly)
{
  EXPECT_EQ(write(mMatrix, matrix()).as_status(), Status::Good);
  EXPECT_EQ(write(mMatrix, Variant{Array<int32_t>{1, 2, 3, 4}}).as_status(), Status::BadTypeMismatch);
  EXPECT_EQ(write(mMatrix, Variant{int32_t{1}}).as_status(), Status::BadTypeMismatch);
}

// F3: "A ByteString is structurally the same as a one dimensional array of Byte. A Server shall accept a
// ByteString if an array of Byte is expected" (Part 4 section 5.10.4.2).
// @relation(AC-SVR-PROBE-F3-VALUERANK-CHECKED-ON-WRITE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AByteStringIsAcceptedWhereAnArrayOfByteIsExpected)
{
  EXPECT_EQ(write(mByteArray, Variant{ByteString{7, 8, 9}}).as_status(), Status::Good);
  EXPECT_EQ(write(mByteArray, Variant{Array<uint8_t>{7, 8}}).as_status(), Status::Good) << "control";
  EXPECT_EQ(write(mByteArray, Variant{uint8_t{7}}).as_status(), Status::BadTypeMismatch)
    << "a Byte scalar is not an array";
  EXPECT_EQ(write(mTinyByteArray, Variant{ByteString{7, 8, 9}}).as_status(), Status::Good)
    << "an array of a simple DataType derived from Byte is an array of Byte on the wire";
}

// F4a, fixed in P6. Without the TimestampWrite bit only null timestamps are writable (Part 3 section
// 8.57); a Server that does not write a timestamp says so with Bad_WriteNotSupported (Part 4 section
// 5.10.4.2).
// @relation(AC-SVR-PROBE-F4A-TIMESTAMPWRITE-CHECKED, scope=function)
TEST_F(AddressSpaceRedesignProbes, ASourceTimestampIsRefusedWithoutTimestampWrite)
{
  DataValue value{Variant{int32_t{7}}};
  value.source_timestamp() = DateTime::now();
  EXPECT_EQ(write(mPlain, std::move(value)).as_status(), Status::BadWriteNotSupported);
}

// F4a: "0 means only null timestamps are writable" (Part 3 section 8.57): a null SourceTimestamp is
// writable without TimestampWrite, and so is a Value with none.
// @relation(AC-SVR-PROBE-F4A-TIMESTAMPWRITE-CHECKED, scope=function)
TEST_F(AddressSpaceRedesignProbes, ANullSourceTimestampIsWritableWithoutTimestampWrite)
{
  DataValue value{Variant{int32_t{7}}};
  value.source_timestamp() = DateTime{};
  EXPECT_EQ(write(mPlain, std::move(value)).as_status(), Status::Good);
  EXPECT_EQ(write(mPlain, DataValue{Variant{int32_t{8}}}).as_status(), Status::Good)
    << "control: no timestamp";
}

// Control for F4a: with TimestampWrite the timestamp is written and read back.
TEST_F(AddressSpaceRedesignProbes, ASourceTimestampIsStoredWithTimestampWrite)
{
  const auto stamp = DateTime::now();
  DataValue value{Variant{int32_t{7}}};
  value.source_timestamp() = stamp;
  ASSERT_EQ(write(mTimestampWritable, std::move(value)).as_status(), Status::Good);
  const auto stored = read(mTimestampWritable);
  ASSERT_TRUE(stored.source_timestamp().has_value());
  EXPECT_EQ(*stored.source_timestamp(), stamp);
}

// F4b, fixed in P6. "If the SourceTimestamp or the ServerTimestamp is specified, the Server shall use these
// values" (Part 4 section 5.10.4.2), and with StatusWrite the written StatusCode is the Value's (Part 3
// section 8.57). An indexRange write rebuilds the DataValue and drops both.
// @relation(AC-SVR-PROBE-F4B-INDEXRANGE-WRITE-KEEPS-STATUS-AND-TIMESTAMP, scope=function)
TEST_F(AddressSpaceRedesignProbes, AnIndexRangeWriteKeepsTheWrittenStatusAndSourceTimestamp)
{
  const auto stamp = DateTime::now();
  DataValue value{Variant{Array<int32_t>{9}}};
  value.status() = StatusCode{Status::UncertainInitialValue};
  value.source_timestamp() = stamp;
  ASSERT_EQ(write(mSliceable, std::move(value), "1").as_status(), Status::Good);

  const auto stored = read(mSliceable);
  EXPECT_EQ(stored.status().value_or(StatusCode{Status::Good}).as_status(), Status::UncertainInitialValue);
  ASSERT_TRUE(stored.source_timestamp().has_value());
  EXPECT_EQ(*stored.source_timestamp(), stamp);
}

// F4b: the written ServerTimestamp is the client's too, on an indexRange Write as on a whole one, and is
// what a cached-value read returns.
// @relation(AC-SVR-PROBE-F4B-INDEXRANGE-WRITE-KEEPS-STATUS-AND-TIMESTAMP, scope=function)
TEST_F(AddressSpaceRedesignProbes, AnIndexRangeWriteKeepsTheWrittenServerTimestamp)
{
  const DateTime stamp{std::chrono::sys_days{std::chrono::year{2024} / 1 / 1}};
  DataValue value{Variant{Array<int32_t>{5}}};
  value.server_timestamp() = stamp;
  ASSERT_EQ(write(mSliceable, std::move(value), "2").as_status(), Status::Good);

  // A cached-value read (maxAge of Int32 max or more, Part 4 section 5.10.2.2): a fresher read reports the
  // time the value is read from its source instead.
  auto response = mSession->attributes().try_read_sync(ReadRequestBuilder()
                                                         .read(mSliceable)
                                                         .attribute(AttributeId::Value)
                                                         .timestamps(TimestampsToReturn::Both)
                                                         .max_age(std::numeric_limits<int32_t>::max())
                                                         .build());
  ASSERT_TRUE(response.is_good());
  ASSERT_EQ(response.value().results().size(), 1u);
  const auto& stored = response.value().results()[0];
  ASSERT_TRUE(stored.server_timestamp().has_value());
  EXPECT_EQ(*stored.server_timestamp(), stamp) << "the Server kept its own time, not the written one";
}

// F8 (found while probing F4), fixed in P6. Without the StatusWrite bit "only StatusCode Good is writable"
// (Part 3 section 8.57): a DataValue that states Good explicitly is still writable.
// @relation(AC-SVR-PROBE-F8-EXPLICIT-GOOD-STATUS-WRITABLE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AnExplicitGoodStatusIsWritableWithoutStatusWrite)
{
  DataValue value{Variant{int32_t{8}}};
  value.status() = StatusCode{Status::Good};
  EXPECT_EQ(write(mPlain, std::move(value)).as_status(), Status::Good);
}

// Control for F8: a Bad StatusCode is refused without StatusWrite.
TEST_F(AddressSpaceRedesignProbes, ABadStatusIsRefusedWithoutStatusWrite)
{
  DataValue value{Variant{int32_t{8}}};
  value.status() = StatusCode{Status::BadSensorFailure};
  EXPECT_EQ(write(mPlain, std::move(value)).as_status(), Status::BadWriteNotSupported);
}

// F8: a Good subcode is not "StatusCode Good" (Part 3 section 8.57), so it is refused without StatusWrite as
// a Bad one is.
// @relation(AC-SVR-PROBE-F8-EXPLICIT-GOOD-STATUS-WRITABLE, scope=function)
TEST_F(AddressSpaceRedesignProbes, AGoodSubcodeIsRefusedWithoutStatusWrite)
{
  DataValue value{Variant{int32_t{8}}};
  value.status() = StatusCode{Status::GoodLocalOverride};
  EXPECT_EQ(write(mPlain, std::move(value)).as_status(), Status::BadWriteNotSupported);
}

namespace
{

const NodeId unregisteredNamespaceRoleId{40, uint32_t{9902}};

class AddressSpaceRedesignRoleProbe : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    auto roles = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});
    RoleConfiguration::RoleDefinition role;
    role.roleId = unregisteredNamespaceRoleId;
    role.roleBit = 9;
    role.browseName = QualifiedName{1, "UnregisteredNamespaceRole"};
    ASSERT_TRUE(roles->add_role(std::move(role)));
    components.roleConfiguration = std::move(roles);
  }
};

}  // namespace

// F6, fixed in P6. A Role configured in a namespace the Server has not registered cannot be materialised
// under RoleSet. Start-up skipped it and reported nothing, so an administrator could not tell why the Role
// is missing. No silent overrides: the skip is reported, for that Role only.
// @relation(AC-SVR-PROBE-F6-UNMATERIALISED-ROLE-REPORTED, scope=function)
TEST_F(AddressSpaceRedesignRoleProbe, ARoleInANamespaceNotRegisteredAtStartIsReported)
{
  bool reported = false;
  std::size_t notCreated = 0;
  for (const auto& record : mServerLogSink->records())
  {
    if (record.level >= LogLevel::Warning && record.message.find("9902") != std::string::npos)
    {
      reported = true;
    }
    if (record.message.find("is not created under RoleSet") != std::string::npos)
    {
      ++notCreated;
    }
  }
  EXPECT_TRUE(reported) << "a configured Role that could not be created is reported at start-up";
  EXPECT_EQ(notCreated, 1u) << "control: the Roles that were created are not reported";
}
