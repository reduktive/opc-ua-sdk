// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 4: Attribute Service Set - Write Compliance Integration Tests
///
/// Tests covering Part 4 Attribute Write requirements (ATTR-WRITE-*).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_access_level_ex_type.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_range.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_server.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_timestamps_to_return.h"
#include "ua_data_access_utils.h"
#include "ua_server_configuration.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include "ua_to_string.h"

#include <memory>

#include <cstdint>
#include <limits>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using ::testing::ElementsAre;

namespace
{

/// Read one attribute and return its DataValue. Asserts response shape; failure
/// inside this helper records a non-fatal failure but returns whatever the server sent.
DataValue read_back(Session& session, const NodeId& node, AttributeId attr = AttributeId::Value,
  TimestampsToReturn ts = TimestampsToReturn::Both)
{
  auto resp = session.attributes().read_sync(read_value(node, attr, ts));
  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.results().size(), 1u);
  if (resp.results().size() != 1u)
  {
    return DataValue{};
  }
  return std::move(resp.results()[0]);
}

/// Read a Value at maxAge Int32 max, the cached-value read of Part 4 5.10.2.2: the value the Server
/// holds is returned with the ServerTimestamp it holds. A read at a smaller maxAge is entitled to a
/// fresh ServerTimestamp once the held one is older than maxAge, so a written ServerTimestamp is only
/// observable through this read.
DataValue read_back_cached(Session& session, const NodeId& node, TimestampsToReturn ts)
{
  auto request = read_value(node, AttributeId::Value, ts);
  request.max_age() = static_cast<double>(std::numeric_limits<int32_t>::max());
  auto resp = session.attributes().read_sync(std::move(request));
  EXPECT_THAT(resp, ServiceResultIsGood());
  EXPECT_EQ(resp.results().size(), 1u);
  if (resp.results().size() != 1u)
  {
    return DataValue{};
  }
  return std::move(resp.results()[0]);
}

}  // namespace

// ===========================================================================
// Basic Write tests
// ===========================================================================

// Write Int32 value, read back, verify match
// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, WriteValue_Int32)
{
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{777}}));
  ASSERT_THAT(resp, WriteSucceeds());

  EXPECT_THAT(read_back(*mSession, mWritableVariableId), good_value_of<int32_t>(777));
}

// Requirement: SVR-ATTR-WRITE-008 (SHALL)
// A Server shall return a Bad_TypeMismatch error if the data type of the written
// value is not the same type or subtype of the Attribute's DataType.
// Spec: Part 4, section 5.10.4.2, line 3954
// Covers SVR-ATTR-WRITE-026 (coverage-audit retag).
TEST_F(ComplianceWithNodes, WriteValue_String)
{
  // Write a String to an Int32-typed variable - should be rejected.
  auto result = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{String{"Hello"}}));
  ASSERT_THAT(result, Good());
  EXPECT_THAT(std::move(result).value(), WriteFailsWith(Status::BadTypeMismatch));
}

// A null Value written to a scalar Variable with no AllowNulls Property is either accepted or refused
// as Bad_TypeMismatch (Part 4 5.10.4; the CTT's Attribute Write Values Err-009 accepts exactly those
// two). Bad_InvalidState describes the server, not the request, and is never the answer.
TEST_F(ComplianceWithNodes, WriteValue_NullVariantIsAcceptedOrTypeMismatch)
{
  auto result =
    mSession->attributes().try_write_sync(WriteRequestBuilder().write(mWritableVariableId, Variant{}));
  ASSERT_THAT(result, Good());
  const auto response = std::move(result).value();
  ASSERT_EQ(response.results().size(), 1u);
  const StatusCode status = response.results()[0];
  EXPECT_TRUE(status.is_good() || status == Status::BadTypeMismatch) << to_string(status);
}

// Write -> Read roundtrip for writable variable
// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, WriteReadRoundTrip)
{
  // Write a specific value
  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{12345}})),
    WriteSucceeds());

  // Read it back
  EXPECT_THAT(read_back(*mSession, mWritableVariableId), good_value_of<int32_t>(12345));

  // Write a different value
  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{-999}})),
    WriteSucceeds());

  // Read it back again
  EXPECT_THAT(read_back(*mSession, mWritableVariableId), good_value_of<int32_t>(-999));
}

// Write multiple nodes in single request
// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, WriteMultipleNodes)
{
  auto resp = mSession->attributes().write_sync(WriteRequestBuilder()
                                                  .write(mWritableVariableId, Variant{int32_t{111}})
                                                  .write(mWritableVariableId, Variant{int32_t{222}}));

  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_THAT(resp.results().payload(), ElementsAre(Good(), Good()));

  // The last write wins - read back to verify
  EXPECT_THAT(read_back(*mSession, mWritableVariableId), good_value_of<int32_t>(222));
}

// Write DataValue with explicit StatusCode -> status preserved (requires StatusWrite access).
// @relation(SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, WriteStatusCodeInDataValue)
{
  // Use the full-access variable which has StatusWrite.
  DataValue dvToWrite;
  dvToWrite.value() = Variant{int32_t{42}};
  dvToWrite.status() = StatusCode{Status::UncertainLastUsableValue};

  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mFullAccessVariableId, std::move(dvToWrite))),
    WriteSucceeds());

  auto dv = read_back(*mSession, mFullAccessVariableId);
  ASSERT_TRUE(dv.status().has_value()) << "Status should be preserved for variable with StatusWrite access";
  EXPECT_EQ(dv.status()->as_status(), Status::UncertainLastUsableValue);
}

// ===========================================================================
// Requirement-specific Write tests
// ===========================================================================

// Requirement: SVR-ATTR-WRITE-007 (SHALL)
// If the SourceTimestamp or the ServerTimestamp is specified, the Server shall use these values.
// Spec: Part 4, section 5.10.4.2, line 3951
// @verifies CL-ATTR-027
// @relation(AC-SVR-ATTR-WRITE-007-SUPPLIED-TIMESTAMPS, scope=function)
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-007, SVR-ATTR-WRITE-031, CL-ATTR-027, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_007_SourceTimestampPreserved)
{
  // Write with an explicit source timestamp (requires TimestampWrite access level).
  DateTime sourceTs{2020, 6, 15, 10, 30, 0.0};
  DataValue dvToWrite;
  dvToWrite.value() = Variant{int32_t{707}};
  dvToWrite.source_timestamp() = sourceTs;

  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mFullAccessVariableId, std::move(dvToWrite))),
    WriteSucceeds());

  // Read back with Source timestamps
  auto dv = read_back(*mSession, mFullAccessVariableId, AttributeId::Value, TimestampsToReturn::Source);
  ASSERT_TRUE(dv.source_timestamp().has_value()) << "Source timestamp should be preserved";
  EXPECT_EQ(dv.source_timestamp().value(), sourceTs);
}

// Requirement: SVR-ATTR-WRITE-007 (SHALL)
// ServerTimestamp variant
// @relation(AC-SVR-ATTR-WRITE-007-SUPPLIED-TIMESTAMPS, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_007_ServerTimestampPreserved)
{
  // Write with an explicit server timestamp (requires TimestampWrite access level).
  DateTime serverTs{2020, 6, 15, 11, 0, 0.0};
  DataValue dvToWrite;
  dvToWrite.value() = Variant{int32_t{708}};
  dvToWrite.server_timestamp() = serverTs;

  auto result = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mFullAccessVariableId, std::move(dvToWrite)));
  ASSERT_THAT(result, Good());
  EXPECT_THAT(std::move(result).value(), WriteSucceeds())
    << "Write with TimestampWrite access should succeed";

  // The cached-value read returns the ServerTimestamp that was written (Part 4 5.10.4.2, "the
  // Server shall use these values").
  auto dv = read_back_cached(*mSession, mFullAccessVariableId, TimestampsToReturn::Server);
  ASSERT_TRUE(dv.server_timestamp().has_value()) << "Server timestamp should be present";
  EXPECT_EQ(dv.server_timestamp().value(), serverTs);

  // A read at maxAge 0 obliges a new read from the data source (Part 4 5.10.2.2). The Server is that
  // source and knows the value accurate now, so the six-year-old stamp is not returned as current.
  const DateTime beforeFreshRead = DateTime::now();
  auto fresh = read_back(*mSession, mFullAccessVariableId, AttributeId::Value, TimestampsToReturn::Server);
  EXPECT_THAT(fresh, good_value_of<int32_t>(708));
  ASSERT_TRUE(fresh.server_timestamp().has_value());
  EXPECT_GE(fresh.server_timestamp().value(), beforeFreshRead)
    << "a maxAge 0 read must not return a ServerTimestamp older than the request";
}

// Requirement: SVR-ATTR-WRITE-009 (SHALL)
// Based on the DataType hierarchy, subtypes of the Attribute DataType shall be accepted.
// Spec: Part 4, section 5.10.4.2, line 3955
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-008, SVR-ATTR-WRITE-009, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_008_SubtypeAccepted)
{
  // mNumberVariableId has DataType = Number (abstract supertype of all numeric types).
  // Writing an Int32 value (which is a subtype of Number) should be accepted.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mNumberVariableId, Variant{int32_t{999}})),
    WriteSucceeds())
    << "Int32 (subtype of Number) should be accepted";

  // Also verify a Double (another subtype of Number) is accepted.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mNumberVariableId, Variant{double{3.14}})),
    WriteSucceeds())
    << "Double (subtype of Number) should be accepted";

  // Verify a non-numeric type (String) is rejected.
  EXPECT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mNumberVariableId, Variant{String{"not a number"}})),
    WriteFailsWith(Status::BadTypeMismatch))
    << "String (not a subtype of Number) should be rejected";
}

// Requirement: SVR-ATTR-WRITE-010 (SHALL)
// Writing a value whose DataType is not a subtype of the node's declared abstract DataType
// shall return Bad_TypeMismatch. Integer and UInteger are sibling subtypes of Number; a signed
// integer is not a valid UInteger and vice-versa.
// Spec: Part 4, section 7.7.1 (Write), section 5.6.2 type-compatibility.
TEST_F(ComplianceWithNodes, ATTR_WRITE_010_AbstractSubtypeMismatchRejected)
{
  // mUIntegerVariableId has DataType = UInteger (Byte/UInt16/UInt32/UInt64 only).
  // A signed integer is NOT a subtype of UInteger.
  for (Variant signedValue :
    {Variant{int8_t{-1}}, Variant{int16_t{-1}}, Variant{int32_t{-1}}, Variant{int64_t{-1}}})
  {
    EXPECT_THAT(
      mSession->attributes().write_sync(WriteRequestBuilder().write(mUIntegerVariableId, signedValue)),
      WriteFailsWith(Status::BadTypeMismatch))
      << "Signed integer should be rejected for a UInteger-typed node";
  }

  // An unsigned integer IS a subtype of UInteger and must be accepted.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mUIntegerVariableId, Variant{uint32_t{7}})),
    WriteSucceeds())
    << "UInt32 (subtype of UInteger) should be accepted";
}

// Requirement: SVR-ATTR-WRITE-008 (SHALL)
// The built-in base type of a named DataType subtype shall be enforced on Write. Duration is a
// subtype of Double, so a non-Double value must be rejected with Bad_TypeMismatch.
// Spec: Part 4, section 7.7.1 (Write); Part 3, section 5.6.2 (DataType subtyping).
TEST_F(ComplianceWithNodes, ATTR_WRITE_008_BuiltInBaseTypeOfSubtypeEnforced)
{
  // mDurationVariableId has DataType = Duration ( subset of  Double). A non-Double value is rejected.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mDurationVariableId, Variant{int32_t{5}})),
    WriteFailsWith(Status::BadTypeMismatch))
    << "Int32 should be rejected for a Duration ( subset of  Double) node";

  EXPECT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mDurationVariableId, Variant{String{"nope"}})),
    WriteFailsWith(Status::BadTypeMismatch))
    << "String should be rejected for a Duration ( subset of  Double) node";

  // A Double value IS the built-in base type and must be accepted.
  EXPECT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mDurationVariableId, Variant{double{2500.0}})),
    WriteSucceeds())
    << "Double (built-in base of Duration) should be accepted";
}

// Requirement: SVR-ATTR-WRITE-002 (SHALL)
// Writing a null String for the text for a locale shall delete the String for that locale.
// Spec: Part 4, section 5.10.4.1, line 3919
// @verifies CL-ATTR-021
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-002, SVR-ATTR-WRITE-031, CL-ATTR-021, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_002_NullTextDeletesLocale)
{
  // First, set up a known locale so we have something to delete.
  ASSERT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(
      mWritableDisplayNameNodeId, Variant{LocalizedText{"en", "EnglishDisplay"}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "Setup write should succeed";

  // Write empty text for the "en" locale - this should delete the "en" entry.
  ASSERT_THAT(mSession->attributes().write_sync(WriteRequestBuilder().write(
                mWritableDisplayNameNodeId, Variant{LocalizedText{"en", ""}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "Write should succeed with WriteMask.DisplayName";

  // Read back DisplayName and verify the text for "en" is empty (deleted).
  auto dv = read_back(*mSession, mWritableDisplayNameNodeId, AttributeId::DisplayName);
  EXPECT_THAT(dv, Good());
  auto displayName = dv.value().as<LocalizedText>();
  EXPECT_TRUE(displayName.text().empty())
    << "Expected empty text after deleting 'en' locale, got: " << std::string_view{displayName.text()};
}

// Requirement: SVR-ATTR-WRITE-003 (SHALL)
// Writing a null String for the text and a null String for the locale shall delete all entries.
// Spec: Part 4, section 5.10.4.1, line 3921
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-003, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_003_NullTextAndLocaleDeletesAll)
{
  // First, set up a known display name so there is something to delete.
  ASSERT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(
      mWritableDisplayNameNodeId, Variant{LocalizedText{"en", "ToBeDeleted"}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "Setup write should succeed";

  // Write empty text and empty locale - this should delete all locale entries.
  ASSERT_THAT(mSession->attributes().write_sync(WriteRequestBuilder().write(
                mWritableDisplayNameNodeId, Variant{LocalizedText{"", ""}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "Write should succeed with WriteMask.DisplayName";

  // Read back DisplayName - text and locale should both be empty after deleting all entries.
  auto dv = read_back(*mSession, mWritableDisplayNameNodeId, AttributeId::DisplayName);
  EXPECT_THAT(dv, Good());
  auto displayName = dv.value().as<LocalizedText>();
  EXPECT_TRUE(displayName.text().empty())
    << "Expected empty text after deleting all locale entries, got: " << std::string_view{displayName.text()};
  EXPECT_TRUE(displayName.locale().empty())
    << "Expected empty locale after deleting all locale entries, got: "
    << std::string_view{displayName.locale()};
}

// ===========================================================================
// Negative Write tests
// ===========================================================================

// Requirement: SVR-ATTR-WRITE-006 (SHALL)
// If the indexRange parameter is specified then the Value shall be an array
// even if only one element is being written.
// Spec: Part 4, section 5.10.4.2, line 3949
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-006, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_006_IndexRangeRequiresArray)
{
  // Write a scalar value with an index range - should be rejected.
  // The spec requires the written value to be an array when indexRange is specified.
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{42}}).index_range(String{"0"}));
  EXPECT_THAT(resp, WriteFailsWith(Status::BadIndexRangeNoData));
}

// Requirement: SVR-ATTR-WRITE-011 (SHALL)
// A Server shall accept a ByteString if an array of Byte is expected.
// Spec: Part 4, section 5.10.4.2, line 3960
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-011, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_011_ByteStringAcceptedAsArray)
{
  // mByteArrayVariableId has DataType = Byte and ValueRank = 1 (one-dimensional array).
  // Writing a ByteString to a Byte array variable should succeed per the spec.
  ByteString bs{uint8_t{10}, uint8_t{20}, uint8_t{30}};
  EXPECT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mByteArrayVariableId, Variant{std::move(bs)})),
    WriteSucceeds())
    << "ByteString to Byte array variable should succeed";

  // Read back and verify the values match.
  auto dv = read_back(*mSession, mByteArrayVariableId);
  EXPECT_THAT(dv, Good());
  // The value may come back as either a ByteString or an Array<uint8_t> depending on
  // how the server stores it. Verify the data matches either way.
  if (dv.value().is_byte_string())
  {
    auto readBack = dv.value().as<ByteString>();
    ASSERT_EQ(readBack.size(), 3u);
    EXPECT_EQ(readBack[0], uint8_t{10});
    EXPECT_EQ(readBack[1], uint8_t{20});
    EXPECT_EQ(readBack[2], uint8_t{30});
  }
  else
  {
    auto readBack = dv.value().as<Array<uint8_t>>();
    ASSERT_EQ(readBack.size(), 3u);
    EXPECT_EQ(readBack[0], 10u);
    EXPECT_EQ(readBack[1], 20u);
    EXPECT_EQ(readBack[2], 30u);
  }

  // Also verify that ByteString to a non-Byte variable is still rejected.
  ByteString bs2{uint8_t{1}, uint8_t{2}};
  EXPECT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mWritableVariableId, Variant{std::move(bs2)})),
    WriteFailsWith(Status::BadTypeMismatch))
    << "ByteString to Int32 variable should be BadTypeMismatch";
}

// Requirement: SVR-ATTR-WRITE-021 (SHALL)
// Bad_IndexRangeNoData - Index range results in no data.
// Spec: Part 4, section 5.10.4.4, line 4014
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-021, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_021_BadIndexRangeNoData)
{
  // First write a scalar value (not an array).
  ASSERT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{42}})),
    WriteSucceeds());

  // Now try to write with an index range on a scalar - should fail.
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{Array<int32_t>{99}}).index_range(String{"100"}));
  EXPECT_THAT(resp, WriteFailsWith(Status::BadIndexRangeNoData));
}

// Requirement: SVR-ATTR-WRITE-022 (SHALL)
// Bad_WriteNotSupported - Server does not support the requested value/status/timestamp
// combination for this Node. Server shall not perform any write on this Node.
// Spec: Part 4, section 5.10.4.4, line 4016
// @verifies CL-ATTR-028
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-005, SVR-ATTR-WRITE-022, SVR-ATTR-WRITE-031, CL-ATTR-028, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_022_BadWriteNotSupported)
{
  // Write only a StatusCode without a value - our variable only has CurrentRead + CurrentWrite
  // access level (no StatusWrite), so only StatusCode Good is writable (Part 3 section 8.57). An Uncertain
  // one is a status this Node does not support writing: BadWriteNotSupported.
  DataValue dvToWrite;
  dvToWrite.status() = StatusCode{Status::UncertainLastUsableValue};

  auto result = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, std::move(dvToWrite)));
  ASSERT_THAT(result, Good());
  EXPECT_THAT(std::move(result).value(), WriteFailsWith(Status::BadWriteNotSupported))
    << "Status-only write without StatusWrite access should be rejected";
}

// Requirement: SVR-ATTR-WRITE-025 (SHALL)
// Bad_OutOfRange - Value is outside the valid range (e.g. not contained in the
// enumeration data type).
// Spec: Part 4, section 5.10.4.4, line 4025
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-025, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_025_BadOutOfRange)
{
  // mEnumVariableId has DataType = ServerState (enum, valid values 0-7).
  // Writing a value outside this range should return BadOutOfRange.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mEnumVariableId, Variant{int32_t{999}})),
    WriteFailsWith(Status::BadOutOfRange))
    << "Out-of-range enum value should be rejected";
}

// Part 3 section 8.58: WriteFullArrayOnly advertises that the Variable supports whole-array writes but not
// IndexRange writes. Part 4 section section 5.10.4.2 and 5.10.4.4 require Bad_WriteNotSupported and no
// mutation for that unsupported combination. The valid in-bounds range isolates this rule from malformed or
// empty range handling.
// @verifies AC-SVR-ATTR-WRITE-005-INDEXRANGE-NOT-WRITABLE
TEST_F(ComplianceWithNodes, ATTR_WRITE_005_IndexRangeOnNodeThatCannotTakeOneIsNotSupported)
{
  auto addressSpace = mServer.server().address_space();

  // A four-element Int32 array Variable that advertises WriteFullArrayOnly: whole-array writes are
  // supported, partial ones are not.
  const NodeId fullArrayOnlyId{mTestNamespaceIndex, uint32_t{1016}};
  auto node = addressSpace.create_node_sync(fullArrayOnlyId, NodeClass::Variable);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  auto variable = node.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "FullArrayOnlyInt32"});
  variable->set_display_name(LocalizedText{"", "FullArrayOnlyInt32"});
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->set_value_rank(ValueRank{1});
  variable->set_array_dimensions(std::vector<uint32_t>{4});
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable->set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
    AccessLevelExType::Bit::CurrentWrite,
    AccessLevelExType::Bit::WriteFullArrayOnly});
  Array<int32_t> initial;
  for (int32_t i = 0; i < 4; ++i)
  {
    initial.push_back(i);
  }
  variable->write_value_sync(initial);
  auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
  objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, fullArrayOnlyId);

  // Antecedent: the Node really does advertise the bit over the wire, so the refusal below is owed to
  // a stated capability of the Node and not to anything the test asserts by fiat.
  auto advertised = read_back(*mSession, fullArrayOnlyId, AttributeId::AccessLevelEx);
  ASSERT_THAT(advertised, Good());
  const auto* accessLevelEx = advertised.value().try_as<uint32_t>();
  ASSERT_NE(accessLevelEx, nullptr);
  ASSERT_TRUE(AccessLevelExType{*accessLevelEx}.test(AccessLevelExType::Bit::WriteFullArrayOnly))
    << "the Node under test must advertise WriteFullArrayOnly";

  // Control: a WHOLE-array write is exactly what this Node does support, so a refusal below cannot be
  // read as the Node being unwritable. It also establishes the known value that makes "no part of the
  // value is written" falsifiable.
  Array<int32_t> whole;
  for (int32_t i = 1; i <= 4; ++i)
  {
    whole.push_back(i);
  }
  ASSERT_THAT(mSession->attributes().write_sync(WriteRequestBuilder().write(fullArrayOnlyId, Variant{whole})),
    WriteSucceeds())
    << "a full-array write to a WriteFullArrayOnly Variable must be accepted";

  // Obligation: the range is syntactically well formed, names one element that exists, and the
  // supplied value is an array of exactly that one element (SVR-ATTR-WRITE-006), so neither
  // SVR-ATTR-WRITE-020 nor SVR-ATTR-WRITE-021 has anything to say. The only remaining objection is
  // that this Node does not support indexRange writing.
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(fullArrayOnlyId, Variant{Array<int32_t>{99}}).index_range(String{"1"}));
  EXPECT_THAT(resp, WriteFailsWith(Status::BadWriteNotSupported))
    << "An indexRange write to a Node that cannot be written in part is Bad_WriteNotSupported";

  // Second conjunct: no part of the value is written - the slice must not have been merged in.
  auto dv = read_back(*mSession, fullArrayOnlyId);
  EXPECT_THAT(dv, Good());
  ASSERT_TRUE(dv.value().is_array()) << "the Node's value must still be the array it was written";
  const auto& stored = dv.value().as<Array<int32_t>>();
  ASSERT_EQ(stored.size(), 4u);
  for (int32_t i = 0; i < 4; ++i)
  {
    EXPECT_EQ(stored[static_cast<size_t>(i)], i + 1)
      << "A refused indexRange write must leave every element untouched";
  }
}

// Requirement: SVR-ATTR-WRITE-007 (SHALL)
// Part 4 section 5.10.4.2 - if the SourceTimestamp or the ServerTimestamp is specified, the Server shall
// use these values. Both must survive together: a historian replaying data supplies the original
// instants, and stamping either of them with the moment of receipt destroys the only reason to send
// them. The two single-timestamp arms prove each field independently; this combined arm proves that
// preserving one never causes the other to be discarded.
// @relation(AC-SVR-ATTR-WRITE-007-SUPPLIED-TIMESTAMPS, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_007_SuppliedSourceAndServerTimestampsAreTheOnesStored)
{
  // mFullAccessVariableId carries TimestampWrite, so the combination is a supported one.
  DateTime sourceTs{2019, 3, 4, 5, 6, 0.0};
  DateTime serverTs{2019, 3, 4, 5, 7, 0.0};
  DataValue dvToWrite;
  dvToWrite.value() = Variant{int32_t{7070}};
  dvToWrite.source_timestamp() = sourceTs;
  dvToWrite.server_timestamp() = serverTs;

  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mFullAccessVariableId, std::move(dvToWrite))),
    WriteSucceeds())
    << "Write of value plus both timestamps should succeed with TimestampWrite access";

  auto dv = read_back_cached(*mSession, mFullAccessVariableId, TimestampsToReturn::Both);
  EXPECT_THAT(dv, good_value_of<int32_t>(7070));
  ASSERT_TRUE(dv.source_timestamp().has_value()) << "Source timestamp requested via Both";
  EXPECT_EQ(dv.source_timestamp().value(), sourceTs) << "The supplied SourceTimestamp must be the stored one";
  ASSERT_TRUE(dv.server_timestamp().has_value()) << "Server timestamp requested via Both";
  EXPECT_EQ(dv.server_timestamp().value(), serverTs) << "The supplied ServerTimestamp must be the stored one";
}

// Requirement: SVR-ATTR-WRITE-022 (SHALL NOT)
// Part 4 section 5.10.4.4 - Bad_WriteNotSupported means the Server does not support the requested
// value/status/timestamp combination for this Node, and the Server shall not perform any write on
// the Node. The plausible implementation writes the parts it does support and reports the refusal
// only for the rest, leaving the client with a Node it believes it did not change and a value it
// did in fact overwrite. The read-back is what distinguishes the two behaviours, so it asserts on
// both the value and the status the request carried.
// @verifies AC-SVR-ATTR-WRITE-022-WRITENOTSUPPORTED-ATOMIC
TEST_F(ComplianceWithNodes, ATTR_WRITE_022_UnsupportedCombinationLeavesTheNodeUnchanged)
{
  // Establish a known value so "the Node is unchanged" is falsifiable.
  ASSERT_THAT(mSession->attributes().write_sync(
                WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{4242}})),
    WriteSucceeds())
    << "Setup write should succeed";

  // mWritableVariableId has CurrentRead + CurrentWrite only: it supports the value and neither the
  // status nor the timestamp. Requesting all three at once is an unsupported combination.
  DataValue dvToWrite;
  dvToWrite.value() = Variant{int32_t{909}};
  dvToWrite.status() = StatusCode{Status::UncertainLastUsableValue};
  dvToWrite.source_timestamp() = DateTime{2021, 1, 2, 3, 4, 0.0};

  auto result = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, std::move(dvToWrite)));
  ASSERT_THAT(result, Good());
  EXPECT_THAT(std::move(result).value(), WriteFailsWith(Status::BadWriteNotSupported))
    << "Value+status+timestamp to a value-only Node is an unsupported combination";

  // The supported part must not have been written on its own.
  auto dv = read_back(*mSession, mWritableVariableId);
  EXPECT_THAT(dv, good_value_of<int32_t>(4242)) << "The value must not have been written";
  if (dv.status().has_value())
  {
    EXPECT_NE(dv.status()->as_status(), Status::UncertainLastUsableValue)
      << "The status must not have been written";
  }
}

// Requirement: SVR-ATTR-WRITE-027 (SHALL)
// Bad_DataEncodingUnsupported - Encoding is not supported.
// Spec: Part 4, section 5.10.4.4, line 4031
// NOTE: Unlike ReadValueId, WriteValue has no dataEncoding field in the OPC UA
// specification. The encoding is implicit in the message encoding (UA Binary).
// This means BadDataEncodingUnsupported cannot be triggered at the Write service
// level - it would only occur if the transport-level message encoding were
// unsupported, which is handled before the Write service is invoked.
// This test serves as a smoke test verifying the implicit encoding works correctly.
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-WRITE-027, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithNodes, ATTR_WRITE_027_BadDataEncodingUnsupported)
{
  // Write using the implicit UA Binary encoding - should succeed.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{42}})),
    WriteSucceeds())
    << "Write with implicit UA Binary encoding should succeed";
}

// A Variable whose declared numeric range is narrower than its DataType's. The bound is carried by
// the Node itself - AnalogItemType plus an EURange Property (Part 8 section 5.2) - and enforced by the SDK's
// own Data Access write check, which the server takes in its ServerConfig (dataAccessWritePolicy) at
// creation, so it is set here rather than in a test body. Nothing in this fixture decides the outcome
// of a write: it supplies the Node and its declared range, and the server's check does the refusing.
class ComplianceWithRangeCheckedNodes : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // Double-typed Variable declaring EURange [0, 100]: 150.0 is a perfectly good Double and an
    // impossible value for this Node.
    mRangedVariableId = NodeId{mTestNamespaceIndex, uint32_t{1017}};
    auto rangedNode = addressSpace.create_node_sync(mRangedVariableId, NodeClass::Variable);
    auto ranged = rangedNode.as<VariableAccessor>();
    ASSERT_TRUE(ranged.has_value());
    ranged->set_browse_name(QualifiedName{mTestNamespaceIndex, "RangedDouble"});
    ranged->set_display_name(LocalizedText{"", "RangedDouble"});
    ranged->set_data_type(NodeId{DataTypeId::Double});
    ranged->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    ranged->write_value_sync(double{50.0});
    rangedNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});

    auto euRangeId = NodeId{mTestNamespaceIndex, uint32_t{1018}};
    auto euRangeNode = addressSpace.create_node_sync(euRangeId, NodeClass::Variable);
    auto euRange = euRangeNode.as<VariableAccessor>();
    ASSERT_TRUE(euRange.has_value());
    euRange->set_browse_name(QualifiedName{0, "EURange"});
    euRange->set_data_type(NodeId{DataTypeId::Range});
    auto range = std::make_unique<Range>();
    range->low() = 0.0;
    range->high() = 100.0;
    euRange->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    euRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    rangedNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRangeId);

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mRangedVariableId);
  }

  void configure_server_config(ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.dataAccessWritePolicy = DataAccessOutOfRangePolicy::Reject;
  }

  NodeId mRangedVariableId;
};

// Requirement: SVR-ATTR-WRITE-025 (SHALL)
// Part 4 section 5.10.4.4 - a written value that is of the right type but outside the valid range draws
// Bad_OutOfRange. The distinction from Bad_TypeMismatch is the whole content of the requirement: an
// Int32 of 8 written to a ServerState-typed Node, or a Double of 150.0 written to a Node declaring
// EURange [0, 100], passes every type check there is. A server that validates only the encoded type
// stores a value nothing can name and reports Good; a server that notices something is wrong but
// answers Bad_TypeMismatch tells the client to send a different TYPE, which is not the fault and
// leaves it with no way to correct the request. Both magnitudes are exercised - the enumeration whose
// defined set is exhaustive, and the numeric bound the Node declares - because an implementation that
// special-cases enumerations passes the first on its own. The below-the-floor cases (-1, -0.5) are
// separate: a check written as an unsigned comparison or as "value <= high" admits them.
// Each refusal is followed by a read-back, so "refused" is not merely a status code: the store must
// still hold the value the preceding accepted write put there.
// @verifies AC-SVR-ATTR-WRITE-025-OUTOFRANGE
TEST_F(ComplianceWithRangeCheckedNodes, ATTR_WRITE_025_RightTypeWrongMagnitudeIsOutOfRangeNotTypeMismatch)
{
  // --- Enumeration DataType: ServerState defines exactly 0..7 (Running .. Unknown). ---

  // Control: a member of the defined set is accepted, so the refusals below cannot be read as this
  // Node rejecting every write. It also establishes the value that makes "not written" falsifiable.
  ASSERT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mEnumVariableId, Variant{int32_t{3}})),
    WriteSucceeds())
    << "Suspended (3) is a defined ServerState and must be accepted";
  ASSERT_THAT(read_back(*mSession, mEnumVariableId), good_value_of<int32_t>(3));

  // One past the highest defined member: correctly typed, not a value the enumeration names.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mEnumVariableId, Variant{int32_t{8}})),
    WriteFailsWith(Status::BadOutOfRange))
    << "An Int32 outside the enumeration's defined set is Bad_OutOfRange, not Bad_TypeMismatch";

  // Below the lowest defined member.
  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mEnumVariableId, Variant{int32_t{-1}})),
    WriteFailsWith(Status::BadOutOfRange))
    << "A negative Int32 is outside the enumeration's defined set";

  EXPECT_THAT(read_back(*mSession, mEnumVariableId), good_value_of<int32_t>(3))
    << "A refused out-of-range write must leave the stored enumeration value alone";

  // --- Numeric range declared by the Node: EURange [0, 100] on a Double. ---

  // Control, for the same two reasons as above.
  ASSERT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mRangedVariableId, Variant{double{75.0}})),
    WriteSucceeds())
    << "75.0 is inside the declared range and must be accepted";
  ASSERT_THAT(read_back(*mSession, mRangedVariableId), good_value_of<double>(75.0));

  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mRangedVariableId, Variant{double{150.0}})),
    WriteFailsWith(Status::BadOutOfRange))
    << "A Double above the declared range is Bad_OutOfRange, not Bad_TypeMismatch";

  EXPECT_THAT(
    mSession->attributes().write_sync(WriteRequestBuilder().write(mRangedVariableId, Variant{double{-0.5}})),
    WriteFailsWith(Status::BadOutOfRange))
    << "A Double below the declared range is Bad_OutOfRange";

  EXPECT_THAT(read_back(*mSession, mRangedVariableId), good_value_of<double>(75.0))
    << "A refused out-of-range write must leave the stored numeric value alone";
}
