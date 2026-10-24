// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_binary_codec.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_structure_factory.h"
#include "ua_memory_stream.h"
#include "ua_namespace_array.h"
#include "ua_open_secure_channel_request.h"
#include "ua_data_type_registration.h"
#include "ua_date_time.h"
#include "ua_guid.h"
#include "ua_variant.h"
#include "ua_string.h"
#include "ua_status_code.h"
#include "ua_localized_text.h"
#include "ua_qualified_name.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_expanded_node_id.h"
#include "ua_diagnostic_info.h"
#include "ua_data_value.h"
#include "ua_xml_element.h"
#include "ua_decimal.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_identity_criteria_type.h"
#include "ua_ref_structure.h"
#include "ua_array.h"
#include "ua_structure.h"
#include "ua_exceptions.h"

using namespace ua;

namespace
{
const EncodingLimits& make_limits()
{
  static EncodingLimits limits = []
  {
    const auto cfg = ApplicationConfig::load_default();
    return make_encoding_limits(cfg);
  }();
  return limits;
}

StackDepth make_limit()
{
  auto cfg = ApplicationConfig::load_default();
  return StackDepth{cfg.execution_limits().decodeWorkLimit};
}

DateTime decode_raw_date_time(int64_t encodedValue)
{
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(make_limit(), encodedValue);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  DateTime decoded;
  decoder.decode(make_limit(), decoded);
  return decoded;
}
}  // namespace

TEST(UaBinaryCodecTests, SampleStructure)
{
  memory_stream_device::Dynamic device{};
  MemoryStream memoryStream{device};
  UaBinaryEncoder binaryEncoder(CodecNamespaceContext{}, memoryStream);

  OpenSecureChannelRequest input;
  input.request_header().request_handle() = 25;
  input.request_type() = SecurityTokenRequestType::Renew;
  input.requested_lifetime() = 60000;
  binaryEncoder.encode(make_limit(), input);

  StructureFactory uaBinaryFactory;
  register_ua_data_types_with_factory({}, &uaBinaryFactory, nullptr);

  memoryStream.seek_from_start(0);
  UaBinaryDecoder binaryDecoder{uaBinaryFactory.resolver(), memoryStream, make_limits()};
  OpenSecureChannelRequest output;
  binaryDecoder.decode(make_limit(), output);

  EXPECT_EQ(input.request_header().authentication_token(), output.request_header().authentication_token());
  EXPECT_EQ(input.request_header().timestamp(), output.request_header().timestamp());
  EXPECT_EQ(input.request_header().request_handle(), output.request_header().request_handle());
  EXPECT_EQ(input.request_header().return_diagnostics(), output.request_header().return_diagnostics());
  EXPECT_EQ(input.request_header().audit_entry_id(), output.request_header().audit_entry_id());
  EXPECT_EQ(input.request_header().timeout_hint(), output.request_header().timeout_hint());
  EXPECT_EQ(input.request_header().additional_header(), output.request_header().additional_header());

  EXPECT_EQ(input.client_nonce(), output.client_nonce());
  EXPECT_EQ(input.client_protocol_version(), output.client_protocol_version());
  EXPECT_EQ(input.request_type(), output.request_type());
  EXPECT_EQ(input.requested_lifetime(), output.requested_lifetime());
  EXPECT_EQ(input.security_mode(), output.security_mode());

  ASSERT_EQ(input, output);
}

TEST(UaBinaryCodecTests, SampleExtensionObject)
{
  memory_stream_device::Dynamic device{};
  MemoryStream memoryStream{device};
  UaBinaryEncoder binaryEncoder(CodecNamespaceContext{}, memoryStream);

  OpenSecureChannelRequest input;
  input.request_header().request_handle() = 25;
  input.request_type() = SecurityTokenRequestType::Renew;
  input.requested_lifetime() = 60000;
  binaryEncoder.encode(make_limit(), &input);

  StructureFactory uaBinaryFactory;
  register_ua_data_types_with_factory({}, &uaBinaryFactory, nullptr);

  memoryStream.seek_from_start(0);
  UaBinaryDecoder binaryDecoder{uaBinaryFactory.resolver(), memoryStream, make_limits()};
  unique_ptr<Structure> output;
  binaryDecoder.decode(make_limit(), output);

  OpenSecureChannelRequest* concreteOutput = dynamic_cast<OpenSecureChannelRequest*>(output.get());
  GTEST_ASSERT_NE(concreteOutput, nullptr);
  GTEST_ASSERT_EQ(input, *concreteOutput);
}

TEST(UaBinaryCodecTests, DateTime_EncodeUnixEpochAsFiletimeTicks)
{
  using namespace ua;

  // Arrange
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Unix epoch (1970-01-01 00:00:00 UTC)
  DateTime unixEpoch{1970, 1, 1, 0, 0, 0.0, 0};

  // Act: encode DateTime, then decode raw int64 value back to verify the filetime ticks
  encoder.encode(make_limit(), unixEpoch);

  // OPC UA DateTime is number of 100ns intervals since 1601-01-01 (Windows FILETIME epoch)
  // Seconds between 1601-01-01 and 1970-01-01 = 11644473600
  // Ticks (100ns) = seconds * 10,000,000
  const int64_t expectedFiletimeTicks = 11644473600LL * 10000000LL;  // 116444736000000000

  stream.seek_from_start(0);
  StructureFactory factory;  // empty is fine for primitive decoding
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  int64_t rawEncoded{0};
  decoder.decode(make_limit(), rawEncoded);

  EXPECT_EQ(rawEncoded, expectedFiletimeTicks);

  // Also verify that decoding the same buffer as DateTime yields back the unix epoch
  stream.seek_from_start(0);
  DateTime decoded{};
  decoder.decode(make_limit(), decoded);
  EXPECT_EQ(decoded.value(), unixEpoch.value());
}

TEST(UaBinaryCodecTests, DateTime_MinValueEncodesAsZeroAndDecodesBack)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  DateTime minDt{std::chrono::sys_time<datetime::OneHundredNanoSeconds>{DateTime::min()}};
  encoder.encode(make_limit(), minDt);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  int64_t raw{123};
  decoder.decode(make_limit(), raw);
  EXPECT_EQ(raw, 0);

  stream.seek_from_start(0);
  DateTime decoded{};
  decoder.decode(make_limit(), decoded);
  EXPECT_EQ(decoded.value(), DateTime::min());
}

TEST(UaBinaryCodecTests, DateTime_MaxValueEncodesAsInt64MaxAndDecodesBack)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  DateTime maxDt{std::chrono::sys_time<datetime::OneHundredNanoSeconds>{DateTime::max()}};
  encoder.encode(make_limit(), maxDt);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  int64_t raw{0};
  decoder.decode(make_limit(), raw);
  EXPECT_EQ(raw, std::numeric_limits<int64_t>::max());

  stream.seek_from_start(0);
  DateTime decoded{};
  decoder.decode(make_limit(), decoded);
  EXPECT_EQ(decoded.value(), DateTime::max());
}

// @relation(AC-COMP-SDK-POST-DATETIME-BOUNDS, scope=function)
TEST(UaBinaryCodecTests, DateTime_OutOfPlatformRangeWireValuesDecodeToNearestBound)
{
  // Part 6 section 5.2.2.5: values outside the development platform's range decode to its bounds.
  EXPECT_EQ(decode_raw_date_time(-1).value(), DateTime::min());
  EXPECT_EQ(decode_raw_date_time(std::numeric_limits<int64_t>::min()).value(), DateTime::min());
  EXPECT_EQ(decode_raw_date_time(std::numeric_limits<int64_t>::max() - 1).value(), DateTime::max());
}

TEST(UaBinaryCodecTests, DateTime_RoundTripSpecificValue)
{
  using namespace ua;
  using namespace std::chrono;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // 2023-03-04 05:06:07.890 UTC
  DateTime input{
    2023,
    3,
    4,
    5,
    6,
    7.890,  // seconds with milliseconds
    0  // UTC offset
  };

  encoder.encode(make_limit(), input);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DateTime output{};
  decoder.decode(make_limit(), output);

  EXPECT_EQ(output.value(), input.value());
}

TEST(UaBinaryCodecTests, Guid_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  Guid input = Guid::parse("01234567-89ab-cdef-0123-456789abcdef");
  encoder.encode(make_limit(), input);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Guid output{};
  decoder.decode(make_limit(), output);

  EXPECT_EQ(output, input);
}

TEST(UaBinaryCodecTests, String_And_ByteString_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // String via string_view
  const std::string text = "Hello OPC UA";
  encoder.encode(make_limit(), string_view{text});

  // Empty ByteString
  ByteString bytesEmpty{};
  encoder.encode(make_limit(), bytesEmpty);

  // Non-empty ByteString
  ByteString bytes{uint8_t('A'), uint8_t('B'), uint8_t('C')};
  encoder.encode(make_limit(), bytes);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  String decodedString;
  decoder.decode(make_limit(), decodedString);
  EXPECT_EQ(static_cast<std::string>(decodedString), text);

  ByteString decodedEmpty;
  decoder.decode(make_limit(), decodedEmpty);
  EXPECT_TRUE(decodedEmpty.empty());

  ByteString decodedBytes;
  decoder.decode(make_limit(), decodedBytes);
  EXPECT_EQ(decodedBytes, bytes);
}

// @verifies CL-ADDRSP-001
// @relation(CL-ADDRSP-001, scope=function)
TEST(UaBinaryCodecTests, NodeId_And_ExpandedNodeId_Variants_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Two-byte encoding candidate (ns=0, id<=255)
  NodeId n1{static_cast<uint32_t>(42)};
  encoder.encode(make_limit(), n1);

  // Four-byte encoding candidate (ns<=255, id<=65535)
  NodeId n2{0, static_cast<uint32_t>(65000)};
  encoder.encode(make_limit(), n2);

  // Numeric with namespace index
  NodeId n3{2, static_cast<uint32_t>(123456)};
  encoder.encode(make_limit(), n3);

  // String identifier
  NodeId n4{1, string_view{"My.Node"}};
  encoder.encode(make_limit(), n4);

  // GUID identifier
  Guid g = Guid::parse("00112233-4455-6677-8899-aabbccddeeff");
  NodeId n5{3, g};
  encoder.encode(make_limit(), n5);

  // Opaque identifier
  ByteString opq{uint8_t{0xDE}, uint8_t{0xAD}, uint8_t{0xBE}, uint8_t{0xEF}};
  NodeId n6{4, opq};
  encoder.encode(make_limit(), n6);

  // ExpandedNodeId with namespace URI and server index
  ExpandedNodeId en1{NodeId{static_cast<uint32_t>(101)}, string_view{"urn:test:ns"}, 5};
  encoder.encode(make_limit(), en1);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  NodeId dn1, dn2, dn3, dn4, dn5, dn6;
  decoder.decode(make_limit(), dn1);
  decoder.decode(make_limit(), dn2);
  decoder.decode(make_limit(), dn3);
  decoder.decode(make_limit(), dn4);
  decoder.decode(make_limit(), dn5);
  decoder.decode(make_limit(), dn6);
  EXPECT_EQ(dn1, n1);
  EXPECT_EQ(dn2, n2);
  EXPECT_EQ(dn3, n3);
  EXPECT_EQ(dn4, n4);
  EXPECT_EQ(dn5, n5);
  EXPECT_EQ(dn6, n6);

  ExpandedNodeId den1;
  decoder.decode(make_limit(), den1);
  EXPECT_EQ(den1, en1);
}

TEST(UaBinaryCodecTests, StatusCode_QualifiedName_LocalizedText_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  StatusCode sc{Status::BadOutOfMemory};
  QualifiedName qn{2, "Speed"};
  LocalizedText lt{LocaleId{"en-US"}, String{"Localized text"}};

  encoder.encode(make_limit(), sc);
  encoder.encode(make_limit(), qn);
  encoder.encode(make_limit(), lt);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  StatusCode dsc;
  QualifiedName dqn;
  LocalizedText dlt;

  decoder.decode(make_limit(), dsc);
  decoder.decode(make_limit(), dqn);
  decoder.decode(make_limit(), dlt);

  EXPECT_EQ(dsc, sc);
  EXPECT_EQ(dqn, qn);
  EXPECT_EQ(dlt, lt);
}

TEST(UaBinaryCodecTests, Variant_Scalar_And_Array_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  Variant vScalar{int32_t{123456}};
  Array<int32_t> arr;
  arr.payload() = {1, 2, 3, 4};
  Variant vArray{arr};

  encoder.encode(make_limit(), vScalar);
  encoder.encode(make_limit(), vArray);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Variant dvScalar, dvArray;
  decoder.decode(make_limit(), dvScalar);
  decoder.decode(make_limit(), dvArray);

  EXPECT_EQ(dvScalar, vScalar);
  EXPECT_EQ(dvArray, vArray);
}

// OPC 10000-6 5.2.2.16: an array Variant carries its element type in the encoding mask whatever its length,
// so an EMPTY array of QualifiedName arrives as an empty array of QualifiedName - not as a Variant with no
// type, which a client cannot tell from "no value" (the CTT's Base Info Core Structure 2 read
// ServerCapabilities.ConformanceUnits, stored as an empty QualifiedName array, as type 0).
TEST(UaBinaryCodecTests, Variant_EmptyTypedArray_KeepsItsElementType)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  const Variant empty{Array<QualifiedName>{}};
  encoder.encode(make_limit(), empty);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  Variant decoded;
  decoder.decode(make_limit(), decoded);

  EXPECT_FALSE(decoded.empty()) << "an empty typed array must not decode as a Variant with no value";
  const auto* array = decoded.try_as<Array<QualifiedName>>();
  ASSERT_NE(array, nullptr) << "the element type QualifiedName must survive the round trip";
  EXPECT_EQ(array->size(), 0u);
}

// Defect (b): an Array<DataValue> Variant encodes its array body to the wire but the decoder
// previously dropped it (the BuiltInTypeId::DataValue array case was commented out), producing an
// empty/Null Variant and leaving the array bytes unread (stream desync). This asserts a full
// round-trip with non-trivial DataValues.
TEST(UaBinaryCodecTests, Variant_ArrayOfDataValue_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  Array<DataValue> arr;
  arr.payload() = {DataValue{Variant{int32_t{42}}},
    DataValue{Variant{int32_t{-7}}, StatusCode{Status::UncertainNoCommunicationLastUsableValue}}};
  Variant vArray{arr};

  encoder.encode(make_limit(), vArray);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Variant out;
  decoder.decode(make_limit(), out);

  EXPECT_EQ(out, vArray);
  EXPECT_TRUE(out.is_array());
}

// Defect (a): a scalar Variant encoding byte with a reserved built-in type-id (26-63) was silently
// decoded as Null (no bytes consumed, no error). A well-formed decoder must reject it with
// BadDecodingError at the wire boundary.
TEST(UaBinaryCodecTests, Variant_ScalarReservedTypeId_Rejected)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Reserved scalar type-id 26 (no array bit). 26 has no matching BuiltInTypeId enumerator.
  encoder.encode(make_limit(), uint8_t{26});

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Variant out;
  try
  {
    decoder.decode(make_limit(), out);
    FAIL() << "Expected UaException for reserved scalar Variant type-id";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadDecodingError);
  }
}

// Defect (c): an array Variant encoding byte with a reserved built-in type-id (26-63) previously
// either silently desynced the stream (no dims bit) or threw a misleading InvalidVariantAccess (dims
// bit). A well-formed decoder must reject it with BadDecodingError at the wire boundary.
TEST(UaBinaryCodecTests, Variant_ArrayReservedTypeId_Rejected)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Array bit (0x80) set with reserved type-id 26, followed by an array length of 0.
  encoder.encode(make_limit(), uint8_t{0x80 | 26});
  encoder.encode(make_limit(), int32_t{0});

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Variant out;
  try
  {
    decoder.decode(make_limit(), out);
    FAIL() << "Expected UaException for reserved array Variant type-id";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadDecodingError);
  }
}

TEST(UaBinaryCodecTests, String_And_ByteString_NullAndEmpty_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Null (default-constructed) String and ByteString
  String nullStr{};
  ByteString nullBytes{};

  // Empty values explicitly set
  String emptyStr{""};
  ByteString emptyBytes;  // stays empty

  encoder.encode(make_limit(), nullStr);
  encoder.encode(make_limit(), nullBytes);
  encoder.encode(make_limit(), emptyStr);
  encoder.encode(make_limit(), emptyBytes);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  String dNullStr, dEmptyStr;
  ByteString dNullBytes, dEmptyBytes;

  decoder.decode(make_limit(), dNullStr);
  decoder.decode(make_limit(), dNullBytes);
  decoder.decode(make_limit(), dEmptyStr);
  decoder.decode(make_limit(), dEmptyBytes);

  // After round-trip both null and empty are observable as empty containers
  EXPECT_TRUE(dNullStr.empty());
  EXPECT_TRUE(dNullBytes.empty());
  EXPECT_TRUE(dEmptyStr.empty());
  EXPECT_TRUE(dEmptyBytes.empty());
}

TEST(UaBinaryCodecTests, XmlElement_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  XmlElement xml;
  xml.value() = "<root attr=\"1\"><child/>text</root>";
  encoder.encode(make_limit(), xml);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  XmlElement out;
  decoder.decode(make_limit(), out);
  EXPECT_EQ(out, xml);
}

TEST(UaBinaryCodecTests, Decimal_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  Decimal dec;
  dec.scale() = 2;
  // Value bytes represent 123456 (little endian as per spec, but here we just round-trip bytes)
  dec.value() = ByteString{uint8_t{0x40}, uint8_t{0xE2}, uint8_t{0x01}};
  encoder.encode(make_limit(), dec);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Decimal out;
  decoder.decode(make_limit(), out);
  EXPECT_EQ(out, dec);
}

// Defect: decode(Decimal) read the ExtensionObject body-encoding byte but then re-validated the
// TypeId (always equal at that point) instead of the encoding, so a non-binary encoding byte was
// never rejected - the body would be decoded as garbage. A well-formed decoder must reject it with
// BadDecodingError at the wire boundary.
TEST(UaBinaryCodecTests, Decimal_RejectsNonBinaryEncodingByte)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Correct Decimal TypeId, but a non-binary body-encoding byte (2 = XML; the encoder always writes 1).
  encoder.encode(make_limit(), NodeId(ObjectId::DecimalDataType_Encoding_DefaultBinary));
  encoder.encode(make_limit(), uint8_t{2});

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Decimal out;
  try
  {
    decoder.decode(make_limit(), out);
    FAIL() << "Expected UaException for non-binary Decimal encoding byte";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadDecodingError);
  }
}

TEST(UaBinaryCodecTests, DiagnosticInfo_WithNested_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  DiagnosticInfo info;
  info.symbolic_id() = 10;
  info.namespace_uri() = 2;
  info.locale() = 0;
  info.localized_text() = 55;
  info.additional_info() = std::string{"additional"};
  info.inner_status_code() = StatusCode{Status::BadOutOfMemory};
  info.inner_diagnostic_info() = make_unique<DiagnosticInfo>();
  info.inner_diagnostic_info()->symbolic_id() = 99;

  encoder.encode(make_limit(), info);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DiagnosticInfo out;
  decoder.decode(make_limit(), out);
  EXPECT_EQ(out, info);
}

TEST(UaBinaryCodecTests, DataValue_Full_And_Null_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  // Full DataValue
  DataValue full;
  full.value() = Variant{int32_t{777}};
  full.status() = StatusCode{Status::UncertainNoCommunicationLastUsableValue};
  full.source_timestamp() = DateTime{1970, 1, 1, 0, 0, 1.0, 0};
  full.server_timestamp() = DateTime{1970, 1, 1, 0, 0, 2.0, 0};
  full.source_pico_seconds() = 1234;
  full.server_pico_seconds() = 4321;

  // Null DataValue (default)
  DataValue nul{};

  encoder.encode(make_limit(), full);
  encoder.encode(make_limit(), nul);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  DataValue dFull, dNull;
  decoder.decode(make_limit(), dFull);
  decoder.decode(make_limit(), dNull);

  EXPECT_EQ(dFull, full);
  EXPECT_EQ(dNull, nul);
}

TEST(UaBinaryCodecTests, Variant_Null_And_ArrayOfVariant_RoundTrip)
{
  using namespace ua;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  Variant vNull{};  // empty variant

  Array<Variant> vArr;
  vArr.payload().push_back(Variant{int16_t{-7}});
  vArr.payload().push_back(Variant{String{"abc"}});
  vArr.payload().push_back(Variant{Guid::parse("00112233-4455-6677-8899-aabbccddeeff")});
  Variant vArrayOfVariant{vArr};

  encoder.encode(make_limit(), vNull);
  encoder.encode(make_limit(), vArrayOfVariant);

  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};

  Variant dNull, dArrayOfVariant;
  decoder.decode(make_limit(), dNull);
  decoder.decode(make_limit(), dArrayOfVariant);

  EXPECT_EQ(dNull, vNull);
  EXPECT_EQ(dArrayOfVariant, vArrayOfVariant);
}

TEST(UaBinaryCodecTests, CodecNamespaceTranslator_TranslatesNestedNodeIdInsideVariantOnDecode)
{
  using namespace ua;

  // Encode a nested Array<Variant> containing a NodeId with a non-zero namespace index.
  Array<Variant> outer;
  {
    Array<Variant> inner;
    inner.payload().push_back(Variant{NodeId{2, 42}});
    outer.payload().push_back(Variant{inner});
  }

  Variant input{outer};

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  enc.encode(make_limit(), input);

  stream.seek_from_start(0);

  StructureFactory factory;
  CodecNamespaceContext cfg;
  cfg.translateNodeId = [](NodeId& id)
  {
    if (id.namespace_index() != 0)
    {
      id.namespace_index() = 7;
    }
  };

  UaBinaryDecoder dec{factory.resolver(), stream, make_limits(), cfg};
  Variant output;
  dec.decode(make_limit(), output);

  // Expect the embedded NodeId's namespace index to be translated by the codec hook.
  const auto& outOuter = output.as<Array<Variant>>();
  ASSERT_EQ(outOuter.payload().size(), 1u);
  const auto& outInner = outOuter.payload().front().as<Array<Variant>>();
  ASSERT_EQ(outInner.payload().size(), 1u);
  const auto& outId = outInner.payload().front().as<NodeId>();
  EXPECT_EQ(outId.namespace_index(), 7u);
  EXPECT_EQ(outId.identifier().get_numeric(), 42u);
}

// ============================================================================
// LocalizedText aggregate codec defensive fallback tests
// ============================================================================

TEST(UaBinaryCodecTests, AggregateLocalizedTextEncodesFirstTranslation)
{
  using namespace ua;

  // Construct an aggregate LocalizedText with two translations.
  std::vector<LocalizedText::Scalar> translations;
  translations.emplace_back(LocaleId{String{"en-US"}}, String{"Hello"});
  translations.emplace_back(LocaleId{String{"de-DE"}}, String{"Hallo"});
  auto aggregate = LocalizedText::from_translations(std::move(translations));
  ASSERT_TRUE(aggregate.is_aggregate());

  // Encode.
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  encoder.encode(make_limit(), aggregate);

  // Decode and verify the first-inserted translation is produced.
  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  LocalizedText decoded;
  decoder.decode(make_limit(), decoded);

  EXPECT_TRUE(decoded.is_scalar());
  EXPECT_EQ(decoded.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(decoded.text(), String{"Hello"});
}

TEST(UaBinaryCodecTests, DecodedLocalizedTextIsAlwaysScalar)
{
  using namespace ua;

  // Encode a scalar LocalizedText.
  LocalizedText original{LocaleId{String{"en-US"}}, String{"Hello"}};
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  encoder.encode(make_limit(), original);

  // Decode and assert scalar.
  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  LocalizedText decoded;
  decoder.decode(make_limit(), decoded);

  EXPECT_TRUE(decoded.is_scalar());
  EXPECT_EQ(decoded, original);
}

TEST(UaBinaryCodecTests, AggregateLocalizedTextEncodesToNonEmptyDecodableBytes)
{
  using namespace ua;

  // Construct an aggregate LocalizedText.
  std::vector<LocalizedText::Scalar> translations;
  translations.emplace_back(LocaleId{String{"en-US"}}, String{"Hello"});
  translations.emplace_back(LocaleId{String{"de-DE"}}, String{"Hallo"});
  auto aggregate = LocalizedText::from_translations(std::move(translations));

  // Encode.
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  encoder.encode(make_limit(), aggregate);

  // Verify the bytes are decodable (no corruption).
  stream.seek_from_start(0);
  StructureFactory factory;
  UaBinaryDecoder decoder{factory.resolver(), stream, make_limits()};
  LocalizedText decoded;
  EXPECT_NO_THROW(decoder.decode(make_limit(), decoded));
  EXPECT_FALSE(decoded.text().empty());
}

namespace
{
RefStructure<Structure> make_identity_rule(IdentityCriteriaType criteriaType, string_view criteria)
{
  auto rule = make_unique<IdentityMappingRuleType>();
  rule->criteria_type() = criteriaType;
  rule->criteria() = String{criteria};
  RefStructure<Structure> ref;
  ref = unique_ptr<Structure>{std::move(rule)};
  return ref;
}

const IdentityMappingRuleType& as_rule(const RefStructure<Structure>& ref)
{
  const auto* rule = dynamic_cast<const IdentityMappingRuleType*>(ref.get());
  EXPECT_NE(rule, nullptr) << "decoded array element is not an IdentityMappingRuleType";
  return *rule;
}
}  // namespace

// Regression: a Variant holding a populated Array<RefStructure<Structure>>
// (e.g. Array<IdentityMappingRuleType>) must round-trip through the binary
// codec. The decoder previously decoded ExtensionObject arrays as Array<bool>,
// which mis-aligned the stream and hung downstream reads.
TEST(UaBinaryCodecTests, Variant_ArrayOfExtensionObject_Populated_RoundTrip)
{
  Array<RefStructure<Structure>> rules;
  rules.push_back(make_identity_rule(IdentityCriteriaType::Thumbprint, "0123456789ABCDEF"));
  rules.push_back(make_identity_rule(IdentityCriteriaType::X509Subject, "CN=Server, O=Org"));
  Variant input{std::move(rules)};

  ASSERT_TRUE(input.is_array());
  ASSERT_TRUE(input.is_array_of_structure());

  memory_stream_device::Dynamic device{};
  MemoryStream memoryStream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, memoryStream);
  encoder.encode(make_limit(), input);

  StructureFactory uaBinaryFactory;
  register_ua_data_types_with_factory({}, &uaBinaryFactory, nullptr);

  memoryStream.seek_from_start(0);
  UaBinaryDecoder decoder{uaBinaryFactory.resolver(), memoryStream, make_limits()};
  Variant output;
  ASSERT_NO_THROW(decoder.decode(make_limit(), output));

  ASSERT_TRUE(output.is_array());
  ASSERT_TRUE(output.is_array_of_structure());

  const auto& decoded = output.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(decoded.size(), 2u);

  const IdentityMappingRuleType& first = as_rule(decoded.payload()[0]);
  EXPECT_EQ(first.criteria_type(), IdentityCriteriaType::Thumbprint);
  EXPECT_EQ(first.criteria(), String{"0123456789ABCDEF"});

  const IdentityMappingRuleType& second = as_rule(decoded.payload()[1]);
  EXPECT_EQ(second.criteria_type(), IdentityCriteriaType::X509Subject);
  EXPECT_EQ(second.criteria(), String{"CN=Server, O=Org"});

  EXPECT_EQ(output, input);
}

// Companion to the populated case: an empty Array<RefStructure<Structure>>
// Variant must also round-trip (this path already worked, pinning it guards
// against the fix regressing the empty case).
TEST(UaBinaryCodecTests, Variant_ArrayOfExtensionObject_Empty_RoundTrip)
{
  Array<RefStructure<Structure>> rules;  // empty
  Variant input{std::move(rules)};

  ASSERT_TRUE(input.is_array());
  ASSERT_TRUE(input.is_array_of_structure());

  memory_stream_device::Dynamic device{};
  MemoryStream memoryStream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, memoryStream);
  encoder.encode(make_limit(), input);

  StructureFactory uaBinaryFactory;
  register_ua_data_types_with_factory({}, &uaBinaryFactory, nullptr);

  memoryStream.seek_from_start(0);
  UaBinaryDecoder decoder{uaBinaryFactory.resolver(), memoryStream, make_limits()};
  Variant output;
  ASSERT_NO_THROW(decoder.decode(make_limit(), output));

  ASSERT_TRUE(output.is_array());
  ASSERT_TRUE(output.is_array_of_structure());
  EXPECT_EQ(output.as<Array<RefStructure<Structure>>>().size(), 0u);

  EXPECT_EQ(output, input);
}
