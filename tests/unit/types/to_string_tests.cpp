// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_to_string.h"
#include "ua_error_detail.h"
#include "ua_read_value_id.h"
#include "ua_user_token_type.h"
#include "ua_attribute_write_mask.h"

#include <memory>

using namespace ua;

namespace
{
// Convenience predicate mirroring the existing `.find(...) != npos` style used
// throughout this file. Kept local to avoid pulling in gmock (the unit test
// target links only GTest::gtest).
bool contains(const std::string& haystack, std::string_view needle)
{
  return haystack.find(needle) != std::string::npos;
}
}  // namespace

// --- Primitives ---

TEST(ToStringPrimitives, Boolean)
{
  EXPECT_EQ(to_string(true), "true");
  EXPECT_EQ(to_string(false), "false");
}

TEST(ToStringPrimitives, Integers)
{
  EXPECT_EQ(to_string(int8_t{-128}), "-128");
  EXPECT_EQ(to_string(int8_t{127}), "127");
  EXPECT_EQ(to_string(uint8_t{255}), "255");
  EXPECT_EQ(to_string(int16_t{-1000}), "-1000");
  EXPECT_EQ(to_string(uint16_t{65535}), "65535");
  EXPECT_EQ(to_string(int32_t{42}), "42");
  EXPECT_EQ(to_string(uint32_t{0}), "0");
  EXPECT_EQ(to_string(int64_t{-9999999999LL}), "-9999999999");
  EXPECT_EQ(to_string(uint64_t{18446744073709551615ULL}), "18446744073709551615");
}

TEST(ToStringPrimitives, Floats)
{
  EXPECT_EQ(to_string(3.14f), "3.14");
  EXPECT_EQ(to_string(2.718281828), "2.718281828");
  EXPECT_EQ(to_string(0.0), "0");
}

// --- String types ---

TEST(ToStringTypes, String)
{
  String s{"hello"};
  EXPECT_EQ(to_string(s), "hello");
  EXPECT_EQ(to_string(String{}), "");
}

TEST(ToStringTypes, XmlElement)
{
  XmlElement xml;
  xml = string_view{"<Foo/>"};
  EXPECT_EQ(to_string(xml), "<Foo/>");
}

TEST(ToStringTypes, ByteString)
{
  ByteString bs = {uint8_t{'H'}, uint8_t{'e'}, uint8_t{'l'}, uint8_t{'l'}, uint8_t{'o'}};
  EXPECT_EQ(to_string(bs), "SGVsbG8=");
  EXPECT_EQ(to_string(ByteString{}), "");
}

// --- DateTime ---

TEST(ToStringTypes, DateTimeNonNull)
{
  DateTime dt{2024, 1, 15, 10, 30, 0.0};
  EXPECT_EQ(to_string(dt), "2024-01-15T10:30:00Z");
}

TEST(ToStringTypes, DateTimeWithSubSeconds)
{
  DateTime dt{2024, 6, 15, 12, 0, 0.1234567};
  auto result = to_string(dt);
  EXPECT_TRUE(result.find("2024-06-15T12:00:00.") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.ends_with("Z")) << "Got: " << result;
}

TEST(ToStringTypes, DateTimeNull)
{
  DateTime dt{};
  auto result = to_string(dt);
  EXPECT_TRUE(result.ends_with("Z"));
}

// --- Guid ---

TEST(ToStringTypes, GuidNonNull)
{
  Guid g = Guid::parse("550e8400-e29b-41d4-a716-446655440000");
  EXPECT_EQ(to_string(g), "550e8400-e29b-41d4-a716-446655440000");
}

TEST(ToStringTypes, GuidNull)
{
  Guid g = Guid::parse("00000000-0000-0000-0000-000000000000");
  auto result = to_string(g);
  EXPECT_EQ(result, "00000000-0000-0000-0000-000000000000");
}

// --- NodeId ---

TEST(ToStringTypes, NodeIdNumericNs0)
{
  NodeId n{uint32_t{42}};
  EXPECT_EQ(to_string(n), "i=42");
}

TEST(ToStringTypes, NodeIdNumericWithNamespace)
{
  NodeId n{uint16_t{2}, uint32_t{42}};
  EXPECT_EQ(to_string(n), "ns=2;i=42");
}

TEST(ToStringTypes, NodeIdString)
{
  NodeId n{uint16_t{1}, string_view{"Temperature"}};
  EXPECT_EQ(to_string(n), "ns=1;s=Temperature");
}

// --- ExpandedNodeId ---

TEST(ToStringTypes, ExpandedNodeIdPlain)
{
  ExpandedNodeId en{NodeId{uint32_t{42}}};
  EXPECT_EQ(to_string(en), "i=42");
}

TEST(ToStringTypes, ExpandedNodeIdWithUri)
{
  ExpandedNodeId en{NodeId{uint32_t{42}}, "http://example.com/UA/"};
  auto result = to_string(en);
  EXPECT_EQ(result, "nsu=http://example.com/UA/;i=42");
}

TEST(ToStringTypes, ExpandedNodeIdWithServerIndex)
{
  ExpandedNodeId en{NodeId{uint32_t{42}}, uint32_t{2}};
  auto result = to_string(en);
  EXPECT_EQ(result, "svr=2;i=42");
}

TEST(ToStringTypes, ExpandedNodeIdWithBoth)
{
  ExpandedNodeId en{NodeId{uint32_t{42}}, "http://example.com/", uint32_t{3}};
  auto result = to_string(en);
  EXPECT_EQ(result, "svr=3;nsu=http://example.com/;i=42");
}

// --- Status ---

TEST(ToStringTypes, StatusKnown)
{
  EXPECT_EQ(to_string(Status::Good), "Good");
  EXPECT_EQ(to_string(Status::BadInternalError), "BadInternalError");
  EXPECT_EQ(to_string(Status::BadTimeout), "BadTimeout");
}

TEST(ToStringTypes, StatusUnknown)
{
  auto result = to_string(static_cast<Status>(0x12340000U));
  EXPECT_EQ(result, "Unknown(0x12340000)");
}

// --- StatusCode ---

TEST(ToStringTypes, StatusCodeKnown)
{
  StatusCode sc{Status::BadInternalError};
  auto result = to_string(sc);
  EXPECT_TRUE(result.find("BadInternalError") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("0x80020000") != std::string::npos) << "Got: " << result;
}

TEST(ToStringTypes, StatusCodeGood)
{
  StatusCode sc{Status::Good};
  auto result = to_string(sc);
  EXPECT_EQ(result, "Good (0x00000000)");
}

// --- QualifiedName ---

TEST(ToStringTypes, QualifiedNameNs0)
{
  QualifiedName qn{"Temperature"};
  EXPECT_EQ(to_string(qn), "Temperature");
}

TEST(ToStringTypes, QualifiedNameWithNamespace)
{
  QualifiedName qn{2, "Pressure"};
  EXPECT_EQ(to_string(qn), "2:Pressure");
}

// --- LocalizedText ---

TEST(ToStringTypes, LocalizedTextNoLocale)
{
  LocalizedText lt{String{"Hello"}};
  EXPECT_EQ(to_string(lt), "Hello");
}

TEST(ToStringTypes, LocalizedTextWithLocale)
{
  LocalizedText lt{String{"en"}, String{"Hello"}};
  EXPECT_EQ(to_string(lt), "[en]Hello");
}

// --- Variant ---

TEST(ToStringVariant, Empty)
{
  Variant v{};
  EXPECT_EQ(to_string(v), "Null");
}

TEST(ToStringVariant, ScalarInt32)
{
  Variant v{int32_t{42}};
  EXPECT_EQ(to_string(v), "Int32(42)");
}

TEST(ToStringVariant, ScalarBool)
{
  Variant v{true};
  EXPECT_EQ(to_string(v), "Boolean(true)");
}

TEST(ToStringVariant, ScalarString)
{
  Variant v{String{"test"}};
  EXPECT_EQ(to_string(v), "String(test)");
}

TEST(ToStringVariant, ScalarDouble)
{
  Variant v{3.14};
  EXPECT_EQ(to_string(v), "Double(3.14)");
}

TEST(ToStringVariant, ArrayInt32)
{
  Array<int32_t> arr(Size{3});
  arr[0] = 42;
  arr[1] = 17;
  arr[2] = 3;
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Int32>[42, 17, 3]");
}

TEST(ToStringVariant, ArrayEmpty)
{
  Array<int32_t> arr(Size{0});
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Int32>[]");
}

TEST(ToStringSummaryVariant, ScalarSameAsToString)
{
  Variant v{int32_t{42}};
  EXPECT_EQ(to_summary_string(v), "Int32(42)");
}

TEST(ToStringSummaryVariant, ArrayShowsCount)
{
  Array<int32_t> arr(Size{3});
  arr[0] = 42;
  arr[1] = 17;
  arr[2] = 3;
  Variant v{std::move(arr)};
  EXPECT_EQ(to_summary_string(v), "Array<Int32>[3 elements]");
}

TEST(ToStringSummaryVariant, ArraySingleElement)
{
  Array<int32_t> arr(Size{1});
  arr[0] = 99;
  Variant v{std::move(arr)};
  EXPECT_EQ(to_summary_string(v), "Array<Int32>[1 element]");
}

// --- DataValue ---

TEST(ToStringDataValue, ValueAndStatus)
{
  DataValue dv;
  dv.value() = int32_t{42};
  dv.status() = StatusCode{Status::Good};
  auto result = to_string(dv);
  EXPECT_TRUE(result.find("value=Int32(42)") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("status=Good (0x00000000)") != std::string::npos) << "Got: " << result;
}

TEST(ToStringDataValue, Empty)
{
  DataValue dv;
  EXPECT_EQ(to_string(dv), "{}");
}

TEST(ToStringSummaryDataValue, AbbreviatedVariant)
{
  DataValue dv;
  Array<int32_t> arr(Size{2});
  arr[0] = 1;
  arr[1] = 2;
  dv.value() = std::move(arr);
  dv.status() = StatusCode{Status::Good};
  auto result = to_summary_string(dv);
  EXPECT_TRUE(result.find("value=Array<Int32>[2 elements]") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("status=Good (0x00000000)") != std::string::npos) << "Got: " << result;
}

// --- DiagnosticInfo ---

TEST(ToStringDiagnosticInfo, WithFields)
{
  DiagnosticInfo di;
  di.additional_info() = "details";
  di.inner_status_code() = StatusCode{Status::BadTimeout};
  auto result = to_string(di);
  EXPECT_TRUE(result.find("additionalInfo=details") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("innerStatus=BadTimeout") != std::string::npos) << "Got: " << result;
}

TEST(ToStringDiagnosticInfo, Empty)
{
  DiagnosticInfo di;
  EXPECT_EQ(to_string(di), "{}");
}

TEST(ToStringSummaryDiagnosticInfo, FieldNamesOnly)
{
  DiagnosticInfo di;
  di.additional_info() = "details";
  di.inner_status_code() = StatusCode{Status::BadTimeout};
  auto result = to_summary_string(di);
  EXPECT_TRUE(result.find("additionalInfo=...") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("innerStatus=...") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("details") == std::string::npos) << "Got: " << result;
}

// --- Decimal ---

TEST(ToStringTypes, Decimal)
{
  Decimal d;
  d.scale() = 2;
  d.value() = {uint8_t{'H'}, uint8_t{'i'}};
  auto result = to_string(d);
  EXPECT_TRUE(result.find("Decimal(scale=2") != std::string::npos) << "Got: " << result;
}

// --- BuiltInTypeId ---

TEST(ToStringTypes, BuiltInTypeId)
{
  EXPECT_EQ(to_string(BuiltInTypeId::Int32), "Int32");
  EXPECT_EQ(to_string(BuiltInTypeId::Boolean), "Boolean");
  EXPECT_EQ(to_string(BuiltInTypeId::String), "String");
  EXPECT_EQ(to_string(BuiltInTypeId::Null), "Null");
  EXPECT_EQ(to_string(BuiltInTypeId::DiagnosticInfo), "DiagnosticInfo");
}

// --- Array<bool> (special case due to vector<bool>) ---

TEST(ToStringVariant, ArrayBool)
{
  Array<bool> arr(Size{3});
  arr.payload()[0] = true;
  arr.payload()[1] = false;
  arr.payload()[2] = true;
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Boolean>[true, false, true]");
}

// --- Generated structure types ---

TEST(ToStringGenerated, StructureWithFields)
{
  ReadValueId rv;
  rv.node_id() = NodeId{uint16_t{2}, uint32_t{42}};
  rv.attribute_id() = 13;
  auto result = rv.to_string(0);
  EXPECT_TRUE(result.find("ReadValueId{") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("node_id=ns=2;i=42") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("attribute_id=13") != std::string::npos) << "Got: " << result;
}

TEST(ToStringGenerated, StructureViaFreeFunction)
{
  ReadValueId rv;
  rv.node_id() = NodeId{uint32_t{85}};
  const Structure& base = rv;
  auto result = to_string(base);
  EXPECT_TRUE(result.find("ReadValueId{") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("node_id=i=85") != std::string::npos) << "Got: " << result;
}

TEST(ToStringGenerated, StructureInVariant)
{
  auto rv = make_unique<ReadValueId>();
  rv->node_id() = NodeId{uint32_t{1}};
  Variant v{std::move(rv)};
  auto result = to_string(v);
  EXPECT_TRUE(result.find("ReadValueId{") != std::string::npos) << "Got: " << result;
}

TEST(ToStringGenerated, EnumType)
{
  EXPECT_EQ(to_string(UserTokenType::Anonymous), "Anonymous");
  EXPECT_EQ(to_string(UserTokenType::Certificate), "Certificate");
}

TEST(ToStringGenerated, OptionSetType)
{
  AttributeWriteMask mask{AttributeWriteMask::Bit::AccessLevel, AttributeWriteMask::Bit::DataType};
  auto result = to_string(mask);
  EXPECT_TRUE(result.find("AttributeWriteMask{") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("AccessLevel") != std::string::npos) << "Got: " << result;
  EXPECT_TRUE(result.find("DataType") != std::string::npos) << "Got: " << result;
}

// --- Array<T> free function template ---

TEST(ToStringArray, FreeFunction)
{
  Array<int32_t> arr(Size{3});
  arr[0] = 10;
  arr[1] = 20;
  arr[2] = 30;
  EXPECT_EQ(to_string(arr), "Array[10, 20, 30]");
}

// --- ErrorDetail ---

TEST(ToStringErrorDetail, SimpleNoCode)
{
  ErrorDetail d;
  d.summary = "Something went wrong";
  d.source = "TestComponent";
  EXPECT_EQ(to_string(d), "[TestComponent] Something went wrong");
}

TEST(ToStringErrorDetail, CodeAndSummary)
{
  ErrorDetail d;
  d.code = "NodeNotFound";
  d.summary = "Node not found in address space";
  d.source = "ReadService";
  EXPECT_EQ(to_string(d), "[ReadService] NodeNotFound: Node not found in address space");
}

TEST(ToStringErrorDetail, WithInnerStatus)
{
  ErrorDetail d;
  d.code = "CertExpired";
  d.summary = "Certificate expired";
  d.source = "OpenSslCrypto";
  d.innerStatus = StatusCode{Status::BadCertificateTimeInvalid}.value();
  auto result = to_string(d);
  EXPECT_EQ(
    result, "[OpenSslCrypto] CertExpired: Certificate expired (BadCertificateTimeInvalid (0x80140000))");
}

TEST(ToStringErrorDetail, WithDetailText)
{
  ErrorDetail d;
  d.code = "Timeout";
  d.summary = "Connection timed out";
  d.detail = "10.0.0.5:5432 after 30s (retry 3/3)";
  d.source = "Database";
  EXPECT_EQ(to_string(d),
    "[Database] Timeout: Connection timed out\n"
    "  detail: 10.0.0.5:5432 after 30s (retry 3/3)");
}

TEST(ToStringErrorDetail, CauseChainWithAllFields)
{
  auto inner = std::make_shared<ErrorDetail>();
  inner->code = "ChainFailed";
  inner->summary = "Chain validation failed";
  inner->detail = "/etc/ssl/trusted.pem not found";
  inner->source = "CertStore";
  inner->innerStatus = StatusCode{Status::BadCertificateUntrusted}.value();

  ErrorDetail outer;
  outer.code = "CertExpired";
  outer.summary = "Certificate expired";
  outer.detail = "CN=server, expired 2025-01-01";
  outer.source = "OpenSslCrypto";
  outer.innerStatus = StatusCode{Status::BadCertificateTimeInvalid}.value();
  outer.cause = inner;

  EXPECT_EQ(to_string(outer),
    "[OpenSslCrypto] CertExpired: Certificate expired (BadCertificateTimeInvalid (0x80140000))\n"
    "  detail: CN=server, expired 2025-01-01\n"
    "  caused by: [CertStore] ChainFailed: Chain validation failed (BadCertificateUntrusted (0x801A0000))\n"
    "    detail: /etc/ssl/trusted.pem not found");
}

TEST(ToStringErrorDetail, ThreeLevelCauseChain)
{
  auto root = std::make_shared<ErrorDetail>();
  root->code = "SslError";
  root->summary = "X509_verify_cert failed";
  root->detail = "error 20 at depth 0";
  root->source = "OpenSSL";

  auto mid = std::make_shared<ErrorDetail>();
  mid->code = "ChainFailed";
  mid->summary = "Chain validation failed";
  mid->source = "CertStore";
  mid->cause = root;

  ErrorDetail top;
  top.code = "Rejected";
  top.summary = "Certificate rejected";
  top.source = "SecureChannel";
  top.cause = mid;

  EXPECT_EQ(to_string(top),
    "[SecureChannel] Rejected: Certificate rejected\n"
    "  caused by: [CertStore] ChainFailed: Chain validation failed\n"
    "    caused by: [OpenSSL] SslError: X509_verify_cert failed\n"
    "      detail: error 20 at depth 0");
}

TEST(ToStringErrorDetail, EmptyDetail)
{
  ErrorDetail d;
  EXPECT_EQ(to_string(d), "");
}

TEST(ToStringErrorDetail, NoSource)
{
  ErrorDetail d;
  d.code = "Fail";
  d.summary = "Something failed";
  EXPECT_EQ(to_string(d), "Fail: Something failed");
}

TEST(ToStringErrorDetail, WithIndentParameter)
{
  ErrorDetail d;
  d.code = "Fail";
  d.summary = "Something failed";
  d.detail = "more info";
  d.source = "Test";
  EXPECT_EQ(to_string(d, 4),
    "    [Test] Fail: Something failed\n"
    "      detail: more info");
}

// ===========================================================================
// Coverage additions: every scalar Variant dispatch case, every array element
// type, the indent>0 composite paths, full DataValue / DiagnosticInfo field
// sets, the nested DiagnosticInfo recursion, and every BuiltInTypeId /
// AttributeId enumerator (plus their out-of-range fallbacks).
// ===========================================================================

// --- variant_scalar_to_string: one case per BuiltInTypeId ---

TEST(ToStringVariantScalar, SByte)
{
  Variant v{int8_t{-5}};
  EXPECT_EQ(to_string(v), "SByte(-5)");
}

TEST(ToStringVariantScalar, Byte)
{
  Variant v{uint8_t{200}};
  EXPECT_EQ(to_string(v), "Byte(200)");
}

TEST(ToStringVariantScalar, Int16)
{
  Variant v{int16_t{-300}};
  EXPECT_EQ(to_string(v), "Int16(-300)");
}

TEST(ToStringVariantScalar, UInt16)
{
  Variant v{uint16_t{40000}};
  EXPECT_EQ(to_string(v), "UInt16(40000)");
}

TEST(ToStringVariantScalar, UInt32)
{
  Variant v{uint32_t{4000000000U}};
  EXPECT_EQ(to_string(v), "UInt32(4000000000)");
}

TEST(ToStringVariantScalar, Int64)
{
  Variant v{int64_t{-5000000000LL}};
  EXPECT_EQ(to_string(v), "Int64(-5000000000)");
}

TEST(ToStringVariantScalar, UInt64)
{
  Variant v{uint64_t{10000000000ULL}};
  EXPECT_EQ(to_string(v), "UInt64(10000000000)");
}

TEST(ToStringVariantScalar, Float)
{
  Variant v{1.5f};
  EXPECT_EQ(to_string(v), "Float(1.5)");
}

TEST(ToStringVariantScalar, DateTime)
{
  Variant v{DateTime{2024, 1, 15, 10, 30, 0.0}};
  EXPECT_EQ(to_string(v), "DateTime(2024-01-15T10:30:00Z)");
}

TEST(ToStringVariantScalar, Guid)
{
  Variant v{Guid::parse("550e8400-e29b-41d4-a716-446655440000")};
  EXPECT_EQ(to_string(v), "Guid(550e8400-e29b-41d4-a716-446655440000)");
}

TEST(ToStringVariantScalar, ByteString)
{
  Variant v{ByteString{uint8_t{'H'}, uint8_t{'i'}}};
  EXPECT_EQ(to_string(v), "ByteString(SGk=)");
}

TEST(ToStringVariantScalar, XmlElement)
{
  XmlElement xml;
  xml = string_view{"<Bar/>"};
  Variant v{std::move(xml)};
  EXPECT_EQ(to_string(v), "XmlElement(<Bar/>)");
}

TEST(ToStringVariantScalar, NodeId)
{
  Variant v{NodeId{uint16_t{2}, uint32_t{99}}};
  EXPECT_EQ(to_string(v), "NodeId(ns=2;i=99)");
}

TEST(ToStringVariantScalar, ExpandedNodeId)
{
  Variant v{ExpandedNodeId{NodeId{uint32_t{42}}}};
  EXPECT_EQ(to_string(v), "ExpandedNodeId(i=42)");
}

TEST(ToStringVariantScalar, StatusCode)
{
  Variant v{StatusCode{Status::BadTimeout}};
  EXPECT_TRUE(contains(to_string(v), "StatusCode(BadTimeout"));
}

TEST(ToStringVariantScalar, QualifiedName)
{
  Variant v{QualifiedName{3, "Temp"}};
  EXPECT_EQ(to_string(v), "QualifiedName(3:Temp)");
}

TEST(ToStringVariantScalar, LocalizedText)
{
  Variant v{LocalizedText{String{"en"}, String{"Hi"}}};
  EXPECT_EQ(to_string(v), "LocalizedText([en]Hi)");
}

TEST(ToStringVariantScalar, ExtensionObjectNonNull)
{
  auto rv = std::make_unique<ReadValueId>();
  rv->node_id() = NodeId{uint32_t{7}};
  Variant v{std::move(rv)};
  auto result = to_string(v);
  EXPECT_TRUE(contains(result, "ReadValueId{")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "node_id=i=7")) << "Got: " << result;
}

TEST(ToStringVariantScalar, DataValueTyped)
{
  DataValue inner;
  inner.value() = int32_t{55};
  Variant v{std::move(inner)};
  auto result = to_string(v);
  EXPECT_TRUE(contains(result, "DataValue(")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "value=Int32(55)")) << "Got: " << result;
}

// --- array_to_string: one case per element type ---

TEST(ToStringArrayVariant, SByte)
{
  Array<int8_t> arr{int8_t{-1}, int8_t{2}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<SByte>[-1, 2]");
}

TEST(ToStringArrayVariant, Byte)
{
  Array<uint8_t> arr{uint8_t{1}, uint8_t{255}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Byte>[1, 255]");
}

TEST(ToStringArrayVariant, Int16)
{
  Array<int16_t> arr{int16_t{-7}, int16_t{8}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Int16>[-7, 8]");
}

TEST(ToStringArrayVariant, UInt16)
{
  Array<uint16_t> arr{uint16_t{10}, uint16_t{20}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<UInt16>[10, 20]");
}

TEST(ToStringArrayVariant, UInt32)
{
  Array<uint32_t> arr{uint32_t{100}, uint32_t{200}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<UInt32>[100, 200]");
}

TEST(ToStringArrayVariant, Int64)
{
  Array<int64_t> arr{int64_t{-1000}, int64_t{2000}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Int64>[-1000, 2000]");
}

TEST(ToStringArrayVariant, UInt64)
{
  Array<uint64_t> arr{uint64_t{3000}, uint64_t{4000}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<UInt64>[3000, 4000]");
}

TEST(ToStringArrayVariant, Float)
{
  Array<float> arr{1.5f, 2.5f};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Float>[1.5, 2.5]");
}

TEST(ToStringArrayVariant, Double)
{
  Array<double> arr{1.25, 2.5};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Double>[1.25, 2.5]");
}

TEST(ToStringArrayVariant, String)
{
  Array<String> arr{String{"a"}, String{"b"}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<String>[a, b]");
}

TEST(ToStringArrayVariant, DateTime)
{
  Array<DateTime> arr{DateTime{2024, 1, 1, 0, 0, 0.0}, DateTime{2024, 1, 2, 0, 0, 0.0}};
  Variant v{std::move(arr)};
  auto result = to_string(v);
  EXPECT_TRUE(contains(result, "Array<DateTime>[2024-01-01T00:00:00Z, 2024-01-02T00:00:00Z]"))
    << "Got: " << result;
}

TEST(ToStringArrayVariant, Guid)
{
  Array<Guid> arr{Guid::parse("550e8400-e29b-41d4-a716-446655440000")};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Guid>[550e8400-e29b-41d4-a716-446655440000]");
}

TEST(ToStringArrayVariant, ByteString)
{
  Array<ByteString> arr{ByteString{uint8_t{'H'}, uint8_t{'i'}}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<ByteString>[SGk=]");
}

TEST(ToStringArrayVariant, XmlElement)
{
  XmlElement xml;
  xml = string_view{"<X/>"};
  Array<XmlElement> arr;
  arr.payload() = {xml};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<XmlElement>[<X/>]");
}

TEST(ToStringArrayVariant, NodeId)
{
  Array<NodeId> arr{NodeId{uint32_t{1}}, NodeId{uint32_t{2}}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<NodeId>[i=1, i=2]");
}

TEST(ToStringArrayVariant, ExpandedNodeId)
{
  Array<ExpandedNodeId> arr{ExpandedNodeId{NodeId{uint32_t{5}}}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<ExpandedNodeId>[i=5]");
}

TEST(ToStringArrayVariant, StatusCode)
{
  Array<StatusCode> arr{StatusCode{Status::Good}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<StatusCode>[Good (0x00000000)]");
}

TEST(ToStringArrayVariant, QualifiedName)
{
  Array<QualifiedName> arr{QualifiedName{"Name"}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<QualifiedName>[Name]");
}

TEST(ToStringArrayVariant, LocalizedText)
{
  Array<LocalizedText> arr{LocalizedText{String{"Hi"}}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<LocalizedText>[Hi]");
}

TEST(ToStringArrayVariant, DataValue)
{
  DataValue dv;
  dv.value() = int32_t{9};
  Array<DataValue> arr;
  arr.payload() = {dv};
  Variant v{std::move(arr)};
  auto result = to_string(v);
  // Non-indented array form: each element uses the DataValue single-line format.
  EXPECT_EQ(result, "Array<DataValue>[{value=Int32(9)}]") << "Got: " << result;
}

TEST(ToStringArrayVariant, Variant)
{
  Array<Variant> arr;
  arr.payload() = {Variant{int32_t{7}}, Variant{String{"x"}}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_string(v), "Array<Variant>[Int32(7), String(x)]");
}

TEST(ToStringArrayVariant, ExtensionObjectExpanded)
{
  auto first = std::make_unique<ReadValueId>();
  first->node_id() = NodeId{uint32_t{1}};
  Array<RefStructure<Structure>> arr;
  arr.push_back(RefStructure<Structure>{std::move(first)});
  arr.push_back(RefStructure<Structure>{});  // null element exercises the "null" branch
  Variant v{std::move(arr)};
  auto result = to_string(v);
  EXPECT_TRUE(contains(result, "Array<ExtensionObject>[")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "ReadValueId{")) << "Got: " << result;
  EXPECT_TRUE(contains(result, ", null]")) << "Got: " << result;
}

// --- to_summary_string array element-type dispatch ---

TEST(ToStringSummaryArray, StringCount)
{
  Array<String> arr{String{"a"}, String{"b"}, String{"c"}};
  Variant v{std::move(arr)};
  EXPECT_EQ(to_summary_string(v), "Array<String>[3 elements]");
}

TEST(ToStringSummaryArray, ExtensionObjectCount)
{
  Array<RefStructure<Structure>> arr;
  arr.push_back(RefStructure<Structure>{});
  Variant v{std::move(arr)};
  EXPECT_EQ(to_summary_string(v), "Array<ExtensionObject>[1 element]");
}

// --- indent>0 composite Variant paths ---

TEST(ToStringVariantIndent, ExtensionObjectScalar)
{
  auto rv = std::make_unique<ReadValueId>();
  rv->node_id() = NodeId{uint32_t{4}};
  Variant v{std::move(rv)};
  auto result = to_string(v, 2);
  EXPECT_TRUE(contains(result, "ReadValueId{")) << "Got: " << result;
}

TEST(ToStringVariantIndent, ExtensionObjectArray)
{
  auto rv = std::make_unique<ReadValueId>();
  rv->node_id() = NodeId{uint32_t{4}};
  Array<RefStructure<Structure>> arr;
  arr.push_back(RefStructure<Structure>{std::move(rv)});
  Variant v{std::move(arr)};
  auto result = to_string(v, 2);
  // The indented Array<RefStructure> path renders one element per line.
  EXPECT_TRUE(contains(result, "Array[\n")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "ReadValueId{")) << "Got: " << result;
}

TEST(ToStringVariantIndent, DataValueScalar)
{
  DataValue inner;
  inner.value() = int32_t{1};
  inner.status() = StatusCode{Status::Good};
  Variant v{std::move(inner)};
  auto result = to_string(v, 2);
  EXPECT_TRUE(contains(result, "DataValue({\n")) << "Got: " << result;
}

// --- DataValue with every field set, both indent modes ---

TEST(ToStringDataValue, AllFieldsSingleLine)
{
  DataValue dv;
  dv.value() = int32_t{42};
  dv.status() = StatusCode{Status::Good};
  dv.source_timestamp() = DateTime{2024, 1, 1, 1, 0, 0.0};
  dv.source_pico_seconds() = uint16_t{11};
  dv.server_timestamp() = DateTime{2024, 1, 1, 2, 0, 0.0};
  dv.server_pico_seconds() = uint16_t{22};
  auto result = to_string(dv);
  EXPECT_TRUE(contains(result, "value=Int32(42)")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "status=Good")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "sourceTimestamp=2024-01-01T01:00:00Z")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "sourcePicoSeconds=11")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "serverTimestamp=2024-01-01T02:00:00Z")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "serverPicoSeconds=22")) << "Got: " << result;
}

TEST(ToStringDataValue, AllFieldsIndented)
{
  DataValue dv;
  dv.value() = int32_t{42};
  dv.status() = StatusCode{Status::Good};
  dv.source_timestamp() = DateTime{2024, 1, 1, 1, 0, 0.0};
  dv.source_pico_seconds() = uint16_t{11};
  dv.server_timestamp() = DateTime{2024, 1, 1, 2, 0, 0.0};
  dv.server_pico_seconds() = uint16_t{22};
  auto result = to_string(dv, 2);
  EXPECT_TRUE(contains(result, "{\n")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "value=Int32(42)")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "sourcePicoSeconds=11")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "serverPicoSeconds=22")) << "Got: " << result;
}

TEST(ToStringDataValue, EmptyIndented)
{
  DataValue dv;
  EXPECT_EQ(to_string(dv, 2), "{}");
}

// --- DiagnosticInfo with every field set, both indent modes, and recursion ---

TEST(ToStringDiagnosticInfo, AllFieldsSingleLine)
{
  DiagnosticInfo di;
  di.symbolic_id() = int32_t{1};
  di.namespace_uri() = int32_t{2};
  di.locale() = int32_t{3};
  di.localized_text() = int32_t{4};
  di.additional_info() = "info";
  di.inner_status_code() = StatusCode{Status::BadTimeout};
  auto result = to_string(di);
  EXPECT_TRUE(contains(result, "symbolicId=1")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "namespaceUri=2")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "locale=3")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "localizedText=4")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "additionalInfo=info")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "innerStatus=BadTimeout")) << "Got: " << result;
}

TEST(ToStringDiagnosticInfo, NestedInnerIndented)
{
  DiagnosticInfo di;
  di.symbolic_id() = int32_t{1};
  di.namespace_uri() = int32_t{2};
  di.locale() = int32_t{3};
  di.localized_text() = int32_t{4};
  di.additional_info() = "outer";
  di.inner_status_code() = StatusCode{Status::BadTimeout};
  auto inner = std::make_unique<DiagnosticInfo>();
  inner->symbolic_id() = int32_t{9};
  inner->additional_info() = "innermost";
  di.inner_diagnostic_info() = std::move(inner);

  auto result = to_string(di, 2);
  EXPECT_TRUE(contains(result, "{\n")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "symbolicId=1")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "innerDiagnosticInfo=")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "innermost")) << "Got: " << result;
}

TEST(ToStringDiagnosticInfo, NestedInnerSingleLine)
{
  DiagnosticInfo di;
  di.additional_info() = "outer";
  auto inner = std::make_unique<DiagnosticInfo>();
  inner->additional_info() = "inner";
  di.inner_diagnostic_info() = std::move(inner);
  auto result = to_string(di);
  EXPECT_TRUE(contains(result, "additionalInfo=outer")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "innerDiagnosticInfo={additionalInfo=inner}")) << "Got: " << result;
}

TEST(ToStringDiagnosticInfo, EmptyIndented)
{
  DiagnosticInfo di;
  EXPECT_EQ(to_string(di, 2), "{}");
}

TEST(ToStringSummaryDiagnosticInfo, AllFieldNames)
{
  DiagnosticInfo di;
  di.symbolic_id() = int32_t{1};
  di.namespace_uri() = int32_t{2};
  di.locale() = int32_t{3};
  di.localized_text() = int32_t{4};
  di.additional_info() = "info";
  di.inner_status_code() = StatusCode{Status::BadTimeout};
  di.inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  auto result = to_summary_string(di);
  EXPECT_TRUE(contains(result, "symbolicId=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "namespaceUri=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "locale=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "localizedText=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "innerDiagnosticInfo=...")) << "Got: " << result;
}

// --- to_summary_string(DataValue) with timestamps abbreviated ---

TEST(ToStringSummaryDataValue, TimestampsAbbreviated)
{
  DataValue dv;
  dv.source_timestamp() = DateTime{2024, 1, 1, 1, 0, 0.0};
  dv.source_pico_seconds() = uint16_t{11};
  dv.server_timestamp() = DateTime{2024, 1, 1, 2, 0, 0.0};
  dv.server_pico_seconds() = uint16_t{22};
  auto result = to_summary_string(dv);
  EXPECT_TRUE(contains(result, "sourceTimestamp=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "sourcePicoSeconds=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "serverTimestamp=...")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "serverPicoSeconds=...")) << "Got: " << result;
}

// --- NodeId Guid / opaque identifiers ---

TEST(ToStringTypes, NodeIdGuid)
{
  NodeId n{uint16_t{1}, Guid::parse("550e8400-e29b-41d4-a716-446655440000")};
  EXPECT_EQ(to_string(n), "ns=1;g=550e8400-e29b-41d4-a716-446655440000");
}

TEST(ToStringTypes, NodeIdOpaque)
{
  NodeId n{ByteString{uint8_t{'H'}, uint8_t{'i'}}};
  EXPECT_EQ(to_string(n), "b=SGk=");
}

// --- StatusCode uncommon code ---

TEST(ToStringTypes, StatusCodeUncommon)
{
  StatusCode sc{Status::BadOutOfMemory};
  auto result = to_string(sc);
  EXPECT_TRUE(contains(result, "BadOutOfMemory")) << "Got: " << result;
  EXPECT_TRUE(contains(result, "0x")) << "Got: " << result;
}

// --- BuiltInTypeId: every enumerator + fallback ---

TEST(ToStringBuiltInTypeId, AllNames)
{
  EXPECT_EQ(to_string(BuiltInTypeId::Null), "Null");
  EXPECT_EQ(to_string(BuiltInTypeId::Boolean), "Boolean");
  EXPECT_EQ(to_string(BuiltInTypeId::SByte), "SByte");
  EXPECT_EQ(to_string(BuiltInTypeId::Byte), "Byte");
  EXPECT_EQ(to_string(BuiltInTypeId::Int16), "Int16");
  EXPECT_EQ(to_string(BuiltInTypeId::UInt16), "UInt16");
  EXPECT_EQ(to_string(BuiltInTypeId::Int32), "Int32");
  EXPECT_EQ(to_string(BuiltInTypeId::UInt32), "UInt32");
  EXPECT_EQ(to_string(BuiltInTypeId::Int64), "Int64");
  EXPECT_EQ(to_string(BuiltInTypeId::UInt64), "UInt64");
  EXPECT_EQ(to_string(BuiltInTypeId::Float), "Float");
  EXPECT_EQ(to_string(BuiltInTypeId::Double), "Double");
  EXPECT_EQ(to_string(BuiltInTypeId::String), "String");
  EXPECT_EQ(to_string(BuiltInTypeId::DateTime), "DateTime");
  EXPECT_EQ(to_string(BuiltInTypeId::Guid), "Guid");
  EXPECT_EQ(to_string(BuiltInTypeId::ByteString), "ByteString");
  EXPECT_EQ(to_string(BuiltInTypeId::XmlElement), "XmlElement");
  EXPECT_EQ(to_string(BuiltInTypeId::NodeId), "NodeId");
  EXPECT_EQ(to_string(BuiltInTypeId::ExpandedNodeId), "ExpandedNodeId");
  EXPECT_EQ(to_string(BuiltInTypeId::StatusCode), "StatusCode");
  EXPECT_EQ(to_string(BuiltInTypeId::QualifiedName), "QualifiedName");
  EXPECT_EQ(to_string(BuiltInTypeId::LocalizedText), "LocalizedText");
  EXPECT_EQ(to_string(BuiltInTypeId::ExtensionObject), "ExtensionObject");
  EXPECT_EQ(to_string(BuiltInTypeId::DataValue), "DataValue");
  EXPECT_EQ(to_string(BuiltInTypeId::Variant), "Variant");
  EXPECT_EQ(to_string(BuiltInTypeId::DiagnosticInfo), "DiagnosticInfo");
}

TEST(ToStringBuiltInTypeId, OutOfRangeFallback)
{
  auto result = to_string(static_cast<BuiltInTypeId>(250));
  EXPECT_EQ(result, "Unknown(250)");
}

// --- AttributeId: every enumerator + fallback ---

TEST(ToStringAttributeId, AllNames)
{
  EXPECT_EQ(to_string(AttributeId::NodeId), "NodeId");
  EXPECT_EQ(to_string(AttributeId::NodeClass), "NodeClass");
  EXPECT_EQ(to_string(AttributeId::BrowseName), "BrowseName");
  EXPECT_EQ(to_string(AttributeId::DisplayName), "DisplayName");
  EXPECT_EQ(to_string(AttributeId::Description), "Description");
  EXPECT_EQ(to_string(AttributeId::WriteMask), "WriteMask");
  EXPECT_EQ(to_string(AttributeId::UserWriteMask), "UserWriteMask");
  EXPECT_EQ(to_string(AttributeId::IsAbstract), "IsAbstract");
  EXPECT_EQ(to_string(AttributeId::Symmetric), "Symmetric");
  EXPECT_EQ(to_string(AttributeId::InverseName), "InverseName");
  EXPECT_EQ(to_string(AttributeId::ContainsNoLoops), "ContainsNoLoops");
  EXPECT_EQ(to_string(AttributeId::EventNotifier), "EventNotifier");
  EXPECT_EQ(to_string(AttributeId::Value), "Value");
  EXPECT_EQ(to_string(AttributeId::DataType), "DataType");
  EXPECT_EQ(to_string(AttributeId::ValueRank), "ValueRank");
  EXPECT_EQ(to_string(AttributeId::ArrayDimensions), "ArrayDimensions");
  EXPECT_EQ(to_string(AttributeId::AccessLevel), "AccessLevel");
  EXPECT_EQ(to_string(AttributeId::UserAccessLevel), "UserAccessLevel");
  EXPECT_EQ(to_string(AttributeId::MinimumSamplingInterval), "MinimumSamplingInterval");
  EXPECT_EQ(to_string(AttributeId::Historizing), "Historizing");
  EXPECT_EQ(to_string(AttributeId::Executable), "Executable");
  EXPECT_EQ(to_string(AttributeId::UserExecutable), "UserExecutable");
  EXPECT_EQ(to_string(AttributeId::DataTypeDefinition), "DataTypeDefinition");
  EXPECT_EQ(to_string(AttributeId::RolePermissions), "RolePermissions");
  EXPECT_EQ(to_string(AttributeId::UserRolePermissions), "UserRolePermissions");
  EXPECT_EQ(to_string(AttributeId::AccessRestrictions), "AccessRestrictions");
  EXPECT_EQ(to_string(AttributeId::AccessLevelEx), "AccessLevelEx");
}

TEST(ToStringAttributeId, OutOfRangeFallback)
{
  auto result = to_string(static_cast<AttributeId>(9999));
  EXPECT_EQ(result, "Unknown(9999)");
}
