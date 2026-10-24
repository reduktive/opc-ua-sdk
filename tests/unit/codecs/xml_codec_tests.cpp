// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <limits>
#include <cmath>
#include "ua_xml_codec.h"
#include "ua_application_configuration.h"
#include "ua_structure_factory.h"
#include "ua_argument.h"
#include "ua_date_time.h"
#include "ua_xml_element.h"
#include "ua_expanded_node_id.h"
#include "ua_status_code.h"
#include "ua_qualified_name.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info.h"
#include "ua_variant.h"
#include "ua_codec_namespace_context.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"

using namespace ua;

template<typename T>
void decoding_test(string_view input, string_view elementName, StructureFactory& structureFactory, T& value)
{
  std::vector<char> writableInput;
  writableInput.resize(input.size() + 1);
  std::copy(input.begin(), input.end(), writableInput.begin());
  writableInput.back() = '\0';

  auto context = xml::parse(writableInput.data());
  auto xmlNextElement = context.xml_element().get_first_child();

  XmlDecoder decoder{structureFactory, *xmlNextElement, EncodingLimits{}};
  auto cfg = ApplicationConfig::load_default();
  StackDepth limit{cfg.execution_limits().decodeWorkLimit};
  decoder.decode(limit, elementName, false, value);
}

// Decode with an explicit CodecNamespaceContext so the translate-at-source hooks
// (translateNodeId / translateQualifiedName / translateExpandedNodeId) are exercised.
template<typename T>
void decoding_test_with_config(string_view input, string_view elementName, StructureFactory& structureFactory,
  const CodecNamespaceContext& namespaceConfig, T& value)
{
  std::vector<char> writableInput;
  writableInput.resize(input.size() + 1);
  std::copy(input.begin(), input.end(), writableInput.begin());
  writableInput.back() = '\0';

  auto context = xml::parse(writableInput.data());
  auto firstElement = context.xml_element().get_first_child();

  XmlDecoder decoder{structureFactory, *firstElement, EncodingLimits{}, namespaceConfig};
  auto cfg = ApplicationConfig::load_default();
  StackDepth limit{cfg.execution_limits().decodeWorkLimit};
  decoder.decode(limit, elementName, false, value);
}

// A non-identity namespace-index mapper: 0 is preserved (NS0 is global), 1->7, 2->8,
// and any index >= 10 is out-of-range and throws BadDecodingError + ErrorDetail,
// mirroring the importer's translate_node_id behaviour.
inline uint16_t map_test_namespace_index(uint16_t index)
{
  switch (index)
  {
  case 0:
    return 0;
  case 1:
    return 7;
  case 2:
    return 8;
  default:
    throw UaException(Status::BadDecodingError,
      make_error_detail("InvalidNodesetXml", "namespace index out of range", "XmlCodecTest"));
  }
}

inline CodecNamespaceContext make_test_index_mapper()
{
  CodecNamespaceContext config;
  config.translateNodeId = [](NodeId& id)
  {
    id.namespace_index() = map_test_namespace_index(id.namespace_index());
  };
  config.translateQualifiedName = [](QualifiedName& name)
  {
    name.namespace_index() = map_test_namespace_index(name.namespace_index());
  };
  return config;
}

class XmlCodecTest : public testing::Test
{
  void SetUp() override
  {
    auto createArgument = []()
    {
      return make_unique<Argument>();
    };

    mStructureFactory.register_type(NodeId{Argument::defaultXmlEncodingId}, createArgument);
  }

  void TearDown() override
  {}

protected:
  StructureFactory mStructureFactory;
};

TEST_F(XmlCodecTest, Boolean)
{
  string_view input0 = "<TestData>true</TestData>";
  string_view input1 = "<TestData>false</TestData>";
  string_view input2 = "<TestData>rubbish!</TestData>";

  string_view elementName = "TestData";

  bool result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_TRUE(result);

  decoding_test(input1, elementName, mStructureFactory, result);
  EXPECT_FALSE(result);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Byte)
{
  string_view input0 = "<TestData>255</TestData>";
  string_view input1 = "<TestData>256</TestData>";
  string_view input2 = "<TestData>-1</TestData>";

  string_view elementName = "TestData";

  uint8_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, static_cast<uint8_t>(255));

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, SByte)
{
  string_view input0 = "<TestData>-128</TestData>";
  string_view input1 = "<TestData>128</TestData>";
  string_view input2 = "<TestData>-129</TestData>";

  string_view elementName = "TestData";

  int8_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, static_cast<int8_t>(-128));

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, UInt32)
{
  string_view input0 = "<TestData>4294967295</TestData>";
  string_view input1 = "<TestData>4294967296</TestData>";
  string_view input2 = "<TestData>-10</TestData>";

  string_view elementName = "TestData";

  uint32_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, 4294967295UL);

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, UInt16)
{
  string_view input0 = "<TestData>65535</TestData>";
  string_view input1 = "<TestData>65536</TestData>";
  string_view input2 = "<TestData>-1</TestData>";

  string_view elementName = "TestData";

  uint16_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, static_cast<uint16_t>(65535));

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Int16)
{
  string_view input0 = "<TestData>-32768</TestData>";
  string_view input1 = "<TestData>32768</TestData>";
  string_view input2 = "<TestData>-32769</TestData>";

  string_view elementName = "TestData";

  int16_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, static_cast<int16_t>(-32768));

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, UInt64)
{
  string_view input0 = "<TestData>18446744073709551615</TestData>";
  string_view input1 = "<TestData>18446744073709551616</TestData>";
  string_view input2 = "<TestData>-1</TestData>";

  string_view elementName = "TestData";

  uint64_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, std::numeric_limits<uint64_t>::max());

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Int64)
{
  string_view input0 = "<TestData>-9223372036854775808</TestData>";
  string_view input1 = "<TestData>9223372036854775808</TestData>";
  string_view input2 = "<TestData>-9223372036854775809</TestData>";

  string_view elementName = "TestData";

  int64_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, std::numeric_limits<int64_t>::min());

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Int32)
{
  string_view input0 = "<TestData>-2147483647</TestData>";
  string_view input1 = "<TestData>2147483648</TestData>";
  string_view input2 = "<TestData>-2147483649</TestData>";

  string_view elementName = "TestData";

  int32_t result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, -2147483647);

  EXPECT_THROW(decoding_test(input1, elementName, mStructureFactory, result), UaException);

  EXPECT_THROW(decoding_test(input2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Float)
{
  string_view good1 = "<TestData>NaN</TestData>";
  string_view good2 = "<TestData>INF</TestData>";
  string_view good3 = "<TestData>-INF</TestData>";
  string_view good4 = "<TestData>123.456</TestData>";
  string_view good5 = "<TestData>+1234.456</TestData>";
  string_view good6 = "<TestData>-.45E-6</TestData>";
  string_view bad1 = "<TestData>1234.4E 56</TestData>";
  string_view bad2 = "<TestData>1E+2.5</TestData>";
  string_view bad3 = "<TestData>-1.2344e56</TestData>";

  string_view elementName = "TestData";

  float result{};

  EXPECT_THROW(decoding_test(good4, "WrongName", mStructureFactory, result), UaException);

  decoding_test(good1, elementName, mStructureFactory, result);
  EXPECT_TRUE(std::isnan(result));

  decoding_test(good2, elementName, mStructureFactory, result);
  EXPECT_EQ(result, std::numeric_limits<float>::infinity());

  decoding_test(good3, elementName, mStructureFactory, result);
  EXPECT_EQ(result, -std::numeric_limits<float>::infinity());

  decoding_test(good4, elementName, mStructureFactory, result);
  EXPECT_FLOAT_EQ(result, 123.456f);

  decoding_test(good5, elementName, mStructureFactory, result);
  EXPECT_FLOAT_EQ(result, 1234.456f);

  decoding_test(good6, elementName, mStructureFactory, result);
  EXPECT_FLOAT_EQ(result, -.45e-6f);

  EXPECT_THROW(decoding_test(bad1, elementName, mStructureFactory, result), UaException);
  EXPECT_THROW(decoding_test(bad2, elementName, mStructureFactory, result), UaException);
  EXPECT_THROW(decoding_test(bad3, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Double)
{
  string_view good1 = "<TestData>NaN</TestData>";
  string_view good2 = "<TestData>INF</TestData>";
  string_view good3 = "<TestData>-INF</TestData>";
  string_view good4 = "<TestData>-1E4</TestData>";
  string_view good5 = "<TestData>1267.43233E12</TestData>";
  string_view good6 = "<TestData>12.78e-2</TestData>";
  string_view good7 = "<TestData>12</TestData>";
  string_view good8 = "<TestData>-0</TestData>";
  string_view good9 = "<TestData>-1.2344e56</TestData>";
  string_view bad1 = "<TestData>1E+2.5</TestData>";
  string_view bad2 = "<TestData>1234.4E 56</TestData>";

  string_view elementName = "TestData";

  double result{};

  EXPECT_THROW(decoding_test(good4, "WrongName", mStructureFactory, result), UaException);

  decoding_test(good1, elementName, mStructureFactory, result);
  EXPECT_TRUE(std::isnan(result));

  decoding_test(good2, elementName, mStructureFactory, result);
  EXPECT_EQ(result, std::numeric_limits<double>::infinity());

  decoding_test(good3, elementName, mStructureFactory, result);
  EXPECT_EQ(result, -std::numeric_limits<double>::infinity());

  decoding_test(good4, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, -1E4);

  decoding_test(good5, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, 1267.43233E12);

  decoding_test(good6, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, 12.78e-2);

  decoding_test(good7, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, 12.0);

  decoding_test(good8, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, 0.0);
  EXPECT_TRUE(std::signbit(result));

  decoding_test(good9, elementName, mStructureFactory, result);
  EXPECT_DOUBLE_EQ(result, -1.2344e56);

  EXPECT_THROW(decoding_test(bad1, elementName, mStructureFactory, result), UaException);
  EXPECT_THROW(decoding_test(bad2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, Guid)
{
  string_view good = "<TestData>C496578A-0DFE-4B8F-870A-745238C6AEAE</TestData>";
  string_view bad1 = "<TestData>C496578A-0DFE-4B8F-870A:745238C6AEAE</TestData>";
  string_view bad2 = "<TestData>C496578A-0DFE-4B8F-870A-745238C6AE</TestData>";

  string_view elementName = "TestData";

  Guid result{};

  EXPECT_THROW(decoding_test(good, "WrongName", mStructureFactory, result), UaException);

  decoding_test(good, elementName, mStructureFactory, result);

  auto bytes = result.as_ua_binary();
  std::array<byte, Guid::length> expected = {byte{0x8A},
    byte{0x57},
    byte{0x96},
    byte{0xC4},
    byte{0xFE},
    byte{0x0D},
    byte{0x8F},
    byte{0x4B},
    byte{0x87},
    byte{0x0A},
    byte{0x74},
    byte{0x52},
    byte{0x38},
    byte{0xC6},
    byte{0xAE},
    byte{0xAE}};
  EXPECT_EQ(bytes, expected);

  EXPECT_THROW(decoding_test(bad1, elementName, mStructureFactory, result), UaException);
  EXPECT_THROW(decoding_test(bad2, elementName, mStructureFactory, result), UaException);
}

TEST_F(XmlCodecTest, String)
{
  string_view input0 = "<TestData>Test String</TestData>";

  string_view elementName = "TestData";

  String result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, "Test String");
}

TEST_F(XmlCodecTest, NodeId)
{
  string_view input0 = "<TestData><Identifier>ns=2;i=345</Identifier></TestData>";

  string_view elementName = "TestData";

  NodeId result{};

  EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);

  decoding_test(input0, elementName, mStructureFactory, result);
  EXPECT_EQ(result, NodeId(2, 345));
}

TEST_F(XmlCodecTest, LocalizedText)
{
  string_view input0 = "<TestData><Locale>en-IE</Locale><Text>MyText</Text></TestData>";
  string_view input1 = "<TestData><Text>MyText</Text></TestData>";
  string_view input2 = "<TestData><Locale>en-IE</Locale></TestData>";
  string_view input3 = "<TestData></TestData>";

  string_view elementName = "TestData";

  {
    LocalizedText result{};
    EXPECT_THROW(decoding_test(input0, "WrongName", mStructureFactory, result), UaException);
  }

  {
    LocalizedText result{};
    decoding_test(input0, elementName, mStructureFactory, result);
    EXPECT_EQ(result.locale(), "en-IE");
    EXPECT_EQ(result.text(), "MyText");
  }

  {
    LocalizedText result{};
    decoding_test(input1, elementName, mStructureFactory, result);
    EXPECT_TRUE(result.locale().empty());
    EXPECT_EQ(result.text(), "MyText");
  }

  {
    LocalizedText result{};
    decoding_test(input2, elementName, mStructureFactory, result);
    EXPECT_EQ(result.locale(), "en-IE");
    EXPECT_TRUE(result.text().empty());
  }

  {
    LocalizedText result{};
    decoding_test(input3, "", mStructureFactory, result);
    EXPECT_TRUE(result.locale().empty());
    EXPECT_TRUE(result.text().empty());
  }
}

TEST_F(XmlCodecTest, Argument)
{
  string_view input0 =
    "<Argument>"
    "<Name>Rule</Name>"
    "<DataType><Identifier>i=15634</Identifier></DataType>"
    "<ValueRank>2</ValueRank>"
    "<ArrayDimensions><UInt32>1</UInt32><UInt32>2</UInt32></ArrayDimensions>"
    "<Description><Locale>en-IE</Locale></Description>"
    "</Argument>";

  Argument result{};
  decoding_test(input0, "Argument", mStructureFactory, result);
  EXPECT_EQ(result.name(), "Rule");
  EXPECT_EQ(result.data_type(), NodeId(15634));
  EXPECT_EQ(result.value_rank(), 2);
  std::vector<uint32_t> arrayDims = {1, 2};
  EXPECT_EQ(result.array_dimensions().payload(), arrayDims);
  EXPECT_TRUE(result.description().locale() == "en-IE");
}

TEST_F(XmlCodecTest, ArrayOfArgument)
{
  // Two Argument structures inside a ListOfArgument wrapper
  string_view xml =
    "<TestData>"
    "    <Argument>"
    "      <Name>A</Name>"
    "      <DataType><Identifier>i=12</Identifier></DataType>"
    "      <ValueRank>0</ValueRank>"
    "    </Argument>"
    "    <Argument>"
    "      <Name>B</Name>"
    "      <DataType><Identifier>i=13</Identifier></DataType>"
    "      <ValueRank>1</ValueRank>"
    "      <ArrayDimensions><UInt32>3</UInt32><UInt32>4</UInt32></ArrayDimensions>"
    "      <Description><Locale>en-US</Locale><Text>desc</Text></Description>"
    "    </Argument>"
    "</TestData>";

  Array<Argument> arr{};
  // Wrong element name should throw
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  // Decode the array
  decoding_test(xml, "TestData", mStructureFactory, arr);

  ASSERT_EQ(arr.size(), 2u);

  const auto& a0 = arr[0];
  EXPECT_EQ(a0.name(), "A");
  EXPECT_EQ(a0.data_type(), NodeId(12));
  EXPECT_EQ(a0.value_rank(), 0);

  const auto& a1 = arr[1];
  EXPECT_EQ(a1.name(), "B");
  EXPECT_EQ(a1.data_type(), NodeId(13));
  EXPECT_EQ(a1.value_rank(), 1);
  std::vector<uint32_t> dims{3, 4};
  EXPECT_EQ(a1.array_dimensions().payload(), dims);
  EXPECT_EQ(a1.description().locale(), "en-US");
  EXPECT_EQ(a1.description().text(), "desc");
}

// =============================================================================
// Companion-spec (uax:-prefixed) value decoding.
//
// NS0 emits value contents in the default Types.xsd namespace with UNPREFIXED
// element names (`<ListOfDouble><Double>...`). 124 of the 140 OPC Foundation
// companion-spec NodeSets instead bind the SAME Types.xsd URI to the `uax:`
// prefix and write `<uax:ListOfDouble><uax:Double>...`. The two forms are
// namespace-identical (one default-namespace redeclaration, the other a prefix
// bound to the same URI), so the decoder must treat them identically.
//
// The codec strips the prefix in element-name presence checks
// (check_element_presence) and in built-in type-name detection
// (get_built_in_type_id), so prefixed *scalars* decode. But array detection
// (typeName.starts_with("ListOf")) and nested-child descent
// (get_first_child("Text") etc.) match the full, still-prefixed name, so
// prefixed arrays and prefixed nested values do not decode. These tests assert
// the correct, prefix-insensitive behaviour.
// =============================================================================

static constexpr string_view uaxDecl = R"( xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd")";

// Control: a prefixed primitive scalar already decodes, because the type-name
// prefix is stripped before built-in lookup. Guards against a regression in
// that path while the array/nested-descent gaps are fixed.
TEST_F(XmlCodecTest, PrefixedScalarVariantDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} + "><uax:Int32>-7</uax:Int32></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_int32());
  EXPECT_EQ(v.as<int32_t>(), -7);
}

// Nested-child descent must ignore the prefix on <uax:Locale>/<uax:Text>.
TEST_F(XmlCodecTest, PrefixedLocalizedTextDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><uax:Locale>en-IE</uax:Locale><uax:Text>MyText</uax:Text></TestData>";
  LocalizedText result{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, result);
  EXPECT_EQ(result.locale(), "en-IE");
  EXPECT_EQ(result.text(), "MyText");
}

// `uax:ListOfDouble` must be recognised as an array of Double.
TEST_F(XmlCodecTest, PrefixedArrayVariantDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><uax:ListOfDouble><uax:Double>1</uax:Double>"
                    "<uax:Double>2.5</uax:Double></uax:ListOfDouble></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<double>>();
  std::vector<double> expected{1.0, 2.5};
  EXPECT_EQ(arr.payload(), expected);
}

// The real companion-spec shape (cf. DynamicTypesTest.NodeSet2.xml
// OptionSetValues property): a prefixed array of prefixed LocalizedText.
// Exercises both array detection and nested-child descent at once.
TEST_F(XmlCodecTest, PrefixedListOfLocalizedTextVariantDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><uax:ListOfLocalizedText>"
                    "<uax:LocalizedText><uax:Text>CanRead</uax:Text></uax:LocalizedText>"
                    "<uax:LocalizedText><uax:Text>CanWrite</uax:Text></uax:LocalizedText>"
                    "</uax:ListOfLocalizedText></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<LocalizedText>>();
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0].text(), "CanRead");
  EXPECT_EQ(arr[1].text(), "CanWrite");
}

// The fix is local-name matching, NOT a hardcoded `uax:` special-case: ANY
// prefix bound to the Types.xsd URI must behave identically. Using a `t:`
// prefix proves the decoder keys on the local name, not the literal `uax`.
TEST_F(XmlCodecTest, NonUaxPrefixDecodes)
{
  static constexpr string_view tDecl = R"( xmlns:t="http://opcfoundation.org/UA/2008/02/Types.xsd")";
  std::string xml = std::string{"<TestData"} + std::string{tDecl} +
                    "><t:ListOfInt32><t:Int32>4</t:Int32><t:Int32>5</t:Int32></t:ListOfInt32></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<int32_t>>();
  std::vector<int32_t> expected{4, 5};
  EXPECT_EQ(arr.payload(), expected);
}

// Regression: the unprefixed (NS0 default-namespace) array form must still
// decode after the local-name change.
TEST_F(XmlCodecTest, UnprefixedArrayStillDecodes)
{
  string_view xml =
    "<TestData><ListOfDouble><Double>1</Double><Double>2.5</Double></ListOfDouble></TestData>";
  Variant v{};
  decoding_test(xml, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<double>>();
  std::vector<double> expected{1.0, 2.5};
  EXPECT_EQ(arr.payload(), expected);
}

// A prefixed ExtensionObject body (Argument struct) must decode: TypeId,
// Body and every struct field carry the prefix.
TEST_F(XmlCodecTest, PrefixedExtensionObjectStructDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><uax:ExtensionObject>"
                    "<uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>"
                    "<uax:Body>"
                    "<uax:Argument>"
                    "<uax:Name>Rule</uax:Name>"
                    "<uax:DataType><uax:Identifier>i=15634</uax:Identifier></uax:DataType>"
                    "<uax:ValueRank>2</uax:ValueRank>"
                    "</uax:Argument>"
                    "</uax:Body>"
                    "</uax:ExtensionObject></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_structure());
  const auto* argument = dynamic_cast<const Argument*>(&v.as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "Rule");
  EXPECT_EQ(argument->data_type(), NodeId(15634));
  EXPECT_EQ(argument->value_rank(), 2);
}

// A prefixed Matrix (`<uax:Matrix>` with prefixed Dimensions + ListOf wrapper)
// must decode, exercising the matrix descent's prefix-insensitive wrapper match.
TEST_F(XmlCodecTest, PrefixedMatrixDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><uax:Matrix>"
                    "<uax:Dimensions><uax:Int32>2</uax:Int32><uax:Int32>2</uax:Int32></uax:Dimensions>"
                    "<uax:ListOfInt32>"
                    "<uax:Int32>1</uax:Int32><uax:Int32>2</uax:Int32>"
                    "<uax:Int32>3</uax:Int32><uax:Int32>4</uax:Int32>"
                    "</uax:ListOfInt32>"
                    "</uax:Matrix></TestData>";
  Variant v{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<int32_t>>();
  ASSERT_TRUE(arr.dimensions().has_value());
  std::vector<int32_t> dims{2, 2};
  EXPECT_EQ(*arr.dimensions(), dims);
  std::vector<int32_t> expected{1, 2, 3, 4};
  EXPECT_EQ(arr.payload(), expected);
}

// Mixed prefixed and unprefixed children in one value (both bind Types.xsd):
// nested-child descent must match each by local name regardless of prefix.
TEST_F(XmlCodecTest, MixedPrefixedUnprefixedLocalizedTextDecodes)
{
  std::string xml = std::string{"<TestData"} + std::string{uaxDecl} +
                    "><Locale>en-IE</Locale><uax:Text>MyText</uax:Text></TestData>";
  LocalizedText result{};
  decoding_test(string_view{xml}, "TestData", mStructureFactory, result);
  EXPECT_EQ(result.locale(), "en-IE");
  EXPECT_EQ(result.text(), "MyText");
}

// Falsifiability: local-name matching must not over-match. A genuinely wrong
// element name (different local name) still fails the presence check.
TEST_F(XmlCodecTest, PrefixInsensitiveButWrongLocalNameStillFails)
{
  std::string xml =
    std::string{"<TestData"} + std::string{uaxDecl} + "><uax:Text>MyText</uax:Text></TestData>";
  LocalizedText result{};
  EXPECT_THROW(decoding_test(string_view{xml}, "WrongName", mStructureFactory, result), UaException);
}

// =============================================================================
// Translate-at-source (P2): the decoder applies an injected namespace-index
// mapper to every NodeId/QualifiedName/ExpandedNodeId it decodes, including ids
// nested inside structure fields and arrays. This replaces the importer's old
// post-decode `translate_variant` walk, which could not reach struct-embedded
// ids. With no mapper the decode is an exact identity (wire/normal decode).
// =============================================================================

TEST_F(XmlCodecTest, NamespaceMapperTranslatesScalarNodeId)
{
  NodeId value{};
  decoding_test_with_config("<TestData><Identifier>ns=1;i=5</Identifier></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    value);
  EXPECT_EQ(value.namespace_index(), 7);
  EXPECT_EQ(value.identifier().get_numeric(), 5u);
}

TEST_F(XmlCodecTest, NamespaceMapperPreservesNamespaceZero)
{
  NodeId value{};
  decoding_test_with_config("<TestData><Identifier>i=42</Identifier></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    value);
  EXPECT_EQ(value.namespace_index(), 0);
  EXPECT_EQ(value.identifier().get_numeric(), 42u);
}

TEST_F(XmlCodecTest, NamespaceMapperTranslatesQualifiedName)
{
  QualifiedName value{};
  decoding_test_with_config("<TestData><NamespaceIndex>1</NamespaceIndex><Name>X</Name></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    value);
  EXPECT_EQ(value.namespace_index(), 7);
  EXPECT_EQ(value.name(), "X");
}

// An ExpandedNodeId's embedded NodeId index is translated exactly once (via the
// NodeId hook the decoder applies on the inner element), and the NamespaceUri is
// preserved. Falsifiable: a double-application would map 1->7 then 7->out-of-range
// and throw.
TEST_F(XmlCodecTest, NamespaceMapperTranslatesExpandedNodeIdIndexOnce)
{
  ExpandedNodeId value{};
  decoding_test_with_config(
    "<TestData><NodeId><Identifier>ns=1;i=5</Identifier></NodeId>"
    "<NamespaceUri>urn:keep</NamespaceUri></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    value);
  EXPECT_EQ(value.node_id().namespace_index(), 7);
  EXPECT_EQ(value.node_id().identifier().get_numeric(), 5u);
  EXPECT_EQ(value.namespace_uri(), "urn:keep");
}

// The motivating gap: a NodeId nested inside a decoded structure field must be
// translated transitively. (Argument::DataType is a NodeId field.)
TEST_F(XmlCodecTest, NamespaceMapperTranslatesNodeIdInsideStructureField)
{
  Variant v{};
  decoding_test_with_config(
    "<TestData><ExtensionObject>"
    "<TypeId><Identifier>i=297</Identifier></TypeId>"
    "<Body><Argument>"
    "<Name>Field</Name>"
    "<DataType><Identifier>ns=1;i=600</Identifier></DataType>"
    "<ValueRank>0</ValueRank>"
    "</Argument></Body>"
    "</ExtensionObject></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    v);
  ASSERT_TRUE(v.is_structure());
  const auto* argument = dynamic_cast<const Argument*>(&v.as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->data_type().namespace_index(), 7);
  EXPECT_EQ(argument->data_type().identifier().get_numeric(), 600u);
}

// Arrays of NodeId must be translated element-by-element. Falsifiable: before
// the config was propagated to nested array decoders, these stayed untranslated.
TEST_F(XmlCodecTest, NamespaceMapperTranslatesArrayOfNodeId)
{
  Variant v{};
  decoding_test_with_config(
    "<TestData><ListOfNodeId>"
    "<NodeId><Identifier>ns=1;i=1</Identifier></NodeId>"
    "<NodeId><Identifier>ns=2;i=2</Identifier></NodeId>"
    "</ListOfNodeId></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<NodeId>>();
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0].namespace_index(), 7);
  EXPECT_EQ(arr[0].identifier().get_numeric(), 1u);
  EXPECT_EQ(arr[1].namespace_index(), 8);
  EXPECT_EQ(arr[1].identifier().get_numeric(), 2u);
}

// An ExtensionObject's TypeId is translated, and the TRANSLATED id is used as the
// factory lookup key. Registering Argument's creator under the translated (ns=7)
// key proves the factory sees the server-side id.
TEST_F(XmlCodecTest, NamespaceMapperTranslatesExtensionObjectTypeId)
{
  mStructureFactory.register_type(NodeId{7, 297u}, []() { return make_unique<Argument>(); });

  Variant v{};
  decoding_test_with_config(
    "<TestData><ExtensionObject>"
    "<TypeId><Identifier>ns=1;i=297</Identifier></TypeId>"
    "<Body><Argument><Name>Custom</Name></Argument></Body>"
    "</ExtensionObject></TestData>",
    "TestData",
    mStructureFactory,
    make_test_index_mapper(),
    v);
  ASSERT_TRUE(v.is_structure());
  const auto* argument = dynamic_cast<const Argument*>(&v.as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "Custom");
}

TEST_F(XmlCodecTest, NamespaceMapperOutOfRangeThrowsWithErrorDetail)
{
  NodeId value{};
  try
  {
    decoding_test_with_config("<TestData><Identifier>ns=10;i=1</Identifier></TestData>",
      "TestData",
      mStructureFactory,
      make_test_index_mapper(),
      value);
    FAIL() << "expected UaException for out-of-range namespace index";
  }
  catch (const UaException& e)
  {
    EXPECT_EQ(e.status(), Status::BadDecodingError);
    EXPECT_NE(e.detail(), nullptr);
  }
}

// Regression guard: with no mapper, decode is an exact identity (no translation).
TEST_F(XmlCodecTest, NoMapperLeavesNamespaceIndexUnchanged)
{
  NodeId value{};
  decoding_test_with_config("<TestData><Identifier>ns=1;i=5</Identifier></TestData>",
    "TestData",
    mStructureFactory,
    CodecNamespaceContext{},
    value);
  EXPECT_EQ(value.namespace_index(), 1);
  EXPECT_EQ(value.identifier().get_numeric(), 5u);
}

TEST_F(XmlCodecTest, DateTime)
{
  // Basic Zulu time
  string_view t1 = "<TestData>2009-10-10T17:11:12Z</TestData>";
  DateTime dt1{};
  EXPECT_THROW(decoding_test(t1, "WrongName", mStructureFactory, dt1), UaException);
  decoding_test(t1, "TestData", mStructureFactory, dt1);
  DateTime expected1{2009, 10, 10, 17, 11, 12, 0};
  EXPECT_EQ(dt1, expected1);

  // Fractional seconds with rounding to 100ns
  string_view t2 = "<TestData>2009-10-10T17:09:01.12345678Z</TestData>";
  DateTime dt2{};
  decoding_test(t2, "TestData", mStructureFactory, dt2);
  DateTime expected2{2009, 10, 10, 17, 9, 1.12345678, 0};
  EXPECT_EQ(dt2, expected2);

  // Without timezone should be treated as UTC by our parser
  string_view t3 = "<TestData>2009-10-10T17:11:12</TestData>";
  DateTime dt3{};
  decoding_test(t3, "TestData", mStructureFactory, dt3);
  EXPECT_EQ(dt3, expected1);

  // Some invalid formats
  DateTime tmp{};
  EXPECT_THROW(decoding_test("<TestData>0000-10-10T17:00:00Z</TestData>", "TestData", mStructureFactory, tmp),
    UaException);
  EXPECT_THROW(
    decoding_test(
      "<TestData>2009-10-10T17:00:00.1234567891234Z</TestData>", "TestData", mStructureFactory, tmp),
    UaException);
  EXPECT_THROW(decoding_test("<TestData>2009-13-10T17:00:00Z</TestData>", "TestData", mStructureFactory, tmp),
    UaException);
}

TEST_F(XmlCodecTest, XmlElement)
{
  string_view good = "<TestData><Inner> &amp; My Test </Inner></TestData>";
  string_view badName = "<TestData><Inner>abc</Inner></TestData>";

  XmlElement value{};
  EXPECT_THROW(decoding_test(good, "WrongName", mStructureFactory, value), UaException);
  decoding_test(good, "TestData", mStructureFactory, value);
  // The XmlElement stores the inner markup/text. Ensure key substrings are present.
  auto s = std::string(value.value());
  EXPECT_NE(s.find("<Inner>"), std::string::npos);
  EXPECT_NE(s.find("My Test"), std::string::npos);

  EXPECT_THROW(decoding_test(badName, "OtherName", mStructureFactory, value), UaException);
}

// An XmlElement decoded from a document keeps the element as the source spelled it: its escapes are
// not escaped again and an apostrophe-delimited attribute holding a quotation mark keeps its
// apostrophes, so the value is well-formed XML that reads back to the same text.
// @verifies AC-COMP-CORE-XML-CODEC-03-PRESERVED-XML-KEEPS-ITS-SOURCE-SPELLING
TEST_F(XmlCodecTest, ADecodedXmlElementKeepsItsSourceSpelling)
{
  constexpr string_view source{
    "<TestData><Inner k='x\"y'>a &amp; b &#x41;</Inner><![CDATA[<c>]]></TestData>"};
  XmlElement value{};
  decoding_test(source, "TestData", mStructureFactory, value);
  EXPECT_EQ(std::string{value.value()}, std::string{source});
}

// An XML array holds at most the maximum array length the decoder is given, as a UA Binary array
// does; one element more is Bad_EncodingLimitsExceeded, and an array at the cap decodes.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST_F(XmlCodecTest, AnXmlArrayLongerThanTheMaximumArrayLengthIsRefused)
{
  const std::string xml = R"(<TestData xmlns:t="http://opcfoundation.org/UA/2008/02/Types.xsd">)"
                          "<t:ListOfInt32><t:Int32>1</t:Int32><t:Int32>2</t:Int32><t:Int32>3</t:Int32>"
                          "</t:ListOfInt32></TestData>";
  const auto decodeWithCap = [&](size_t cap)
  {
    std::vector<char> writable(xml.begin(), xml.end());
    writable.push_back('\0');
    auto context = xml::parse(writable.data());
    auto first = context.xml_element().get_first_child();
    EncodingLimits limits;
    limits.maxArrayLength = cap;
    XmlDecoder decoder{mStructureFactory, *first, limits};
    StackDepth limit{ApplicationConfig::load_default().execution_limits().decodeWorkLimit};
    Variant value;
    decoder.decode(limit, "TestData", false, value);
    return value;
  };

  try
  {
    (void)decodeWithCap(2);
    ADD_FAILURE() << "an array of three was accepted under a cap of two";
  }
  catch (const UaException& error)
  {
    EXPECT_EQ(error.status(), Status::BadEncodingLimitsExceeded);
  }

  const auto atTheCap = decodeWithCap(3);
  ASSERT_TRUE(atTheCap.is_array());
  EXPECT_EQ(atTheCap.as<Array<int32_t>>().payload().size(), 3u);
}

TEST_F(XmlCodecTest, ByteString)
{
  // "foobar" -> base64 "Zm9vYmFy"
  string_view enc = "<TestData>Zm9vYmFy</TestData>";
  ByteString bytes;
  decoding_test(enc, "TestData", mStructureFactory, bytes);
  ByteString expected{uint8_t('f'), uint8_t('o'), uint8_t('o'), uint8_t('b'), uint8_t('a'), uint8_t('r')};
  EXPECT_EQ(bytes, expected);
  EXPECT_THROW(decoding_test(enc, "WrongName", mStructureFactory, bytes), UaException);
}

TEST_F(XmlCodecTest, ExpandedNodeId)
{
  string_view xml =
    "<TestData>"
    "  <NodeId>"
    "    <Identifier>ns=2;i=345</Identifier>"
    "  </NodeId>"
    "  <ServerIndex>1</ServerIndex>"
    "</TestData>";
  ExpandedNodeId x{};
  decoding_test(xml, "TestData", mStructureFactory, x);
  EXPECT_EQ(x.server_index(), 1u);
  EXPECT_EQ(x.node_id(), NodeId(2, 345));
}

TEST_F(XmlCodecTest, StatusCode)
{
  // 0x8000_0010 = BadEncodingLimitsExceeded
  string_view xml = "<TestData>2148007936</TestData>";
  StatusCode sc{};
  decoding_test(xml, "TestData", mStructureFactory, sc);
  StatusCode expected{Status::BadEncodingLimitsExceeded};
  EXPECT_TRUE(sc.equivalent(expected));
}

TEST_F(XmlCodecTest, QualifiedName)
{
  string_view s1 = "<TestData><NamespaceIndex>1</NamespaceIndex><Name>MyName</Name></TestData>";
  string_view s2 = "<TestData><Name>MyName</Name></TestData>";
  string_view s3 = "<TestData><NamespaceIndex>1</NamespaceIndex></TestData>";
  string_view s4 = "<TestData></TestData>";

  {
    QualifiedName q{};
    decoding_test(s1, "TestData", mStructureFactory, q);
    EXPECT_EQ(q.namespace_index(), 1);
    EXPECT_EQ(q.name(), "MyName");
  }

  {
    QualifiedName q{};
    decoding_test(s2, "TestData", mStructureFactory, q);
    EXPECT_EQ(q.namespace_index(), 0);
    EXPECT_EQ(q.name(), "MyName");
  }

  {
    QualifiedName q{};
    decoding_test(s3, "TestData", mStructureFactory, q);
    EXPECT_EQ(q.namespace_index(), 1);
    EXPECT_TRUE(q.name().empty());
  }

  {
    QualifiedName q{};
    decoding_test(s4, "TestData", mStructureFactory, q);
    EXPECT_EQ(q.namespace_index(), 0);
    EXPECT_TRUE(q.name().empty());
    EXPECT_TRUE(q.is_null());
  }
}

TEST_F(XmlCodecTest, DataValue)
{
  string_view xml =
    "<TestData>"
    "  <Value><Int32>42</Int32></Value>"
    "  <StatusCode>2147483652</StatusCode>" /* BadUnexpectedError */
    "  <SourceTimestamp>2009-10-10T17:11:12Z</SourceTimestamp>"
    "  <SourcePicoseconds>10</SourcePicoseconds>"
    "  <ServerTimestamp>2009-10-10T18:00:00Z</ServerTimestamp>"
    "  <ServerPicoseconds>20</ServerPicoseconds>"
    "</TestData>";

  DataValue dv{};
  decoding_test(xml, "TestData", mStructureFactory, dv);

  ASSERT_TRUE(dv.value().is_int32());
  EXPECT_EQ(dv.value().as<int32_t>(), 42);
  ASSERT_TRUE(dv.status().has_value());
  EXPECT_TRUE(dv.status()->is_bad());
  ASSERT_TRUE(dv.source_timestamp().has_value());
  EXPECT_EQ(*dv.source_timestamp(), DateTime(2009, 10, 10, 17, 11, 12, 0));
  ASSERT_TRUE(dv.server_timestamp().has_value());
  EXPECT_EQ(*dv.server_timestamp(), DateTime(2009, 10, 10, 18, 0, 0, 0));
  ASSERT_TRUE(dv.source_pico_seconds().has_value());
  EXPECT_EQ(*dv.source_pico_seconds(), 10);
  ASSERT_TRUE(dv.server_pico_seconds().has_value());
  EXPECT_EQ(*dv.server_pico_seconds(), 20);
}

TEST_F(XmlCodecTest, DiagnosticInfo)
{
  string_view xml =
    "<TestData>"
    "  <SymbolicId>1</SymbolicId>"
    "  <NamespaceUri>2</NamespaceUri>"
    "  <Locale>3</Locale>"
    "  <LocalizedText>4</LocalizedText>"
    "  <AdditionalInfo>info</AdditionalInfo>"
    "  <InnerStatusCode>2147483656</InnerStatusCode>" /* BadOutOfMemory */
    "  <InnerDiagnosticInfo>"
    "    <SymbolicId>5</SymbolicId>"
    "  </InnerDiagnosticInfo>"
    "</TestData>";

  DiagnosticInfo di{};
  decoding_test(xml, "TestData", mStructureFactory, di);
  ASSERT_TRUE(di.symbolic_id().has_value());
  EXPECT_EQ(*di.symbolic_id(), 1);
  ASSERT_TRUE(di.namespace_uri().has_value());
  EXPECT_EQ(*di.namespace_uri(), 2);
  ASSERT_TRUE(di.locale().has_value());
  EXPECT_EQ(*di.locale(), 3);
  ASSERT_TRUE(di.localized_text().has_value());
  EXPECT_EQ(*di.localized_text(), 4);
  ASSERT_TRUE(di.additional_info().has_value());
  EXPECT_EQ(*di.additional_info(), std::string("info"));
  ASSERT_TRUE(di.inner_status_code().has_value());
  EXPECT_TRUE(di.inner_status_code()->is_bad());
  ASSERT_TRUE(di.inner_diagnostic_info() != nullptr);
  ASSERT_TRUE(di.inner_diagnostic_info()->symbolic_id().has_value());
  EXPECT_EQ(*di.inner_diagnostic_info()->symbolic_id(), 5);
}

TEST_F(XmlCodecTest, Variant)
{
  // Scalar
  string_view s1 = "<TestData><Int32>-7</Int32></TestData>";
  Variant v{};
  decoding_test(s1, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_int32());
  EXPECT_EQ(v.as<int32_t>(), -7);

  // Array
  string_view s2 = "<TestData><ListOfDouble><Double>1</Double><Double>2.5</Double></ListOfDouble></TestData>";
  decoding_test(s2, "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_array());
  const auto& arr = v.as<Array<double>>();
  std::vector<double> expected{1.0, 2.5};
  EXPECT_EQ(arr.payload(), expected);

  // Cover all supported scalar types one by one
  // Boolean
  decoding_test("<TestData><Boolean>true</Boolean></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_boolean());
  EXPECT_TRUE(v.as<bool>());

  // SByte
  decoding_test("<TestData><SByte>-8</SByte></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_int8());
  EXPECT_EQ(v.as<int8_t>(), static_cast<int8_t>(-8));

  // Byte
  decoding_test("<TestData><Byte>200</Byte></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_uint8());
  EXPECT_EQ(v.as<uint8_t>(), static_cast<uint8_t>(200));

  // Int16
  decoding_test("<TestData><Int16>-1234</Int16></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_int16());
  EXPECT_EQ(v.as<int16_t>(), static_cast<int16_t>(-1234));

  // UInt16
  decoding_test("<TestData><UInt16>65535</UInt16></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_uint16());
  EXPECT_EQ(v.as<uint16_t>(), static_cast<uint16_t>(65535));

  // UInt32
  decoding_test("<TestData><UInt32>123456</UInt32></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_uint32());
  EXPECT_EQ(v.as<uint32_t>(), static_cast<uint32_t>(123456));

  // Int64
  decoding_test("<TestData><Int64>-123456789</Int64></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_int64());
  EXPECT_EQ(v.as<int64_t>(), static_cast<int64_t>(-123456789));

  // UInt64
  decoding_test("<TestData><UInt64>123456789</UInt64></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_uint64());
  EXPECT_EQ(v.as<uint64_t>(), static_cast<uint64_t>(123456789));

  // Float
  decoding_test("<TestData><Float>3.5</Float></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_float());
  EXPECT_NEAR(v.as<float>(), 3.5f, 1e-6f);

  // Double
  decoding_test("<TestData><Double>-2.25</Double></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_double());
  EXPECT_NEAR(v.as<double>(), -2.25, 1e-12);

  // String
  decoding_test("<TestData><String>hello</String></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_string());
  EXPECT_EQ(v.as<String>(), String{"hello"});

  // DateTime
  decoding_test(
    "<TestData><DateTime>2009-10-10T17:11:12Z</DateTime></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_date_time());
  EXPECT_EQ(v.as<DateTime>(), DateTime(2009, 10, 10, 17, 11, 12, 0));

  // Guid
  decoding_test("<TestData><Guid>8a5796c4-fe0d-8f4b-870a-745238c6aeae</Guid></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_guid());
  EXPECT_TRUE(v.as<Guid>() == Guid::parse("8a5796c4-fe0d-8f4b-870a-745238c6aeae"));

  // ByteString (base64 for 'foo')
  decoding_test("<TestData><ByteString>Zm9v</ByteString></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_byte_string());
  {
    std::vector<byte> foo{byte{'f'}, byte{'o'}, byte{'o'}};
    EXPECT_EQ(v.as<ByteString>(), ByteString{foo});
  }

  // XmlElement
  decoding_test("<TestData><XmlElement><X>y</X></XmlElement></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_xml_element());
  {
    auto s = std::string(v.as<XmlElement>().value());
    EXPECT_NE(s.find("<X>"), std::string::npos);
  }

  // NodeId
  decoding_test("<TestData><NodeId><Identifier>ns=2;i=345</Identifier></NodeId></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_node_id());
  EXPECT_EQ(v.as<NodeId>(), NodeId(2, 345));

  // ExpandedNodeId
  decoding_test(
    "<TestData>"
    "  <ExpandedNodeId>"
    "    <NodeId>"
    "      <Identifier>ns=2;i=345</Identifier>"
    "    </NodeId>"
    "    <ServerIndex>1</ServerIndex>"
    "  </ExpandedNodeId>"
    "</TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_expanded_node_id());
  {
    const auto& en = v.as<ExpandedNodeId>();
    EXPECT_EQ(en.server_index(), 1u);
    EXPECT_EQ(en.node_id(), NodeId(2, 345));
  }

  // StatusCode (BadEncodingLimitsExceeded)
  decoding_test("<TestData><StatusCode>2148007936</StatusCode></TestData>", "TestData", mStructureFactory, v);
  ASSERT_TRUE(v.is_status_code());
  EXPECT_TRUE(v.as<StatusCode>().is_bad());

  // QualifiedName
  decoding_test(
    "<TestData><QualifiedName><NamespaceIndex>1</NamespaceIndex><Name>Q</Name></QualifiedName></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_qualified_name());
  EXPECT_EQ(v.as<QualifiedName>().namespace_index(), 1);
  EXPECT_EQ(v.as<QualifiedName>().name(), "Q");

  // LocalizedText
  decoding_test("<TestData><LocalizedText><Locale>en</Locale><Text>T</Text></LocalizedText></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_localized_text());
  EXPECT_EQ(v.as<LocalizedText>().locale(), "en");
  EXPECT_EQ(v.as<LocalizedText>().text(), "T");

  // DataValue
  decoding_test(
    "<TestData><DataValue><Value><Int32>42</Int32></Value><SourceTimestamp>2009-10-10T17:11:12Z</"
    "SourceTimestamp></DataValue></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_data_value());
  {
    const auto& dv = v.as<DataValue>();
    ASSERT_TRUE(dv.value().is_int32());
    EXPECT_EQ(dv.value().as<int32_t>(), 42);
    ASSERT_TRUE(dv.source_timestamp().has_value());
    EXPECT_EQ(*dv.source_timestamp(), DateTime(2009, 10, 10, 17, 11, 12, 0));
  }

  // Structure (Argument) within ExtensionObject as Variant content
  decoding_test(
    "<TestData><ExtensionObject>"
    "  <TypeId><Identifier>i=297</Identifier></TypeId>"
    "  <Body>"
    "    <Argument>"
    "      <Name>X</Name>"
    "      <DataType><Identifier>i=12</Identifier></DataType>"
    "      <ValueRank>0</ValueRank>"
    "    </Argument>"
    "  </Body>"
    "</ExtensionObject></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_structure());
  {
    const auto& st = v.as<Structure>();
  }

  // Array inside Variant: ListOfUInt32
  decoding_test(
    "<TestData><ListOfUInt32><UInt32>3</UInt32><UInt32>4</UInt32><UInt32>5</UInt32></ListOfUInt32></"
    "TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_array());
  {
    const auto& a = v.as<Array<uint32_t>>();
    std::vector<uint32_t> exp{3u, 4u, 5u};
    EXPECT_EQ(a.payload(), exp);
  }

  // Array of complex type inside Variant: ListOfLocalizedText
  decoding_test(
    "<TestData><ListOfLocalizedText><LocalizedText><Locale>en</Locale><Text>A</Text></"
    "LocalizedText><LocalizedText><Text>B</Text></LocalizedText></ListOfLocalizedText></TestData>",
    "TestData",
    mStructureFactory,
    v);
  ASSERT_TRUE(v.is_array());
  {
    const auto& a = v.as<Array<LocalizedText>>();
    ASSERT_EQ(a.size(), 2u);
    EXPECT_EQ(a[0].locale(), "en");
    EXPECT_EQ(a[0].text(), "A");
    EXPECT_TRUE(a[1].locale().empty());
    EXPECT_EQ(a[1].text(), "B");
  }
}

TEST_F(XmlCodecTest, ArrayOfVariant)
{
  // Mix of scalar and array values encoded as Variants inside an Array<Variant>
  string_view xml =
    "<TestData>"
    "  <Variant><Int32>-7</Int32></Variant>"
    "  <Variant><String>hello</String></Variant>"
    "  <Variant><ListOfUInt32><UInt32>3</UInt32><UInt32>4</UInt32><UInt32>5</UInt32></ListOfUInt32></Variant>"
    "</TestData>";

  Array<Variant> arr{};

  // Wrong element name should throw
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);

  // Decode the array
  decoding_test(xml, "TestData", mStructureFactory, arr);

  ASSERT_EQ(arr.size(), 3u);

  // First element: Int32 -7
  ASSERT_TRUE(arr[0].is_int32());
  EXPECT_EQ(arr[0].as<int32_t>(), -7);

  // Second element: String "hello"
  ASSERT_TRUE(arr[1].is_string());
  EXPECT_EQ(arr[1].as<String>(), String{"hello"});

  // Third element: an array of UInt32 {3,4,5}
  ASSERT_TRUE(arr[2].is_array());
  const auto& inner = arr[2].as<Array<uint32_t>>();
  std::vector<uint32_t> expected{3u, 4u, 5u};
  EXPECT_EQ(inner.payload(), expected);
}

TEST_F(XmlCodecTest, UniquePtrStructure)
{
  // Decode an Argument into unique_ptr<Argument>
  string_view xml =
    "<TestData>"
    "  <TypeId><Identifier>i=297</Identifier></TypeId>"
    "  <Body>"
    "      <Argument>"
    "        <Name>X</Name>"
    "        <DataType><Identifier>i=12</Identifier></DataType>"
    "        <ValueRank>0</ValueRank>"
    "      </Argument>"
    "  </Body>"
    "</TestData>";

  std::unique_ptr<Argument> argPtr;
  decoding_test(xml, "", mStructureFactory, argPtr);
  ASSERT_TRUE(argPtr != nullptr);
  EXPECT_EQ(argPtr->name(), "X");
  EXPECT_EQ(argPtr->data_type(), NodeId(12));
}

// ---- Arrays for all supported element types ----

TEST_F(XmlCodecTest, ArrayOfBoolean)
{
  string_view xml =
    "  <TestData><Boolean>true</Boolean><Boolean>false</Boolean><Boolean>true</Boolean></TestData>";
  Array<bool> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<bool> expected{true, false, true};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfSByte)
{
  string_view xml = "<TestData><SByte>-1</SByte><SByte>0</SByte><SByte>127</SByte></TestData>";
  Array<int8_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<int8_t> expected{-1, 0, 127};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfByte)
{
  string_view xml = "<TestData><Byte>1</Byte><Byte>2</Byte><Byte>255</Byte></TestData>";
  Array<uint8_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<uint8_t> expected{1u, 2u, 255u};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfInt16)
{
  string_view xml = "<TestData><Int16>-3</Int16><Int16>4</Int16></TestData>";
  Array<int16_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<int16_t> expected{-3, 4};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfUInt16)
{
  string_view xml = "<TestData><UInt16>3</UInt16><UInt16>4</UInt16></TestData>";
  Array<uint16_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<uint16_t> expected{3u, 4u};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfInt32)
{
  string_view xml = "<TestData><Int32>-7</Int32><Int32>8</Int32></TestData>";
  Array<int32_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<int32_t> expected{-7, 8};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfUInt32)
{
  string_view xml = "<TestData><UInt32>7</UInt32><UInt32>8</UInt32></TestData>";
  Array<uint32_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<uint32_t> expected{7u, 8u};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfInt64)
{
  string_view xml = "<TestData><Int64>-9</Int64><Int64>10</Int64></TestData>";
  Array<int64_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<int64_t> expected{-9, 10};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfUInt64)
{
  string_view xml = "<TestData><UInt64>9</UInt64><UInt64>10</UInt64></TestData>";
  Array<uint64_t> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<uint64_t> expected{9u, 10u};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfFloat)
{
  string_view xml = "<TestData><Float>1.5</Float><Float>-2.25</Float></TestData>";
  Array<float> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_NEAR(arr[0], 1.5f, 1e-6f);
  EXPECT_NEAR(arr[1], -2.25f, 1e-6f);
}

TEST_F(XmlCodecTest, ArrayOfDouble)
{
  string_view xml = "<TestData><Double>1</Double><Double>2.5</Double></TestData>";
  Array<double> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  std::vector<double> expected{1.0, 2.5};
  EXPECT_EQ(arr.payload(), expected);
}

TEST_F(XmlCodecTest, ArrayOfString)
{
  string_view xml = "<TestData><String>a</String><String>b</String><String></String></TestData>";
  Array<String> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 3u);
  EXPECT_EQ(arr[0], String{"a"});
  EXPECT_EQ(arr[1], String{"b"});
  EXPECT_EQ(arr[2], String{""});
}

TEST_F(XmlCodecTest, ArrayOfByteString)
{
  string_view xml = "<TestData><ByteString>Zm8=</ByteString><ByteString>YmFy</ByteString></TestData>";
  Array<ByteString> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  std::vector<byte> fo{byte{'f'}, byte{'o'}};
  std::vector<byte> bar{byte{'b'}, byte{'a'}, byte{'r'}};
  EXPECT_EQ(arr[0], ByteString{fo});
  EXPECT_EQ(arr[1], ByteString{bar});
}

TEST_F(XmlCodecTest, ArrayOfGuid)
{
  string_view xml =
    "<TestData>"
    "  <Guid>8a5796c4-fe0d-8f4b-870a-745238c6aeae</Guid>"
    "  <Guid>00000000-0000-0000-0000-000000000000</Guid>"
    "</TestData>";
  Array<Guid> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_TRUE(arr[0] == Guid::parse("8a5796c4-fe0d-8f4b-870a-745238c6aeae"));
  EXPECT_TRUE(arr[1] == Guid::parse("00000000-0000-0000-0000-000000000000"));
}

TEST_F(XmlCodecTest, ArrayOfNodeId)
{
  string_view xml =
    "<TestData>"
    "  <NodeId><Identifier>ns=1;i=100</Identifier></NodeId>"
    "  <NodeId><Identifier>ns=2;s=Hello</Identifier></NodeId>"
    "</TestData>";
  Array<NodeId> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0], NodeId(1, 100));
  EXPECT_EQ(arr[1], NodeId(2, std::string("Hello")));
}

TEST_F(XmlCodecTest, ArrayOfExpandedNodeId)
{
  string_view xml =
    "<TestData>"
    "  <ExpandedNodeId>"
    "    <NodeId>"
    "      <Identifier>ns=2;i=345</Identifier>"
    "    </NodeId>"
    "    <ServerIndex>1</ServerIndex>"
    "  </ExpandedNodeId>"
    "  <ExpandedNodeId>"
    "    <NodeId>"
    "      <Identifier>ns=3;s=Name</Identifier>"
    "    </NodeId>"
    "  </ExpandedNodeId>"
    "</TestData>";
  Array<ExpandedNodeId> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0].server_index(), 1u);
  EXPECT_EQ(arr[0].node_id(), NodeId(2, 345));
  EXPECT_EQ(arr[1].server_index(), 0u);
  EXPECT_EQ(arr[1].node_id(), NodeId(3, std::string("Name")));
}

TEST_F(XmlCodecTest, ArrayOfDateTime)
{
  string_view xml =
    "<TestData>"
    "  <DateTime>2009-10-10T17:11:12Z</DateTime>"
    "  <DateTime>2009-10-10T18:00:00Z</DateTime>"
    "</TestData>";
  Array<DateTime> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0], DateTime(2009, 10, 10, 17, 11, 12, 0));
  EXPECT_EQ(arr[1], DateTime(2009, 10, 10, 18, 0, 0, 0));
}

TEST_F(XmlCodecTest, ArrayOfXmlElement)
{
  string_view xml =
    "<TestData>"
    "  <XmlElement><Inner>A</Inner></XmlElement>"
    "  <XmlElement><X><Y>B</Y></X></XmlElement>"
    "</TestData>";
  Array<XmlElement> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  auto s0 = std::string(arr[0].value());
  auto s1 = std::string(arr[1].value());
  EXPECT_NE(s0.find("<Inner>"), std::string::npos);
  EXPECT_NE(s1.find("<Y>"), std::string::npos);
}

TEST_F(XmlCodecTest, ArrayOfQualifiedName)
{
  string_view xml =
    "<TestData>"
    "  <QualifiedName><NamespaceIndex>1</NamespaceIndex><Name>A</Name></QualifiedName>"
    "  <QualifiedName><Name>B</Name></QualifiedName>"
    "</TestData>";
  Array<QualifiedName> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0].namespace_index(), 1);
  EXPECT_EQ(arr[0].name(), "A");
  EXPECT_EQ(arr[1].namespace_index(), 0);
  EXPECT_EQ(arr[1].name(), "B");
}

TEST_F(XmlCodecTest, ArrayOfLocalizedText)
{
  string_view xml =
    "<TestData>"
    "  <LocalizedText><Locale>en-IE</Locale><Text>My</Text></LocalizedText>"
    "  <LocalizedText><Text>Text</Text></LocalizedText>"
    "</TestData>";
  Array<LocalizedText> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_EQ(arr[0].locale(), "en-IE");
  EXPECT_EQ(arr[0].text(), "My");
  EXPECT_TRUE(arr[1].locale().empty());
  EXPECT_EQ(arr[1].text(), "Text");
}

TEST_F(XmlCodecTest, ArrayOfStatusCode)
{
  string_view xml =
    "<TestData>"
    "  <StatusCode>0</StatusCode>"
    "  <StatusCode>2148007936</StatusCode>" /* BadEncodingLimitsExceeded */
    "</TestData>";
  Array<StatusCode> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  EXPECT_TRUE(arr[0].is_good());
  EXPECT_TRUE(arr[1].is_bad());
}

TEST_F(XmlCodecTest, ArrayOfDiagnosticInfo)
{
  string_view xml =
    "<TestData>"
    "  <DiagnosticInfo><SymbolicId>1</SymbolicId></DiagnosticInfo>"
    "  <DiagnosticInfo><InnerDiagnosticInfo><SymbolicId>2</SymbolicId></InnerDiagnosticInfo></DiagnosticInfo>"
    "</TestData>";
  Array<DiagnosticInfo> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  ASSERT_TRUE(arr[0].symbolic_id().has_value());
  EXPECT_EQ(*arr[0].symbolic_id(), 1);
  ASSERT_TRUE(arr[1].inner_diagnostic_info() != nullptr);
  ASSERT_TRUE(arr[1].inner_diagnostic_info()->symbolic_id().has_value());
  EXPECT_EQ(*arr[1].inner_diagnostic_info()->symbolic_id(), 2);
}

TEST_F(XmlCodecTest, ArrayOfDataValue)
{
  string_view xml =
    "<TestData>"
    "  <DataValue>"
    "    <Value><Int32>42</Int32></Value>"
    "    <SourceTimestamp>2009-10-10T17:11:12Z</SourceTimestamp>"
    "  </DataValue>"
    "  <DataValue>"
    "    <Value><String>ok</String></Value>"
    "    <StatusCode>2147483652</StatusCode>"
    "  </DataValue>"
    "</TestData>";
  Array<DataValue> arr{};
  EXPECT_THROW(decoding_test(xml, "WrongName", mStructureFactory, arr), UaException);
  decoding_test(xml, "TestData", mStructureFactory, arr);
  ASSERT_EQ(arr.size(), 2u);
  ASSERT_TRUE(arr[0].value().is_int32());
  EXPECT_EQ(arr[0].value().as<int32_t>(), 42);
  ASSERT_TRUE(arr[0].source_timestamp().has_value());
  EXPECT_EQ(*arr[0].source_timestamp(), DateTime(2009, 10, 10, 17, 11, 12, 0));
  ASSERT_TRUE(arr[1].value().is_string());
  EXPECT_EQ(arr[1].value().as<String>(), String{"ok"});
  ASSERT_TRUE(arr[1].status().has_value());
  EXPECT_TRUE(arr[1].status()->is_bad());
}
