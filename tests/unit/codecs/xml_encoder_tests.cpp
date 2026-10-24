// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <limits>
#include <optional>
#include "ua_xml_codec.h"
#include "ua_application_configuration.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"
#include "ua_argument.h"
#include "ua_rational_number.h"
#include "ua_ref_structure.h"
#include "ua_structure.h"
#include "ua_unknown_structure.h"
#include "ua_node_id.h"
#include "ua_date_time.h"
#include "ua_xml_element.h"
#include "ua_expanded_node_id.h"
#include "ua_status_code.h"
#include "ua_qualified_name.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info.h"
#include "ua_variant.h"
#include "ua_decimal.h"

using namespace ua;

namespace
{
uint16_t get_namespace_index(string_view uri)
{
  if (uri == "http://opcfoundation.org/UA/")
    return 0;
  if (uri == "http://yourorganisation.org/test/")
    return 2;
  return 0;
}
}  // namespace

class XmlEncoderTest : public testing::Test
{
protected:
  void SetUp() override
  {
    auto createArgument = []()
    {
      return make_unique<Argument>();
    };
    mStructureFactory.register_type(NodeId{Argument::defaultXmlEncodingId}, createArgument);

    auto createRationalNumber = []()
    {
      return make_unique<RationalNumber>();
    };
    mStructureFactory.register_type(NodeId{RationalNumber::defaultXmlEncodingId}, createRationalNumber);
  }

  template<typename T>
  std::string encode(const T& value, string_view elementName = "Value")
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream(device);
    XmlEncoder encoder(CodecNamespaceContext{get_namespace_index, {}, {}, {}}, stream);
    auto cfg = ApplicationConfig::load_default();
    StackDepth limit{cfg.execution_limits().decodeWorkLimit};
    encoder.encode(limit, elementName, value);
    auto data = device.get_data();
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
  }

  template<typename T>
  void round_trip(const T& value, string_view elementName = "Value")
  {
    std::string xml = encode(value, elementName);

    // Prepare for decoding
    std::vector<char> writableInput(xml.begin(), xml.end());
    writableInput.push_back('\0');

    auto context = xml::parse(writableInput.data());
    auto rootElement = context.xml_element();

    auto firstElement = rootElement.get_first_child();
    ASSERT_TRUE(firstElement.has_value()) << "XML has no child element: " << xml;

    XmlDecoder decoder(mStructureFactory, *firstElement, EncodingLimits{});
    T decodedValue;
    auto cfg = ApplicationConfig::load_default();
    StackDepth limit{cfg.execution_limits().decodeWorkLimit};
    decoder.decode(limit, elementName, false, decodedValue);

    if constexpr (std::is_same_v<T, NodeId>)
    {
      EXPECT_EQ(value.namespace_index(), decodedValue.namespace_index());
      EXPECT_EQ(value.id_type(), decodedValue.id_type());
      if (value.is_numeric())
        EXPECT_EQ(value.identifier().get_numeric(), decodedValue.identifier().get_numeric());
      if (value.is_string())
        EXPECT_EQ(
          std::string(value.identifier().get_string()), std::string(decodedValue.identifier().get_string()));
      if (value.is_guid())
        EXPECT_EQ(
          value.identifier().get_guid().as_string(), decodedValue.identifier().get_guid().as_string());
      if (value.is_opaque())
        EXPECT_EQ(value.identifier().get_opaque(), decodedValue.identifier().get_opaque());
    }
    else
    {
      EXPECT_TRUE(value == decodedValue) << "Round trip failed for XML: " << xml;
    }
  }

  StructureFactory mStructureFactory;
};

TEST_F(XmlEncoderTest, ScalarTypes)
{
  EXPECT_EQ(encode(true), "<Value>true</Value>");
  EXPECT_EQ(encode(false), "<Value>false</Value>");
  EXPECT_EQ(encode(static_cast<uint8_t>(255)), "<Value>255</Value>");
  EXPECT_EQ(encode(static_cast<int8_t>(-128)), "<Value>-128</Value>");
  EXPECT_EQ(encode(static_cast<uint16_t>(65535)), "<Value>65535</Value>");
  EXPECT_EQ(encode(static_cast<int16_t>(-32768)), "<Value>-32768</Value>");
  EXPECT_EQ(encode(static_cast<uint32_t>(1234567)), "<Value>1234567</Value>");
  EXPECT_EQ(encode(static_cast<int32_t>(-1234567)), "<Value>-1234567</Value>");
  EXPECT_EQ(encode(static_cast<uint64_t>(123456789012345ULL)), "<Value>123456789012345</Value>");
  EXPECT_EQ(encode(static_cast<int64_t>(-123456789012345LL)), "<Value>-123456789012345</Value>");

  // Float/Double formatting might vary slightly, but simple ones should be stable
  EXPECT_EQ(encode(1.25f), "<Value>1.25</Value>");
  EXPECT_EQ(encode(2.5), "<Value>2.5</Value>");
}

TEST_F(XmlEncoderTest, ScalarRoundTrip)
{
  round_trip(true);
  round_trip(false);
  round_trip(static_cast<uint8_t>(42));
  round_trip(static_cast<int8_t>(-42));
  round_trip(static_cast<uint16_t>(1000));
  round_trip(static_cast<int16_t>(-1000));
  round_trip(static_cast<uint32_t>(1000000));
  round_trip(static_cast<int32_t>(-1000000));
  round_trip(static_cast<uint64_t>(1000000000000ULL));
  round_trip(static_cast<int64_t>(-1000000000000LL));
  round_trip(123.456f);
  round_trip(123.456789);
}

TEST_F(XmlEncoderTest, StringEscaping)
{
  EXPECT_EQ(encode(string_view("Normal")), "<Value>Normal</Value>");
  EXPECT_EQ(encode(string_view("A & B < C > D \" E ' F")),
    "<Value>A &amp; B &lt; C &gt; D &quot; E &apos; F</Value>");

  round_trip(String("A & B < C > D \" E ' F"));
}

TEST_F(XmlEncoderTest, DateTime)
{
  DateTime dt(2024, 5, 1, 12, 30, 0, 0);
  EXPECT_EQ(encode(dt), "<Value>2024-05-01T12:30:00Z</Value>");
  round_trip(dt);

  DateTime nullDt;
  EXPECT_EQ(encode(nullDt), "<Value>1601-01-01T00:00:00Z</Value>");
  // Round trip for null DateTime might be tricky depending on XmlDecoder implementation
}

TEST_F(XmlEncoderTest, Guid)
{
  Guid guid = Guid::parse("12345678-1234-1234-1234-1234567890ab");
  EXPECT_EQ(encode(guid), "<Value>12345678-1234-1234-1234-1234567890ab</Value>");
  round_trip(guid);
}

TEST_F(XmlEncoderTest, ByteString)
{
  ByteString bs{uint8_t{1}, uint8_t{2}, uint8_t{3}, uint8_t{4}};
  // Base64 of {1, 2, 3, 4} is "AQIDBA=="
  EXPECT_EQ(encode(bs), "<Value>AQIDBA==</Value>");
  round_trip(bs);
}

TEST_F(XmlEncoderTest, NodeId)
{
  NodeId n1(0, 100);
  EXPECT_EQ(encode(n1), "<Value><Identifier>i=100</Identifier></Value>");
  round_trip(n1);

  NodeId n2(1, String("StringID"));
  EXPECT_EQ(encode(n2), "<Value><Identifier>ns=1;s=StringID</Identifier></Value>");
  round_trip(n2);

  Guid g = Guid::parse("12345678-1234-1234-1234-1234567890ab");
  NodeId n3(1, g);
  EXPECT_EQ(
    encode(n3), "<Value><Identifier>ns=1;g=12345678-1234-1234-1234-1234567890ab</Identifier></Value>");
  round_trip(n3);

  std::vector<byte> opaque = {byte{'O'}, byte{'P'}};  // "T1A="
  NodeId n4(1, ByteString(opaque));
  EXPECT_EQ(encode(n4), "<Value><Identifier>ns=1;b=T1A=</Identifier></Value>");
  round_trip(n4);
}

TEST_F(XmlEncoderTest, QualifiedName)
{
  QualifiedName qn(1, "Name");
  EXPECT_EQ(encode(qn), "<Value><NamespaceIndex>1</NamespaceIndex><Name>Name</Name></Value>");
  round_trip(qn);
}

TEST_F(XmlEncoderTest, LocalizedText)
{
  LocalizedText lt("en-US", "Hello");
  EXPECT_EQ(encode(lt), "<Value><Locale>en-US</Locale><Text>Hello</Text></Value>");
  round_trip(lt);
}

TEST_F(XmlEncoderTest, DataValue)
{
  DataValue dv;
  dv.value() = 123;
  dv.status() = StatusCode(Status::Good);
  DateTime st(2024, 1, 1, 0, 0, 0, 0);
  dv.source_timestamp() = st;

  std::string xml = encode(dv);
  EXPECT_TRUE(xml.find("<Value><Int32>123</Int32></Value>") != std::string::npos);
  EXPECT_TRUE(xml.find("<StatusCode>0</StatusCode>") != std::string::npos);
  EXPECT_TRUE(xml.find("<SourceTimestamp>2024-01-01T00:00:00Z</SourceTimestamp>") != std::string::npos);

  round_trip(dv);
}

TEST_F(XmlEncoderTest, VariantScalar)
{
  Variant v(static_cast<int32_t>(42));
  EXPECT_EQ(encode(v), "<Value><Int32>42</Int32></Value>");
  round_trip(v);

  Variant v2(String("test"));
  EXPECT_EQ(encode(v2), "<Value><String>test</String></Value>");
  round_trip(v2);
}

TEST_F(XmlEncoderTest, VariantArray)
{
  Array<int32_t> arr;
  arr.payload().push_back(1);
  arr.payload().push_back(2);
  Variant v(arr);
  EXPECT_EQ(encode(v), "<Value><ListOfInt32><Int32>1</Int32><Int32>2</Int32></ListOfInt32></Value>");
  round_trip(v);
}

TEST_F(XmlEncoderTest, Arrays)
{
  Array<int32_t> arr;
  arr.payload().push_back(10);
  arr.payload().push_back(20);

  EXPECT_EQ(encode(arr, "List"), "<List><Int32>10</Int32><Int32>20</Int32></List>");

  // Round trip for Array<T> requires careful use of XmlDecoder which expects ListOfT if it was a Variant
  // or just repeated elements if it was a field.
  // XmlDecoder::decode(..., elementName, ..., Array<T>& value) currently NOT IMPLEMENTED in ua_xml_codec.cpp
  // Wait, let me check ua_xml_codec.h/cpp for Array decoding.
}

TEST_F(XmlEncoderTest, Decimal)
{
  Decimal d;
  d.scale() = 2;
  d.value() = ByteString{0x01, 0x02};  // Base64: "AQI="
  EXPECT_EQ(encode(d), "<Value><Scale>2</Scale><Value>AQI=</Value></Value>");
  round_trip(d);
}

TEST_F(XmlEncoderTest, MatrixVariant)
{
  Array<int32_t> arr;
  arr.payload() = {1, 2, 3, 4};
  arr.add_and_validate_dimensions({2, 2});
  Variant v(arr);

  // Matrix encoding
  std::string xml = encode(v);
  EXPECT_TRUE(xml.find("<Matrix>") != std::string::npos);
  EXPECT_TRUE(xml.find("<Dimensions><Int32>2</Int32><Int32>2</Int32></Dimensions>") != std::string::npos);
  EXPECT_TRUE(
    xml.find("<ListOfInt32><Int32>1</Int32><Int32>2</Int32><Int32>3</Int32><Int32>4</Int32></ListOfInt32>") !=
    std::string::npos);

  round_trip(v);
}

TEST_F(XmlEncoderTest, VariantWithDiagnosticInfoRejected)
{
  // Variant cannot be constructed with DiagnosticInfo, but we can test the decoder
  // by providing an XML that claims to contain one.
  string_view xml = "<Value><DiagnosticInfo><SymbolicId>1</SymbolicId></DiagnosticInfo></Value>";

  std::vector<char> writableInput(xml.begin(), xml.end());
  writableInput.push_back('\0');

  auto context = xml::parse(writableInput.data());
  auto rootElement = context.xml_element();
  auto firstElement = rootElement.get_first_child();

  XmlDecoder decoder(mStructureFactory, *firstElement, EncodingLimits{});
  Variant v;
  auto cfg = ApplicationConfig::load_default();
  StackDepth limit{cfg.execution_limits().decodeWorkLimit};
  EXPECT_THROW(decoder.decode(limit, "Value", false, v), UaException);
}

namespace
{
// Builds a populated RationalNumber for ExtensionObject round-trip tests.
RationalNumber make_rational_number(int32_t numerator, uint32_t denominator)
{
  RationalNumber value;
  value.numerator() = numerator;
  value.denominator() = denominator;
  return value;
}

// Builds a populated Argument (an NS0 built-in struct) for ExtensionObject round-trip tests.
Argument make_argument(string_view name)
{
  Argument value;
  value.name() = String{name};
  value.data_type() = NodeId{0, 12};  // String DataType
  value.value_rank() = -1;
  return value;
}

// Re-parses encoded XML and decodes it back through the production codec, returning the value.
template<typename T>
T decode_xml(StructureFactory& factory, const std::string& xml, string_view elementName)
{
  std::vector<char> writableInput(xml.begin(), xml.end());
  writableInput.push_back('\0');

  auto context = xml::parse(writableInput.data());
  auto rootElement = context.xml_element();
  auto firstElement = rootElement.get_first_child();
  EXPECT_TRUE(firstElement.has_value()) << "XML has no child element: " << xml;

  XmlDecoder decoder(factory, *firstElement, EncodingLimits{});
  T decoded{};
  auto cfg = ApplicationConfig::load_default();
  StackDepth limit{cfg.execution_limits().decodeWorkLimit};
  decoder.decode(limit, elementName, false, decoded);
  return decoded;
}
}  // namespace

// A scalar Variant holding an ExtensionObject must emit <TypeId> and a <Body> that wraps the
// fields in a <TypeName xmlns="..."> element, so the value round-trips. Before the fix the scalar
// path routed through the bare const Structure& overload and emitted neither, losing the type.
TEST_F(XmlEncoderTest, ScalarExtensionObjectBuiltInRoundTrip)
{
  Variant value{RefStructure<Structure>{make_unique<RationalNumber>(make_rational_number(1, 2))}};

  std::string xml = encode(value);

  // Structural expectations: TypeId present, Body wraps fields in the type-named element with the
  // owning namespace URI as the default xmlns.
  EXPECT_NE(xml.find("<TypeId>"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<Body>"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<RationalNumber xmlns=\"http://opcfoundation.org/UA/\">"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<Numerator>1</Numerator>"), std::string::npos) << xml;

  Variant decoded = decode_xml<Variant>(mStructureFactory, xml, "Value");
  ASSERT_TRUE(decoded.get_built_in_type() == BuiltInTypeId::ExtensionObject) << xml;
  const auto& ref = decoded.as<RefStructure<Structure>>();
  ASSERT_TRUE(static_cast<bool>(ref)) << xml;
  const auto* rational = dynamic_cast<const RationalNumber*>(ref.get());
  ASSERT_NE(rational, nullptr) << xml;
  EXPECT_EQ(rational->numerator(), 1);
  EXPECT_EQ(rational->denominator(), 2u);
}

// A scalar Variant holding an application/registered struct (here Argument) must likewise round-trip.
TEST_F(XmlEncoderTest, ScalarExtensionObjectArgumentRoundTrip)
{
  Variant value{RefStructure<Structure>{make_unique<Argument>(make_argument("arg0"))}};

  std::string xml = encode(value);

  EXPECT_NE(xml.find("<TypeId>"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<Argument xmlns=\"http://opcfoundation.org/UA/\">"), std::string::npos) << xml;

  Variant decoded = decode_xml<Variant>(mStructureFactory, xml, "Value");
  ASSERT_TRUE(decoded.get_built_in_type() == BuiltInTypeId::ExtensionObject) << xml;
  const auto& ref = decoded.as<RefStructure<Structure>>();
  ASSERT_TRUE(static_cast<bool>(ref)) << xml;
  const auto* argument = dynamic_cast<const Argument*>(ref.get());
  ASSERT_NE(argument, nullptr) << xml;
  EXPECT_EQ(std::string(argument->name()), "arg0");
  EXPECT_EQ(argument->value_rank(), -1);
}

// An array Variant of ExtensionObjects must wrap each element body in the type-named element and
// round-trip. Before the fix the array path wrote <TypeId>+<Body> but dumped fields bare.
TEST_F(XmlEncoderTest, ArrayExtensionObjectRoundTrip)
{
  Array<RefStructure<Structure>> arr;
  arr.payload().emplace_back(make_unique<RationalNumber>(make_rational_number(1, 2)));
  arr.payload().emplace_back(make_unique<RationalNumber>(make_rational_number(3, 4)));
  Variant value{arr};

  std::string xml = encode(value);
  EXPECT_NE(xml.find("<RationalNumber xmlns=\"http://opcfoundation.org/UA/\">"), std::string::npos) << xml;

  Variant decoded = decode_xml<Variant>(mStructureFactory, xml, "Value");
  const auto& decodedArr = decoded.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(decodedArr.payload().size(), 2u) << xml;
  const auto* first = dynamic_cast<const RationalNumber*>(decodedArr.payload()[0].get());
  const auto* second = dynamic_cast<const RationalNumber*>(decodedArr.payload()[1].get());
  ASSERT_NE(first, nullptr) << xml;
  ASSERT_NE(second, nullptr) << xml;
  EXPECT_EQ(first->numerator(), 1);
  EXPECT_EQ(second->numerator(), 3);
}

// A null ExtensionObject must survive a round-trip as null (no TypeId placeholder).
TEST_F(XmlEncoderTest, NullExtensionObjectRoundTrip)
{
  Variant value{RefStructure<Structure>{}};
  ASSERT_TRUE(value.get_built_in_type() == BuiltInTypeId::ExtensionObject);

  std::string xml = encode(value);
  Variant decoded = decode_xml<Variant>(mStructureFactory, xml, "Value");
  const auto& ref = decoded.as<RefStructure<Structure>>();
  EXPECT_FALSE(static_cast<bool>(ref)) << xml;
}

// An unresolved (opaque) XML-sourced ExtensionObject body must round-trip verbatim through
// decode -> encode -> decode, even when the type is not registered with the factory.
TEST_F(XmlEncoderTest, OpaqueExtensionObjectXmlRoundTrip)
{
  // Encode a resolved RationalNumber, then decode it with a factory that does NOT know the type,
  // forcing the UnknownStructure (opaque) path. Re-encode and re-decode with the unaware factory
  // and confirm the preserved body survives.
  Variant resolved{RefStructure<Structure>{make_unique<RationalNumber>(make_rational_number(5, 6))}};
  std::string xml = encode(resolved);

  StructureFactory emptyFactory;  // no registered types -> RationalNumber is unresolved
  Variant opaque = decode_xml<Variant>(emptyFactory, xml, "Value");
  const auto& opaqueRef = opaque.as<RefStructure<Structure>>();
  ASSERT_TRUE(static_cast<bool>(opaqueRef)) << xml;
  ASSERT_NE(dynamic_cast<const UnknownStructure*>(opaqueRef.get()), nullptr) << xml;

  // Re-encode the opaque value and decode again with the AWARE factory; the body must now reify.
  std::string reXml = encode(opaque);
  Variant reified = decode_xml<Variant>(mStructureFactory, reXml, "Value");
  const auto& reifiedRef = reified.as<RefStructure<Structure>>();
  ASSERT_TRUE(static_cast<bool>(reifiedRef)) << reXml;
  const auto* rational = dynamic_cast<const RationalNumber*>(reifiedRef.get());
  ASSERT_NE(rational, nullptr) << reXml;
  EXPECT_EQ(rational->numerator(), 5);
  EXPECT_EQ(rational->denominator(), 6u);
}

namespace
{
template<typename F>
std::optional<Status> thrown_status(F&& f)
{
  try
  {
    f();
  }
  catch (const UaException& error)
  {
    return error.status();
  }
  return std::nullopt;
}

XmlElement xml_element_of(string_view payload)
{
  XmlElement value;
  value = payload;
  return value;
}

Variant opaque_xml_body(string_view body)
{
  return Variant{RefStructure<Structure>{make_unique<UnknownStructure>(NodeId{0, 1234},
    UnknownStructure::BodyEncoding::Xml,
    ByteString{span<const byte>{reinterpret_cast<const byte*>(body.data()), body.size()}})}};
}
}  // namespace

// An XmlElement value is written into the document verbatim, so a payload that is not exactly one
// well-formed element (a stray closing tag that ends the enclosing element and authors its own, a
// second top-level element, bare text, an unterminated element) would inject markup into an export.
// Each is refused with Bad_EncodingError before anything of it is written.
// @verifies AC-COMP-CORE-XML-CODEC-01-A-RAW-XML-PAYLOAD-IS-ONE-WELL-FORMED-ELEMENT
TEST_F(XmlEncoderTest, AnXmlElementThatIsNotOneWellFormedElementIsRefused)
{
  for (const string_view payload : {string_view{"<a/></Value><Injected/><Value>"},
         string_view{"<a/><b/>"},
         string_view{"bare text"},
         string_view{"<a>"},
         string_view{"<a/>tail"},
         string_view{"   "},
         // The parser stops at a NUL, so a NUL must not let it check a prefix of what is written.
         string_view{"<a/>\0</Value><Injected/>", 24},
         // A prolog, a declaration or a comment ahead of the element, or a declaration inside it.
         string_view{"<?xml version=\"1.0\"?><a/>"},
         string_view{"<!DOCTYPE a><a/>"},
         string_view{"<!-- c --><a/>"},
         string_view{"<a><!DOCTYPE a></a>"},
         string_view{"<a><?xml version='1.0'?></a>"},
         // The lexical rules a non-validating parser lets through.
         string_view{"<a x=\"1<2\"/>"},
         string_view{"<a>&bogus;</a>"},
         string_view{"<a>&amp</a>"},
         string_view{"<a>&#0;</a>"},
         string_view{"<a>\x01</a>"},
         string_view{"<a>\xFF</a>"},
         string_view{"<a>]]></a>"},
         // Comments, names and attributes the parser does not check.
         string_view{"<a><!-- a -- b --></a>"},
         string_view{"<a><!-- c ---></a>"},
         string_view{"<a x=\"1\" x=\"2\"/>"},
         string_view{"<a=b/>"},
         string_view{"<a x=\"1\"y=\"2\"/>"},
         string_view{"<a x=1/>"},
         // Names outside the XML Name productions, and a processing instruction whose target runs into
         // its data.
         string_view{"<a\xC2\xA0"
                     "b/>"},
         string_view{"<a\xC3\x97/>"},
         string_view{"<\xCC\x80/>"},
         string_view{"<a><?pi\"x?></a>"}})
  {
    const auto refused = thrown_status([&] { (void)encode(xml_element_of(payload)); });
    ASSERT_TRUE(refused.has_value()) << payload;
    EXPECT_EQ(*refused, Status::BadEncodingError) << payload;
  }
}

// The preserved body of an XML-sourced opaque ExtensionObject is written verbatim too, under the
// same rule.
// @verifies AC-COMP-CORE-XML-CODEC-01-A-RAW-XML-PAYLOAD-IS-ONE-WELL-FORMED-ELEMENT
TEST_F(XmlEncoderTest, AnOpaqueXmlBodyThatIsNotOneWellFormedElementIsRefused)
{
  for (const string_view body : {string_view{"<Body><X/></Body></Value><Injected/>"},
         string_view{"<Body/><Body/>"},
         string_view{"<Body>"},
         string_view{"<Body/>\0</Value><Injected/>", 27}})
  {
    const auto refused = thrown_status([&] { (void)encode(opaque_xml_body(body)); });
    ASSERT_TRUE(refused.has_value()) << body;
    EXPECT_EQ(*refused, Status::BadEncodingError) << body;
  }
}

// control: one well-formed element, with attributes, escapes, CDATA and a comment inside it, is
// written byte for byte, as an XmlElement and as an opaque body.
// @verifies AC-COMP-CORE-XML-CODEC-01-A-RAW-XML-PAYLOAD-IS-ONE-WELL-FORMED-ELEMENT
TEST_F(XmlEncoderTest, OneWellFormedElementIsWrittenVerbatim)
{
  const string_view payload{
    "<a k=\"1\" q='say \"hi\"'>t &amp; u &#x41;&#65;<![CDATA[<raw>]]><!-- c --><?pi data?><b/></a>"};
  EXPECT_EQ(encode(xml_element_of(payload)), "<Value>" + std::string{payload} + "</Value>");
  const string_view spaced{" <a/>\n"};
  const string_view quoted{"<a q='>' r=\"&lt;\" s = 'x' ><!-- \"quoted\" - dash --><b:c d.e-f=\"1\"/></a>"};
  EXPECT_EQ(encode(xml_element_of(quoted)), "<Value>" + std::string{quoted} + "</Value>");
  // A zero-padded character reference and a non-ASCII Name are legal XML.
  const string_view padded{"<\xC3\xA9 a\xCC\x80=\"&#x000000000041;\">&#x000000000041;</\xC3\xA9>"};
  EXPECT_EQ(encode(xml_element_of(padded)), "<Value>" + std::string{padded} + "</Value>");
  EXPECT_EQ(encode(xml_element_of(spaced)), "<Value>" + std::string{spaced} + "</Value>");

  const string_view body{"<Body><X a=\"1\">t &amp; u</X></Body>"};
  EXPECT_NE(encode(opaque_xml_body(body)).find(body), std::string::npos);
}

// A String is element text: a NUL or an invalid UTF-8 byte in it is written as U+FFFD, so the
// document is neither truncated at the NUL nor refused by a conforming parser.
// @verifies AC-COMP-CORE-XML-CODEC-02-WRITTEN-TEXT-IS-WELL-FORMED-XML
TEST_F(XmlEncoderTest, AStringWithANulOrInvalidUtf8IsWrittenAsTheReplacementCharacter)
{
  const String value{
    std::string{"a\0b\xFF"
                "c",
      5}};
  EXPECT_EQ(encode(value),
    "<Value>a\xEF\xBF\xBD"
    "b\xEF\xBF\xBD"
    "c</Value>");
}

// Part 6 5.3.1.4 maps Float and Double to xs:float and xs:double, whose special values are spelled
// NaN, INF and -INF; a finite value is written as before.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST_F(XmlEncoderTest, SpecialFloatingPointValuesUseTheXsdLexicalForms)
{
  EXPECT_EQ(encode(std::numeric_limits<double>::quiet_NaN()), "<Value>NaN</Value>");
  EXPECT_EQ(encode(std::numeric_limits<double>::infinity()), "<Value>INF</Value>");
  EXPECT_EQ(encode(-std::numeric_limits<double>::infinity()), "<Value>-INF</Value>");
  EXPECT_EQ(encode(std::numeric_limits<float>::quiet_NaN()), "<Value>NaN</Value>");
  EXPECT_EQ(encode(std::numeric_limits<float>::infinity()), "<Value>INF</Value>");
  EXPECT_EQ(encode(-std::numeric_limits<float>::infinity()), "<Value>-INF</Value>");
  EXPECT_EQ(encode(1.5), "<Value>1.5</Value>");
}

// A binary-sourced opaque ExtensionObject cannot be re-encoded as XML; the encoder must reject it.
TEST_F(XmlEncoderTest, OpaqueExtensionObjectBinaryRejected)
{
  Variant value{RefStructure<Structure>{make_unique<UnknownStructure>(
    NodeId{0, 1234}, UnknownStructure::BodyEncoding::Binary, ByteString{0x01, 0x02})}};

  EXPECT_THROW(encode(value), UaException);
}

// Regression guard: a struct-typed field nested inside another struct uses the bare (no TypeId)
// path and must continue to round-trip unchanged. The fix must not perturb this path.
TEST_F(XmlEncoderTest, NestedStructFieldBarePathUnchanged)
{
  // The bare path is exercised by encode(StackDepth, string_view, const Structure&) and the
  // matching decode(StackDepth, string_view, bool, Structure&). Drive it directly.
  RationalNumber value = make_rational_number(7, 8);

  memory_stream_device::Dynamic device;
  MemoryStream stream(device);
  XmlEncoder encoder(CodecNamespaceContext{get_namespace_index, {}, {}, {}}, stream);
  auto cfg = ApplicationConfig::load_default();
  StackDepth limit{cfg.execution_limits().decodeWorkLimit};
  encoder.encode(limit, "Field", static_cast<const Structure&>(value));
  auto data = device.get_data();
  std::string xml(reinterpret_cast<const char*>(data.data()), data.size());

  // Bare path: no TypeId / no Body wrapper, just the field element directly under <Field>.
  EXPECT_EQ(xml.find("<TypeId>"), std::string::npos) << xml;
  EXPECT_EQ(xml.find("<Body>"), std::string::npos) << xml;
  EXPECT_NE(xml.find("<Numerator>7</Numerator>"), std::string::npos) << xml;

  std::vector<char> writableInput(xml.begin(), xml.end());
  writableInput.push_back('\0');
  auto contextXml = xml::parse(writableInput.data());
  auto firstElement = contextXml.xml_element().get_first_child();
  ASSERT_TRUE(firstElement.has_value()) << xml;
  XmlDecoder decoder(mStructureFactory, *firstElement, EncodingLimits{});
  RationalNumber decoded;
  decoder.decode(limit, "Field", false, decoded);
  EXPECT_EQ(decoded.numerator(), 7);
  EXPECT_EQ(decoded.denominator(), 8u);
}
