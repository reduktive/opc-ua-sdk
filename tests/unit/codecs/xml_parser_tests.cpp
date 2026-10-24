// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ua_xml_parser.h"
#include "ua_exceptions.h"
#include "ua_string.h"
#include "ua_date_time.h"
#include "ua_guid.h"
#include "ua_byte_string.h"
#include "ua_node_id.h"
#include "ua_expanded_node_id.h"
#include "ua_status_code.h"
#include "ua_qualified_name.h"

#include <type_traits>
#include <cstring>
#include <string>
#include <ios>

using namespace ua;

// Header-hygiene guard (P5): the public xml:: surface must expose only distinct, opaque handle
// types - never `std::any`, `void*`, or any XML-library type. If someone reintroduces a
// `std::any` handle (or collapses these to `void*`), these static_asserts fail at compile time,
// catching the regression before it can leak the backend into the public ABI.
static_assert(
  std::is_same_v<decltype(std::declval<const ua::xml::Element>().handle()), ua::xml::detail::NodeHandle*>,
  "xml::Element::handle() must return the opaque detail::NodeHandle* (no std::any / void* / XML type)");
static_assert(std::is_same_v<decltype(std::declval<const ua::xml::Attribute>().handle()),
                ua::xml::detail::AttributeHandle*>,
  "xml::Attribute::handle() must return the opaque detail::AttributeHandle* (no std::any / void* / XML "
  "type)");

TEST(XmlParserTest, Byte)
{
  uint8_t result{0};
  xml::parser::parse("230", result);
  EXPECT_EQ(result, uint8_t{230});

  EXPECT_ANY_THROW(xml::parser::parse("", result));
  EXPECT_ANY_THROW(xml::parser::parse("300", result));
  EXPECT_ANY_THROW(xml::parser::parse("-1", result));
}

TEST(XmlParserTest, SByte)
{
  int8_t result{0};
  xml::parser::parse("-120", result);
  EXPECT_EQ(result, int8_t{-120});

  xml::parser::parse("125", result);
  EXPECT_EQ(result, int8_t{125});

  EXPECT_ANY_THROW(xml::parser::parse("150", result));
  EXPECT_ANY_THROW(xml::parser::parse(" 120", result));
}

TEST(XmlParserTest, UInt16)
{
  uint16_t result{0};
  xml::parser::parse("64000", result);
  EXPECT_EQ(result, uint16_t{64000});

  EXPECT_ANY_THROW(xml::parser::parse("66000", result));
  EXPECT_ANY_THROW(xml::parser::parse("-10", result));
}

TEST(XmlParserTest, Int16)
{
  int16_t result{0};
  xml::parser::parse("-32000", result);
  EXPECT_EQ(result, int16_t{-32000});

  EXPECT_ANY_THROW(xml::parser::parse("33000", result));
  EXPECT_ANY_THROW(xml::parser::parse("-33000", result));
}

TEST(XmlParserTest, UInt32)
{
  uint32_t result{0};
  xml::parser::parse("4294967295", result);
  EXPECT_EQ(result, uint32_t{4294967295});

  EXPECT_ANY_THROW(xml::parser::parse("4294967296", result));
  EXPECT_ANY_THROW(xml::parser::parse("-10", result));
}

TEST(XmlParserTest, Int32)
{
  int32_t result{0};
  xml::parser::parse("-2147483647", result);
  EXPECT_EQ(result, int32_t{-2147483647});

  EXPECT_ANY_THROW(xml::parser::parse("2147483648", result));
  EXPECT_ANY_THROW(xml::parser::parse("-2147483649", result));
}

// A leading '+' is skipped before the digits are read, and the digits end where the input view ends:
// the view "+1" taken from the buffer "+12" reads 1. Reading to the end of the unstripped length
// reached one character past the view and read 12, or refused a well-formed value as having trailing
// characters.
// @verifies AC-COMP-CORE-XML-CODEC-04-TEXT-IS-READ-WITHIN-ITS-OWN-VIEW
TEST(XmlParserTest, APlusSignedNumberIsReadWithinItsView)
{
  constexpr std::string_view buffer{"+12"};
  int32_t result{0};
  EXPECT_NO_THROW(xml::parser::parse(buffer.substr(0, 2), result));
  EXPECT_EQ(result, 1);

  uint16_t unsignedResult{0};
  EXPECT_NO_THROW(xml::parser::parse(std::string_view{"+65535"}.substr(0, 3), unsignedResult));
  EXPECT_EQ(unsignedResult, 65u);
}

// control: a '+'-signed number that fills its whole input is read in full.
// @verifies AC-COMP-CORE-XML-CODEC-04-TEXT-IS-READ-WITHIN-ITS-OWN-VIEW
TEST(XmlParserTest, APlusSignedNumberFillingItsInputIsReadInFull)
{
  int32_t result{0};
  xml::parser::parse("+12", result);
  EXPECT_EQ(result, 12);
  EXPECT_ANY_THROW(xml::parser::parse("+", result));
}

// What follows the seconds of an xs:dateTime is nothing, "Z", or a whole offset: a tail that merely
// ends in 'Z', a doubled 'Z' and text after an offset are Bad_DecodingError.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST(XmlParserTest, ADateTimeTailOtherThanZOrAnOffsetIsRefused)
{
  DateTime result;
  for (const std::string_view text : {std::string_view{"2009-10-10T17:11:12XYZ"},
         std::string_view{"2009-10-10T17:11:12ZZ"},
         std::string_view{"2009-10-10T17:11:12+05:00junk"},
         std::string_view{"2009-10-10T17:11:12+05:00Z"}})
  {
    try
    {
      xml::parser::parse(text, result);
      ADD_FAILURE() << "accepted: " << text;
    }
    catch (const UaException& error)
    {
      EXPECT_EQ(error.status(), Status::BadDecodingError) << text;
    }
  }
}

TEST(XmlParserTest, UInt64)
{
  uint64_t result{0};
  xml::parser::parse("18446744073709551615", result);
  EXPECT_EQ(result, uint64_t{18446744073709551615ULL});

  EXPECT_ANY_THROW(xml::parser::parse("18446744073709551616", result));
  EXPECT_ANY_THROW(xml::parser::parse("-10", result));
}

TEST(XmlParserTest, Int64)
{
  int64_t result{0};
  xml::parser::parse("-9223372036854775808", result);
  EXPECT_EQ(result, int64_t{LLONG_MIN});

  EXPECT_ANY_THROW(xml::parser::parse("9223372036854775808", result));
  EXPECT_ANY_THROW(xml::parser::parse("-9223372036854775809", result));
}

TEST(XmlParserTest, Float)
{
  float result{0};
  xml::parser::parse("Nan", result);
  EXPECT_TRUE(std::isnan(result));

  xml::parser::parse("INF", result);
  EXPECT_EQ(std::numeric_limits<float>::infinity(), result);

  xml::parser::parse("-INF", result);
  EXPECT_EQ(-std::numeric_limits<float>::infinity(), result);

  xml::parser::parse("123.456", result);
  EXPECT_EQ(result, float{123.456f});

  xml::parser::parse("+1234.456", result);
  EXPECT_EQ(result, float{1234.456f});

  xml::parser::parse("-.45E-6", result);
  EXPECT_EQ(result, float{-.45E-6f});

  EXPECT_ANY_THROW(xml::parser::parse("1234.4E 56", result));
  EXPECT_ANY_THROW(xml::parser::parse("1E+2.5", result));
  EXPECT_ANY_THROW(xml::parser::parse("-1.2344e56", result));
}

TEST(XmlParserTest, Double)
{
  double result{0};
  xml::parser::parse("Nan", result);
  EXPECT_TRUE(std::isnan(result));

  xml::parser::parse("INF", result);
  EXPECT_EQ(std::numeric_limits<double>::infinity(), result);

  xml::parser::parse("-INF", result);
  EXPECT_EQ(-std::numeric_limits<double>::infinity(), result);

  xml::parser::parse("-1E4", result);
  EXPECT_EQ(result, double{-1E4});

  xml::parser::parse("1267.43233E12", result);
  EXPECT_EQ(result, double{1267.43233E12});

  xml::parser::parse("12.78e-2", result);
  EXPECT_EQ(result, double{12.78e-2});

  xml::parser::parse("12", result);
  EXPECT_EQ(result, double{12});

  xml::parser::parse("-0", result);
  EXPECT_EQ(result, double{-0});

  xml::parser::parse("-1.2344e56", result);
  EXPECT_EQ(result, double{-1.2344e56});

  EXPECT_ANY_THROW(xml::parser::parse("1E+2.5", result));
  EXPECT_ANY_THROW(xml::parser::parse("1234.4E 56", result));
}

TEST(XmlParserTest, DateTime)
{
  using namespace std::literals::chrono_literals;

  DateTime result;
  xml::parser::parse("2009-10-10T17:11:12Z", result);
  EXPECT_EQ(result, (DateTime{2009y, std::chrono::October, 10d, 17h, 11min, 12}));

  xml::parser::parse("2009-10-10T17:11:12-05:30", result);
  DateTime expected{2009y, std::chrono::October, 10d, 17h, 11min, 12, -330min};
  EXPECT_EQ(result, expected);

  xml::parser::parse("2009-10-10T17:09:01.12345678Z", result);
  EXPECT_EQ(result, (DateTime{2009y, std::chrono::October, 10d, 17h, 9min, 1.12345678}));

  xml::parser::parse("2009-10-10T17:08:00.123-05:00", result);
  EXPECT_EQ(result, (DateTime{2009y, std::chrono::October, 10d, 17h, 8min, 00.123, -300min}));

  xml::parser::parse("2009-10-10T17:08:00.123+05:00", result);
  EXPECT_EQ(result, (DateTime{2009y, std::chrono::October, 10d, 17h, 8min, 00.123, +300min}));

  xml::parser::parse("2009-10-10T17:11:12", result);
  EXPECT_EQ(result, (DateTime{2009y, std::chrono::October, 10d, 17h, 11min, 12}));

  EXPECT_ANY_THROW(xml::parser::parse("009-10-10T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("0000-10-10T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-10T17:00:00 ", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-10T17:00:00.1234567891234Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-13-10T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-10T17:61:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-32T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-10T17:00:64Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-10-10T17:0000Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-02-30T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2009-06-31T17:00:00Z", result));
  EXPECT_ANY_THROW(xml::parser::parse("2023-02-29T17:00:00Z", result));
}

template<typename... Ts>
std::array<std::byte, sizeof...(Ts)> make_bytes(Ts&&... args) noexcept
{
  return {std::byte(std::forward<Ts>(args))...};
}

auto array_from_span(span<const byte> input)
{
  std::array<byte, Guid::length> output;
  std::copy(input.begin(), input.end(), output.begin());
  return output;
}

TEST(XmlParserTest, Guid)
{
  auto goodBytes = make_bytes(
    0x8A, 0x57, 0x96, 0xC4, 0xFE, 0x0D, 0x8F, 0x4B, 0x87, 0x0A, 0x74, 0X52, 0X38, 0XC6, 0XAE, 0XAE);

  Guid result;
  xml::parser::parse("C496578A-0DFE-4B8F-870A-745238C6AEAE", result);
  EXPECT_THAT(result.as_ua_binary(), testing::ContainerEq(goodBytes));

  EXPECT_ANY_THROW(xml::parser::parse("C496578A:0DFE:4B8F:870A:745238C6AEAE", result));
  EXPECT_ANY_THROW(xml::parser::parse("C496578A-0DFE-4B8F-870A-745238C6AE", result));
}

TEST(XmlParserTest, ByteString)
{
  ByteString expected{'f', 'o', 'o', 'b', 'a', 'r'};

  ByteString result;
  xml::parser::parse("Zm9vYmFy", result);
  EXPECT_EQ(result, expected);
}

// OPC 10000-6 5.3.1.8: an XML ByteString is xs:base64Binary, whose whitespace XML Schema collapses, so a
// value a NodeSet wraps across lines (as OPC 40223 Pumps wraps its TypeDictionaries) decodes to the same
// bytes.
TEST(XmlParserTest, AByteStringWrappedAcrossLinesDecodesToTheSameBytes)
{
  const ByteString expected{'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z', '!'};

  ByteString result;
  xml::parser::parse("Zm9vYmFy\n      YmF6IQ==", result);
  EXPECT_EQ(result, expected);
  xml::parser::parse(" Zm9v\r\n\tYmFy YmF6 IQ==\n", result);
  EXPECT_EQ(result, expected);
  xml::parser::parse(" \n\t ", result);
  EXPECT_TRUE(result.empty());
}

TEST(XmlParserTest, NodeId)
{
  NodeId result;
  xml::parser::parse("ns=2;i=345", result);
  EXPECT_EQ(result, (NodeId{2, 345}));
}

TEST(XmlParserTest, ExpandedNodeId)
{
  ExpandedNodeId result;
  xml::parser::parse("svr=1;ns=2;i=345", result);

  EXPECT_EQ(result, (ExpandedNodeId{NodeId{2, 345}, 1}));
}

TEST(XmlParserTest, StatusCode)
{
  StatusCode result;
  xml::parser::parse("2148007936", result);

  EXPECT_EQ(result, StatusCode(Status::BadEncodingLimitsExceeded));
}

// --- Non-destructive document parsing (NS0 .rodata enablement) -----------------------------------
// The importer parses XML non-destructively so the source buffer (e.g. the const NS0 .rodata array)
// is never written. rapidxml therefore no longer expands entities in place; the xml:: value
// accessors expand them lazily instead. These tests pin that behaviour.

TEST(XmlParserDocumentTest, ExpandsEntitiesInElementAndAttributeValues)
{
  // Element text exercises all five predefined entities plus decimal and hex character references;
  // the attribute value exercises an ampersand entity.
  const char* document = "<root attr=\"x&amp;y\">a&lt;b&gt;c&quot;d&apos;e &#65;&#x42;</root>";

  auto context = xml::parse(document);
  auto root = context.xml_element().get_first_child("root");
  ASSERT_TRUE(root.has_value());

  EXPECT_EQ(root->get_value(), string_view("a<b>c\"d'e AB"));

  auto attribute = root->get_first_attribute_value("attr");
  ASSERT_TRUE(attribute.has_value());
  EXPECT_EQ(attribute.value(), string_view("x&y"));
}

TEST(XmlParserDocumentTest, ValueWithoutEntitiesIsZeroCopyViewOfSource)
{
  const char* document = "<root>plainvalue</root>";

  auto context = xml::parse(document);
  auto root = context.xml_element().get_first_child("root");
  ASSERT_TRUE(root.has_value());

  const string_view value = root->get_value();
  EXPECT_EQ(value, string_view("plainvalue"));

  // No entities to expand -> the view must alias the source buffer rather than a parse-arena copy.
  EXPECT_GE(value.data(), document);
  EXPECT_LT(value.data(), document + std::strlen(document));
}

TEST(XmlParserDocumentTest, ParsingDoesNotMutateTheSourceBuffer)
{
  // Falsifiable guard for non-destructive parsing: under the old destructive flags rapidxml would
  // have inserted NUL terminators and expanded the entity in place, mutating `buffer`.
  const std::string original = "<root attr=\"x&amp;y\">a&lt;b</root>";
  std::string buffer = original;

  auto context = xml::parse(buffer.c_str());
  auto root = context.xml_element().get_first_child("root");
  ASSERT_TRUE(root.has_value());
  EXPECT_EQ(root->get_value(), string_view("a<b"));

  EXPECT_EQ(buffer, original);
}

TEST(XmlParserDocumentTest, ParsesDirectlyFromReadOnlyStringLiteral)
{
  // A string literal lives in read-only storage; a write would fault. Reaching the assertions at all
  // proves rapidxml never wrote to the buffer.
  auto context = xml::parse("<root>value</root>");
  auto root = context.xml_element().get_first_child("root");
  ASSERT_TRUE(root.has_value());
  EXPECT_EQ(root->get_value(), string_view("value"));
}

// ============================================================================================
// Security review 2026-09-28: element nesting is bounded BEFORE the backing parser recurses into
// the document (an unbounded document is a stack overflow the process cannot catch).
// ============================================================================================

namespace
{

std::string nested_open_tags(std::size_t levels, std::string_view each = "<a>")
{
  std::string document;
  document.reserve(levels * each.size());
  for (std::size_t i = 0; i < levels; ++i)
  {
    document += each;
  }
  return document;
}

std::string well_formed_nesting(std::size_t levels)
{
  std::string document = nested_open_tags(levels);
  for (std::size_t i = 0; i < levels; ++i)
  {
    document += "</a>";
  }
  return document;
}

::testing::AssertionResult rejects_with(const std::string& document, std::size_t bound, Status expected)
{
  try
  {
    (void)ua::xml::parse(document.c_str(), bound);
  }
  catch (const UaException& exception)
  {
    if (exception.status_code().as_status() == expected)
    {
      return ::testing::AssertionSuccess();
    }
    return ::testing::AssertionFailure()
           << "wrong status: 0x" << std::hex << exception.status_code().as_uint32();
  }
  catch (const std::exception& exception)
  {
    return ::testing::AssertionFailure() << "a non-UaException escaped: " << exception.what();
  }
  return ::testing::AssertionFailure() << "the document was parsed";
}

::testing::AssertionResult rejects_as_too_deep(const std::string& document, std::size_t bound)
{
  return rejects_with(document, bound, Status::BadEncodingLimitsExceeded);
}

}  // namespace

// @relation(AC-CL-ADDRSP-007-XML-ELEMENT-NESTING-IS-BOUNDED, scope=function)
TEST(XmlParserTest, ParseRejectsNestingBeyondTheBound)
{
  EXPECT_TRUE(rejects_as_too_deep(well_formed_nesting(17), 16));
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(17), 16))
    << "an unterminated document is refused on the way down";
}

// @relation(AC-CL-ADDRSP-007-XML-ELEMENT-NESTING-IS-BOUNDED, scope=function)  // control arm
TEST(XmlParserTest, ParseAcceptsNestingAtTheBound)
{
  auto context = ua::xml::parse(well_formed_nesting(16).c_str(), 16);
  EXPECT_TRUE(context.xml_element().get_first_child().has_value()) << "exactly the bound is admitted";
  // The default bound admits every nesting the decoder's own default depth (100 values, 3 XML levels
  // each) implies.
  auto deep = ua::xml::parse(well_formed_nesting(ua::xml::defaultMaxXmlElementDepth).c_str());
  EXPECT_TRUE(deep.xml_element().get_first_child().has_value());
}

// Every lexical construct the backing parser skips is skipped the same way by the bound: none can
// hide an open tag from the count, and none can fake a close.
// @relation(AC-CL-ADDRSP-007-XML-ELEMENT-NESTING-IS-BOUNDED, scope=function)
TEST(XmlParserTest, ParseDepthBoundCannotBeBypassedByLexicalConstructs)
{
  constexpr std::size_t bound = 8;
  constexpr std::size_t over = bound + 1;
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a x=\"/>\">"), bound))
    << "quoted '/>' is not self-closing";
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a x='/>'>"), bound));
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a><![CDATA[</b>]]>"), bound))
    << "a close inside CDATA does not count";
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a><!--</b>-->"), bound))
    << "a close inside a comment does not count";
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a><?p </b>?>"), bound))
    << "a close inside a processing instruction does not count";
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a><!DOCTYPE x [</b>]>"), bound))
    << "a close inside a DOCTYPE subset does not count";
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(over, "<a><!x </b>>"), bound))
    << "a close inside another declaration does not count";
  EXPECT_TRUE(
    rejects_with(nested_open_tags(3, "</x>") + nested_open_tags(over), bound, Status::BadDecodingError))
    << "a close that outruns its opens is refused as malformed, so it cannot pre-pay depth";
  // The parser's own start-tag grammar: a quote is an ordinary character inside an element or
  // attribute NAME, and only a quoted attribute VALUE can hide a '>'.
  EXPECT_TRUE(rejects_as_too_deep(std::string{"<a\">"} + nested_open_tags(over), bound))
    << "a quote inside an element name hides nothing";
  EXPECT_TRUE(rejects_as_too_deep(std::string{"<a b'=\"x\">"} + nested_open_tags(over), bound))
    << "a quote inside an attribute name hides nothing";
  // A DOCTYPE is only a DOCTYPE with whitespace after the keyword; otherwise the parser skips the
  // declaration at its first '>' and the '[' hides nothing.
  EXPECT_TRUE(rejects_as_too_deep(std::string{"<!DOCTYPEx[>"} + nested_open_tags(over) + "]>", bound))
    << "a keyword without whitespace is not a bracketed DOCTYPE";
  // And the constructs that really do not nest are still admitted at the bound.
  auto selfClosing = ua::xml::parse(nested_open_tags(bound * 4, "<a/>").c_str(), bound);
  EXPECT_TRUE(selfClosing.xml_element().get_first_child().has_value());
}

// The document that crashed the process before the bound existed: refused, not a SIGSEGV.
// @relation(AC-CL-ADDRSP-007-XML-ELEMENT-NESTING-IS-BOUNDED, scope=function)
TEST(XmlParserTest, ParseRejectsAMillionLevelDocumentWithoutCrashing)
{
  EXPECT_TRUE(rejects_as_too_deep(nested_open_tags(1'000'000), ua::xml::defaultMaxXmlElementDepth));
}
