// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <string>
#include "ua_xml_writer.h"
#include "ua_memory_stream.h"
#include "ua_exceptions.h"

using namespace ua;

namespace
{

class XmlWriterTest : public testing::Test
{
protected:
  // Returns the bytes written so far as a string.
  std::string output() const
  {
    auto data = mDevice.get_data();
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
  }

  memory_stream_device::Dynamic mDevice;
  MemoryStream<memory_stream_device::Dynamic> mStream{mDevice};
  XmlWriter mWriter{mStream};
};

}  // namespace

TEST_F(XmlWriterTest, Declaration)
{
  mWriter.write_declaration();
  EXPECT_EQ(output(), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
}

TEST_F(XmlWriterTest, ElementWithTextNoAttributes)
{
  mWriter.start_element("Name");
  mWriter.text("text");
  mWriter.end_element("Name");
  EXPECT_EQ(output(), "<Name>text</Name>");
}

TEST_F(XmlWriterTest, EmptyElementSelfCloses)
{
  mWriter.start_element("Name");
  mWriter.end_element("Name");
  EXPECT_EQ(output(), "<Name/>");
}

TEST_F(XmlWriterTest, EmptyElementWithAttributesSelfCloses)
{
  mWriter.start_element("UAVariable");
  mWriter.attribute("NodeId", "i=1");
  mWriter.attribute("BrowseName", "1:X");
  mWriter.end_element("UAVariable");
  EXPECT_EQ(output(), "<UAVariable NodeId=\"i=1\" BrowseName=\"1:X\"/>");
}

TEST_F(XmlWriterTest, ElementWithMultipleAttributesAndText)
{
  mWriter.start_element("UAVariable");
  mWriter.attribute("NodeId", "i=1");
  mWriter.attribute("BrowseName", "1:X");
  mWriter.text("body");
  mWriter.end_element("UAVariable");
  EXPECT_EQ(output(), "<UAVariable NodeId=\"i=1\" BrowseName=\"1:X\">body</UAVariable>");
}

TEST_F(XmlWriterTest, AttributeValueEscaping)
{
  mWriter.start_element("E");
  mWriter.attribute("A", "& < > \" '");
  mWriter.end_element("E");
  EXPECT_EQ(output(), "<E A=\"&amp; &lt; &gt; &quot; &apos;\"/>");
}

TEST_F(XmlWriterTest, TextEscaping)
{
  mWriter.start_element("E");
  mWriter.text("& < > \" '");
  mWriter.end_element("E");
  EXPECT_EQ(output(), "<E>&amp; &lt; &gt; &quot; &apos;</E>");
}

// XML 1.0 admits neither the C0 controls other than tab, line feed and carriage return nor a byte
// sequence that is not UTF-8, not even as a character reference, so the writer replaces each with
// U+FFFD instead of emitting a document a conforming parser refuses or truncates at a NUL.
// @verifies AC-COMP-CORE-XML-CODEC-02-WRITTEN-TEXT-IS-WELL-FORMED-XML
TEST_F(XmlWriterTest, ForbiddenControlsAndMalformedUtf8BecomeTheReplacementCharacter)
{
  const std::string text{
    "a\x00"
    "b\x01"
    "c\x1f"
    "d\xC3\x28"
    "e\xE0\x80\xAF"
    "f\xED\xA0\x80"
    "g\xEF\xBF\xBE"
    "h\xFF",
    23};
  mWriter.start_element("E");
  mWriter.attribute("A", string_view{"x\x0By\x0Cz", 5});
  mWriter.text(text);
  mWriter.end_element("E");
  const std::string fffd{"\xEF\xBF\xBD"};
  EXPECT_EQ(output(),
    "<E A=\"x" + fffd + "y" + fffd + "z\">a" + fffd + "b" + fffd + "c" + fffd + "d" + fffd + "(e" + fffd +
      fffd + fffd + "f" + fffd + fffd + fffd + "g" + fffd + fffd + fffd + "h" + fffd + "</E>");
}

// A conforming parser normalises a literal tab, line feed or carriage return in an attribute value to
// a space and folds a literal carriage return in text into a line feed, so the writer spells those as
// character references and the value reads back as written.
// @verifies AC-COMP-CORE-XML-CODEC-02-WRITTEN-TEXT-IS-WELL-FORMED-XML
TEST_F(XmlWriterTest, WhitespaceControlsThatAParserWouldNormaliseAreCharacterReferences)
{
  mWriter.start_element("E");
  mWriter.attribute("A", "1\t2\n3\r4");
  mWriter.text("5\r6");
  mWriter.end_element("E");
  EXPECT_EQ(output(), "<E A=\"1&#x9;2&#xA;3&#xD;4\">5&#xD;6</E>");
}

// control: well-formed multi-byte UTF-8 (two, three and four bytes), DEL and the tab and line feed a
// parser keeps in text are written unchanged.
// @verifies AC-COMP-CORE-XML-CODEC-02-WRITTEN-TEXT-IS-WELL-FORMED-XML
TEST_F(XmlWriterTest, WellFormedUtf8AndPermittedCharactersPassThroughUnchanged)
{
  const std::string text{"\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80 \x7F\t\n"};
  mWriter.start_element("E");
  mWriter.attribute("A", "\xC3\xA9\xE2\x82\xAC");
  mWriter.text(text);
  mWriter.end_element("E");
  EXPECT_EQ(output(), "<E A=\"\xC3\xA9\xE2\x82\xAC\">" + text + "</E>");
}

TEST_F(XmlWriterTest, NestedElementsViaScope)
{
  {
    XmlWriter::ElementScope outer(mWriter, "Outer");
    mWriter.attribute("k", "v");
    {
      XmlWriter::ElementScope inner(mWriter, "Inner");
      mWriter.text("leaf");
    }
  }
  EXPECT_EQ(output(), "<Outer k=\"v\"><Inner>leaf</Inner></Outer>");
}

TEST_F(XmlWriterTest, NestedElementsManual)
{
  // A child written into a still-pending parent flushes the parent's `>` and prevents it from
  // self-closing.
  mWriter.start_element("Parent");
  mWriter.start_element("Child");
  mWriter.end_element("Child");
  mWriter.end_element("Parent");
  EXPECT_EQ(output(), "<Parent><Child/></Parent>");
}

TEST_F(XmlWriterTest, RawPassthroughFlushesPendingStartTag)
{
  mWriter.start_element("Value");
  mWriter.raw("<uax:Int32>42</uax:Int32>");
  mWriter.end_element("Value");
  EXPECT_EQ(output(), "<Value><uax:Int32>42</uax:Int32></Value>");
}

TEST_F(XmlWriterTest, RawPassthroughVerbatimNoEscaping)
{
  // raw() must not escape its argument - it embeds pre-rendered markup byte-for-byte.
  mWriter.raw("<a b=\"&amp;\">x</a>");
  EXPECT_EQ(output(), "<a b=\"&amp;\">x</a>");
}

TEST_F(XmlWriterTest, AttributeWithoutPendingTagThrows)
{
  mWriter.start_element("E");
  mWriter.text("flushed");  // flushes the pending start tag
  EXPECT_THROW(mWriter.attribute("late", "value"), UaException);
}

TEST_F(XmlWriterTest, SiblingElements)
{
  {
    XmlWriter::ElementScope root(mWriter, "Root");
    {
      XmlWriter::ElementScope a(mWriter, "A");
      mWriter.text("1");
    }
    {
      XmlWriter::ElementScope b(mWriter, "B");
      mWriter.text("2");
    }
  }
  EXPECT_EQ(output(), "<Root><A>1</A><B>2</B></Root>");
}
