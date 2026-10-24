// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Text into built-in types (public API review 2026-10, item 7). Each of NodeId, ExpandedNodeId, Guid,
// DateTime and QualifiedName has parse (throws Bad_DecodingError) and try_parse (a bad Result), and each
// reads back exactly what its to_string writes. QualifiedName text is the OPC 10000-4 Annex A form, with
// '&' before a reserved character of the name.

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_to_string.h"

namespace
{
using namespace ua;

Guid sample_guid()
{
  return Guid::parse("72962b91-fa75-4ae6-8d28-b404dc7daf63");
}

TEST(TextParseNodeId, EveryIdentifierTypeRoundTrips)
{
  const std::vector<NodeId> ids{NodeId{uint32_t{85}},
    NodeId{2, uint32_t{345}},
    NodeId{0, "Temperature"},
    NodeId{3, "Line 1.Boiler"},
    NodeId{4, sample_guid()},
    NodeId{5, ByteString{std::vector<uint8_t>{0x61, 0x00, 0xff}}}};
  for (const auto& id : ids)
  {
    EXPECT_EQ(NodeId::parse(to_string(id)), id) << to_string(id);
    const auto parsed = NodeId::try_parse(to_string(id));
    ASSERT_TRUE(parsed.is_good()) << to_string(id);
    EXPECT_EQ(parsed.value(), id);
  }
}

TEST(TextParseNodeId, TheNamespaceTextIsParsedNotKeptAsAName)
{
  // The removed one-argument constructor made this the namespace-0 string id "ns=2;s=Foo".
  const auto id = NodeId::parse("ns=2;s=Foo");
  EXPECT_EQ(id.namespace_index(), 2);
  EXPECT_EQ(id, (NodeId{2, "Foo"}));
}

TEST(TextParseNodeId, MalformedTextIsADecodingError)
{
  const std::vector<std::pair<std::string, std::string>> cases{{"", ""},
    {"x=1", "x=1"},
    {"i=5abc", "5abc"},
    {"ns=0;i=1", "0;i=1"},
    {"ns=2i=1", "2i=1"},
    {"ns=70000;i=1", "70000;i=1"}};
  for (const auto& [text, actual] : cases)
  {
    EXPECT_THROW(NodeId::parse(text), UaException) << text;
    const auto parsed = NodeId::try_parse(text);
    ASSERT_TRUE(parsed.is_bad()) << text;
    EXPECT_EQ(parsed.status_code().as_status(), Status::BadDecodingError) << text;
    ASSERT_NE(parsed.shared_detail(), nullptr) << text;
    EXPECT_EQ(parsed.shared_detail()->code, "NodeIdParseFailed") << text;
    EXPECT_EQ(parsed.shared_detail()->source, "NodeId") << text;
    ASSERT_EQ(parsed.shared_detail()->context.size(), 1) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().key, ContextKeys::actual.value()) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().value, actual) << text;
  }
}

TEST(TextParseExpandedNodeId, RoundTripsWithServerIndexAndNamespaceUri)
{
  const auto byIndex = ExpandedNodeId::parse("svr=1;ns=2;i=345");
  EXPECT_EQ(ExpandedNodeId::parse(to_string(byIndex)), byIndex);
  const auto byUri = ExpandedNodeId::parse("svr=2;nsu=urn:x;s=Name");
  EXPECT_EQ(ExpandedNodeId::parse(to_string(byUri)), byUri);
  EXPECT_EQ(byUri.namespace_uri(), "urn:x");
  for (const auto& id : {byIndex, byUri})
  {
    const auto parsed = ExpandedNodeId::try_parse(to_string(id));
    ASSERT_TRUE(parsed.is_good()) << to_string(id);
    EXPECT_EQ(parsed.value(), id);
  }
}

TEST(TextParseExpandedNodeId, AnIndexBesideAUriIsADecodingError)
{
  const auto parsed = ExpandedNodeId::try_parse("nsu=urn:x;ns=2;i=3");
  ASSERT_TRUE(parsed.is_bad());
  EXPECT_EQ(parsed.status_code().as_status(), Status::BadDecodingError);
  ASSERT_NE(parsed.shared_detail(), nullptr);
  EXPECT_EQ(parsed.shared_detail()->code, "NodeIdParseFailed");
  EXPECT_EQ(parsed.shared_detail()->source, "NodeId");
  ASSERT_EQ(parsed.shared_detail()->context.size(), 1);
  EXPECT_EQ(parsed.shared_detail()->context.front().key, ContextKeys::actual.value());
  EXPECT_EQ(parsed.shared_detail()->context.front().value, "ns=2;i=3");

  const auto invalidServerIndex = ExpandedNodeId::try_parse("svr=0;ns=2;i=3");
  ASSERT_TRUE(invalidServerIndex.is_bad());
  EXPECT_EQ(invalidServerIndex.status_code().as_status(), Status::BadDecodingError);
  ASSERT_NE(invalidServerIndex.shared_detail(), nullptr);
  EXPECT_EQ(invalidServerIndex.shared_detail()->code, "InvalidExpandedNodeId");
  EXPECT_EQ(invalidServerIndex.shared_detail()->source, "ExpandedNodeId");
  EXPECT_EQ(invalidServerIndex.shared_detail()->summary, "svr= format cannot be used for server index zero");
}

TEST(TextParseGuid, TheCanonicalFormRoundTripsInEitherCase)
{
  const auto guid = sample_guid();
  EXPECT_EQ(Guid::parse(guid.as_string()), guid);
  EXPECT_EQ(Guid::parse("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), guid);
  for (const std::string text : {guid.as_string(), std::string{"72962B91-FA75-4AE6-8D28-B404DC7DAF63"}})
  {
    const auto parsed = Guid::try_parse(text);
    ASSERT_TRUE(parsed.is_good()) << text;
    EXPECT_EQ(parsed.value(), guid);
  }
}

TEST(TextParseGuid, FormsToStringNeverWritesAreRefused)
{
  for (const std::string text : {"{72962b91-fa75-4ae6-8d28-b404dc7daf63}",
         "72962b91fa754ae68d28b404dc7daf63",
         "72962b91-fa75-4ae6-8d28-b404dc7daf6",
         "72962b91-fa75-4ae6-8d28-b404dc7daf6g"})
  {
    const auto parsed = Guid::try_parse(text);
    ASSERT_TRUE(parsed.is_bad()) << text;
    EXPECT_EQ(parsed.status_code().as_status(), Status::BadDecodingError) << text;
    ASSERT_NE(parsed.shared_detail(), nullptr) << text;
    EXPECT_EQ(parsed.shared_detail()->code, "InvalidGuidFormat") << text;
    EXPECT_EQ(parsed.shared_detail()->source, "Guid") << text;
    ASSERT_EQ(parsed.shared_detail()->context.size(), 1) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().key, ContextKeys::value.value()) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().value, text) << text;
  }
}

TEST(TextParseDateTime, RoundTripsToTheHundredNanosecond)
{
  const auto instant = DateTime::parse("2026-10-06T08:15:30.1234567Z");
  EXPECT_EQ(DateTime::parse(to_string(instant)), instant);
  const auto now = DateTime::now();
  EXPECT_EQ(DateTime::parse(to_string(now)), now) << to_string(now);
  for (const auto& value : {instant, now})
  {
    const auto parsed = DateTime::try_parse(to_string(value));
    ASSERT_TRUE(parsed.is_good()) << to_string(value);
    EXPECT_EQ(parsed.value(), value);
  }
}

TEST(TextParseDateTime, ALocalTimeIsADecodingError)
{
  const auto parsed = DateTime::try_parse("2026-10-06T08:15:30");
  ASSERT_TRUE(parsed.is_bad());
  EXPECT_EQ(parsed.status_code().as_status(), Status::BadDecodingError);
  ASSERT_NE(parsed.shared_detail(), nullptr);
  EXPECT_EQ(parsed.shared_detail()->code, "DateTimeParseError");
  EXPECT_EQ(parsed.shared_detail()->source, "DateTime");
  ASSERT_EQ(parsed.shared_detail()->context.size(), 1);
  EXPECT_EQ(parsed.shared_detail()->context.front().key, ContextKeys::value.value());
  EXPECT_EQ(parsed.shared_detail()->context.front().value, "2026-10-06T08:15:30");
}

TEST(TextParseQualifiedName, ANamespaceIndexIsAPrefixOnlyOutsideNamespaceZero)
{
  EXPECT_EQ(to_string(QualifiedName{2, "Foo"}), "2:Foo");
  EXPECT_EQ(to_string(QualifiedName{0, "Foo"}), "Foo");
  EXPECT_EQ(QualifiedName::parse("2:Foo"), (QualifiedName{2, "Foo"}));
  EXPECT_EQ(QualifiedName::parse("Foo"), (QualifiedName{0, "Foo"}));
  EXPECT_EQ(QualifiedName::parse("0:Foo"), (QualifiedName{0, "Foo"}));
}

TEST(TextParseQualifiedName, AReservedCharacterOfTheNameIsEscaped)
{
  // API-7.4: {0, "2:Foo"} and {2, "Foo"} no longer print alike.
  EXPECT_EQ(to_string(QualifiedName{0, "2:Foo"}), "2&:Foo");
  EXPECT_EQ(QualifiedName::parse("2&:Foo"), (QualifiedName{0, "2:Foo"}));
  // OPC 10000-4 Annex A's own examples.
  EXPECT_EQ(QualifiedName::parse("&/Name_1"), (QualifiedName{0, "/Name_1"}));
  EXPECT_EQ(QualifiedName::parse("&.Name_2"), (QualifiedName{0, ".Name_2"}));
  EXPECT_EQ(QualifiedName::parse("&:Name_3"), (QualifiedName{0, ":Name_3"}));
  EXPECT_EQ(QualifiedName::parse("&&Name_4"), (QualifiedName{0, "&Name_4"}));
  EXPECT_EQ(QualifiedName::parse("2:Block&.Output"), (QualifiedName{2, "Block.Output"}));
}

TEST(TextParseQualifiedName, EveryReservedCharacterRoundTrips)
{
  const QualifiedName name{7, "a/b.c<d>e:f#g!h&i"};
  EXPECT_EQ(to_string(name), "7:a&/b&.c&<d&>e&:f&#g&!h&&i");
  EXPECT_EQ(QualifiedName::parse(to_string(name)), name);
  const QualifiedName digits{0, "12"};
  EXPECT_EQ(QualifiedName::parse(to_string(digits)), digits) << "digits without a colon are a name";
  const QualifiedName empty{5, ""};
  EXPECT_EQ(QualifiedName::parse(to_string(empty)), empty);
  for (const auto& value : {name, digits, empty})
  {
    const auto parsed = QualifiedName::try_parse(to_string(value));
    ASSERT_TRUE(parsed.is_good()) << to_string(value);
    EXPECT_EQ(parsed.value(), value);
  }
}

TEST(TextParseQualifiedName, MalformedTextIsADecodingError)
{
  for (const std::string text : {"2:Foo:Bar", "a.b", "Foo&", "Foo&x", "70000:Foo"})
  {
    EXPECT_THROW(QualifiedName::parse(text), UaException) << text;
    const auto parsed = QualifiedName::try_parse(text);
    ASSERT_TRUE(parsed.is_bad()) << text;
    EXPECT_EQ(parsed.status_code().as_status(), Status::BadDecodingError) << text;
    ASSERT_NE(parsed.shared_detail(), nullptr) << text;
    EXPECT_EQ(parsed.shared_detail()->code, "QualifiedNameParseFailed") << text;
    EXPECT_EQ(parsed.shared_detail()->source, "QualifiedName") << text;
    ASSERT_EQ(parsed.shared_detail()->context.size(), 1) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().key, ContextKeys::value.value()) << text;
    EXPECT_EQ(parsed.shared_detail()->context.front().value, text) << text;
  }
}

TEST(TextParseQualifiedName, TheConstructorDoesNotParse)
{
  const QualifiedName name{"2:Foo"};
  EXPECT_EQ(name.namespace_index(), 0);
  EXPECT_EQ(static_cast<string_view>(name.name()), "2:Foo");
}

}  // namespace
