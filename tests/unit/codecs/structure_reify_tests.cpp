// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_ref_structure.h"
#include "ua_structure.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"
#include "ua_xml_codec.h"

using namespace ua;

namespace
{

StackDepth make_limit()
{
  return StackDepth{ApplicationConfig::load_default().execution_limits().decodeWorkLimit};
}

EncodingLimits make_limits()
{
  return make_encoding_limits(ApplicationConfig::load_default());
}

// Produce a binary-sourced opaque UnknownStructure for an Argument by encoding then decoding with no
// resolver.
unique_ptr<Structure> make_binary_opaque(const Argument& argument)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(make_limit(), &argument);
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{StructureResolver{}, stream, make_limits()};
  unique_ptr<Structure> opaque;
  decoder.decode(make_limit(), opaque);
  return opaque;
}

// Produce an XML-sourced opaque UnknownStructure from canonical ExtensionObject XML.
unique_ptr<Structure> make_xml_opaque(string_view xml)
{
  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto first = context.xml_element().get_first_child();
  XmlDecoder decoder{StructureResolver{}, *first, EncodingLimits{}};
  unique_ptr<Structure> opaque;
  decoder.decode(make_limit(), "Value", false, opaque);
  return opaque;
}

StructureResolver argument_resolver(const NodeId& encodingId)
{
  return [encodingId](const NodeId& id) -> unique_ptr<Structure>
  {
    return (id == encodingId) ? make_unique<Argument>() : nullptr;
  };
}

Argument sample_argument()
{
  Argument argument;
  argument.name() = "Speed";
  argument.data_type() = NodeId{0, 11u};
  argument.value_rank() = -1;
  return argument;
}

constexpr string_view argumentXml =
  "<Value>"
  "<TypeId><Identifier>i=297</Identifier></TypeId>"
  "<Body><Argument>"
  "<Name>Speed</Name>"
  "<DataType><Identifier>i=11</Identifier></DataType>"
  "<ValueRank>-1</ValueRank>"
  "</Argument></Body>"
  "</Value>";

// Canonical XML whose embedded DataType id is in a file-local namespace (ns=1) - the import-provenance
// case for translate-at-decode_unknown.
constexpr string_view argumentXmlNs1 =
  "<Value>"
  "<TypeId><Identifier>i=297</Identifier></TypeId>"
  "<Body><Argument>"
  "<Name>Speed</Name>"
  "<DataType><Identifier>ns=1;i=600</Identifier></DataType>"
  "<ValueRank>-1</ValueRank>"
  "</Argument></Body>"
  "</Value>";

}  // namespace

// A binary-sourced opaque value reifies to the concrete type once a resolver knows its encoding id.
TEST(StructureReifyTest, ReifyBinaryOpaqueToConcreteType)
{
  auto opaque = make_binary_opaque(sample_argument());
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);

  auto result =
    decode_unknown(*unknown, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());
  ASSERT_TRUE(result.is_good());
  auto* argument = dynamic_cast<Argument*>(result.value().get());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "Speed");
  EXPECT_EQ(argument->data_type(), (NodeId{0, 11u}));
}

// An XML-sourced opaque value reifies to the concrete type.
TEST(StructureReifyTest, ReifyXmlOpaqueToConcreteType)
{
  auto opaque = make_xml_opaque(argumentXml);
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);

  auto result =
    decode_unknown(*unknown, argument_resolver(NodeId{Argument::defaultXmlEncodingId}), make_limits());
  ASSERT_TRUE(result.is_good());
  auto* argument = dynamic_cast<Argument*>(result.value().get());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "Speed");
  EXPECT_EQ(argument->data_type(), (NodeId{0, 11u}));
}

// When the resolver still cannot resolve the type, decode_unknown returns the value unchanged (still opaque).
TEST(StructureReifyTest, ReifyUnresolvedReturnsOpaqueUnchanged)
{
  auto opaque = make_binary_opaque(sample_argument());
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);

  auto result = decode_unknown(*unknown, StructureResolver{}, make_limits());
  ASSERT_TRUE(result.is_good());
  EXPECT_NE(dynamic_cast<UnknownStructure*>(result.value().get()), nullptr);
}

// Reify applies the namespace config, translating embedded ids - the import-provenance path (a body
// whose embedded DataType id is in a file-local namespace gets the server index at decode_unknown time).
TEST(StructureReifyTest, ReifyTranslatesEmbeddedIds)
{
  auto opaque = make_xml_opaque(argumentXmlNs1);
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);

  CodecNamespaceContext ns;
  ns.translateNodeId = [](NodeId& id)
  {
    if (id.namespace_index() == 1)
    {
      id.namespace_index() = 7;
    }
  };

  auto result =
    decode_unknown(*unknown, argument_resolver(NodeId{Argument::defaultXmlEncodingId}), make_limits(), ns);
  ASSERT_TRUE(result.is_good());
  auto* argument = dynamic_cast<Argument*>(result.value().get());
  ASSERT_NE(argument, nullptr);
  // The embedded DataType id (ns=1;i=600 in the body) carries the translated server index.
  EXPECT_EQ(argument->data_type().namespace_index(), 7);
  EXPECT_EQ(argument->data_type().identifier().get_numeric(), 600u);
}

// decode_unknowns_in_place upgrades a scalar opaque value held in a Variant.
TEST(StructureReifyTest, ReifyInPlaceScalar)
{
  Variant value{make_binary_opaque(sample_argument())};
  ASSERT_TRUE(value.is_structure());
  ASSERT_NE(dynamic_cast<const UnknownStructure*>(&value.as<Structure>()), nullptr);

  decode_unknowns_in_place(
    value, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  ASSERT_TRUE(value.is_structure());
  EXPECT_EQ(dynamic_cast<const UnknownStructure*>(&value.as<Structure>()), nullptr);
  const auto* argument = dynamic_cast<const Argument*>(&value.as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "Speed");
}

// decode_unknowns_in_place upgrades each opaque element of a structure array.
TEST(StructureReifyTest, ReifyInPlaceArray)
{
  Array<RefStructure<Structure>> array;
  array.payload().emplace_back(make_binary_opaque(sample_argument()));
  array.payload().emplace_back(make_binary_opaque(sample_argument()));
  Variant value{std::move(array)};
  ASSERT_TRUE(value.is_array_of_structure());

  decode_unknowns_in_place(
    value, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  auto& reified = value.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(reified.payload().size(), 2u);
  for (auto& reference : reified.payload())
  {
    EXPECT_EQ(dynamic_cast<const UnknownStructure*>(&(*reference)), nullptr);
    EXPECT_NE(dynamic_cast<const Argument*>(&(*reference)), nullptr);
  }
}

// A Variant decoded from the wire, with no resolver, as the client decodes a server's response.
Variant decode_wire_variant(const std::vector<byte>& bytes)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  stream.write_all(bytes);
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{StructureResolver{}, stream, make_limits()};
  Variant value;
  decoder.decode(make_limit(), value);
  return value;
}

// An ExtensionObject with encoding byte 0 has no body, and the decoder leaves its element empty. A server
// can send an array of them; reifying such an array dereferenced the empty element and aborted the client.
TEST(StructureReifyTest, ReifyInPlaceSkipsEmptyElementsOfADecodedArray)
{
  // Variant: ExtensionObject array (0x16 | 0x80) of 2, each NodeId ns=0;i=0 (0x00 0x00) with no body (0x00).
  auto value = decode_wire_variant({byte{0x96}, byte{0x02}, byte{0x00}, byte{0x00}, byte{0x00}, byte{0x00},
    byte{0x00}, byte{0x00}, byte{0x00}, byte{0x00}, byte{0x00}});
  ASSERT_TRUE(value.is_array_of_structure());
  ASSERT_EQ(value.as<Array<RefStructure<Structure>>>().payload().size(), 2u);
  ASSERT_FALSE(value.as<Array<RefStructure<Structure>>>().payload()[1]);

  decode_unknowns_in_place(value, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  for (const auto& reference : value.as<Array<RefStructure<Structure>>>().payload())
  {
    EXPECT_FALSE(reference) << "an element with no body stays empty";
  }
}

// The same for a single ExtensionObject with no body.
TEST(StructureReifyTest, ReifyInPlaceSkipsADecodedScalarWithNoBody)
{
  auto value = decode_wire_variant({byte{0x16}, byte{0x00}, byte{0x00}, byte{0x00}});
  ASSERT_TRUE(value.is_structure());
  ASSERT_FALSE(value.as<RefStructure<Structure>>());

  decode_unknowns_in_place(value, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  EXPECT_FALSE(value.as<RefStructure<Structure>>()) << "an ExtensionObject with no body stays empty";
}

// Empty elements are skipped, and the opaque elements around them are still reified.
TEST(StructureReifyTest, ReifyInPlaceReifiesTheElementsAroundAnEmptyOne)
{
  Array<RefStructure<Structure>> array;
  array.payload().emplace_back(make_binary_opaque(sample_argument()));
  array.payload().emplace_back();
  Variant value{std::move(array)};

  decode_unknowns_in_place(value, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  const auto& reified = value.as<Array<RefStructure<Structure>>>().payload();
  ASSERT_EQ(reified.size(), 2u);
  ASSERT_TRUE(reified[0]);
  EXPECT_NE(dynamic_cast<const Argument*>(&(*reified[0])), nullptr);
  EXPECT_FALSE(reified[1]);
}

// decode_unknowns_in_place is a no-op (and idempotent) when the resolver cannot resolve the type.
TEST(StructureReifyTest, ReifyInPlaceNoOpWhenUnresolved)
{
  Variant value{make_binary_opaque(sample_argument())};

  decode_unknowns_in_place(value, StructureResolver{}, make_limits());

  ASSERT_TRUE(value.is_structure());
  EXPECT_NE(dynamic_cast<const UnknownStructure*>(&value.as<Structure>()), nullptr);
}

// ============================================================================================
// Security review 2026-09-28: a hostile server's XML body is bounded and never loses the caller's
// completion (a malformed body is Bad_DecodingError with a detail; the value stays opaque).
// ============================================================================================

namespace
{

unique_ptr<UnknownStructure> xml_opaque_with_body(string_view body)
{
  std::vector<uint8_t> bytes(body.begin(), body.end());
  return make_unique<UnknownStructure>(NodeId{Argument::defaultXmlEncodingId},
    UnknownStructure::BodyEncoding::Xml,
    ByteString{std::move(bytes)});
}

}  // namespace

// @relation(AC-CL-ADDRSP-007-XML-ELEMENT-NESTING-IS-BOUNDED, scope=function)
TEST(StructureReifyTest, DecodeUnknownDeeplyNestedXmlBodyIsRejectedNotCrashed)
{
  std::string body = "<Body>";
  for (int i = 0; i < 2000; ++i)
  {
    body += "<a>";
  }
  auto opaque = xml_opaque_with_body(body);
  auto result =
    decode_unknown(*opaque, argument_resolver(NodeId{Argument::defaultXmlEncodingId}), make_limits());
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded);
}

// The client reifies XML bodies a server chose under the client's EncodingLimits: an array in the
// body longer than the maximum array length is Bad_EncodingLimitsExceeded, as it is in UA Binary, and
// one at the limit reifies.
// @verifies AC-COMP-CORE-XML-CODEC-06-XML-TEXT-FOLLOWS-THE-XSD-LEXICAL-FORMS-AND-LIMITS
TEST(StructureReifyTest, AReifiedXmlArrayLongerThanTheMaximumArrayLengthIsRefused)
{
  const std::string body =
    "<Body><Argument><Name>Speed</Name><DataType><Identifier>i=11</Identifier></DataType>"
    "<ValueRank>1</ValueRank><ArrayDimensions><UInt32>1</UInt32><UInt32>2</UInt32>"
    "<UInt32>3</UInt32></ArrayDimensions></Argument></Body>";
  auto limits = make_limits();

  limits.maxArrayLength = 2;
  auto refused = decode_unknown(
    *xml_opaque_with_body(body), argument_resolver(NodeId{Argument::defaultXmlEncodingId}), limits);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadEncodingLimitsExceeded);

  limits.maxArrayLength = 3;
  auto reified = decode_unknown(
    *xml_opaque_with_body(body), argument_resolver(NodeId{Argument::defaultXmlEncodingId}), limits);
  ASSERT_TRUE(reified.is_good());
  const auto* argument = dynamic_cast<const Argument*>(reified.value().get());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->array_dimensions().payload().size(), 3u);
}

// Part 6 section 5.2.2.8: a body that does not decode is reported as Bad_DecodingError; the parser's own
// exception type must not escape past the reify boundary (it lost the caller's completion).
// @relation(AC-CL-ADDRSP-013-A-BODY-THAT-CANNOT-BE-REIFIED-IS-A-DECODING-ERROR, scope=function)
TEST(StructureReifyTest, DecodeUnknownMalformedXmlBodyIsBadDecodingErrorWithDetail)
{
  auto opaque = xml_opaque_with_body("x");
  auto result =
    decode_unknown(*opaque, argument_resolver(NodeId{Argument::defaultXmlEncodingId}), make_limits());
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadDecodingError);
  const auto detail = result.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ExtensionObjectBodyDecodeFailed");
}

// @relation(AC-CL-ADDRSP-013-A-BODY-THAT-CANNOT-BE-REIFIED-IS-A-DECODING-ERROR, scope=function)
TEST(StructureReifyTest, DecodeUnknownsInPlaceLeavesAMalformedValueIntact)
{
  Variant value{xml_opaque_with_body("x")};
  ASSERT_NO_THROW(decode_unknowns_in_place(value,
    argument_resolver(NodeId{Argument::defaultXmlEncodingId}),
    make_limits(),
    CodecNamespaceContext{}));
  ASSERT_TRUE(value.is_structure());
  EXPECT_NE(dynamic_cast<const UnknownStructure*>(&value.as<Structure>()), nullptr)
    << "the value stays opaque rather than being dropped";
}
