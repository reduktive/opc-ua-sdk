// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_encoding_limits.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_structure_factory.h"
#include "ua_unknown_structure.h"
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

Argument sample_argument()
{
  Argument argument;
  argument.name() = "Speed";
  argument.data_type() = NodeId{0, 11u};  // Double
  argument.value_rank() = -1;
  return argument;
}

// --- binary helpers ---

std::vector<byte> binary_encode_ext(const Structure* value)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(make_limit(), value);
  const auto data = device.get_data();
  return std::vector<byte>(data.begin(), data.end());
}

unique_ptr<Structure> binary_decode_ext(
  const std::vector<byte>& bytes, const StructureResolver& resolver, const EncodingLimits& limits)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  stream.write_all(bytes);
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{resolver, stream, limits};
  unique_ptr<Structure> out;
  decoder.decode(make_limit(), out);
  return out;
}

// --- xml helpers ---

std::string xml_encode_ext(const Structure* value)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  XmlEncoder encoder{CodecNamespaceContext{[](string_view) { return uint16_t{0}; }, {}, {}, {}}, stream};
  encoder.encode(make_limit(), "Value", value);
  const auto data = device.get_data();
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

unique_ptr<Structure> xml_decode_ext(string_view xml, const StructureResolver& resolver)
{
  std::vector<char> writable(xml.begin(), xml.end());
  writable.push_back('\0');
  auto context = xml::parse(writable.data());
  auto first = context.xml_element().get_first_child();
  XmlDecoder decoder{resolver, *first, EncodingLimits{}};
  unique_ptr<Structure> out;
  decoder.decode(make_limit(), "Value", false, out);
  return out;
}

StructureResolver argument_resolver(const NodeId& encodingId)
{
  return [encodingId](const NodeId& id) -> unique_ptr<Structure>
  {
    return (id == encodingId) ? make_unique<Argument>() : nullptr;
  };
}

// Canonical XML ExtensionObject for an Argument value, named "Value". The Body wraps the fields in a
// single <Argument> type element - the form the decoder expects (matching the codec's Variant
// ExtensionObject shape). i=297 is this SDK's Argument DefaultXml encoding id.
constexpr string_view argumentExtObjXml =
  "<Value>"
  "<TypeId><Identifier>i=297</Identifier></TypeId>"
  "<Body><Argument>"
  "<Name>Speed</Name>"
  "<DataType><Identifier>i=11</Identifier></DataType>"
  "<ValueRank>-1</ValueRank>"
  "</Argument></Body>"
  "</Value>";

}  // namespace

// An ExtensionObject whose binary encoding id the decoder cannot resolve is preserved verbatim, tagged
// Binary, and re-encodes byte-for-byte identically.
TEST(OpaqueStructureCodecTest, BinaryUnknownExtensionObjectRoundTripsVerbatim)
{
  const Argument argument = sample_argument();
  const std::vector<byte> original = binary_encode_ext(&argument);

  auto decoded = binary_decode_ext(original, StructureResolver{}, make_limits());
  auto* unknown = dynamic_cast<UnknownStructure*>(decoded.get());
  ASSERT_NE(unknown, nullptr);
  EXPECT_EQ(unknown->body_encoding(), UnknownStructure::BodyEncoding::Binary);
  EXPECT_EQ(unknown->encoding_id(), NodeId{Argument::defaultBinaryEncodingId});

  const std::vector<byte> roundtrip = binary_encode_ext(decoded.get());
  EXPECT_EQ(roundtrip, original);
}

// Falsifiability: with a resolver that DOES know the type, the same bytes decode to the concrete type,
// never an opaque structure.
TEST(OpaqueStructureCodecTest, BinaryKnownTypeDecodesConcretely)
{
  const Argument argument = sample_argument();
  const std::vector<byte> bytes = binary_encode_ext(&argument);

  auto decoded =
    binary_decode_ext(bytes, argument_resolver(NodeId{Argument::defaultBinaryEncodingId}), make_limits());

  EXPECT_EQ(dynamic_cast<UnknownStructure*>(decoded.get()), nullptr);
  auto* concrete = dynamic_cast<Argument*>(decoded.get());
  ASSERT_NE(concrete, nullptr);
  EXPECT_EQ(concrete->name(), "Speed");
}

// A declared body length exceeding the ByteString limit is rejected before any allocation.
TEST(OpaqueStructureCodecTest, BinaryUnknownBodyLengthBoundedByLimit)
{
  // Craft an ExtensionObject header: TypeId, encoding byte 1 (binary), then an oversized length.
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(make_limit(), NodeId{0, 9999u});
  uint8_t encoding{1};
  encoder.encode(make_limit(), encoding);
  int32_t declaredLength{1000};
  encoder.encode(make_limit(), declaredLength);
  const auto data = device.get_data();
  const std::vector<byte> bytes(data.begin(), data.end());

  EncodingLimits tightLimits = make_limits();
  tightLimits.maxByteStringLength = 10;

  EXPECT_THROW(binary_decode_ext(bytes, StructureResolver{}, tightLimits), UaException);
}

// An XML ExtensionObject whose type the decoder cannot resolve is preserved verbatim (tagged Xml); the
// re-encoded XML decodes back to the concrete type once a resolver is supplied - proving the body
// survived faithfully.
TEST(OpaqueStructureCodecTest, XmlUnknownExtensionObjectRoundTripsAndReifies)
{
  auto opaque = xml_decode_ext(argumentExtObjXml, StructureResolver{});
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);
  EXPECT_EQ(unknown->body_encoding(), UnknownStructure::BodyEncoding::Xml);
  EXPECT_EQ(unknown->encoding_id(), NodeId{Argument::defaultXmlEncodingId});

  const std::string reEncoded = xml_encode_ext(opaque.get());
  auto reified = xml_decode_ext(reEncoded, argument_resolver(NodeId{Argument::defaultXmlEncodingId}));
  auto* concrete = dynamic_cast<Argument*>(reified.get());
  ASSERT_NE(concrete, nullptr);
  EXPECT_EQ(concrete->name(), "Speed");
  EXPECT_EQ(concrete->data_type(), (NodeId{0, 11u}));
}

// The document is parsed without entity translation, so a preserved body still holds its source
// escapes; the body is kept exactly as the source spelled it (a printer that escaped it again turned
// `&amp;` into `&amp;amp;`), and an apostrophe-delimited attribute holding a quotation mark keeps its
// apostrophes so the preserved body stays well-formed. Re-encoding writes the same bytes.
// @verifies AC-COMP-CORE-XML-CODEC-03-PRESERVED-XML-KEEPS-ITS-SOURCE-SPELLING
TEST(OpaqueStructureCodecTest, APreservedXmlBodyKeepsItsSourceEscapes)
{
  constexpr string_view body{
    "<Body><Argument><Name>a &amp; b &lt; c</Name><X q='say \"hi\"' r=\"it's\"/>"
    "</Argument></Body>"};
  const std::string xml =
    "<Value><TypeId><Identifier>i=297</Identifier></TypeId>" + std::string{body} + "</Value>";

  auto opaque = xml_decode_ext(xml, StructureResolver{});
  auto* unknown = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);
  const auto& preserved = unknown->encoded_data();
  EXPECT_EQ(
    (std::string{reinterpret_cast<const char*>(preserved.data()), preserved.size()}), std::string{body});

  const std::string reEncoded = xml_encode_ext(opaque.get());
  EXPECT_NE(reEncoded.find(body), std::string::npos) << reEncoded;
  EXPECT_EQ(reEncoded.find("&amp;amp;"), std::string::npos) << reEncoded;
}

// Cross-encoding: an XML-sourced opaque body re-encodes into a BINARY ExtensionObject (using encoding
// byte 2) and decodes back as the same opaque value - same Xml tag, encoding id, and body.
TEST(OpaqueStructureCodecTest, XmlSourcedOpaqueReEncodesToBinaryPreservingBody)
{
  auto opaque = xml_decode_ext(argumentExtObjXml, StructureResolver{});
  auto* xmlOpaque = dynamic_cast<UnknownStructure*>(opaque.get());
  ASSERT_NE(xmlOpaque, nullptr);

  const std::vector<byte> asBinary = binary_encode_ext(opaque.get());
  auto roundTripped = binary_decode_ext(asBinary, StructureResolver{}, make_limits());

  auto* binOpaque = dynamic_cast<UnknownStructure*>(roundTripped.get());
  ASSERT_NE(binOpaque, nullptr);
  EXPECT_EQ(binOpaque->body_encoding(), UnknownStructure::BodyEncoding::Xml);
  EXPECT_EQ(binOpaque->encoding_id(), xmlOpaque->encoding_id());
  EXPECT_EQ(binOpaque->encoded_data(), xmlOpaque->encoded_data());
}

// A binary-sourced opaque body cannot be re-encoded as XML (the XML encoding id is not held); the
// encoder fails loudly rather than fabricate.
TEST(OpaqueStructureCodecTest, BinarySourcedOpaqueCannotEncodeAsXml)
{
  const Argument argument = sample_argument();
  auto opaque = binary_decode_ext(binary_encode_ext(&argument), StructureResolver{}, make_limits());
  ASSERT_NE(dynamic_cast<UnknownStructure*>(opaque.get()), nullptr);

  EXPECT_THROW(xml_encode_ext(opaque.get()), UaException);
}
