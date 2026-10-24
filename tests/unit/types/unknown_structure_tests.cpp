// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_byte_string.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"
#include "ua_unknown_structure.h"

using namespace ua;

namespace
{

ByteString make_body(std::initializer_list<uint8_t> bytes)
{
  return ByteString{bytes};
}

}  // namespace

// The empty-body form holds only the encoding id; the body is empty and defaults to Binary.
TEST(UnknownStructureTest, EmptyBodyFormHoldsOnlyEncodingId)
{
  const NodeId encodingId{0, 297u};
  UnknownStructure unknown{encodingId};

  EXPECT_EQ(unknown.encoding_id(), encodingId);
  EXPECT_EQ(unknown.body_encoding(), UnknownStructure::BodyEncoding::Binary);
  EXPECT_EQ(unknown.encoded_data().size(), 0u);
}

// The body-preserving form round-trips the encoding id, the body-encoding tag, and the raw bytes.
TEST(UnknownStructureTest, PreservesEncodingTagAndBody)
{
  const NodeId encodingId{2, 5001u};
  const ByteString body = make_body({0xDE, 0xAD, 0xBE, 0xEF});

  UnknownStructure unknown{encodingId, UnknownStructure::BodyEncoding::Xml, body};

  EXPECT_EQ(unknown.encoding_id(), encodingId);
  EXPECT_EQ(unknown.body_encoding(), UnknownStructure::BodyEncoding::Xml);
  EXPECT_EQ(unknown.encoded_data(), body);
}

// The DataType id is genuinely unknown - only the encoding id is held - so type_id is unsupported.
TEST(UnknownStructureTest, TypeIdIsUnsupported)
{
  UnknownStructure unknown{NodeId{0, 297u}};

  EXPECT_THROW(unknown.type_id(), UaException);
  EXPECT_THROW((void)unknown.type_id(CodecNamespaceContext{}), UaException);
}

// is_of_type can never positively match a queried DataType id (the structure's type is unknown).
TEST(UnknownStructureTest, IsOfTypeAlwaysFalse)
{
  UnknownStructure unknown{NodeId{0, 297u}};

  EXPECT_FALSE(unknown.is_of_type(CodecNamespaceContext{}, NodeId{0, 296u}));
  EXPECT_FALSE(unknown.is_of_type(CodecNamespaceContext{}, unknown.encoding_id()));
}

// clone produces an independent copy that preserves the encoding id, tag, and body.
TEST(UnknownStructureTest, CloneCopiesEncodingTagAndBody)
{
  const NodeId encodingId{3, 42u};
  const ByteString body = make_body({0x01, 0x02, 0x03});
  UnknownStructure original{encodingId, UnknownStructure::BodyEncoding::Binary, body};

  auto cloned = original.clone();
  ASSERT_NE(cloned, nullptr);

  const auto* clonedUnknown = dynamic_cast<const UnknownStructure*>(cloned.get());
  ASSERT_NE(clonedUnknown, nullptr);
  EXPECT_NE(clonedUnknown, &original);  // distinct object
  EXPECT_EQ(clonedUnknown->encoding_id(), encodingId);
  EXPECT_EQ(clonedUnknown->body_encoding(), UnknownStructure::BodyEncoding::Binary);
  EXPECT_EQ(clonedUnknown->encoded_data(), body);
}

// to_string surfaces the encoding id, the body-encoding kind, and the body size.
TEST(UnknownStructureTest, ToStringDescribesEncodingAndBody)
{
  UnknownStructure unknown{NodeId{2, 5001u}, UnknownStructure::BodyEncoding::Xml, make_body({0xAA, 0xBB})};

  const std::string text = unknown.to_string();
  EXPECT_NE(text.find("Xml"), std::string::npos);
  EXPECT_NE(text.find("bodySize=2"), std::string::npos);
}
