// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7 - verify cross-spec UAUnion code generation: the generated companion
/// union (``ua::uniontest::TestUnion``) binary-encodes and decodes each variant
/// losslessly, and registers into a StructureFactory with its namespace index
/// resolved at runtime (the union encode_id/register path).

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_structure_factory.h"

#include "ua_uniontest_data_type_registration.h"
#include "ua_uniontest_test_union.h"

using namespace ua;
using namespace std::string_view_literals;

namespace
{
using TestUnion = ua::uniontest::TestUnion;
constexpr auto unionUri = "urn:example:union-test"sv;
constexpr uint16_t unionIndex = 4;  // deliberately non-default

StackDepth stack_limit()
{
  const auto cfg = ApplicationConfig::load_default();
  return StackDepth{cfg.execution_limits().decodeWorkLimit};
}

const EncodingLimits& encoding_limits()
{
  static EncodingLimits limits = []
  {
    return make_encoding_limits(ApplicationConfig::load_default());
  }();
  return limits;
}

// Binary round-trip a TestUnion through a concrete decode (fields are built-ins,
// so no factory polymorphism is needed for the value itself).
TestUnion round_trip(const TestUnion& input)
{
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(stack_limit(), input);

  StructureFactory factory;  // empty - supplies a resolver for the decoder
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, encoding_limits()};
  TestUnion output;
  decoder.decode(stack_limit(), output);
  return output;
}
}  // namespace

// The integer-selecting variant round-trips: active field + value preserved.
TEST(UnionCodecTests, IntVariantRoundTrips)
{
  TestUnion input;
  input.int_value(4242);
  ASSERT_EQ(input.active_field(), TestUnion::Field::IntValue);

  const TestUnion output = round_trip(input);
  EXPECT_EQ(output.active_field(), TestUnion::Field::IntValue);
  ASSERT_NE(output.try_int_value(), nullptr);
  EXPECT_EQ(output.int_value(), 4242);
  EXPECT_EQ(output.try_text_value(), nullptr) << "inactive variant must not be set";
}

// The string-selecting variant round-trips independently.
TEST(UnionCodecTests, TextVariantRoundTrips)
{
  TestUnion input;
  input.text_value(String{"profibus"});
  ASSERT_EQ(input.active_field(), TestUnion::Field::TextValue);

  const TestUnion output = round_trip(input);
  EXPECT_EQ(output.active_field(), TestUnion::Field::TextValue);
  ASSERT_NE(output.try_text_value(), nullptr);
  EXPECT_EQ(output.text_value(), "profibus");
}

// The empty (no-field) union round-trips as Field::None.
TEST(UnionCodecTests, EmptyUnionRoundTrips)
{
  TestUnion input;
  ASSERT_EQ(input.active_field(), TestUnion::Field::None);
  EXPECT_EQ(round_trip(input).active_field(), TestUnion::Field::None);
}

// The union registers into a StructureFactory with its encoding NodeId resolved
// at runtime from the spec URI (the companion union encode_id/register path),
// landing at the table's non-default index.
TEST(UnionCodecTests, RegistersWithRuntimeResolvedNamespaceIndex)
{
  auto lookup = [](string_view uri) -> uint16_t
  {
    return uri == unionUri ? unionIndex : uint16_t{0};
  };
  const CodecNamespaceContext ctx{lookup, {}, {}, {}};

  StructureFactory factory;
  ASSERT_NO_THROW(ua::uniontest::register_ua_uniontest_data_types_with_factory(ctx, &factory, nullptr));

  // TestUnion's Default Binary encoding id is i=5001 in the union-test namespace,
  // resolved to the table's index 4 at registration time.
  auto created = factory.create_instance(NodeId{unionIndex, 5001u});
  ASSERT_NE(created, nullptr) << "union encoding id must resolve via the factory at the runtime index";
  EXPECT_NE(dynamic_cast<TestUnion*>(created.get()), nullptr);
}
