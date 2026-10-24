// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase A (item 1) - verify SymbolicName-based identifier sanitization on a real
/// companion spec. BACnet's NodeSet uses field/enum names that are not valid C++
/// identifiers (hyphens, spaces, leading digits), with the C++-safe spelling in a
/// sibling ``SymbolicName`` attribute. The generator must:
///   * derive valid C++ identifiers (from SymbolicName, else sanitised), and
///   * keep the original spec spelling for any on-wire string.
/// These tests prove the generated BACnet types compile, the sanitised enum
/// members carry the correct values, and an all-enum struct binary round-trips
/// losslessly (so the encode/decode field handling agrees end to end).

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_structure_factory.h"

#include "ua_bacnet_ba_cnet_day.h"
#include "ua_bacnet_ba_cnet_day_of_week.h"
#include "ua_bacnet_ba_cnet_month.h"
#include "ua_bacnet_ba_cnet_week_n_day.h"
#include "ua_bacnet_data_type_registration.h"
#include "ua_bacnet_namespace_uri.h"

using namespace ua;
using namespace std::string_view_literals;

namespace
{
using ua::bacnet::BACnetDay;
using ua::bacnet::BACnetDayOfWeek;
using ua::bacnet::BACnetMonth;
using ua::bacnet::BACnetWeekNDay;

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

BACnetWeekNDay round_trip(const BACnetWeekNDay& input)
{
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(stack_limit(), input);

  StructureFactory factory;  // empty - supplies a resolver for the decoder
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, encoding_limits()};
  BACnetWeekNDay output;
  decoder.decode(stack_limit(), output);
  return output;
}
}  // namespace

// A field name that is illegal as a C++ identifier in the NodeSet
// (``Name="days numbered 1-7"``) is emitted from its ``SymbolicName``
// (``days_numbered_1_7``) and carries the spec's numeric value.
TEST(BACnetCodecTests, SanitisedEnumMemberHasCorrectValue)
{
  EXPECT_EQ(static_cast<int32_t>(BACnetDay::days_numbered_1_7), 1);
  EXPECT_EQ(static_cast<int32_t>(BACnetDay::days_numbered_29_31), 5);
}

// The enum to_string helper compiles and returns the C++ (sanitised) spelling -
// enum values travel on the wire as int32, so this string is diagnostic only.
TEST(BACnetCodecTests, SanitisedEnumToString)
{
  EXPECT_EQ(ua::bacnet::to_string(BACnetDay::days_numbered_1_7), "days_numbered_1_7");
}

// An all-enum BACnet struct round-trips: each enum field (including the sanitised
// BACnetDay) is preserved through binary encode/decode.
TEST(BACnetCodecTests, WeekNDayRoundTrips)
{
  BACnetWeekNDay input;
  input.month() = BACnetMonth::March;
  input.day() = BACnetDay::days_numbered_15_21;
  input.day_of_week() = BACnetDayOfWeek::Wednesday;

  const BACnetWeekNDay output = round_trip(input);
  EXPECT_EQ(output.month(), BACnetMonth::March);
  EXPECT_EQ(output.day(), BACnetDay::days_numbered_15_21);
  EXPECT_EQ(output.day_of_week(), BACnetDayOfWeek::Wednesday);
}

// The BACnet data types register into a StructureFactory with their encoding
// NodeIds resolved at runtime from the spec URI, and an encodable struct is
// constructible via the factory at the runtime namespace index.
TEST(BACnetCodecTests, RegistersWithRuntimeResolvedNamespaceIndex)
{
  constexpr uint16_t bacnetIndex = 7;  // deliberately non-default
  auto lookup = [](string_view uri) -> uint16_t
  {
    return uri == ua::bacnet::specNamespaceUri ? bacnetIndex : uint16_t{0};
  };
  const CodecNamespaceContext ctx{lookup, {}, {}, {}};

  StructureFactory factory;
  ASSERT_NO_THROW(ua::bacnet::register_ua_bacnet_data_types_with_factory(ctx, &factory, nullptr));

  auto created = factory.create_instance(
    NodeId{bacnetIndex, static_cast<uint32_t>(BACnetWeekNDay::defaultBinaryEncodingId)});
  ASSERT_NE(created, nullptr) << "BACnet encoding id must resolve via the factory at runtime index";
  EXPECT_NE(dynamic_cast<BACnetWeekNDay*>(created.get()), nullptr);
}
