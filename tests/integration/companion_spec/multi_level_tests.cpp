// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase B (item 5) - multi-level companion stacking. lvl2 depends on a non-NS0
/// lookup spec (lvl1): ua::lvl2::Lvl2Line has fields typed by ua::lvl1::Lvl1Point.
/// These tests prove the cross-spec type resolves (the field IS ua::lvl1::Lvl1Point,
/// which only compiles if the canonical-namespace remapping + cross-spec
/// qualification worked) and that a value with nested cross-spec structs binary
/// round-trips losslessly (the nested lvl1 codec is reached across the link).

#include <gtest/gtest.h>
#include <type_traits>

#include "ua_application_configuration.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_structure_factory.h"

#include "ua_lvl1_lvl1_point.h"
#include "ua_lvl2_lvl2_line.h"

using namespace ua;

namespace
{
using ua::lvl1::Lvl1Point;
using ua::lvl2::Lvl2Line;

// Compile-time proof that the cross-spec field type resolved to the lvl1 type
// (not the Structure base it would fall back to without canonicalisation).
static_assert(
  std::is_same_v<std::remove_cvref_t<decltype(std::declval<Lvl2Line>().start_point())>, Lvl1Point>,
  "Lvl2Line.start_point must be the cross-spec ua::lvl1::Lvl1Point");

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

Lvl2Line round_trip(const Lvl2Line& input)
{
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(stack_limit(), input);

  StructureFactory factory;
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, encoding_limits()};
  Lvl2Line output;
  decoder.decode(stack_limit(), output);
  return output;
}
}  // namespace

// A level-2 struct with nested level-1 structs round-trips: the nested lvl1
// Lvl1Point fields are encoded/decoded across the spec boundary.
TEST(MultiLevelTests, Lvl2LineWithNestedLvl1PointsRoundTrips)
{
  Lvl2Line input;
  input.start_point().x() = 1;
  input.start_point().y() = 2;
  input.end_point().x() = 30;
  input.end_point().y() = 40;
  input.thickness() = 7;

  const Lvl2Line output = round_trip(input);

  EXPECT_EQ(output.start_point().x(), 1);
  EXPECT_EQ(output.start_point().y(), 2);
  EXPECT_EQ(output.end_point().x(), 30);
  EXPECT_EQ(output.end_point().y(), 40);
  EXPECT_EQ(output.thickness(), 7);
}

// The lvl1 lookup spec's own type registers + round-trips standalone (sanity that
// the lvl1 library built from the same multi-level run is itself well-formed).
TEST(MultiLevelTests, Lvl1PointRoundTrips)
{
  Lvl1Point input;
  input.x() = 11;
  input.y() = 22;

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(stack_limit(), input);

  StructureFactory factory;
  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, encoding_limits()};
  Lvl1Point output;
  decoder.decode(stack_limit(), output);

  EXPECT_EQ(output.x(), 11);
  EXPECT_EQ(output.y(), 22);
}
