// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7 companion-spec integration tests - codec / registration rows.
///
/// Row 3: cross-spec field round-trip - a DI structure whose fields are NS0
///        types (StatusCode, QualifiedName[], DiagnosticInfo) encodes and
///        decodes losslessly.
/// Row 5: per-spec registration coexistence - NS0 and DI types register into a
///        single StructureFactory with no collision, and both resolve.
/// Row 6: runtime namespace-index resolution under a NON-default namespace table
///        - the DI type resolves its own NodeId (and encoding id) via the spec
///        URI at runtime, landing in whatever index the table assigns DI.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_type_registration.h"  // NS0: register_ua_data_types_with_factory
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_status_code.h"
#include "ua_structure_factory.h"
#include "ua_utilities.h"  // utils::to_underlying

#include "ua_di_data_type_registration.h"  // DI: register_ua_di_data_types_with_factory
#include "ua_di_object_id.h"
#include "ua_di_parameter_result_data_type.h"

using namespace ua;
using namespace std::string_view_literals;

namespace
{
constexpr auto diUri = "http://opcfoundation.org/UA/DI/"sv;

// A deliberately NON-default namespace table: DI is assigned index 3 (not the
// usual 1/2), so a hard-coded NS0 assumption would resolve the wrong index.
constexpr uint16_t diIndex = 3;

CodecNamespaceContext make_context()
{
  auto lookup = [](string_view uri) -> uint16_t
  {
    return uri == diUri ? diIndex : uint16_t{0};
  };
  return CodecNamespaceContext{lookup, {}, {}, {}};
}

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
}  // namespace

// Row 6 - runtime ns-index resolution under a non-default table.
TEST(DiCodecTests, RuntimeNamespaceIndexResolution)
{
  const auto ctx = make_context();
  ua::di::ParameterResultDataType value;

  // type_id resolves the DI URI to the table's index at runtime - NOT NS0.
  const NodeId typeId = value.type_id(ctx);
  EXPECT_EQ(typeId, (NodeId{diIndex, ua::utils::to_underlying(ua::di::ParameterResultDataType::typeId)}));
  EXPECT_EQ(typeId.namespace_index(), diIndex);
}

// Row 5 - per-spec registration coexistence.
TEST(DiCodecTests, PerSpecRegistrationCoexistence)
{
  const auto ctx = make_context();
  StructureFactory factory;

  // Both specs register into the SAME factory without collision.
  ASSERT_NO_THROW(register_ua_data_types_with_factory(ctx, &factory, nullptr));
  ASSERT_NO_THROW(ua::di::register_ua_di_data_types_with_factory(ctx, &factory, nullptr));

  // The DI encoding id (resolved at the non-default index 3) is now known to the
  // factory and constructs the DI type.
  const NodeId diEncodingId{
    diIndex, static_cast<uint32_t>(ua::di::ObjectId::ParameterResultDataType_Encoding_DefaultBinary)};
  auto created = factory.create_instance(diEncodingId);
  ASSERT_NE(created, nullptr) << "DI encoding id must resolve via the shared factory";
  EXPECT_NE(dynamic_cast<ua::di::ParameterResultDataType*>(created.get()), nullptr);

  // A well-known NS0 encoding id still resolves too - the DI registration did
  // not clobber NS0's entries.
  const NodeId ns0KeyValuePair{0, static_cast<uint32_t>(ua::ObjectId::KeyValuePair_Encoding_DefaultBinary)};
  EXPECT_NE(factory.create_instance(ns0KeyValuePair), nullptr)
    << "NS0 registration must coexist with DI registration";
}

// Row 3 - cross-spec field round-trip (NS0-typed fields on a DI structure).
TEST(DiCodecTests, CrossSpecFieldRoundTrip)
{
  const auto ctx = make_context();

  ua::di::ParameterResultDataType input;
  input.status_code() = ua::StatusCode{ua::Status::BadDeviceFailure};
  input.node_path().push_back(QualifiedName{0, "DeviceHealth"});
  input.node_path().push_back(QualifiedName{diIndex, "Maintenance"});

  // Encode the DI structure's fields (NS0 types) with the binary codec.
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder{ctx, stream};
  encoder.encode(stack_limit(), input);

  // Decode back into a fresh DI instance via a factory-backed decoder.
  StructureFactory factory;
  register_ua_data_types_with_factory(ctx, &factory, nullptr);
  ua::di::register_ua_di_data_types_with_factory(ctx, &factory, nullptr);

  stream.seek_from_start(0);
  UaBinaryDecoder decoder{factory.resolver(), stream, encoding_limits()};
  ua::di::ParameterResultDataType output;
  decoder.decode(stack_limit(), output);

  EXPECT_EQ(output.status_code().as_uint32(), input.status_code().as_uint32());
  ASSERT_EQ(output.node_path().size(), 2u);
  EXPECT_EQ(output.node_path()[0].name(), "DeviceHealth");
  EXPECT_EQ(output.node_path()[1].namespace_index(), diIndex);
  EXPECT_EQ(output.node_path()[1].name(), "Maintenance");
}
