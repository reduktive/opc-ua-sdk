// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the native-structure decode wiring the tier-2 client read path relies on
// (client design section 8.6, matrix row ClientReadComplex.NativeStructureDecodedInPlaceNoBrowse).
//
// The client decode path (ua_client_secure_channel_impl.cpp) decodes ExtensionObjects with the resolver of
// the core `ua::StructureFactory` that `CoreClientImpl` seeds via `register_ua_data_types_with_factory` - the
// exact seeding replicated here. That resolver is a SYNCHRONOUS, self-contained function with no wire
// access, so a NATIVE NS0 structure resolves IN-PLACE (no Browse is even possible), whereas a VENDOR
// encoding the seeding never registered resolves to nullptr (the codec then preserves it as an opaque
// UnknownStructure - the lazy-resolve-via-Browse gap the integration row reports).
//
// This is distinct from tests/unit/client/type_resolver/client_type_registry_tests.cpp, which covers the
// per-Connection precedence registry `ua::client::detail::StructureFactory` (UNWIRED into the decode path);
// here the subject is the core `ua::StructureFactory` that IS wired.
//
// Falsifiability: a decode path seeded WITHOUT the NS0 types would fail SeededFactoryResolvesNativeStructure
// (native structures would surface opaque); a resolver that somehow reached the wire could not satisfy the
// "synchronous, no-Browse" contract this test's structure encodes.

#include "ua_structure_factory.h"

#include "ua_codec_namespace_context.h"
#include "ua_data_type_registration.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_server_status_data_type.h"
#include "ua_structure.h"

#include <gtest/gtest.h>

#include <memory>

namespace
{

// Seeds @p factory exactly as CoreClientImpl does for the client decode path. StructureFactory is neither
// copyable nor movable, so it is seeded in place at each call site rather than returned by value.
void seed_like_client(ua::StructureFactory& factory)
{
  ua::register_ua_data_types_with_factory(ua::CodecNamespaceContext{}, &factory, nullptr);
}

}  // namespace

// A native NS0 structure encoding resolves IN-PLACE to its concrete typed instance through the client's
// seeded factory resolver - synchronously, so no Browse discovery is needed (or possible).
TEST(ClientNativeStructureDecode, SeededFactoryResolvesNativeStructure)
{
  ua::StructureFactory factory;
  seed_like_client(factory);
  auto resolver = factory.resolver();

  std::unique_ptr<ua::Structure> instance =
    resolver(ua::NodeId{ua::ObjectId::ServerStatusDataType_Encoding_DefaultBinary});

  ASSERT_NE(instance, nullptr)
    << "the client-seeded factory must resolve a native NS0 encoding in-place (no Browse required)";
  EXPECT_NE(dynamic_cast<ua::ServerStatusDataType*>(instance.get()), nullptr)
    << "the resolved instance must be the concrete generated type, ready for in-place decode";
}

// A vendor encoding the seeding never registered resolves to nullptr - the codec then preserves it as an
// opaque UnknownStructure. This is the client-observable substrate of the (unbuilt) lazy-resolve gap.
TEST(ClientNativeStructureDecode, SeededFactoryLeavesVendorEncodingUnresolved)
{
  ua::StructureFactory factory;
  seed_like_client(factory);
  auto resolver = factory.resolver();

  std::unique_ptr<ua::Structure> instance = resolver(ua::NodeId{uint16_t{5}, uint32_t{77001}});

  EXPECT_EQ(instance, nullptr)
    << "an unregistered vendor encoding must resolve to nullptr (decoded opaque; no lazy Browse is wired)";
}
