// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7 companion-spec integration tests - compile/coexistence rows.
///
/// Row 2: a companion-spec (DI) data type derives from the NS0 ``::ua::Structure``
///        base and is usable polymorphically through it (cross-spec inheritance
///        compiles, links, and behaves).
/// Row 4: NS0 and DI identifier enums are distinct types that coexist in a single
///        translation unit without name collision (``ua::ObjectId`` +
///        ``ua::di::ObjectId``).
///
/// These rows are about the *shape* of the generated code, so the fact that this
/// file compiles and links against both ``sdk`` and ``ua_di_types`` is itself a
/// large part of the assertion; the runtime checks pin the behaviour.

#include <gtest/gtest.h>

#include <type_traits>

#include "ua_data_type_of.h"
#include "ua_di_datatype_id.h"
#include "ua_di_device_health_enumeration.h"
#include "ua_di_namespace_uri.h"
#include "ua_di_object_id.h"
#include "ua_di_objecttype_id.h"
#include "ua_di_parameter_result_data_type.h"

#include "ua_object_id.h"
#include "ua_status_code.h"
#include "ua_structure.h"

// Row 2 - cross-spec parent class.
TEST(DiCompileTests, CrossSpecParentClassDerivesFromNs0Structure)
{
  ua::di::ParameterResultDataType value;

  // The DI type IS-A NS0 ``ua::Structure`` and is usable through that base.
  ::ua::Structure& asBase = value;

  // It advertises the DI namespace URI, not NS0's.
  EXPECT_EQ(ua::di::ParameterResultDataType::typeNamespaceUri, "http://opcfoundation.org/UA/DI/");

  // Polymorphic clone through the NS0 base yields the concrete DI type back.
  auto cloned = asBase.clone();
  ASSERT_NE(cloned, nullptr);
  EXPECT_NE(dynamic_cast<ua::di::ParameterResultDataType*>(cloned.get()), nullptr)
    << "clone() through the NS0 base must preserve the DI dynamic type";

  // NS0-typed fields declared by the DI type are reachable and settable.
  value.status_code() = ua::StatusCode{ua::Status::BadDeviceFailure};
  EXPECT_EQ(value.status_code().as_uint32(), ua::StatusCode{ua::Status::BadDeviceFailure}.as_uint32());
}

// Row 4 - identifier-enum coexistence.
TEST(DiCompileTests, IdentifierEnumsCoexistInOneTranslationUnit)
{
  // Distinct enum *types* - proven at compile time.
  static_assert(
    !std::is_same_v<ua::ObjectId, ua::di::ObjectId>, "NS0 and DI ObjectId must be distinct enum types");
  static_assert(!std::is_same_v<ua::ObjectTypeId, ua::di::ObjectTypeId>,
    "NS0 and DI ObjectTypeId must be distinct enum types");

  // Each carries its own spec's numbering, side by side in this TU.
  const ua::ObjectId ns0 = ua::ObjectId::ObjectsFolder;
  const ua::di::ObjectId di = ua::di::ObjectId::DeviceSet;
  const ua::di::ObjectTypeId diDeviceType = ua::di::ObjectTypeId::DeviceType;

  EXPECT_EQ(static_cast<uint32_t>(di), 5001u);
  EXPECT_EQ(static_cast<uint32_t>(diDeviceType), 1002u);
  EXPECT_NE(static_cast<uint32_t>(ns0), static_cast<uint32_t>(di));
}

// Item 8b section 9.3 (D-20): a companion specification's structure and enumeration name their DataType by
// its identifier in the specification's own namespace and that namespace's URI, never as namespace 0.
TEST(DiCompileTests, ACompanionDataTypeCarriesItsNamespaceUri)
{
  const auto structure = ua::data_type_of<ua::di::ParameterResultDataType>();
  EXPECT_EQ(structure.namespace_uri(), ua::String{ua::di::specNamespaceUri});
  EXPECT_EQ(structure.node_id().identifier().get_numeric(),
    static_cast<uint32_t>(ua::utils::to_underlying(ua::di::DataTypeId::ParameterResultDataType)));

  const auto enumeration = ua::data_type_of<ua::di::DeviceHealthEnumeration>();
  EXPECT_EQ(enumeration.namespace_uri(), ua::String{ua::di::specNamespaceUri});
  EXPECT_EQ(enumeration.node_id().identifier().get_numeric(),
    static_cast<uint32_t>(ua::utils::to_underlying(ua::di::DataTypeId::DeviceHealthEnumeration)));
}
