// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_value_shape_validation.h"

#include "ua_array.h"
#include "ua_error_detail.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace
{

using ua::client::detail::validate_variable_write_shape;
using ua::client::detail::VariableShape;

const ua::NodeId node{42};

ua::Variant matrix(std::vector<std::int32_t> dimensions)
{
  std::size_t count = 1;
  for (const auto dimension : dimensions)
  {
    count *= static_cast<std::size_t>(dimension);
  }
  return ua::Variant{ua::Array<std::int32_t>{dimensions, std::vector<std::int32_t>(count, std::int32_t{7})}};
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, RejectsScalarForFixedRankArray)
{
  auto result = validate_variable_write_shape(node,
    ua::Variant{std::int32_t{7}},
    VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{3, 4}});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadTypeMismatch});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "VariableValueRankMismatch");
  EXPECT_NE(ua::to_string(*result.shared_detail()).find("i=42"), std::string::npos);
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, RejectsOneDimensionalArrayForRankTwo)
{
  auto result = validate_variable_write_shape(node,
    ua::Variant{ua::Array<std::int32_t>{1, 2, 3}},
    VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{3, 4}});
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadTypeMismatch});
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, AcceptsMatchingMatrixAtOrBelowMaximumExtents)
{
  EXPECT_TRUE(validate_variable_write_shape(
    node, matrix({2, 4}), VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{3, 4}})
                .is_good());
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, RejectsDimensionAboveAdvertisedMaximum)
{
  auto result = validate_variable_write_shape(
    node, matrix({4, 2}), VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{3, 4}});

  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadOutOfRange});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "VariableArrayDimensionExceeded");
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, ZeroMaximumDimensionIsUnbounded)
{
  EXPECT_TRUE(validate_variable_write_shape(node,
    ua::Variant{ua::Array<std::int32_t>(ua::Size{1000})},
    VariableShape{.valueRank = 1, .arrayDimensions = std::vector<std::uint32_t>{0}})
                .is_good());
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, NullDimensionsAndScalarRankAcceptScalar)
{
  EXPECT_TRUE(
    validate_variable_write_shape(node, ua::Variant{std::int32_t{7}}, VariableShape{.valueRank = -1})
      .is_good());
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, NullVariantDefersAllowNullsDecisionToServer)
{
  EXPECT_TRUE(validate_variable_write_shape(
    node, ua::Variant{}, VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{3, 4}})
                .is_good());
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, HandlesFlexibleValueRankConstants)
{
  EXPECT_TRUE(validate_variable_write_shape(node, matrix({2, 2}), VariableShape{.valueRank = -2}).is_good());
  EXPECT_TRUE(
    validate_variable_write_shape(node, ua::Variant{std::int32_t{1}}, VariableShape{.valueRank = -3})
      .is_good());
  EXPECT_TRUE(validate_variable_write_shape(
    node, ua::Variant{ua::Array<std::int32_t>{1, 2}}, VariableShape{.valueRank = -3})
                .is_good());
  EXPECT_EQ(validate_variable_write_shape(node, matrix({1, 2}), VariableShape{.valueRank = -3}).status_code(),
    ua::StatusCode{ua::Status::BadTypeMismatch});
  EXPECT_TRUE(validate_variable_write_shape(node, matrix({1, 2}), VariableShape{.valueRank = 0}).is_good());
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, RejectsInconsistentServerShapeMetadata)
{
  auto result = validate_variable_write_shape(
    node, matrix({2, 2}), VariableShape{.valueRank = 2, .arrayDimensions = std::vector<std::uint32_t>{4}});
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadUnexpectedError});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "VariableShapeMetadataInvalid");
}

// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST(ValueShapeValidation, AllowsByteStringAndByteArrayShapeEquivalence)
{
  const std::vector<std::uint8_t> bytes{1, 2, 3, 4};
  EXPECT_TRUE(validate_variable_write_shape(node,
    ua::Variant{ua::ByteString{bytes}},
    VariableShape{.valueRank = 1, .arrayDimensions = std::vector<std::uint32_t>{4}})
                .is_good());
  EXPECT_TRUE(validate_variable_write_shape(node,
    ua::Variant{ua::Array<std::uint8_t>{1, 2, 3, 4}},
    VariableShape{.valueRank = -1, .arrayDimensions = std::nullopt})
                .is_good());
}

}  // namespace
