// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_builder.h"

#include "ua_error_detail.h"
#include "ua_status.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::NumericRangeBuilder;

// @verifies CL-ADDRSP-006
// @verifies CL-ATTR-008
// @relation(CL-ADDRSP-006, CL-ATTR-008, scope=function)
TEST(ClientNumericRangeBuilder, BuildsSingleAndMultiDimensionWireForms)
{
  auto result = NumericRangeBuilder::from_dimensions({ua::DimensionRange{5, 5}, ua::DimensionRange{7, 9}}, 2);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ua::NumericRange{"5,7:9"});
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST(ClientNumericRangeBuilder, RejectsDescendingStructuredBounds)
{
  auto result = NumericRangeBuilder::from_dimensions({ua::DimensionRange{7, 5}}, 1);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadIndexRangeInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeBoundsInvalid");
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
// @relation(AC-CL-ATTR-009-NUMERICRANGE-ALLDIMS, scope=function)
TEST(ClientNumericRangeBuilder, RejectsWrongDimensionCountWithRichDetail)
{
  auto result = NumericRangeBuilder::from_string(ua::NumericRange{"0:1"}, 2);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadIndexRangeInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.numeric_range_builder");
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST(ClientNumericRangeBuilder, AcceptsEmptyWholeValueForKnownRank)
{
  auto fromString = NumericRangeBuilder::from_string(ua::NumericRange{}, 2);
  ASSERT_TRUE(fromString.is_good());
  EXPECT_TRUE(fromString.value().empty());

  auto fromDimensions = NumericRangeBuilder::from_dimensions({}, 2);
  ASSERT_TRUE(fromDimensions.is_good());
  EXPECT_TRUE(fromDimensions.value().empty());
}

}  // namespace
