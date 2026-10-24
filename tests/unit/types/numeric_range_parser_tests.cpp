// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "gtest/gtest.h"
#include "ua_numeric_range_parser.h"
#include "ua_result.h"

using namespace ua;

TEST(NumericRangeParser, EmptyStringReturnsValidEmptyResult)
{
  auto result = parse_numeric_range(NumericRange{""});
  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().empty());
  EXPECT_EQ(result.value().dimension_count(), 0u);
}

TEST(NumericRangeParser, SingleIndex)
{
  auto result = parse_numeric_range(NumericRange{"3"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimension_count(), 1u);
  EXPECT_EQ(result.value().dimensions[0].low, 3u);
  EXPECT_EQ(result.value().dimensions[0].high, 3u);
  EXPECT_EQ(result.value().element_count(0), 1u);
}

TEST(NumericRangeParser, SingleRange)
{
  auto result = parse_numeric_range(NumericRange{"2:5"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimension_count(), 1u);
  EXPECT_EQ(result.value().dimensions[0].low, 2u);
  EXPECT_EQ(result.value().dimensions[0].high, 5u);
  EXPECT_EQ(result.value().element_count(0), 4u);
}

TEST(NumericRangeParser, TwoDimensions)
{
  auto result = parse_numeric_range(NumericRange{"2:5,0:3"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimension_count(), 2u);
  EXPECT_EQ(result.value().dimensions[0].low, 2u);
  EXPECT_EQ(result.value().dimensions[0].high, 5u);
  EXPECT_EQ(result.value().dimensions[1].low, 0u);
  EXPECT_EQ(result.value().dimensions[1].high, 3u);
}

TEST(NumericRangeParser, ZeroIndex)
{
  auto result = parse_numeric_range(NumericRange{"0"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimension_count(), 1u);
  EXPECT_EQ(result.value().dimensions[0].low, 0u);
  EXPECT_EQ(result.value().dimensions[0].high, 0u);
  EXPECT_EQ(result.value().element_count(0), 1u);
}

// Covers SVR-ATTR-READ-026 (coverage-audit retag).
TEST(NumericRangeParser, EqualLowHighIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"5:5"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, ZeroToZeroIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"0:0"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, ReversedRangeIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"7:3"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, NonNumericIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"abc"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, BareCommaIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{","});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, TrailingCommaIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"2:5,"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, LeadingCommaIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{",2:5"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, TooManyColonsIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"1:2:3"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, LeadingColonIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{":5"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, TrailingColonIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"5:"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, LargeIndexAtUint32MaxBoundary)
{
  auto result = parse_numeric_range(NumericRange{"4294967295"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimensions[0].low, UINT32_MAX);
  EXPECT_EQ(result.value().dimensions[0].high, UINT32_MAX);
}

TEST(NumericRangeParser, OverflowBeyondUint32MaxIsInvalid)
{
  auto result = parse_numeric_range(NumericRange{"4294967296"});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeInvalid);
}

TEST(NumericRangeParser, ElementCountOutOfBoundsReturnsZero)
{
  auto result = parse_numeric_range(NumericRange{"3"});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().element_count(1), 0u);
}
