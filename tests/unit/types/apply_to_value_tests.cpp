// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// index_range_utils::apply_to_value narrows a DataValue's Value to an IndexRange per Part 4 section 7.27
// (NR-10 rule 9). A bad status or an empty range leaves the DataValue unchanged; a syntactically valid range
// that selects nothing, a dimension-count mismatch included, sets Bad_IndexRangeNoData; Bad_IndexRangeInvalid
// is only for invalid syntax.

#include <gtest/gtest.h>

#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_numeric_range.h"
#include "ua_numeric_range_parser.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <cstdint>
#include <vector>

using namespace ua;

namespace
{

// The five-element Int32 array {10, 20, 30, 40, 50}.
DataValue five_elements()
{
  return DataValue{Variant{Array<int32_t>{10, 20, 30, 40, 50}}};
}

// The 2x3 Int32 matrix {1, 2, 3, 4, 5, 6}, row-major.
DataValue matrix_2x3()
{
  return DataValue{Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6}}}};
}

Status status_of(const DataValue& value)
{
  return value.status().value_or(StatusCode{Status::Good}).as_status();
}

}  // namespace

// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-VALID-RANGE-NARROWS, scope=function)
TEST(ApplyToValue, AValidRangeNarrowsTheValue)
{
  auto value = matrix_2x3();
  index_range_utils::apply_to_value(value, NumericRange{"0:1,1:2"});

  EXPECT_EQ(status_of(value), Status::Good);
  const auto* narrowed = value.value().try_as<Array<int32_t>>();
  ASSERT_NE(narrowed, nullptr);
  EXPECT_EQ(std::vector<int32_t>(narrowed->begin(), narrowed->end()), (std::vector<int32_t>{2, 3, 5, 6}));
  ASSERT_TRUE(narrowed->dimensions().has_value());
  EXPECT_EQ(*narrowed->dimensions(), (Dimensions{2, 2}));
}

// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-EMPTY-RANGE-UNCHANGED, scope=function)
TEST(ApplyToValue, AnEmptyRangeLeavesTheValue)
{
  auto value = matrix_2x3();
  index_range_utils::apply_to_value(value, NumericRange{});

  EXPECT_EQ(status_of(value), Status::Good);
  EXPECT_EQ(value, matrix_2x3());
}

// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-SELECTS-NOTHING-NO-DATA, scope=function)
TEST(ApplyToValue, ARangeSelectingNothingIsIndexRangeNoData)
{
  DataValue value{Variant{Array<int32_t>{10, 20, 30, 40, 50}}};
  index_range_utils::apply_to_value(value, NumericRange{"10:12"});

  EXPECT_EQ(status_of(value), Status::BadIndexRangeNoData);
  EXPECT_TRUE(value.value().empty()) << "a bad status leaves a value in place";
}

// Fewer and more dimensions than the matrix has are two equivalence classes, and both are driven.
// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-DIMENSION-MISMATCH-NO-DATA, scope=function)
TEST(ApplyToValue, ADimensionCountMismatchIsIndexRangeNoData)
{
  auto fewer = matrix_2x3();
  index_range_utils::apply_to_value(fewer, NumericRange{"0:1"});
  EXPECT_EQ(status_of(fewer), Status::BadIndexRangeNoData) << "a one-dimension range on a 2x3 matrix";
  EXPECT_TRUE(fewer.value().empty()) << "a bad status leaves a value in place";

  auto more = matrix_2x3();
  index_range_utils::apply_to_value(more, NumericRange{"0:1,0:1,0:1"});
  EXPECT_EQ(status_of(more), Status::BadIndexRangeNoData) << "a three-dimension range on a 2x3 matrix";
  EXPECT_TRUE(more.value().empty()) << "a bad status leaves a value in place";
}

// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-UNCERTAIN-NARROWS, scope=function)
TEST(ApplyToValue, AnUncertainValueIsNarrowed)
{
  DataValue value{Variant{Array<int32_t>{10, 20, 30, 40, 50}}};
  value.status() = StatusCode{Status::UncertainLastUsableValue};
  index_range_utils::apply_to_value(value, NumericRange{"2:3"});

  EXPECT_EQ(status_of(value), Status::UncertainLastUsableValue);
  const auto* narrowed = value.value().try_as<Array<int32_t>>();
  ASSERT_NE(narrowed, nullptr);
  EXPECT_EQ(std::vector<int32_t>(narrowed->begin(), narrowed->end()), (std::vector<int32_t>{30, 40}));
}

// The Bad class of the status (Part 4 section 7.11.1, Table 135: a Bad value is "to be ignored"). A valid and
// a malformed range are both driven, so the Bad check is shown to come before the range is parsed.
// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-BAD-INPUT-UNCHANGED, scope=function)
TEST(ApplyToValue, ABadValueIsLeftUnchanged)
{
  DataValue waiting;
  waiting.status() = StatusCode{Status::BadWaitingForInitialData};
  const DataValue waitingGiven = waiting;
  index_range_utils::apply_to_value(waiting, NumericRange{"2:3"});
  EXPECT_EQ(status_of(waiting), Status::BadWaitingForInitialData) << "a null Bad value with the range 2:3";
  EXPECT_TRUE(waiting.value().empty()) << "a null Bad value was given a Value";
  EXPECT_EQ(waiting, waitingGiven) << "a null Bad value with the range 2:3 was changed";

  auto failed = five_elements();
  failed.status() = StatusCode{Status::BadDeviceFailure};
  const DataValue failedGiven = failed;
  index_range_utils::apply_to_value(failed, NumericRange{"2:3"});
  EXPECT_EQ(status_of(failed), Status::BadDeviceFailure) << "a Bad array with the range 2:3";
  EXPECT_EQ(failed, failedGiven) << "a Bad array with the range 2:3 was changed";

  auto malformed = five_elements();
  malformed.status() = StatusCode{Status::BadDeviceFailure};
  index_range_utils::apply_to_value(malformed, NumericRange{"x"});
  EXPECT_EQ(status_of(malformed), Status::BadDeviceFailure) << "a Bad array with the malformed range x";
  EXPECT_EQ(malformed, failedGiven) << "a Bad array with the malformed range x was changed";
  const auto* whole = malformed.value().try_as<Array<int32_t>>();
  ASSERT_NE(whole, nullptr) << "the Bad array lost its Value";
  EXPECT_EQ(std::vector<int32_t>(whole->begin(), whole->end()), (std::vector<int32_t>{10, 20, 30, 40, 50}));
}

// The three ways the function fails: a malformed range, a valid range that selects nothing, and a
// dimension-count mismatch. Each sets a Bad status that carries an ErrorDetail, and a null Value.
// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-FAILURE-CARRIES-ERROR-DETAIL, scope=function)
TEST(ApplyToValue, AFailureCarriesAnErrorDetail)
{
  struct Case
  {
    const char* what;
    DataValue value;
    const char* range;
    Status expected;
  };

  Case cases[] = {{"the malformed range x", five_elements(), "x", Status::BadIndexRangeInvalid},
    {"the range 10:12 beyond the array", five_elements(), "10:12", Status::BadIndexRangeNoData},
    {"the one-dimension range 0:1 on a 2x3 matrix", matrix_2x3(), "0:1", Status::BadIndexRangeNoData}};
  for (auto& [what, value, range, expected] : cases)
  {
    index_range_utils::apply_to_value(value, NumericRange{range});
    EXPECT_EQ(status_of(value), expected) << what;
    ASSERT_TRUE(value.status().has_value()) << what << " set no status";
    EXPECT_NE(value.status()->shared_detail(), nullptr) << what << ": the status carries no ErrorDetail";
    EXPECT_TRUE(value.value().empty()) << what << " left a Value in place";
  }
}
