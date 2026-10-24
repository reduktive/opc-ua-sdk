// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// NR-35: the Data Access write checks of OPC 10000-8 as pure core functions. `apply_analog_range` checks
// every element of a value against a Range and rejects or clamps by the caller's policy (Part 8 section
// 5.3.2.2); `check_enum_strings_index` and `check_enum_values_member` check a MultiStateDiscrete and a
// MultiStateValueDiscrete value (sections 5.3.3.3 and 5.3.3.4). Each answers a refusal as a bad VoidResult
// carrying an ErrorDetail whose context names the offending value and its element index. Each element is
// compared and clamped in its own type, and Clamp refuses an element it has no value for (DL-38).

#include <gtest/gtest.h>

#include "ua_array.h"
#include "ua_array_base.h"
#include "ua_data_access_utils.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_localized_text.h"
#include "ua_range.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace ua;

namespace
{

Range make_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

// The value the ErrorDetail's context holds under @p key, or nothing.
std::optional<std::string> context_of(const VoidResult& result, std::string_view key)
{
  const auto* detail = result.error_detail();
  if (detail == nullptr)
    return std::nullopt;
  for (const auto& entry : detail->context)
    if (entry.key == key)
      return entry.value;
  return std::nullopt;
}

// The context value under @p key read as a number, so "150" and "150.000000" compare equal.
std::optional<double> numeric_context_of(const VoidResult& result, std::string_view key)
{
  const auto text = context_of(result, key);
  if (!text)
    return std::nullopt;
  return std::stod(*text);
}

std::string code_of(const VoidResult& result)
{
  const auto* detail = result.error_detail();
  return detail == nullptr ? std::string{"<no ErrorDetail>"} : detail->code;
}

EnumValueType enum_value(int64_t value)
{
  EnumValueType entry;
  entry.value() = value;
  return entry;
}

}  // namespace

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-IN-RANGE-GOOD, scope=function)
TEST(DataAccessUtils, AValueInsideTheRangeIsGoodAndUnchanged)
{
  const auto range = make_range(0.0, 100.0);

  Variant inside{double{50.0}};
  const auto insideResult =
    data_access_utils::apply_analog_range(inside, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(insideResult.status_code().as_status(), Status::Good);
  EXPECT_EQ(inside, Variant{double{50.0}}) << to_string(inside);

  Variant atLimit{double{100.0}};
  const auto atLimitResult =
    data_access_utils::apply_analog_range(atLimit, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(atLimitResult.status_code().as_status(), Status::Good) << "the high limit is inside the range";
  EXPECT_EQ(atLimit, Variant{double{100.0}}) << to_string(atLimit);

  Variant array{Array<int32_t>{0, 50, 100}};
  const auto arrayResult =
    data_access_utils::apply_analog_range(array, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(arrayResult.status_code().as_status(), Status::Good);
  EXPECT_EQ(array, (Variant{Array<int32_t>{0, 50, 100}})) << to_string(array);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-OUT-OF-RANGE-REJECTED, scope=function)
// @relation(AC-SVR-DA-003-ARRAY-WRITE-RANGE-CHECKED, scope=function)
TEST(DataAccessUtils, AnElementOutsideTheRangeIsRejectedWithItsIndex)
{
  const auto range = make_range(0.0, 100.0);

  Variant scalar{double{150.0}};
  const auto scalarResult =
    data_access_utils::apply_analog_range(scalar, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(scalarResult.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(scalarResult), "AnalogOutOfRange");
  EXPECT_EQ(numeric_context_of(scalarResult, ContextKeys::actual.value()), 150.0);
  EXPECT_EQ(numeric_context_of(scalarResult, ContextKeys::min.value()), 0.0);
  EXPECT_EQ(numeric_context_of(scalarResult, ContextKeys::max.value()), 100.0);
  EXPECT_EQ(context_of(scalarResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(scalar, Variant{double{150.0}}) << to_string(scalar) << ": a refused value was changed";

  Variant array{Array<int32_t>{10, 20, 150, 200}};
  const auto arrayResult =
    data_access_utils::apply_analog_range(array, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(arrayResult.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(arrayResult), "AnalogOutOfRange");
  EXPECT_EQ(numeric_context_of(arrayResult, ContextKeys::actual.value()), 150.0)
    << "the detail does not name the first element outside the range";
  EXPECT_EQ(context_of(arrayResult, ContextKeys::index.value()), std::string{"2"});
  EXPECT_EQ(array, (Variant{Array<int32_t>{10, 20, 150, 200}}))
    << to_string(array) << ": a refused array was changed";
}

// The ErrorDetail names a refused Double by the shortest text that reads back as it, so a value just outside
// a limit is not shown as the limit.
// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-OUT-OF-RANGE-REJECTED, scope=function)
TEST(DataAccessUtils, ARefusedDoubleIsReportedExactly)
{
  Variant justAbove{double{1.0000001}};
  const auto result = data_access_utils::apply_analog_range(
    justAbove, make_range(0.0, 1.0), DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(result.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(result), "AnalogOutOfRange");
  EXPECT_EQ(context_of(result, ContextKeys::actual.value()), std::string{"1.0000001"});
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-CLAMP-KEEPS-TYPE, scope=function)
TEST(DataAccessUtils, ClampKeepsTheTypeAndAnswersGoodClamped)
{
  const auto range = make_range(0.0, 10.0);

  Variant array{Array<int16_t>{-5, 3, 12}};
  const auto arrayResult =
    data_access_utils::apply_analog_range(array, range, DataAccessOutOfRangePolicy::Clamp);
  EXPECT_TRUE(arrayResult.is_good());
  EXPECT_EQ(arrayResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(array, (Variant{Array<int16_t>{0, 3, 10}}))
    << to_string(array) << ": the clamped array lost its Int16 type or values";

  Variant single{float{10.6F}};
  const auto floatResult =
    data_access_utils::apply_analog_range(single, range, DataAccessOutOfRangePolicy::Clamp);
  EXPECT_TRUE(floatResult.is_good());
  EXPECT_EQ(floatResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(single, Variant{float{10.0F}})
    << to_string(single) << ": the clamped Float lost its type or was not clamped to the limit";

  Variant inside{double{4.0}};
  const auto insideResult =
    data_access_utils::apply_analog_range(inside, range, DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(insideResult.status_code().as_status(), Status::Good)
    << "a value that was not changed is reported clamped";
  EXPECT_EQ(inside, Variant{double{4.0}}) << to_string(inside);
}

// The flattened elements of a Matrix are clamped as an array's are, and the Matrix keeps its ArrayDimensions.
// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-CLAMP-KEEPS-TYPE, scope=function)
TEST(DataAccessUtils, ClampKeepsTheDimensionsOfAMatrix)
{
  Variant matrix{Array<double>{Dimensions{2, 2}, std::vector<double>{50.0, 150.0, -5.0, 20.0}}};
  const auto result =
    data_access_utils::apply_analog_range(matrix, make_range(0.0, 100.0), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
  const auto* clamped = matrix.try_as<Array<double>>();
  ASSERT_NE(clamped, nullptr) << to_string(matrix) << ": the clamped value is not a Double array";
  EXPECT_EQ(clamped->payload(), (std::vector<double>{50.0, 100.0, 0.0, 20.0})) << to_string(matrix);
  ASSERT_TRUE(clamped->dimensions().has_value()) << to_string(matrix) << ": the Matrix lost its dimensions";
  EXPECT_EQ(*clamped->dimensions(), (Dimensions{2, 2})) << to_string(matrix);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-NAN-LIMIT-UNBOUNDED, scope=function)
// @relation(AC-SVR-DA-025-UNKNOWN-LIMIT-UNBOUNDED-ON-WRITE, scope=function)
TEST(DataAccessUtils, ANaNLimitLeavesThatSideUnbounded)
{
  const auto range = make_range(0.0, std::numeric_limits<double>::quiet_NaN());

  Variant above{double{1000.0}};
  const auto aboveResult =
    data_access_utils::apply_analog_range(above, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(aboveResult.status_code().as_status(), Status::Good) << "an unknown high limit bounded the value";
  EXPECT_EQ(above, Variant{double{1000.0}}) << to_string(above);

  Variant below{double{-5.0}};
  const auto belowResult =
    data_access_utils::apply_analog_range(below, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(belowResult.status_code().as_status(), Status::BadOutOfRange)
    << "the known low limit no longer applies";
}

// An integer element's limits are computed in its own type, and a NaN limit still bounds nothing.
// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-NAN-LIMIT-UNBOUNDED, scope=function)
TEST(DataAccessUtils, ANaNLimitLeavesThatSideUnboundedForAnInteger)
{
  const auto range = make_range(0.0, std::numeric_limits<double>::quiet_NaN());

  Variant above{int32_t{1000}};
  const auto aboveResult =
    data_access_utils::apply_analog_range(above, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(aboveResult.status_code().as_status(), Status::Good) << "an unknown high limit bounded the Int32";
  EXPECT_EQ(above, Variant{int32_t{1000}}) << to_string(above);

  Variant below{int32_t{-5}};
  const auto belowResult =
    data_access_utils::apply_analog_range(below, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(belowResult.status_code().as_status(), Status::BadOutOfRange)
    << "the known low limit no longer applies to the Int32";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-INVERTED-RANGE-CHECKS-NOTHING, scope=function)
TEST(DataAccessUtils, AnInvertedRangeChecksNothing)
{
  const auto range = make_range(100.0, 0.0);

  Variant rejected{double{500.0}};
  const auto rejectResult =
    data_access_utils::apply_analog_range(rejected, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(rejectResult.status_code().as_status(), Status::Good);
  EXPECT_EQ(rejected, Variant{double{500.0}}) << to_string(rejected);

  Variant clamped{double{-500.0}};
  const auto clampResult =
    data_access_utils::apply_analog_range(clamped, range, DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(clampResult.status_code().as_status(), Status::Good);
  EXPECT_EQ(clamped, Variant{double{-500.0}}) << to_string(clamped);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-ELEMENT-COMPARED-IN-ITS-OWN-TYPE, scope=function)
TEST(DataAccessUtils, EachElementIsComparedAndKeptInItsOwnType)
{
  Variant unsignedArray{Array<uint64_t>{15000000000000000000ULL, 5}};
  const auto unsignedResult = data_access_utils::apply_analog_range(
    unsignedArray, make_range(10.0, 2e19), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(unsignedResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(unsignedArray, (Variant{Array<uint64_t>{15000000000000000000ULL, 10}}))
    << to_string(unsignedArray) << ": a UInt64 inside the range was not kept as written";

  Variant signedArray{Array<int64_t>{9007199254740993, -1}};
  const auto signedResult = data_access_utils::apply_analog_range(
    signedArray, make_range(0.0, 1e19), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(signedResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(signedArray, (Variant{Array<int64_t>{9007199254740993, 0}}))
    << to_string(signedArray) << ": an Int64 above 2^53 inside the range was not kept as written";

  // 9007199254740993 is 2^53 + 1, which a Double cannot hold: compared as a Double it equals the limit.
  Variant aboveTheLimit{int64_t{9007199254740993}};
  const auto rejectResult = data_access_utils::apply_analog_range(
    aboveTheLimit, make_range(0.0, 9007199254740992.0), DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(rejectResult.status_code().as_status(), Status::BadOutOfRange)
    << "an Int64 one above the high limit was accepted";
  EXPECT_EQ(code_of(rejectResult), "AnalogOutOfRange");
  EXPECT_EQ(context_of(rejectResult, ContextKeys::actual.value()), std::string{"9007199254740993"});
  EXPECT_EQ(context_of(rejectResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(aboveTheLimit, Variant{int64_t{9007199254740993}})
    << to_string(aboveTheLimit) << ": a refused value was changed";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-INTEGER-AGAINST-FRACTIONAL-LIMITS, scope=function)
TEST(DataAccessUtils, AnIntegerIsComparedWithTheIntegersInsideAFractionalRange)
{
  Variant aboveHigh{int32_t{12}};
  const auto aboveResult = data_access_utils::apply_analog_range(
    aboveHigh, make_range(0.0, 10.6), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(aboveResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(aboveHigh, Variant{int32_t{10}})
    << to_string(aboveHigh) << ": the integer was not clamped to the high limit's floor";

  Variant belowLow{int32_t{-3}};
  const auto belowResult = data_access_utils::apply_analog_range(
    belowLow, make_range(-0.5, 10.0), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(belowResult.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(belowLow, Variant{int32_t{0}})
    << to_string(belowLow) << ": the integer was not clamped to the low limit's ceiling";

  const auto range = make_range(0.0, 10.6);

  Variant pastTheFloor{int32_t{11}};
  const auto pastResult =
    data_access_utils::apply_analog_range(pastTheFloor, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(pastResult.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(numeric_context_of(pastResult, ContextKeys::actual.value()), 11.0);
  EXPECT_EQ(pastTheFloor, Variant{int32_t{11}}) << to_string(pastTheFloor) << ": a refused value was changed";

  Variant atTheFloor{int32_t{10}};
  const auto atResult =
    data_access_utils::apply_analog_range(atTheFloor, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(atResult.status_code().as_status(), Status::Good);
  EXPECT_EQ(atTheFloor, Variant{int32_t{10}}) << to_string(atTheFloor);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-CLAMPED-FLOAT-INSIDE-RANGE, scope=function)
TEST(DataAccessUtils, AClampedFloatIsInsideTheRange)
{
  // 0.1 has no exact Float; the nearest, 0.1f, lies above it.
  Variant single{float{0.2F}};
  const auto result =
    data_access_utils::apply_analog_range(single, make_range(0.0, 0.1), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
  const auto* clamped = single.try_as<float>();
  ASSERT_NE(clamped, nullptr) << to_string(single) << ": the clamped value is not a Float";
  EXPECT_EQ(*clamped, std::nextafter(0.1F, 0.0F)) << "not the largest Float at or below the high limit";
  EXPECT_LE(static_cast<double>(*clamped), 0.1) << "the clamped Float lies outside the range";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-CLAMPED-FLOAT-INSIDE-RANGE, scope=function)
TEST(DataAccessUtils, AFloatClampedToTheLowLimitIsInsideTheRange)
{
  // 0.7 has no exact Float; the nearest, 0.7f, lies below it.
  Variant single{float{-1.0F}};
  const auto result =
    data_access_utils::apply_analog_range(single, make_range(0.7, 1.0), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
  const auto* clamped = single.try_as<float>();
  ASSERT_NE(clamped, nullptr) << to_string(single) << ": the clamped value is not a Float";
  EXPECT_EQ(*clamped, std::nextafter(0.7F, 1.0F)) << "not the smallest Float at or above the low limit";
  EXPECT_GE(static_cast<double>(*clamped), 0.7) << "the clamped Float lies outside the range";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-NO-VALUE-OF-THE-TYPE-REFUSED, scope=function)
TEST(DataAccessUtils, ClampRefusesAnElementWhoseTypeHasNoValueInTheRange)
{
  Variant byte{uint8_t{5}};
  const auto byteResult =
    data_access_utils::apply_analog_range(byte, make_range(300.0, 400.0), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(byteResult.status_code().as_status(), Status::BadOutOfRange)
    << "a Byte was clamped to a range no Byte lies in";
  EXPECT_EQ(code_of(byteResult), "AnalogOutOfRange");
  EXPECT_EQ(context_of(byteResult, ContextKeys::actual.value()), std::string{"5"});
  EXPECT_EQ(context_of(byteResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(byte, Variant{uint8_t{5}}) << to_string(byte) << ": a refused value was changed";

  Variant integer{int32_t{1}};
  const auto integerResult =
    data_access_utils::apply_analog_range(integer, make_range(0.4, 0.6), DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(integerResult.status_code().as_status(), Status::BadOutOfRange)
    << "an Int32 was clamped to a range no integer lies in";
  EXPECT_EQ(code_of(integerResult), "AnalogOutOfRange");
  EXPECT_EQ(context_of(integerResult, ContextKeys::actual.value()), std::string{"1"});
  EXPECT_EQ(context_of(integerResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(integer, Variant{int32_t{1}}) << to_string(integer) << ": a refused value was changed";
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-CLAMP-STORES-NO-INFINITY, scope=function)
TEST(DataAccessUtils, ClampRefusesWhenTheNearestValueIsInfinite)
{
  // 1e39 is above the largest finite Float, so the only Float at or above the low limit is +infinity.
  const auto range = make_range(1e39, std::numeric_limits<double>::quiet_NaN());

  Variant finite{float{5.0F}};
  const auto clampResult =
    data_access_utils::apply_analog_range(finite, range, DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(clampResult.status_code().as_status(), Status::BadOutOfRange)
    << to_string(finite) << ": Clamp stored an infinity it was not given";
  EXPECT_EQ(code_of(clampResult), "AnalogOutOfRange");
  EXPECT_EQ(context_of(clampResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(finite, Variant{float{5.0F}}) << to_string(finite) << ": a refused value was changed";

  // -1e39 is below the lowest finite Float, so the only Float at or below the high limit is -infinity.
  Variant belowLowest{float{5.0F}};
  const auto highSideResult = data_access_utils::apply_analog_range(belowLowest,
    make_range(std::numeric_limits<double>::quiet_NaN(), -1e39),
    DataAccessOutOfRangePolicy::Clamp);
  EXPECT_EQ(highSideResult.status_code().as_status(), Status::BadOutOfRange)
    << to_string(belowLowest) << ": Clamp stored an infinity it was not given, on the high side";
  EXPECT_EQ(code_of(highSideResult), "AnalogOutOfRange");
  EXPECT_EQ(context_of(highSideResult, ContextKeys::index.value()), std::string{"0"});
  EXPECT_EQ(belowLowest, Variant{float{5.0F}}) << to_string(belowLowest) << ": a refused value was changed";

  constexpr float infinity = std::numeric_limits<float>::infinity();
  Variant infinite{infinity};
  const auto rejectResult =
    data_access_utils::apply_analog_range(infinite, range, DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(rejectResult.status_code().as_status(), Status::Good)
    << "+infinity, at or above the low limit with no high limit, was refused";
  EXPECT_EQ(infinite, Variant{infinity}) << to_string(infinite);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-01-NAN-ELEMENT-OUTSIDE, scope=function)
TEST(DataAccessUtils, ANaNElementIsOutsideARangeWithAKnownLimit)
{
  constexpr double nan = std::numeric_limits<double>::quiet_NaN();
  const auto range = make_range(0.0, 100.0);

  // The ErrorDetail's actual is not asserted: the decimal text of a NaN depends on the platform.
  for (const auto policy : {DataAccessOutOfRangePolicy::Reject, DataAccessOutOfRangePolicy::Clamp})
  {
    const bool clamp = policy == DataAccessOutOfRangePolicy::Clamp;
    Variant value{nan};
    const auto result = data_access_utils::apply_analog_range(value, range, policy);
    EXPECT_EQ(result.status_code().as_status(), Status::BadOutOfRange)
      << (clamp ? "Clamp" : "Reject") << " accepted a NaN against a range with known limits";
    EXPECT_EQ(code_of(result), "AnalogOutOfRange") << (clamp ? "Clamp" : "Reject");
    EXPECT_EQ(context_of(result, ContextKeys::index.value()), std::string{"0"})
      << (clamp ? "Clamp" : "Reject");
    const auto* kept = value.try_as<double>();
    ASSERT_NE(kept, nullptr) << to_string(value);
    EXPECT_TRUE(std::isnan(*kept)) << to_string(value) << ": a refused NaN was changed";
  }

  Variant unknown{nan};
  const auto unknownResult =
    data_access_utils::apply_analog_range(unknown, make_range(nan, nan), DataAccessOutOfRangePolicy::Reject);
  EXPECT_EQ(unknownResult.status_code().as_status(), Status::Good)
    << "a range with no known limit checked the NaN";
  const auto* unchanged = unknown.try_as<double>();
  ASSERT_NE(unchanged, nullptr) << to_string(unknown);
  EXPECT_TRUE(std::isnan(*unchanged)) << to_string(unknown);
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-02-INDEX-CHECKED, scope=function)
TEST(DataAccessUtils, AnIndexOutsideTheEnumStringsIsOutOfRange)
{
  const std::vector<LocalizedText> enumStrings{
    LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}};

  const auto last = data_access_utils::check_enum_strings_index(Variant{uint32_t{2}}, enumStrings);
  EXPECT_EQ(last.status_code().as_status(), Status::Good);

  const auto pastTheEnd = data_access_utils::check_enum_strings_index(Variant{uint32_t{3}}, enumStrings);
  EXPECT_EQ(pastTheEnd.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(pastTheEnd), "MultiStateIndexOutOfRange");
  EXPECT_EQ(context_of(pastTheEnd, ContextKeys::actual.value()), std::string{"3"});
  EXPECT_EQ(context_of(pastTheEnd, ContextKeys::sizeMax.value()), std::string{"3"});

  const auto negative = data_access_utils::check_enum_strings_index(Variant{int32_t{-1}}, enumStrings);
  EXPECT_EQ(negative.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(negative), "MultiStateIndexOutOfRange");
  EXPECT_EQ(context_of(negative, ContextKeys::actual.value()), std::string{"-1"});
  EXPECT_EQ(context_of(negative, ContextKeys::sizeMax.value()), std::string{"3"});
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-03-MEMBER-CHECKED, scope=function)
TEST(DataAccessUtils, AValueNoEnumValueDefinesIsOutOfRange)
{
  const std::vector<EnumValueType> enumValues{enum_value(1), enum_value(4), enum_value(8)};

  const auto defined = data_access_utils::check_enum_values_member(Variant{int32_t{4}}, enumValues);
  EXPECT_EQ(defined.status_code().as_status(), Status::Good);

  const auto inAGap = data_access_utils::check_enum_values_member(Variant{int32_t{5}}, enumValues);
  EXPECT_EQ(inAGap.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(inAGap), "MultiStateValueInvalid");
  EXPECT_EQ(context_of(inAGap, ContextKeys::actual.value()), std::string{"5"});
  EXPECT_EQ(context_of(inAGap, ContextKeys::index.value()), std::string{"0"});
}

// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-03-UINT64-ABOVE-INT64-MATCHES-NO-ENTRY, scope=function)
TEST(DataAccessUtils, AUInt64AboveTheInt64RangeMatchesNoEnumEntry)
{
  // 18446744073709551615 converted to an Int64 by a cast is -1, the Value of the first entry.
  const Variant value{Array<uint64_t>{1, 18446744073709551615ULL}};

  const std::vector<EnumValueType> enumValues{enum_value(-1), enum_value(1)};
  const auto member = data_access_utils::check_enum_values_member(value, enumValues);
  EXPECT_EQ(member.status_code().as_status(), Status::BadOutOfRange)
    << "a UInt64 above the Int64 range matched an EnumValue";
  EXPECT_EQ(code_of(member), "MultiStateValueInvalid");
  EXPECT_EQ(context_of(member, ContextKeys::actual.value()), std::string{"18446744073709551615"});
  EXPECT_EQ(context_of(member, ContextKeys::index.value()), std::string{"1"});

  const std::vector<LocalizedText> enumStrings{
    LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}};
  const auto index = data_access_utils::check_enum_strings_index(value, enumStrings);
  EXPECT_EQ(index.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_EQ(code_of(index), "MultiStateIndexOutOfRange");
  EXPECT_EQ(context_of(index, ContextKeys::actual.value()), std::string{"18446744073709551615"});
  EXPECT_EQ(context_of(index, ContextKeys::sizeMax.value()), std::string{"3"});
  EXPECT_EQ(context_of(index, ContextKeys::index.value()), std::string{"1"});
}

// A floating element's actual is the shortest text that reads back as the same value (DL-42); a NaN's text is
// the C library's, so it is not asserted. The bounds of the Int64 range are exact Doubles: -2^63 is an Int64
// and 2^63 is not.
// @relation(AC-COMP-CORE-DATA-ACCESS-UTILS-03-FLOATING-ELEMENT-CHECKED, scope=function)
TEST(DataAccessUtils, AFloatingEnumElementIsCheckedByItsValue)
{
  const std::vector<EnumValueType> enumValues{enum_value(1), enum_value(4), enum_value(8)};

  const auto integral = data_access_utils::check_enum_values_member(Variant{double{4.0}}, enumValues);
  EXPECT_EQ(integral.status_code().as_status(), Status::Good)
    << "the Double 4.0 did not match the EnumValue 4";

  const std::tuple<const char*, double, const char*> refused[]{
    {"5.0", 5.0, "5"}, {"4.5", 4.5, "4.5"}, {"NaN", std::numeric_limits<double>::quiet_NaN(), nullptr}};
  for (const auto& [name, element, actual] : refused)
  {
    SCOPED_TRACE(std::string{"the Double "} + name);
    const auto result = data_access_utils::check_enum_values_member(Variant{element}, enumValues);
    EXPECT_EQ(result.status_code().as_status(), Status::BadOutOfRange);
    EXPECT_EQ(code_of(result), "MultiStateValueInvalid");
    EXPECT_EQ(context_of(result, ContextKeys::index.value()), std::string{"0"});
    if (actual != nullptr)
    {
      EXPECT_EQ(context_of(result, ContextKeys::actual.value()), std::string{actual});
    }
  }

  const auto integralFloat = data_access_utils::check_enum_values_member(Variant{float{4.0F}}, enumValues);
  EXPECT_EQ(integralFloat.status_code().as_status(), Status::Good)
    << "the Float 4.0 did not match the EnumValue 4";
  const auto fractionalFloat = data_access_utils::check_enum_values_member(Variant{float{4.5F}}, enumValues);
  EXPECT_EQ(fractionalFloat.status_code().as_status(), Status::BadOutOfRange)
    << "the Float 4.5 matched an EnumValue";
  EXPECT_EQ(code_of(fractionalFloat), "MultiStateValueInvalid");
  EXPECT_EQ(context_of(fractionalFloat, ContextKeys::actual.value()), std::string{"4.5"});
  EXPECT_EQ(context_of(fractionalFloat, ContextKeys::index.value()), std::string{"0"});

  const std::vector<EnumValueType> extremes{
    enum_value(std::numeric_limits<int64_t>::min()), enum_value(std::numeric_limits<int64_t>::max())};
  const auto lowest =
    data_access_utils::check_enum_values_member(Variant{double{-9223372036854775808.0}}, extremes);
  EXPECT_EQ(lowest.status_code().as_status(), Status::Good)
    << "the Double -2^63 did not match the EnumValue -9223372036854775808";
  const auto pastTheHighest =
    data_access_utils::check_enum_values_member(Variant{double{9223372036854775808.0}}, extremes);
  EXPECT_EQ(pastTheHighest.status_code().as_status(), Status::BadOutOfRange)
    << "the Double 2^63, outside the Int64 range, matched an EnumValue";
  EXPECT_EQ(code_of(pastTheHighest), "MultiStateValueInvalid");
  EXPECT_EQ(context_of(pastTheHighest, ContextKeys::index.value()), std::string{"0"});

  const std::vector<LocalizedText> enumStrings{
    LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}};
  const auto index = data_access_utils::check_enum_strings_index(Variant{double{1.0}}, enumStrings);
  EXPECT_EQ(index.status_code().as_status(), Status::Good) << "the Double 1.0 did not index the entry 1";

  const auto fractional = data_access_utils::check_enum_strings_index(Variant{double{1.5}}, enumStrings);
  EXPECT_EQ(fractional.status_code().as_status(), Status::BadOutOfRange) << "the Double 1.5 indexed an entry";
  EXPECT_EQ(code_of(fractional), "MultiStateIndexOutOfRange");
  EXPECT_EQ(context_of(fractional, ContextKeys::actual.value()), std::string{"1.5"});
  EXPECT_EQ(context_of(fractional, ContextKeys::sizeMax.value()), std::string{"3"});
  EXPECT_EQ(context_of(fractional, ContextKeys::index.value()), std::string{"0"});
}

// A Property named by Part 8 as a semantic one is semantic without the flag.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST(DataAccessUtilsSemanticProperty, APart8NameIsSemantic)
{
  EXPECT_TRUE(data_access_utils::is_semantic_property(QualifiedName{0, "EURange"}, AccessLevelExType{}));
  EXPECT_TRUE(data_access_utils::is_semantic_property(QualifiedName{0, "EnumValues"}, AccessLevelExType{}));
}

// The SemanticChange bit makes a Property of any name semantic.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST(DataAccessUtilsSemanticProperty, TheFlagMakesAnyPropertySemantic)
{
  EXPECT_TRUE(data_access_utils::is_semantic_property(
    QualifiedName{2, "Anything"}, AccessLevelExType{AccessLevelExType::Bit::SemanticChange}));
}

// Neither another namespace-0 name nor a Part 8 name outside namespace 0 is semantic without the flag.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST(DataAccessUtilsSemanticProperty, AnotherPropertyIsNot)
{
  EXPECT_FALSE(data_access_utils::is_semantic_property(QualifiedName{0, "Definition"}, AccessLevelExType{}));
  EXPECT_FALSE(data_access_utils::is_semantic_property(QualifiedName{2, "EURange"}, AccessLevelExType{}));
}
