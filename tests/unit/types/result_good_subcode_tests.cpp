// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A result can carry a Good subcode, and a result holding a value can be Uncertain.
// `Result<void>(StatusCode)` is good for any Good code and keeps it; `Result<T>(T value, StatusCode status)`
// and `Result<StatusCode>::with_value(value, status)` hold the value with a Good or Uncertain status and keep
// the status; given a Bad code they give a result without a value carrying the shared "ValueWithBadStatus"
// ErrorDetail where NDEBUG is defined, and assert where it is not. The release and debug arms of a criterion
// are compiled in the build type they describe. The members a result has always had are also tested in
// result_uncertain_value_tests.cpp.

#include <gtest/gtest.h>

#include "ua_data_value.h"
#include "ua_variant.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <cstdint>
#include <memory>
#include <utility>

using namespace ua;

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-01-VOID-GOOD-CLAMPED, scope=function)
TEST(ResultGoodSubcode, VoidResultFromGoodClampedIsGoodAndKeepsTheCode)
{
  const VoidResult result = StatusCode{Status::GoodClamped};

  EXPECT_TRUE(result.is_good());
  EXPECT_FALSE(result.is_bad());
  EXPECT_FALSE(result.is_uncertain());
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-VALUE-GOOD-CLAMPED, scope=function)
TEST(ResultGoodSubcode, ValueWithGoodClampedIsGoodAndKeepsBoth)
{
  const Result<int32_t> result{int32_t{42}, StatusCode{Status::GoodClamped}};

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 42);
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-03-WITH-VALUE-GOOD-CLAMPED, scope=function)
TEST(ResultGoodSubcode, WithValueAndGoodClampedIsGoodAndKeepsBoth)
{
  const auto result =
    Result<StatusCode>::with_value(StatusCode{Status::BadTimeout}, StatusCode{Status::GoodClamped});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as_status(), Status::BadTimeout);
  EXPECT_EQ(result.status_code().as_status(), Status::GoodClamped);
}

// transform_error forwards a result holding a value unchanged, its Good subcode included, through both of its
// overloads.
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-04-TRANSFORM-ERROR-KEEPS-GOOD-SUBCODE, scope=function)
TEST(ResultGoodSubcode, TransformErrorKeepsTheGoodSubcode)
{
  int mappingCalls = 0;
  const auto mapping = [&mappingCalls](const StatusCode&)
  {
    ++mappingCalls;
    return StatusCode{Status::BadInternalError};
  };
  Result<int32_t> clamped{int32_t{42}, StatusCode{Status::GoodClamped}};

  const Result<int32_t> fromLvalue = std::as_const(clamped).transform_error(mapping);
  ASSERT_TRUE(fromLvalue.is_good());
  EXPECT_EQ(fromLvalue.value(), 42);
  EXPECT_EQ(fromLvalue.status_code().as_status(), Status::GoodClamped)
    << "the const& overload returned " << fromLvalue.status_code().as_uint32();

  const Result<int32_t> fromRvalue = std::move(clamped).transform_error(mapping);
  ASSERT_TRUE(fromRvalue.is_good());
  EXPECT_EQ(fromRvalue.value(), 42);
  EXPECT_EQ(fromRvalue.status_code().as_status(), Status::GoodClamped)
    << "the && overload returned " << fromRvalue.status_code().as_uint32();

  EXPECT_EQ(mappingCalls, 0) << "the mapping was called on a good result";
}

// A Bad code that carries its own ErrorDetail gives ValueWithBadStatus with that detail as its cause; a code
// without one gets the shared ValueWithBadStatus detail. Both value forms build their result with
// ua::detail::value_with_bad_status, which runs in every build.
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-OWN-DETAIL-BECOMES-CAUSE, scope=function)
TEST(ResultGoodSubcode, ValueWithBadStatusKeepsTheCodesOwnDetailAsItsCause)
{
  const shared_ptr<const ErrorDetail> own =
    ErrorDetail::build("RangeCheck", "The value is outside the range", "ResultGoodSubcodeTest");
  const StatusCode withOwnDetail{Status::BadOutOfRange, own};

  const StatusCode first = ua::detail::value_with_bad_status(withOwnDetail);
  EXPECT_EQ(first.as_status(), Status::BadOutOfRange);
  ASSERT_NE(first.shared_detail(), nullptr);
  EXPECT_EQ(first.shared_detail()->code, "ValueWithBadStatus");
  EXPECT_EQ(first.shared_detail()->cause.get(), own.get())
    << "the code's own detail is not the cause of ValueWithBadStatus";

  for (int attempt = 0; attempt < 2; ++attempt)
  {
    const StatusCode plain = ua::detail::value_with_bad_status(StatusCode{Status::BadOutOfRange});
    EXPECT_EQ(plain.as_status(), Status::BadOutOfRange);
    EXPECT_EQ(plain.shared_detail().get(), ua::detail::value_with_bad_status_detail().get())
      << "a code without a detail does not get the shared ValueWithBadStatus detail (call " << attempt << ")";
    ASSERT_NE(plain.shared_detail(), nullptr);
    EXPECT_EQ(plain.shared_detail()->cause, nullptr);
  }
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-05-HAS-VALUE-AND-SEVERITY-PREDICATES, scope=function)
TEST(ResultGoodSubcode, HasValueAndTheSeverityPredicatesAnswerForEveryKindOfResult)
{
  const Result<int32_t> good{int32_t{1}};
  const Result<int32_t> clamped{int32_t{2}, StatusCode{Status::GoodClamped}};
  const Result<int32_t> uncertainWithValue{int32_t{3}, StatusCode{Status::UncertainLastUsableValue}};
  const Result<int32_t> uncertainWithoutValue{StatusCode{Status::UncertainLastUsableValue}};
  const Result<int32_t> bad{StatusCode{Status::BadSensorFailure}};

  EXPECT_TRUE(good.has_value());
  EXPECT_TRUE(clamped.has_value());
  EXPECT_TRUE(uncertainWithValue.has_value());
  EXPECT_FALSE(uncertainWithoutValue.has_value());
  EXPECT_FALSE(bad.has_value());

  for (const auto* result : {&good, &clamped})
  {
    EXPECT_FALSE(result->is_not_good());
    EXPECT_TRUE(result->is_not_bad());
    EXPECT_TRUE(result->is_not_uncertain());
  }
  for (const auto* result : {&uncertainWithValue, &uncertainWithoutValue})
  {
    EXPECT_TRUE(result->is_not_good());
    EXPECT_TRUE(result->is_not_bad()) << "is_not_bad() answers the severity, not whether a value is held";
    EXPECT_FALSE(result->is_not_uncertain());
  }
  EXPECT_TRUE(bad.is_not_good());
  EXPECT_FALSE(bad.is_not_bad());
  EXPECT_TRUE(bad.is_not_uncertain());

  const auto statusValued =
    Result<StatusCode>::with_value(StatusCode{Status::Good}, StatusCode{Status::UncertainSensorNotAccurate});
  EXPECT_TRUE(statusValued.has_value());
  EXPECT_TRUE(statusValued.is_not_good());
  EXPECT_TRUE(statusValued.is_not_bad());
  EXPECT_FALSE(statusValued.is_not_uncertain());

  const Result<StatusCode> statusWithoutValue{StatusCode{Status::Uncertain}};
  EXPECT_FALSE(statusWithoutValue.has_value());
  EXPECT_TRUE(statusWithoutValue.is_not_good());
  EXPECT_TRUE(statusWithoutValue.is_not_bad());
  EXPECT_FALSE(statusWithoutValue.is_not_uncertain());

  const VoidResult voidUncertain{StatusCode{Status::Uncertain}};
  EXPECT_TRUE(voidUncertain.is_not_good());
  EXPECT_TRUE(voidUncertain.is_not_bad());
  EXPECT_FALSE(voidUncertain.is_not_uncertain());
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-07-COMBINED-STATUS-ANSWERS-ONE-CODE, scope=function)
TEST(ResultGoodSubcode, CombinedStatusAnswersTheWorseCodeAndThenTheMoreSpecificOne)
{
  struct Row
  {
    Status outer;
    Status inner;
    Status answered;
  };

  const Row rows[] = {
    {Status::GoodLocalOverride, Status::Good, Status::GoodLocalOverride},
    {Status::Good, Status::GoodClamped, Status::GoodClamped},
    {Status::Good, Status::Good, Status::Good},
    {Status::UncertainLastUsableValue, Status::GoodLocalOverride, Status::UncertainLastUsableValue},
    {Status::GoodLocalOverride, Status::UncertainSensorNotAccurate, Status::UncertainSensorNotAccurate},
    {Status::GoodLocalOverride, Status::BadSensorFailure, Status::BadSensorFailure},
    {Status::UncertainLastUsableValue, Status::Uncertain, Status::UncertainLastUsableValue},
    {Status::GoodLocalOverride, Status::GoodClamped, Status::GoodClamped},
    {Status::UncertainLastUsableValue,
      Status::UncertainSensorNotAccurate,
      Status::UncertainSensorNotAccurate},
  };
  for (const Row& row : rows)
  {
    const StatusCode answered = ua::detail::combined_status(StatusCode{row.outer}, StatusCode{row.inner});
    EXPECT_EQ(answered.as_status(), row.answered)
      << "outer " << StatusCode{row.outer}.as_uint32() << ", inner " << StatusCode{row.inner}.as_uint32();
  }

  const shared_ptr<const ErrorDetail> outerDetail =
    ErrorDetail::build("Override", "The value is overridden", "ResultGoodSubcodeTest");
  const StatusCode answered =
    ua::detail::combined_status(StatusCode{Status::GoodLocalOverride, outerDetail}, StatusCode{Status::Good});
  EXPECT_EQ(answered.shared_detail().get(), outerDetail.get()) << "the answered code lost its own detail";
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-08-A-THROWING-FORM-GIVES-ONLY-A-GOOD-VALUE, scope=function)
TEST(ResultGoodSubcode, AThrowingFormGivesTheValueOfAGoodResultAndThrowsForAnyOther)
{
  EXPECT_EQ(ua::detail::good_value(Result<int32_t>{int32_t{1}}), 1);
  EXPECT_EQ(ua::detail::good_value(Result<int32_t>{int32_t{2}, StatusCode{Status::GoodClamped}}), 2);

  const auto thrownStatus = [](Result<int32_t> result)
  {
    try
    {
      static_cast<void>(ua::detail::good_value(std::move(result)));
    }
    catch (const UaException& error)
    {
      return error.status();
    }
    return Status::Good;
  };
  EXPECT_EQ(thrownStatus(Result<int32_t>{int32_t{3}, StatusCode{Status::UncertainLastUsableValue}}),
    Status::UncertainLastUsableValue)
    << "an Uncertain value was returned by a throwing form";
  EXPECT_EQ(thrownStatus(Result<int32_t>{StatusCode{Status::UncertainLastUsableValue}}),
    Status::UncertainLastUsableValue);
  EXPECT_EQ(thrownStatus(Result<int32_t>{StatusCode{Status::BadSensorFailure}}), Status::BadSensorFailure);
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-08-A-THROWING-DATAVALUE-READ-CARRIES-A-GOOD-SUBCODE, scope=function)
TEST(ResultGoodSubcode, AThrowingDataValueReadPutsTheResultsGoodSubcodeOnTheDataValue)
{
  DataValue plain;
  plain.value() = Variant{int32_t{5}};

  const DataValue overridden =
    ua::detail::good_data_value(Result<DataValue>{plain, StatusCode{Status::GoodLocalOverride}});
  ASSERT_TRUE(overridden.status().has_value());
  EXPECT_EQ(overridden.status()->as_status(), Status::GoodLocalOverride);

  const DataValue unchanged = ua::detail::good_data_value(Result<DataValue>{plain});
  EXPECT_FALSE(unchanged.status().has_value()) << "a plain Good result set the DataValue's status";

  DataValue clamped = plain;
  clamped.status() = StatusCode{Status::GoodClamped};
  const DataValue own =
    ua::detail::good_data_value(Result<DataValue>{clamped, StatusCode{Status::GoodLocalOverride}});
  ASSERT_TRUE(own.status().has_value());
  EXPECT_EQ(own.status()->as_status(), Status::GoodClamped) << "the DataValue's own subcode was replaced";

  EXPECT_THROW(
    static_cast<void>(ua::detail::good_data_value(Result<DataValue>{plain, StatusCode{Status::Uncertain}})),
    UaException);
}

#ifdef NDEBUG

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-VALUE-BAD-CODE-RELEASE, scope=function)
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-OWN-DETAIL-BECOMES-CAUSE, scope=function)
TEST(ResultGoodSubcode, ValueWithABadCodeHoldsNoValueAndCarriesValueWithBadStatus)
{
  const Result<int32_t> first{int32_t{42}, StatusCode{Status::BadOutOfRange}};
  const Result<int32_t> second{int32_t{42}, StatusCode{Status::BadOutOfRange}};

  for (const auto* result : {&first, &second})
  {
    EXPECT_TRUE(result->is_bad());
    EXPECT_FALSE(result->has_value());
    EXPECT_EQ(result->status_code().as_status(), Status::BadOutOfRange);
  }
  for (const auto* result : {&first, &second})
  {
    ASSERT_NE(result->shared_detail(), nullptr);
    EXPECT_EQ(result->shared_detail()->code, "ValueWithBadStatus");
    EXPECT_FALSE(static_cast<bool>(*result)) << "the error result holds a value";
    EXPECT_EQ(result->value_or(-1), -1) << "the value was kept for " << result->status_code().as_uint32();
  }
  EXPECT_EQ(first.shared_detail().get(), second.shared_detail().get())
    << "the ValueWithBadStatus detail is built again for every misuse instead of shared";

  // DL-24: a code that carries its own ErrorDetail keeps it, as the cause of ValueWithBadStatus.
  const shared_ptr<const ErrorDetail> own =
    ErrorDetail::build("RangeCheck", "The value is outside the range", "ResultGoodSubcodeTest");
  const Result<int32_t> withOwnDetail{int32_t{42}, StatusCode{Status::BadOutOfRange, own}};
  EXPECT_TRUE(withOwnDetail.is_bad());
  EXPECT_EQ(withOwnDetail.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_FALSE(static_cast<bool>(withOwnDetail)) << "the error result holds a value";
  EXPECT_EQ(withOwnDetail.value_or(-1), -1);
  ASSERT_NE(withOwnDetail.shared_detail(), nullptr);
  EXPECT_EQ(withOwnDetail.shared_detail()->code, "ValueWithBadStatus");
  EXPECT_EQ(withOwnDetail.shared_detail()->cause.get(), own.get())
    << "the code's own detail is not the cause of ValueWithBadStatus";
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-03-WITH-VALUE-BAD-CODE-RELEASE, scope=function)
// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-OWN-DETAIL-BECOMES-CAUSE, scope=function)
TEST(ResultGoodSubcode, WithValueAndABadCodeHoldsNoValueAndCarriesValueWithBadStatus)
{
  const auto bad =
    Result<StatusCode>::with_value(StatusCode{Status::Good}, StatusCode{Status::BadOutOfRange});

  EXPECT_TRUE(bad.is_bad());
  EXPECT_FALSE(bad.has_value());
  EXPECT_EQ(bad.status_code().as_status(), Status::BadOutOfRange);
  for (const auto* result : {&bad})
  {
    ASSERT_NE(result->shared_detail(), nullptr);
    EXPECT_EQ(result->shared_detail()->code, "ValueWithBadStatus");
    EXPECT_FALSE(static_cast<bool>(*result)) << "the error result holds a value";
    EXPECT_EQ(result->value_or(StatusCode{Status::BadTimeout}).as_status(), Status::BadTimeout)
      << "the value was kept for " << result->status_code().as_uint32();
  }

  // DL-24: a status that carries its own ErrorDetail keeps it, as the cause of ValueWithBadStatus.
  const shared_ptr<const ErrorDetail> own =
    ErrorDetail::build("RangeCheck", "The value is outside the range", "ResultGoodSubcodeTest");
  const auto withOwnDetail =
    Result<StatusCode>::with_value(StatusCode{Status::Good}, StatusCode{Status::BadOutOfRange, own});
  EXPECT_TRUE(withOwnDetail.is_bad());
  EXPECT_EQ(withOwnDetail.status_code().as_status(), Status::BadOutOfRange);
  EXPECT_FALSE(static_cast<bool>(withOwnDetail)) << "the error result holds a value";
  EXPECT_EQ(withOwnDetail.value_or(StatusCode{Status::BadTimeout}).as_status(), Status::BadTimeout);
  ASSERT_NE(withOwnDetail.shared_detail(), nullptr);
  EXPECT_EQ(withOwnDetail.shared_detail()->code, "ValueWithBadStatus");
  EXPECT_EQ(withOwnDetail.shared_detail()->cause.get(), own.get())
    << "the status's own detail is not the cause of ValueWithBadStatus";
}

#else

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-VALUE-BAD-CODE-DEBUG, scope=function)
TEST(ResultGoodSubcodeDeathTest, ValueWithABadCodeAssertsInDebugBuilds)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto construct = []
  {
    const Result<int32_t> result{int32_t{42}, StatusCode{Status::BadOutOfRange}};
    static_cast<void>(result);
  };
  EXPECT_DEATH(construct(), "requires a status that is not Bad");
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-03-WITH-VALUE-BAD-CODE-DEBUG, scope=function)
TEST(ResultGoodSubcodeDeathTest, WithValueAndABadCodeAssertsInDebugBuilds)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const auto construct = []
  {
    const auto result =
      Result<StatusCode>::with_value(StatusCode{Status::Good}, StatusCode{Status::BadOutOfRange});
    static_cast<void>(result);
  };
  EXPECT_DEATH(construct(), "requires a status that is not Bad");
}

#endif
