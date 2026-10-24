// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A result holding a value can be Uncertain, and a value's status travels with it. `Result<T>(value, status)`
// and `Result<StatusCode>::with_value(value, status)` hold the value for an Uncertain code; `transform` keeps
// the code it was given, `and_then` answers the combined code of the two steps, and `transform_error` leaves
// a result holding a value alone. These tests use only members that a result has always had, so they also run
// against a result that discards an Uncertain code's value.

#include <gtest/gtest.h>

#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <cstdint>
#include <string>
#include <utility>

using namespace ua;

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-02-VALUE-UNCERTAIN-HOLDS-THE-VALUE, scope=function)
TEST(ResultUncertainValue, AValueWithAnUncertainCodeHoldsTheValueAndTheCode)
{
  const Result<int32_t> result{int32_t{42}, StatusCode{Status::UncertainLastUsableValue}};

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_FALSE(result.is_good());
  EXPECT_FALSE(static_cast<bool>(result)) << "an Uncertain result converts to true";
  EXPECT_EQ(result.status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(result.value_or(-1), 42) << "the value was discarded";
  int32_t held = -1;
  EXPECT_NO_THROW(held = result.value());
  EXPECT_EQ(held, 42);
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-03-WITH-VALUE-UNCERTAIN-HOLDS-THE-VALUE, scope=function)
TEST(ResultUncertainValue, WithValueAndAnUncertainCodeHoldsTheValueAndTheCode)
{
  const auto result = Result<StatusCode>::with_value(
    StatusCode{Status::BadSensorFailure}, StatusCode{Status::UncertainSensorNotAccurate});

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().as_status(), Status::UncertainSensorNotAccurate);
  EXPECT_EQ(result.value_or(StatusCode{Status::BadTimeout}).as_status(), Status::BadSensorFailure)
    << "the held StatusCode value was discarded";
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-05-VALUE-WITHOUT-A-VALUE-THROWS-THE-CODE, scope=function)
TEST(ResultUncertainValue, TheValueOfAnUncertainResultWithoutOneThrowsItsCode)
{
  const Result<int32_t> result{StatusCode{Status::UncertainNoCommunicationLastUsableValue}};

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.value_or(-1), -1);
  try
  {
    static_cast<void>(result.value());
    FAIL() << "value() returned for a result holding no value";
  }
  catch (const UaException& error)
  {
    EXPECT_EQ(error.status(), Status::UncertainNoCommunicationLastUsableValue);
  }
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-06-TRANSFORM-KEEPS-THE-CODE, scope=function)
TEST(ResultUncertainValue, TransformKeepsAGoodSubcodeAndAnUncertainCode)
{
  const auto toText = [](const int32_t& value)
  {
    return std::to_string(value);
  };

  const Result<int32_t> clamped{int32_t{7}, StatusCode{Status::GoodClamped}};
  const Result<std::string> fromClamped = clamped.transform(toText);
  EXPECT_EQ(fromClamped.status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(fromClamped.value_or("none"), "7");

  Result<int32_t> uncertain{int32_t{8}, StatusCode{Status::UncertainLastUsableValue}};
  const Result<std::string> fromUncertain = std::as_const(uncertain).transform(toText);
  EXPECT_EQ(fromUncertain.status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(fromUncertain.value_or("none"), "8");

  const Result<std::string> moved =
    std::move(uncertain).transform([](int32_t value) { return std::to_string(value); });
  EXPECT_EQ(moved.status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(moved.value_or("none"), "8");

  const Result<int32_t> none{StatusCode{Status::Uncertain}};
  const Result<std::string> fromNone = none.transform(toText);
  EXPECT_EQ(fromNone.status_code().as_status(), Status::Uncertain);
  EXPECT_EQ(fromNone.value_or("none"), "none");
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-06-AND-THEN-COMBINES-THE-CODES, scope=function)
TEST(ResultUncertainValue, AndThenAnswersTheCombinedCodeOfBothSteps)
{
  const auto plainGood = [](const int32_t& value) -> Result<std::string>
  {
    return std::to_string(value);
  };
  const auto overridden = [](const int32_t& value) -> Result<std::string>
  {
    return Result<std::string>{std::to_string(value), StatusCode{Status::GoodLocalOverride}};
  };
  const auto uncertain = [](const int32_t& value) -> Result<std::string>
  {
    return Result<std::string>{std::to_string(value), StatusCode{Status::UncertainSensorNotAccurate}};
  };
  const auto failed = [](const int32_t&) -> Result<std::string>
  {
    return StatusCode{Status::BadSensorFailure};
  };

  const Result<int32_t> clamped{int32_t{1}, StatusCode{Status::GoodClamped}};
  const Result<int32_t> lastUsable{int32_t{2}, StatusCode{Status::UncertainLastUsableValue}};

  // A plain Good from the second step takes the first step's code.
  EXPECT_EQ(clamped.and_then(plainGood).status_code().as_status(), Status::GoodClamped);
  EXPECT_EQ(clamped.and_then(plainGood).value_or("none"), "1");
  EXPECT_EQ(lastUsable.and_then(plainGood).status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(lastUsable.and_then(plainGood).value_or("none"), "2");
  // The worse severity of the two is answered.
  EXPECT_EQ(clamped.and_then(uncertain).status_code().as_status(), Status::UncertainSensorNotAccurate);
  EXPECT_EQ(lastUsable.and_then(overridden).status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(lastUsable.and_then(overridden).value_or("none"), "2");
  EXPECT_EQ(clamped.and_then(failed).status_code().as_status(), Status::BadSensorFailure);
  // Both steps carry a subcode of the same severity: the second step's code is answered.
  EXPECT_EQ(clamped.and_then(overridden).status_code().as_status(), Status::GoodLocalOverride);
  EXPECT_EQ(lastUsable.and_then(uncertain).status_code().as_status(), Status::UncertainSensorNotAccurate);
}

// @relation(AC-COMP-CORE-RESULT-GOOD-SUBCODE-04-TRANSFORM-ERROR-KEEPS-GOOD-SUBCODE, scope=function)
TEST(ResultUncertainValue, TransformErrorLeavesAnUncertainResultHoldingAValueAlone)
{
  int mappingCalls = 0;
  const auto mapping = [&mappingCalls](const StatusCode&)
  {
    ++mappingCalls;
    return StatusCode{Status::BadInternalError};
  };
  const Result<int32_t> uncertain{int32_t{42}, StatusCode{Status::UncertainLastUsableValue}};

  const Result<int32_t> mapped = uncertain.transform_error(mapping);
  EXPECT_EQ(mapped.status_code().as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(mapped.value_or(-1), 42);
  EXPECT_EQ(mappingCalls, 0) << "the mapping was called on a result holding a value";

  const Result<int32_t> withoutValue{StatusCode{Status::UncertainLastUsableValue}};
  const Result<int32_t> mappedWithoutValue = withoutValue.transform_error(mapping);
  EXPECT_EQ(mappedWithoutValue.status_code().as_status(), Status::BadInternalError);
  EXPECT_EQ(mappingCalls, 1);
}
