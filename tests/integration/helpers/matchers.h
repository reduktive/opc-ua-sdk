// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_INTEGRATION_HELPERS_MATCHERS_H
#define UA_INTEGRATION_HELPERS_MATCHERS_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ua_data_value.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <ostream>
#include <type_traits>
#include <utility>

namespace ua::test_helpers
{

namespace matchers_detail
{

template<typename T>
concept HasIsGood = requires(const T& t) {
  { t.is_good() } -> std::convertible_to<bool>;
};

template<typename T>
concept HasStatusOpt = requires(const T& t) {
  { t.status().has_value() } -> std::convertible_to<bool>;
  { t.status().value().is_good() } -> std::convertible_to<bool>;
};

template<typename T>
concept HasStatusCode = requires(const T& t) {
  { t.status_code() } -> std::convertible_to<ua::StatusCode>;
};

template<typename T>
concept HasServiceResult = requires(const T& t) {
  { t.response_header().service_result() } -> std::convertible_to<ua::StatusCode>;
};

template<typename T>
bool is_good_of(const T& arg)
{
  // Order matters:
  //   1. StatusCode is the leaf type.
  //   2. DataValue has both .status() (optional) and not .is_good() - check HasStatusOpt next.
  //   3. Result<T> has both .is_good() and .status_code() - prefer .is_good() (cheaper, exact).
  //   4. BrowseResult / CallMethodResult / similar have .status_code() but no top-level
  //      .is_good() - fall through to status_code().is_good().
  if constexpr (std::is_same_v<std::decay_t<T>, ua::StatusCode>)
  {
    return arg.is_good();
  }
  else if constexpr (HasStatusOpt<T>)
  {
    return !arg.status().has_value() || arg.status().value().is_good();
  }
  else if constexpr (HasIsGood<T>)
  {
    return arg.is_good();
  }
  else if constexpr (HasStatusCode<T>)
  {
    return arg.status_code().is_good();
  }
  else
  {
    static_assert(sizeof(T) == 0, "Good()/Bad()/HasStatus() cannot inspect this type");
    return false;
  }
}

template<typename T>
ua::StatusCode status_code_of(const T& arg)
{
  if constexpr (std::is_same_v<std::decay_t<T>, ua::StatusCode>)
  {
    return arg;
  }
  else if constexpr (HasStatusOpt<T>)
  {
    return arg.status().value_or(ua::StatusCode{ua::Status::Good});
  }
  else if constexpr (HasStatusCode<T>)
  {
    return arg.status_code();
  }
  else
  {
    static_assert(sizeof(T) == 0, "status_code_of() cannot inspect this type");
    return ua::StatusCode{};
  }
}

}  // namespace matchers_detail

// ---------------------------------------------------------------------------
// Tier 1/2: polymorphic status matchers
//
// Good()/Bad(code) and HasStatus(Status::...) work on anything carrying a status:
//   - ua::StatusCode
//   - ua::DataValue            (status is optional<StatusCode>; empty == good)
//   - ua::Result<T>            (status_code() accessor)
//   - WriteRequest results     (Array<StatusCode> - element type is StatusCode)
//   - Any type with is_good()
//
// Usage:
//   EXPECT_THAT(resp.results()[0], Good());
//   EXPECT_THAT(result, Good());                          // Result<ReadResponse>
//   EXPECT_THAT(resp.results()[0], HasStatus(Status::BadIndexRangeNoData));
//   EXPECT_THAT(channel.status_code(), Good());
//
//   EXPECT_THAT(resp.results(), ElementsAre(Good(), Good(), Good()));
// ---------------------------------------------------------------------------

MATCHER(Good, std::string(negation ? "is not good" : "is good"))
{
  const auto sc = matchers_detail::status_code_of(arg);
  *result_listener << "status = 0x" << std::hex << sc.as_uint32();
  return matchers_detail::is_good_of(arg);
}

MATCHER_P(Bad, expectedStatusCode,
  std::string(negation ? "is not bad with " : "is bad with ") + ::testing::PrintToString(expectedStatusCode))
{
  if (matchers_detail::is_good_of(arg))
  {
    *result_listener << "status is good";
    return false;
  }
  const auto actual = matchers_detail::status_code_of(arg);
  if (!(actual == expectedStatusCode))
  {
    *result_listener << "status = 0x" << std::hex << actual.as_uint32();
    return false;
  }
  return true;
}

// HasStatus on a DataValue treats an empty optional<StatusCode> as Status::Good
// (via value_or). This means a regression that drops the status field entirely
// will fail the matcher with "status = 0x0" rather than a clearer "status was
// absent" message. For negative-path tests where the status field MUST be
// present, use HasStatusPresent() instead.
MATCHER_P(HasStatus, expectedStatus,
  std::string(negation ? "does not have status " : "has status ") + ::testing::PrintToString(expectedStatus))
{
  const auto actual = matchers_detail::status_code_of(arg).as_status();
  if (actual != expectedStatus)
  {
    *result_listener << "status = 0x" << std::hex << static_cast<uint32_t>(actual);
    return false;
  }
  return true;
}

// HasStatusPresent - for negative-path tests on DataValue / ReadResult, where
// an empty status optional indicates a structural regression that should fail
// distinctly from a wrong-status outcome. On types without an optional status
// (StatusCode, Result<T>), behaves identically to HasStatus.
MATCHER_P(HasStatusPresent, expectedStatus,
  std::string(negation ? "does not have present status " : "has present status ") +
    ::testing::PrintToString(expectedStatus))
{
  using ArgT = std::decay_t<arg_type>;
  if constexpr (matchers_detail::HasStatusOpt<ArgT>)
  {
    if (!arg.status().has_value())
    {
      *result_listener << "status optional is empty (treated as Good)";
      return false;
    }
    if (arg.status().value().as_status() != expectedStatus)
    {
      *result_listener << "status = 0x" << std::hex << arg.status().value().as_uint32();
      return false;
    }
    return true;
  }
  else
  {
    const auto actual = matchers_detail::status_code_of(arg).as_status();
    if (actual != expectedStatus)
    {
      *result_listener << "status = 0x" << std::hex << static_cast<uint32_t>(actual);
      return false;
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// Tier 3: response-level matchers
//
// Polymorphic over any response with response_header().service_result():
//   EXPECT_THAT(resp, ServiceResultIsGood());
//   EXPECT_THAT(resp, ServiceResultIs(some_status_code));
// ---------------------------------------------------------------------------

MATCHER(ServiceResultIsGood, std::string(negation ? "service result is not good" : "service result is good"))
{
  static_assert(matchers_detail::HasServiceResult<arg_type>,
    "ServiceResultIsGood() requires a response with response_header().service_result()");
  const auto sc = arg.response_header().service_result();
  *result_listener << "service_result = 0x" << std::hex << sc.as_uint32();
  return sc.is_good();
}

MATCHER_P(ServiceResultIs, expectedStatusCode,
  std::string(negation ? "service result is not " : "service result is ") +
    ::testing::PrintToString(expectedStatusCode))
{
  static_assert(matchers_detail::HasServiceResult<arg_type>,
    "ServiceResultIs() requires a response with response_header().service_result()");
  const auto sc = arg.response_header().service_result();
  if (!(sc == expectedStatusCode))
  {
    *result_listener << "service_result = 0x" << std::hex << sc.as_uint32();
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Tier 2 (value-bearing): typed value matchers on DataValue
//
//   EXPECT_THAT(resp.results()[0], good_value_of<int32_t>(42));
//   EXPECT_THAT(resp.results()[0], good_value_that<double>(::testing::Gt(0.0)));
//
// T must be one of ua::IsBuiltInScalarType (int32_t, NodeId, QualifiedName, etc.).
// ---------------------------------------------------------------------------

template<typename T>
class GoodValueOfMatcher
{
public:
  using is_gtest_matcher = void;

  explicit GoodValueOfMatcher(T expected) : mExpected(std::move(expected))
  {}

  bool MatchAndExplain(const ua::DataValue& dv, ::testing::MatchResultListener* listener) const
  {
    if (dv.status().has_value() && dv.status().value().is_bad())
    {
      *listener << "status = 0x" << std::hex << dv.status().value().as_uint32();
      return false;
    }
    const auto* actual = dv.value().template try_as<T>();
    if (!actual)
    {
      *listener << "value does not hold expected type";
      return false;
    }
    if (!(*actual == mExpected))
    {
      *listener << "value = " << ::testing::PrintToString(*actual);
      return false;
    }
    return true;
  }

  void DescribeTo(std::ostream* os) const
  {
    *os << "is good and value equals " << ::testing::PrintToString(mExpected);
  }

  void DescribeNegationTo(std::ostream* os) const
  {
    *os << "is bad or value does not equal " << ::testing::PrintToString(mExpected);
  }

private:
  T mExpected;
};

template<typename T>
::testing::Matcher<ua::DataValue> good_value_of(T expected)
{
  return GoodValueOfMatcher<T>(std::move(expected));
}

template<typename T>
class GoodValueThatMatcher
{
public:
  using is_gtest_matcher = void;

  explicit GoodValueThatMatcher(::testing::Matcher<T> inner) : mInner(std::move(inner))
  {}

  bool MatchAndExplain(const ua::DataValue& dv, ::testing::MatchResultListener* listener) const
  {
    if (dv.status().has_value() && dv.status().value().is_bad())
    {
      *listener << "status = 0x" << std::hex << dv.status().value().as_uint32();
      return false;
    }
    const auto* actual = dv.value().template try_as<T>();
    if (!actual)
    {
      *listener << "value does not hold expected type";
      return false;
    }
    return mInner.MatchAndExplain(*actual, listener);
  }

  void DescribeTo(std::ostream* os) const
  {
    *os << "is good and value ";
    mInner.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const
  {
    *os << "is bad or value ";
    mInner.DescribeNegationTo(os);
  }

private:
  ::testing::Matcher<T> mInner;
};

template<typename T>
::testing::Matcher<ua::DataValue> good_value_that(::testing::Matcher<T> inner)
{
  return GoodValueThatMatcher<T>(std::move(inner));
}

// ---------------------------------------------------------------------------
// Write shortcuts
//
//   EXPECT_THAT(resp, WriteSucceeds());                // exactly 1 result, Good
//   EXPECT_THAT(resp, WriteFailsWith(Status::BadX));   // exactly 1 result, that status
// ---------------------------------------------------------------------------

MATCHER(WriteSucceeds, std::string(negation ? "write did not succeed" : "write succeeded"))
{
  const auto sc = arg.response_header().service_result();
  if (!sc.is_good())
  {
    *result_listener << "service_result = 0x" << std::hex << sc.as_uint32();
    return false;
  }
  if (arg.results().size() != 1u)
  {
    *result_listener << "results.size() = " << arg.results().size();
    return false;
  }
  if (!arg.results()[0].is_good())
  {
    *result_listener << "result status = 0x" << std::hex << arg.results()[0].as_uint32();
    return false;
  }
  return true;
}

MATCHER_P(WriteFailsWith, expectedStatus,
  std::string(negation ? "write does not fail with " : "write fails with ") +
    ::testing::PrintToString(expectedStatus))
{
  const auto sc = arg.response_header().service_result();
  if (!sc.is_good())
  {
    *result_listener << "service_result = 0x" << std::hex << sc.as_uint32();
    return false;
  }
  if (arg.results().size() != 1u)
  {
    *result_listener << "results.size() = " << arg.results().size();
    return false;
  }
  if (arg.results()[0].as_status() != expectedStatus)
  {
    *result_listener << "result status = 0x" << std::hex << arg.results()[0].as_uint32();
    return false;
  }
  return true;
}

}  // namespace ua::test_helpers

#endif  // UA_INTEGRATION_HELPERS_MATCHERS_H
