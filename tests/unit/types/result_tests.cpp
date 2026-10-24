// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "gtest/gtest.h"
#include "ua_result.h"

using namespace ua;

// --- Result<T> construction ---

TEST(ResultT, ConstructFromValue)
{
  Result<int> r = 42;
  EXPECT_TRUE(r.is_good());
  EXPECT_FALSE(r.is_bad());
  EXPECT_FALSE(r.is_uncertain());
  EXPECT_TRUE(static_cast<bool>(r));
  EXPECT_EQ(r.value(), 42);
  EXPECT_TRUE(r.status_code().is_good());
}

TEST(ResultT, ConstructFromStatusCode)
{
  Result<int> r = StatusCode{Status::BadNodeIdUnknown};
  EXPECT_FALSE(r.is_good());
  EXPECT_TRUE(r.is_bad());
  EXPECT_FALSE(static_cast<bool>(r));
  EXPECT_EQ(r.status_code().as_status(), Status::BadNodeIdUnknown);
}

TEST(ResultT, ConstructFromStatusEnum)
{
  // Status converts implicitly to StatusCode, which converts implicitly to Result<T>
  Result<int> r = StatusCode{Status::BadInternalError};
  EXPECT_TRUE(r.is_bad());
  EXPECT_EQ(r.status_code().as_status(), Status::BadInternalError);
}

TEST(ResultT, ConstructFromMoveOnlyType)
{
  Result<std::unique_ptr<int>> r = std::make_unique<int>(99);
  EXPECT_TRUE(r.is_good());
  EXPECT_EQ(*r.value(), 99);
}

TEST(ResultT, CopyResult)
{
  Result<std::string> r = std::string("hello");
  Result<std::string> copy = r;
  EXPECT_TRUE(copy.is_good());
  EXPECT_EQ(copy.value(), "hello");
}

TEST(ResultT, MoveResult)
{
  Result<std::unique_ptr<int>> r = std::make_unique<int>(7);
  Result<std::unique_ptr<int>> moved = std::move(r);
  EXPECT_TRUE(moved.is_good());
  EXPECT_EQ(*moved.value(), 7);
}

// --- Result<T> value access ---

TEST(ResultT, ValueThrowsOnError)
{
  Result<int> r = StatusCode{Status::BadNodeIdUnknown};
  EXPECT_THROW((void)r.value(), UaException);
  try
  {
    (void)r.value();
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadNodeIdUnknown);
  }
}

TEST(ResultT, ValueOrReturnsValueOnGood)
{
  Result<int> r = 42;
  EXPECT_EQ(r.value_or(0), 42);
}

TEST(ResultT, ValueOrReturnsFallbackOnError)
{
  Result<int> r = StatusCode{Status::BadInternalError};
  EXPECT_EQ(r.value_or(99), 99);
}

TEST(ResultT, ValueOrMoveReturnsValueOnGood)
{
  Result<std::string> r = std::string("hello");
  EXPECT_EQ(std::move(r).value_or("fallback"), "hello");
}

TEST(ResultT, ValueOrMoveReturnsFallbackOnError)
{
  Result<std::string> r = StatusCode{Status::BadInternalError};
  EXPECT_EQ(std::move(r).value_or("fallback"), "fallback");
}

TEST(ResultT, MoveValue)
{
  Result<std::unique_ptr<int>> r = std::make_unique<int>(42);
  auto ptr = std::move(r).value();
  EXPECT_EQ(*ptr, 42);
}

// --- Result<T> monadic operations ---

TEST(ResultT, TransformOnGood)
{
  Result<int> r = 10;
  Result<std::string> mapped = r.transform([](int v) { return std::to_string(v); });
  EXPECT_TRUE(mapped.is_good());
  EXPECT_EQ(mapped.value(), "10");
}

TEST(ResultT, TransformOnError)
{
  Result<int> r = StatusCode{Status::BadTimeout};
  Result<std::string> mapped = r.transform([](int v) { return std::to_string(v); });
  EXPECT_TRUE(mapped.is_bad());
  EXPECT_EQ(mapped.status_code().as_status(), Status::BadTimeout);
}

TEST(ResultT, TransformMoveOnGood)
{
  Result<std::unique_ptr<int>> r = std::make_unique<int>(5);
  Result<int> mapped = std::move(r).transform([](std::unique_ptr<int> p) { return *p; });
  EXPECT_TRUE(mapped.is_good());
  EXPECT_EQ(mapped.value(), 5);
}

TEST(ResultT, AndThenOnGood)
{
  Result<int> r = 42;
  auto chained = r.and_then(
    [](int v) -> Result<std::string>
    {
      if (v > 0)
      {
        return std::to_string(v);
      }
      return StatusCode{Status::BadInvalidArgument};
    });
  EXPECT_TRUE(chained.is_good());
  EXPECT_EQ(chained.value(), "42");
}

TEST(ResultT, AndThenPropagatesError)
{
  Result<int> r = StatusCode{Status::BadTimeout};
  auto chained = r.and_then([](int v) -> Result<std::string> { return std::to_string(v); });
  EXPECT_TRUE(chained.is_bad());
  EXPECT_EQ(chained.status_code().as_status(), Status::BadTimeout);
}

TEST(ResultT, AndThenReturnsError)
{
  Result<int> r = -1;
  auto chained = r.and_then(
    [](int v) -> Result<std::string>
    {
      if (v > 0)
      {
        return std::to_string(v);
      }
      return StatusCode{Status::BadInvalidArgument};
    });
  EXPECT_TRUE(chained.is_bad());
  EXPECT_EQ(chained.status_code().as_status(), Status::BadInvalidArgument);
}

TEST(ResultT, TransformErrorOnError)
{
  Result<int> r = StatusCode{Status::BadTimeout};
  auto mapped = r.transform_error([](StatusCode) { return StatusCode{Status::BadInternalError}; });
  EXPECT_TRUE(mapped.is_bad());
  EXPECT_EQ(mapped.status_code().as_status(), Status::BadInternalError);
}

TEST(ResultT, TransformErrorOnGoodPassesThrough)
{
  Result<int> r = 42;
  auto mapped = r.transform_error([](StatusCode) { return StatusCode{Status::BadInternalError}; });
  EXPECT_TRUE(mapped.is_good());
  EXPECT_EQ(mapped.value(), 42);
}

// --- Result<void> construction ---

TEST(ResultVoid, DefaultConstructIsGood)
{
  Result<void> r;
  EXPECT_TRUE(r.is_good());
  EXPECT_FALSE(r.is_bad());
  EXPECT_TRUE(static_cast<bool>(r));
  EXPECT_TRUE(r.status_code().is_good());
}

TEST(ResultVoid, ConstructFromStatusCode)
{
  Result<void> r = StatusCode{Status::BadInternalError};
  EXPECT_FALSE(r.is_good());
  EXPECT_TRUE(r.is_bad());
  EXPECT_FALSE(static_cast<bool>(r));
  EXPECT_EQ(r.status_code().as_status(), Status::BadInternalError);
}

TEST(ResultVoid, ValueNoOpOnGood)
{
  Result<void> r;
  EXPECT_NO_THROW(r.value());
}

TEST(ResultVoid, ValueThrowsOnError)
{
  Result<void> r = StatusCode{Status::BadTimeout};
  EXPECT_THROW(r.value(), UaException);
  try
  {
    r.value();
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadTimeout);
  }
}

TEST(ResultVoid, CopyResult)
{
  Result<void> r = StatusCode{Status::BadTimeout};
  Result<void> copy = r;
  EXPECT_TRUE(copy.is_bad());
  EXPECT_EQ(copy.status_code().as_status(), Status::BadTimeout);
}

// --- Result<void> for uncertain status ---

TEST(ResultVoid, UncertainStatus)
{
  Result<void> r = StatusCode{Status::Uncertain};
  EXPECT_FALSE(r.is_good());
  EXPECT_FALSE(r.is_bad());
  EXPECT_TRUE(r.is_uncertain());
}

// --- is_result trait ---

TEST(IsResultTrait, ResultTypes)
{
  static_assert(is_result_v<Result<int>>);
  static_assert(is_result_v<Result<void>>);
  static_assert(is_result_v<Result<std::string>>);
  static_assert(!is_result_v<int>);
  static_assert(!is_result_v<StatusCode>);
  static_assert(!is_result_v<std::pair<StatusCode, int>>);
}

// --- Result with string_view-like types ---

TEST(ResultT, WorksWithStringView)
{
  std::string storage = "hello";
  Result<std::string_view> r = std::string_view{storage};
  EXPECT_TRUE(r.is_good());
  EXPECT_EQ(r.value(), "hello");
}

// --- Result error propagation preserves status code flags ---

TEST(ResultT, PreservesStatusCodeFlags)
{
  StatusCode sc{Status::BadNodeIdUnknown};
  sc.overflow(true);
  Result<int> r = sc;
  EXPECT_TRUE(r.status_code().overflow());
  EXPECT_EQ(r.status_code().as_status(), Status::BadNodeIdUnknown);
}
