// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "ua_result.h"
#include "ua_error_detail.h"

using namespace ua;

TEST(BatchResultTests, GoodBatchWithItems)
{
  BatchResult<Result<int>> batch;
  batch.items.push_back(Result<int>{10});
  batch.items.push_back(Result<int>{StatusCode{Status::BadNodeIdUnknown}});
  batch.items.push_back(Result<int>{42});

  EXPECT_TRUE(batch.batchStatus.is_good());
  ASSERT_EQ(batch.items.size(), 3U);
  EXPECT_TRUE(batch.items[0].is_good());
  EXPECT_EQ(batch.items[0].value(), 10);
  EXPECT_TRUE(batch.items[1].is_bad());
  EXPECT_EQ(batch.items[1].status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_TRUE(batch.items[2].is_good());
  EXPECT_EQ(batch.items[2].value(), 42);
}

TEST(BatchResultTests, BadBatchWithErrorDetail)
{
  BatchResult<Result<int>> batch;
  batch.batchStatus = VoidResult{StatusCode{Status::BadUserAccessDenied},
    make_error_detail("AuthzDenied", "Authorization denied for batch operation", "Authorizer")};

  EXPECT_TRUE(batch.batchStatus.is_bad());
  EXPECT_EQ(batch.batchStatus.status_code().as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(batch.batchStatus.error_detail(), nullptr);
  EXPECT_EQ(batch.batchStatus.error_detail()->code, "AuthzDenied");
  EXPECT_EQ(batch.batchStatus.error_detail()->source, "Authorizer");
  EXPECT_TRUE(batch.items.empty());
}

TEST(BatchResultTests, EmptyItemsIsValid)
{
  BatchResult<VoidResult> batch;
  EXPECT_TRUE(batch.batchStatus.is_good());
  EXPECT_TRUE(batch.items.empty());
}

TEST(BatchResultTests, MoveConstructible)
{
  BatchResult<Result<std::string>> batch;
  batch.items.push_back(Result<std::string>{std::string{"hello"}});

  BatchResult<Result<std::string>> moved{std::move(batch)};
  ASSERT_EQ(moved.items.size(), 1U);
  EXPECT_EQ(moved.items[0].value(), "hello");
}
