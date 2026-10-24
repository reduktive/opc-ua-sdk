// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::async::post_owning: the completion it returns owns its object until it answers, and a
// collaborator that answers twice does nothing the second time.

#include "ua_on_strand.h"

#include "ua_logger.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <memory>

namespace
{

struct Operation : std::enable_shared_from_this<Operation>
{};

}  // namespace

// @relation(AC-COMP-CORE-ASYNC-CORO-03-AN-OWNING-COMPLETION-FIRED-TWICE-DOES-NOTHING-THE-SECOND-TIME, scope=function)
TEST(PostOwning, AnOwningCompletionFiredTwiceDoesNothingTheSecondTime)
{
  boost::asio::io_context context;
  int continuations = 0;
  auto operation = std::make_shared<Operation>();
  const std::weak_ptr<Operation> weak = operation;
  auto completion = ua::async::post_owning(operation.get(),
    context.get_executor(),
    ua::Logger{},
    [&continuations](Operation& /*self*/) { ++continuations; });
  operation.reset();

  completion();
  completion();
  context.run();

  EXPECT_EQ(continuations, 1) << "the continuation's runs";
  EXPECT_TRUE(weak.expired()) << "the completion still holds the object it owned after it has answered";
}
