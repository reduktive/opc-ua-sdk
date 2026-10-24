// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_default_object_node.h"
#include "ua_default_view_node.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <atomic>
#include <chrono>
#include <exception>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>

using namespace ua;

namespace
{

WriteValue make_value_write(const NodeId& nodeId, int32_t value)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(AttributeId::Value);
  write.value() = DataValue{Variant{value}};
  return write;
}

struct ViewReentryObservation
{
  std::promise<void> returned;
  std::exception_ptr exception;
  std::optional<BoolResult> initialMembership;
  std::optional<VoidResult> reentrantAdd;
  std::optional<BoolResult> addedMembership;
  std::thread::id workerThread;
  std::thread::id membershipCallbackThread;
  std::thread::id addCallbackThread;
};

}  // namespace

// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-VALUE-WRITE-01-RICH-REFUSAL, scope=function)
// @relation(AC-COMP-SVR-DEFAULT-BASE-NODE-VALUE-WRITE-01-EXACTLY-ONCE, scope=function)
TEST(DefaultNodeAsyncSafety, UnsupportedBaseNodeValueWriteCompletesOnceWithRichFailure)
{
  const NodeId nodeId{3, "object-without-value"};
  auto node = default_ns::ObjectNode::create(nodeId);

  int calls{0};
  std::optional<VoidResult> captured;
  EXPECT_NO_THROW(node->write_value_async(make_value_write(nodeId, 42),
    nullptr,
    [&calls, &captured](VoidResult result)
    {
      ++calls;
      captured = std::move(result);
    }));

  ASSERT_EQ(calls, 1);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), Status::BadAttributeIdInvalid);
  ASSERT_NE(captured->shared_detail(), nullptr);
  const auto detail = captured->shared_detail();
  EXPECT_EQ(captured->status_code().shared_detail(), detail);
  EXPECT_EQ(detail->code, "ValueWriteUnsupported");
  EXPECT_EQ(detail->source, "DefaultBaseNode");
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), to_string(nodeId));
  EXPECT_EQ(::ua::test_utils::error_context(detail.get(), ContextKeys::nodeAttribute.value()),
    to_string(AttributeId::Value));
}

// @relation(AC-COMP-SVR-DEFAULT-VIEW-NODE-MEMBERSHIP-01-REENTRANT, scope=function)
TEST(DefaultNodeAsyncSafety, ViewMembershipCallbackCanReenterLockTakingOperation)
{
  using namespace std::chrono_literals;

  const NodeId viewId{3, "reentrant-view"};
  const NodeId initialMember{3, "initial-member"};
  const NodeId reentrantMember{3, "reentrant-member"};
  auto view = default_ns::ViewNode::create(viewId);

  std::optional<VoidResult> initialAdd;
  view->add_node_to_view_async(
    initialMember, [&initialAdd](VoidResult result) { initialAdd = std::move(result); });
  ASSERT_TRUE(initialAdd.has_value());
  ASSERT_TRUE(initialAdd->is_good());

  auto observation = std::make_shared<ViewReentryObservation>();
  auto returned = observation->returned.get_future();
  std::thread worker(
    [view, initialMember, reentrantMember, observation]
    {
      observation->workerThread = std::this_thread::get_id();
      try
      {
        view->is_node_in_view_async(initialMember,
          [view, reentrantMember, observation](BoolResult result)
          {
            observation->membershipCallbackThread = std::this_thread::get_id();
            observation->initialMembership = std::move(result);
            view->add_node_to_view_async(reentrantMember,
              [observation](VoidResult addResult)
              {
                observation->addCallbackThread = std::this_thread::get_id();
                observation->reentrantAdd = std::move(addResult);
              });
          });
        view->is_node_in_view_async(reentrantMember,
          [observation](BoolResult result) { observation->addedMembership = std::move(result); });
      }
      catch (...)
      {
        observation->exception = std::current_exception();
      }
      observation->returned.set_value();
    });

  if (returned.wait_for(5s) != std::future_status::ready)
  {
    worker.detach();
    FAIL() << "View membership callback deadlocked while re-entering a lock-taking ViewNode method";
  }
  worker.join();

  EXPECT_EQ(observation->exception, nullptr);
  ASSERT_TRUE(observation->initialMembership.has_value());
  ASSERT_TRUE(observation->initialMembership->is_good());
  EXPECT_TRUE(observation->initialMembership->value());
  ASSERT_TRUE(observation->reentrantAdd.has_value());
  EXPECT_TRUE(observation->reentrantAdd->is_good());
  ASSERT_TRUE(observation->addedMembership.has_value());
  ASSERT_TRUE(observation->addedMembership->is_good());
  EXPECT_TRUE(observation->addedMembership->value());
  EXPECT_EQ(observation->membershipCallbackThread, observation->workerThread);
  EXPECT_EQ(observation->addCallbackThread, observation->workerThread);
}

// @relation(AC-COMP-SVR-DEFAULT-VIEW-NODE-MEMBERSHIP-01-THROWING-CALLBACK, scope=function)
TEST(DefaultNodeAsyncSafety, ThrowingViewMembershipCallbackIsContainedAndNotReinvoked)
{
  auto view = default_ns::ViewNode::create(NodeId{3, "throwing-callback-view"});
  std::atomic<int> calls{0};

  EXPECT_NO_THROW(view->is_node_in_view_async(NodeId{3, "candidate"},
    [&calls](BoolResult)
    {
      calls.fetch_add(1, std::memory_order_relaxed);
      throw std::runtime_error{"sentinel membership callback failure"};
    }));
  EXPECT_EQ(calls.load(std::memory_order_relaxed), 1);
}
