// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `SubscriptionConfig`'s tuning fields, proven from the public handle to the wire request (S18).
///
/// Four of the six fields on `SubscriptionConfig` never left the struct. `build_create_subscription_request`
/// hard-coded `requested_lifetime_count() = 30`, `requested_max_keep_alive_count() = 10`, `priority() = 0`
/// and `publishing_enabled() = true`, so a caller who set any of them got the SDK's defaults with nothing to
/// tell them otherwise. `maxKeepAliveCount` is the costly one: with `lifetimeCount` it is what decides how
/// fast a dead server is noticed and how long a dead client keeps server resources alive.
///
/// It survived review for the reason this whole class of defect survives review - the hard-coded value WAS
/// the field's documented default, so every existing test passed either way. These tests therefore assign
/// NON-DEFAULT values throughout and read the captured request back: a test that used 30 and 10 could not
/// distinguish wired from dead.
///
/// The modify path is here for the same reason. ModifySubscription replaces the whole parameter set
/// (OPC 10000-4 5.13.3.1), so it has to re-send the caller's tuning rather than the defaults, or a caller
/// who changes only the publishing interval silently loses it. The other path that outlives the
/// CreateSubscription - the session-CHANGED recreate - is pinned in `connection_impl_tests.cpp`, which is
/// where the reconnect-drive machinery lives.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_connection_ops.h"
#include "ua_create_subscription_response.h"
#include "ua_logger.h"
#include "ua_modify_subscription_response.h"
#include "ua_reconnect_policy.h"
#include "ua_status.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>

namespace
{

using ua::Status;
using ua::StatusCode;
using ua::client::Connection;
using ua::client::Session;
using ua::client::Subscription;
using ua::client::SubscriptionConfig;
using ua::client::SubscriptionModifyConfig;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::KeepAlivePolicy;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

// The SDK's own defaults. Every value a test sets is deliberately NOT one of these - a test that asked for
// the default could not tell a wired field from a dead one, which is exactly how S18 survived.
constexpr std::uint32_t defaultLifetimeCount = 30;
constexpr std::uint32_t defaultMaxKeepAliveCount = 10;
constexpr std::uint8_t defaultPriority = 0;

ua::CreateSubscriptionResponse make_create_response(std::uint32_t id, double interval = 100.0)
{
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = id;
  response.revised_publishing_interval() = interval;
  response.revised_lifetime_count() = 60;
  response.revised_max_keep_alive_count() = 20;
  return response;
}

class SubscriptionTuningWiringTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  void SetUp() override
  {
    ua::client::ReconnectPolicy policy;
    policy.backoff.base = std::chrono::milliseconds{1};
    policy.backoff.max = std::chrono::milliseconds{1};
    policy.backoff.jitterPct = 0.0;
    mConnection = TA::create_with_ops(mCtx.get_executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      policy,
      KeepAlivePolicy{std::chrono::milliseconds{0}});
    // Reach Active, then park Publish: a live Subscription keeps one outstanding at all times, so an
    // answering fake would have pump() (which runs until the io_context is idle) never return.
    TA::reconnect_notify_active(*mConnection);
    pump();
    mSession->publish.set_hold(true);
    mSession->createSubscription.set_result(
      ua::Result<ua::CreateSubscriptionResponse>{make_create_response(/*id=*/77)});
  }

  /// Creates a Subscription through the PUBLIC handle, which is the surface `SubscriptionConfig` belongs to.
  /// Going through ConnectionImpl directly would skip the very hop that was missing.
  ua::Result<Subscription> create(SubscriptionConfig config)
  {
    Connection handle = ConnectionHandleFactory::make_connection(mConnection);
    std::optional<ua::Result<Subscription>> captured;
    handle.subscriptions().create_async(
      std::move(config), [&captured](ua::Result<Subscription> result) { captured = std::move(result); });
    pump();
    return captured.has_value() ? std::move(*captured)
                                : ua::Result<Subscription>{StatusCode{Status::BadTimeout}};
  }
};

// @verifies CL-SUB-011
// @relation(CL-SUB-011, scope=function)
TEST_F(SubscriptionTuningWiringTest, EveryTuningFieldReachesTheCreateRequest)
{
  SubscriptionConfig config;
  config.publishingIntervalMs = 250.0;
  config.lifetimeCount = 900;
  config.maxKeepAliveCount = 300;
  config.priority = 7;
  config.maxNotificationsPerPublish = 42;
  config.publishingEnabled = false;

  const auto created = create(config);
  ASSERT_TRUE(created.is_good()) << "0x" << std::hex << created.status_code().as_uint32();

  const auto requests = mSession->createSubscription.requests();
  ASSERT_EQ(requests.size(), 1U);
  const auto& request = requests.front();
  EXPECT_EQ(request.requested_publishing_interval(), 250.0);
  EXPECT_EQ(request.requested_lifetime_count(), 900U) << "lifetimeCount never left SubscriptionConfig";
  EXPECT_EQ(request.requested_max_keep_alive_count(), 300U)
    << "maxKeepAliveCount decides how fast a dead server is noticed; it never left SubscriptionConfig";
  EXPECT_EQ(request.priority(), 7) << "priority never left SubscriptionConfig";
  EXPECT_EQ(request.max_notifications_per_publish(), 42U);
  EXPECT_FALSE(request.publishing_enabled());
  // And none of them is the value the builder used to hard-code, so this cannot pass against dead fields.
  EXPECT_NE(request.requested_lifetime_count(), defaultLifetimeCount);
  EXPECT_NE(request.requested_max_keep_alive_count(), defaultMaxKeepAliveCount);
  EXPECT_NE(request.priority(), defaultPriority);
}

// OPC 10000-4 5.13.3.2, Table 90: the lifetime count shall be at least three times the keep-alive count. A
// caller who raises ONLY the keep-alive would otherwise leave the default lifetime (30) below the floor for
// their new keep-alive (300), and the server would revise BOTH - handing back a Subscription tuned like
// neither the request nor the default, with nothing to say so.
TEST_F(SubscriptionTuningWiringTest, RaisingOnlyTheKeepAliveRaisesTheLifetimeToTheTable90Floor)
{
  SubscriptionConfig config;
  config.maxKeepAliveCount = 300;

  ASSERT_TRUE(create(config).is_good());

  const auto requests = mSession->createSubscription.requests();
  ASSERT_EQ(requests.size(), 1U);
  const auto& request = requests.front();
  EXPECT_EQ(request.requested_max_keep_alive_count(), 300U);
  EXPECT_EQ(request.requested_lifetime_count(), 900U)
    << "3 x the requested keep-alive, not the default 30 that sits below the Table 90 floor";
}

// A caller who states BOTH is sent verbatim, ratio or no ratio. Overriding an explicit request would be
// worse than the server's own revision: at least the server reports what it chose.
TEST_F(SubscriptionTuningWiringTest, AnExplicitLifetimeIsSentEvenBelowTheRatio)
{
  SubscriptionConfig config;
  config.maxKeepAliveCount = 300;
  config.lifetimeCount = 400;  // below 3 x 300; the server will revise and say so

  ASSERT_TRUE(create(config).is_good());

  const auto requests = mSession->createSubscription.requests();
  ASSERT_EQ(requests.size(), 1U);
  const auto& request = requests.front();
  EXPECT_EQ(request.requested_lifetime_count(), 400U) << "an explicit request is not silently corrected";
}

// ModifySubscription replaces the whole parameter set (OPC 10000-4 5.13.3.1). Changing only the publishing
// interval used to re-send the SDK defaults for the other three, so an operator who tuned a Subscription at
// create and later retimed it lost the tuning - and the server reported success, because it was asked for
// exactly that.
TEST_F(SubscriptionTuningWiringTest, ModifyingOnlyTheIntervalReSendsTheCreatedTuning)
{
  SubscriptionConfig config;
  config.lifetimeCount = 900;
  config.maxKeepAliveCount = 300;
  config.priority = 7;
  auto created = create(config);
  ASSERT_TRUE(created.is_good());

  ua::ModifySubscriptionResponse modifyResponse;
  modifyResponse.revised_publishing_interval() = 500.0;
  mSession->modifySubscription.set_result(
    ua::Result<ua::ModifySubscriptionResponse>{std::move(modifyResponse)});

  SubscriptionModifyConfig modify;
  modify.publishingIntervalMs = 500.0;  // and nothing else
  std::optional<ua::VoidResult> modified;
  created.value().modify_async(modify, [&modified](ua::VoidResult result) { modified = result; });
  pump();
  ASSERT_TRUE(modified.has_value());
  ASSERT_TRUE(modified->is_good()) << "0x" << std::hex << modified->status_code().as_uint32();

  const auto requests = mSession->modifySubscription.requests();
  ASSERT_EQ(requests.size(), 1U);
  const auto& request = requests.front();
  EXPECT_EQ(request.requested_publishing_interval(), 500.0);
  EXPECT_EQ(request.requested_lifetime_count(), 900U) << "the modify reset the caller's lifetime";
  EXPECT_EQ(request.requested_max_keep_alive_count(), 300U) << "the modify reset the caller's keep-alive";
  EXPECT_EQ(request.priority(), 7) << "the modify reset the caller's priority";
}

// And a modify that DOES state a field overrides only that one.
TEST_F(SubscriptionTuningWiringTest, ModifyOverridesOnlyTheFieldsItStates)
{
  SubscriptionConfig config;
  config.lifetimeCount = 900;
  config.maxKeepAliveCount = 300;
  config.priority = 7;
  auto created = create(config);
  ASSERT_TRUE(created.is_good());

  ua::ModifySubscriptionResponse modifyResponse;
  modifyResponse.revised_publishing_interval() = 100.0;
  mSession->modifySubscription.set_result(
    ua::Result<ua::ModifySubscriptionResponse>{std::move(modifyResponse)});

  SubscriptionModifyConfig modify;
  modify.publishingIntervalMs = 100.0;
  modify.priority = 3;
  std::optional<ua::VoidResult> modified;
  created.value().modify_async(modify, [&modified](ua::VoidResult result) { modified = result; });
  pump();
  ASSERT_TRUE(modified.has_value() && modified->is_good());

  const auto requests = mSession->modifySubscription.requests();
  ASSERT_EQ(requests.size(), 1U);
  const auto& request = requests.front();
  EXPECT_EQ(request.priority(), 3) << "the stated field is honoured";
  EXPECT_EQ(request.requested_lifetime_count(), 900U) << "the unstated fields keep their retained values";
  EXPECT_EQ(request.requested_max_keep_alive_count(), 300U);
}

/// Runs one automatic notification-cap adjustment of Subscription 77 to @p cap through the interface the
/// pipeline uses, and returns its outcome.
ua::VoidResult adjust_cap(
  const std::shared_ptr<ConnectionImpl>& connection, boost::asio::io_context& ctx, std::uint32_t cap)
{
  std::optional<ua::VoidResult> adjusted;
  ua::client::detail::ConnectionOpsShim ops{connection, ctx.get_executor()};
  ops.adjust_max_notifications_per_publish(
    77, 100.0, cap, [&adjusted](ua::VoidResult result) { adjusted = std::move(result); });
  ctx.run();
  ctx.restart();
  return adjusted.has_value() ? std::move(*adjusted) : ua::VoidResult{StatusCode{Status::BadTimeout}};
}

/// The maxNotificationsPerPublish a user modify re-sends after an adjustment: the retained value.
std::uint32_t retained_cap_after_modify(
  Subscription& subscription, FakeSessionOps& session, boost::asio::io_context& ctx)
{
  ua::ModifySubscriptionResponse modifyResponse;
  modifyResponse.revised_publishing_interval() = 100.0;
  session.modifySubscription.set_result(
    ua::Result<ua::ModifySubscriptionResponse>{std::move(modifyResponse)});
  SubscriptionModifyConfig modify;
  modify.publishingIntervalMs = 100.0;
  subscription.modify_async(modify, [](ua::VoidResult) {});
  ctx.run();
  ctx.restart();
  const auto requests = session.modifySubscription.requests();
  return requests.empty() ? 0U : requests.back().max_notifications_per_publish();
}

// The automatic cap adjustment answered Uncertain with its response: the server holds the new cap, so the
// Connection retains it (a later user modify re-sends it) and completes with the Uncertain code, the outcome
// the pipeline applies the cap for.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionTuningWiringTest, AnUncertainCapAdjustmentWithItsResponseRetainsTheNewCap)
{
  SubscriptionConfig config;
  config.maxNotificationsPerPublish = 42;
  auto created = create(config);
  ASSERT_TRUE(created.is_good());

  ua::ModifySubscriptionResponse adjustResponse;
  adjustResponse.response_header().service_result() = StatusCode{Status::UncertainLastUsableValue};
  mSession->modifySubscription.set_result(
    ua::Result<ua::ModifySubscriptionResponse>{std::move(adjustResponse)});
  const auto adjusted = adjust_cap(mConnection, mCtx, 21);

  EXPECT_TRUE(adjusted.is_uncertain());
  EXPECT_EQ(adjusted.status_code().value(), StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(retained_cap_after_modify(created.value(), *mSession, mCtx), 21U);
}

// The automatic cap adjustment answered Uncertain without a response: the Connection refuses it
// (Bad_InternalError, ServiceAnswerUncertain, the code as the inner status) and keeps the old cap, so the
// pipeline, which applies the cap only for an outcome that is not Bad, keeps it too.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(SubscriptionTuningWiringTest, AnUncertainCapAdjustmentWithoutAResponseIsRefusedAndKeepsTheCap)
{
  SubscriptionConfig config;
  config.maxNotificationsPerPublish = 42;
  auto created = create(config);
  ASSERT_TRUE(created.is_good());

  const StatusCode uncertain{Status::UncertainLastUsableValue};
  mSession->modifySubscription.set_result(ua::Result<ua::ModifySubscriptionResponse>{uncertain});
  const auto adjusted = adjust_cap(mConnection, mCtx, 21);

  EXPECT_EQ(adjusted.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(adjusted.error_detail(), nullptr);
  EXPECT_EQ(adjusted.error_detail()->code, "ServiceAnswerUncertain");
  EXPECT_EQ(adjusted.error_detail()->innerStatus, uncertain.value());
  EXPECT_EQ(retained_cap_after_modify(created.value(), *mSession, mCtx), 42U);
}

}  // namespace
