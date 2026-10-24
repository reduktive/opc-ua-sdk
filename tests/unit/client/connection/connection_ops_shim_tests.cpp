// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ConnectionOpsShim (section 8.2A.13) - the leaf shim that IMPLEMENTS the
// upward tier-1 interface (WireOps / SubscriptionOps / SupportOps) by weak-referencing ConnectionImpl.
//
// Two behaviours are pinned:
//   1. Alive path - each role method forwards to the matching ConnectionImpl entry point (which dispatches
//      onto the tier-0 session interface); a fake session records that the RIGHT op arrived.
//   2. Connection-gone path - with the weak ConnectionImpl expired, a wire op completes on the executor
//      with Bad_ConnectionClosed carrying the source-tagged ErrorDetail
//      `client.tier1.connection_ops_shim.connection_gone` (the manufactured boundary failure).
//
// Falsifiability: a shim that dropped the request would fail the call_count()==1 assertions; one that
// forgot the source tag would fail the mSource assertion; one that fired the gone path inline (not on the
// executor) would deliver before ctx.run() and fail the "not before run" ordering check.

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_connection_ops.h"

#include "ua_error_detail.h"
#include "ua_namespace_table.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <optional>
#include <string>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionOpsShim;
using ua::client::detail::ConnectionState;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

constexpr std::string_view connectionGoneSource = "client.tier1.connection_ops_shim.connection_gone";

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A live ConnectionImpl in the Active state (bootstrap complete) plus the shim under test built over it.
class ConnectionOpsShimTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    // Run the NamespaceArray bootstrap so the Connection reaches Active (wire ops dispatch straight
    // through) and publishes a NamespaceTable snapshot.
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  // A live shim over the Active Connection, using the runtime executor for boundary failures.
  ConnectionOpsShim make_shim()
  {
    return ConnectionOpsShim{mConnection, mRuntime.executor()};
  }

  // Barrier on the connection strand so a strand-hopping forward (e.g. the send interface) has been processed.
  void drain_strand()
  {
    (void)TA::snapshot(*mConnection);
  }
};

// --- Alive path: WireOps forwards to the tier-0 session interface. ---

TEST_F(ConnectionOpsShimTest, WireOpsReadForwardsToSession)
{
  auto shim = make_shim();
  std::promise<Result<ua::ReadResponse>> done;
  auto future = done.get_future();
  shim.read_async(
    ua::ReadRequest{}, [&done](Result<ua::ReadResponse> result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());
  // The bootstrap NamespaceArray Read already ran; the shim-forwarded Read is the second one.
  EXPECT_EQ(mSession->read.call_count(), 2u) << "the shim Read must reach the tier-0 session interface";
}

TEST_F(ConnectionOpsShimTest, WireOpsWriteForwardsToSession)
{
  auto shim = make_shim();
  std::promise<Result<ua::WriteResponse>> done;
  auto future = done.get_future();
  shim.write_async(
    ua::WriteRequest{}, [&done](Result<ua::WriteResponse> result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());
  EXPECT_EQ(mSession->write.call_count(), 1u) << "the shim Write must reach the tier-0 session interface";
}

TEST_F(ConnectionOpsShimTest, WireOpsMaxNodesPerReadReadsConnectionValue)
{
  auto shim = make_shim();
  EXPECT_EQ(shim.max_nodes_per_read(), mConnection->max_nodes_per_read())
    << "the shim must report the Connection's MaxNodesPerRead (default 100)";
  EXPECT_EQ(shim.max_nodes_per_read(), 100u);
}

// --- Alive path: SubscriptionOps (the send interface) forwards to the Active Connection's Publish issuance. ---

TEST_F(ConnectionOpsShimTest, SubscriptionOpsSendPublishReachesSessionPublish)
{
  auto shim = make_shim();
  shim.send_publish({});
  drain_strand();
  EXPECT_GE(mSession->publish.call_count(), 1u) << "send_publish on an Active Connection issues a Publish";
}

// --- Alive path: SupportOps reflects the Connection's published state. ---

TEST_F(ConnectionOpsShimTest, SupportOpsStateReflectsActive)
{
  auto shim = make_shim();
  EXPECT_EQ(shim.state(), ConnectionState::Active);
}

TEST_F(ConnectionOpsShimTest, SupportOpsNamespaceTableIsPublishedSnapshot)
{
  auto shim = make_shim();
  const auto table = shim.namespace_table();
  ASSERT_NE(table, nullptr) << "after bootstrap the shim exposes the NamespaceTable snapshot";
  EXPECT_EQ(table.get(), mConnection->namespace_table_snapshot().get())
    << "the shim returns the SAME immutable snapshot the Connection published";
}

TEST_F(ConnectionOpsShimTest, SupportOpsPostToExecutorRunsWork)
{
  auto shim = make_shim();
  std::promise<void> ran;
  auto future = ran.get_future();
  shim.post_to_executor([&ran]() { ran.set_value(); });
  EXPECT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "post_to_executor must hand the work to the executor";
}

// --- Connection-gone path: an expired weak ConnectionImpl. ---

// The wire op completes on the executor with Bad_ConnectionClosed carrying the source-tagged ErrorDetail.
TEST(ConnectionOpsShim, ReadCompletesConnectionGoneWithSourceTagWhenConnectionExpired)
{
  boost::asio::io_context ctx;
  // An empty weak: no ConnectionImpl at all (models one destroyed before the call).
  ConnectionOpsShim shim{std::weak_ptr<ConnectionImpl>{}, ctx.get_executor()};

  std::optional<Result<ua::ReadResponse>> captured;
  shim.read_async(
    ua::ReadRequest{}, [&captured](Result<ua::ReadResponse> result) { captured = std::move(result); });

  EXPECT_FALSE(captured.has_value())
    << "the boundary failure must be posted to the executor, not fired inline";
  ctx.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value());
  ASSERT_NE(captured->shared_detail(), nullptr) << "the manufactured failure must carry an ErrorDetail";
  EXPECT_EQ(captured->shared_detail()->source, connectionGoneSource)
    << "the source tag identifies the shim boundary that manufactured the failure";
}

TEST(ConnectionOpsShim, WriteCompletesConnectionGoneWithSourceTagWhenConnectionExpired)
{
  boost::asio::io_context ctx;
  ConnectionOpsShim shim{std::weak_ptr<ConnectionImpl>{}, ctx.get_executor()};

  std::optional<Result<ua::WriteResponse>> captured;
  shim.write_async(
    ua::WriteRequest{}, [&captured](Result<ua::WriteResponse> result) { captured = std::move(result); });
  ctx.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, connectionGoneSource);
}

// The non-async getters degrade safely when the Connection is gone.
TEST(ConnectionOpsShim, GettersDegradeSafelyWhenConnectionExpired)
{
  boost::asio::io_context ctx;
  ConnectionOpsShim shim{std::weak_ptr<ConnectionImpl>{}, ctx.get_executor()};

  EXPECT_EQ(shim.max_nodes_per_read(), 100u) << "gone Connection => the fallback default";
  EXPECT_EQ(shim.state(), ConnectionState::Closed) << "gone Connection => Closed";
  EXPECT_EQ(shim.namespace_table(), nullptr) << "gone Connection => no snapshot";
}

}  // namespace
