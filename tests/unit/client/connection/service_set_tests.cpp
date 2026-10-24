// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::ServiceSet (client design section 7.2A) - the tier-2 public wire-op sub-accessor
// reached via Connection::service_requests().
//
// ServiceSet is a thin move-only value handle over the same ConnectionImpl as its parent Connection. Each
// of its 17 wire ops forwards straight through to the already-built + gated + ErrorDetail-wrapping
// ConnectionImpl funnel. These tests pin, over the FakeSessionOps tier-0 interface:
//   1. each *_async forwards to the matching tier-0 session op (the RIGHT op arrives, exactly once);
//   2. a bad downstream Result is returned UNCHANGED (single-wrap, status + detail preserved - CL-DIAG-001);
//   3. the sync / try_sync wrappers behave per section 7.0 (try_sync returns Result; sync throws on
//   service-bad).
//
// Falsifiability: a handle that dropped the request fails the call_count() assertions; one that swallowed
// the downstream status fails the propagation assertion; a sync wrapper that did not throw on a bad Result
// fails the EXPECT_THROW.

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <utility>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::ReconnectPolicy;
using ua::client::ServiceSet;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A live Active ConnectionImpl plus the ServiceSet under test wrapping it.
class ServiceSetTest : public ::testing::Test
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
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  ServiceSet make_service_set()
  {
    return ConnectionHandleFactory::make_service_set(mConnection);
  }

  // Blocks on an async wire op armed by @p invoke and returns its Result.
  template<typename Response, typename Invoke>
  Result<Response> await(Invoke invoke)
  {
    std::promise<Result<Response>> done;
    auto future = done.get_future();
    invoke([&done](Result<Response> result) { done.set_value(std::move(result)); });
    return future.get();
  }
};

// --- Forwarding: each *_async reaches the matching tier-0 session op exactly once. ---

TEST_F(ServiceSetTest, ReadAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::ReadResponse>([&](auto cb) { ss.read_async(ua::ReadRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  // The bootstrap NamespaceArray Read already ran; the ServiceSet Read is the second one.
  EXPECT_EQ(mSession->read.call_count(), 2u);
}

TEST_F(ServiceSetTest, WriteAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::WriteResponse>([&](auto cb) { ss.write_async(ua::WriteRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->write.call_count(), 1u);
}

TEST_F(ServiceSetTest, BrowseAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result =
    await<ua::BrowseResponse>([&](auto cb) { ss.browse_async(ua::BrowseRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->browse.call_count(), 1u);
}

TEST_F(ServiceSetTest, BrowseNextAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::BrowseNextResponse>(
    [&](auto cb) { ss.browse_next_async(ua::BrowseNextRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->browseNext.call_count(), 1u);
}

TEST_F(ServiceSetTest, TranslateBrowsePathsAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::TranslateBrowsePathsToNodeIdsResponse>([&](auto cb)
    { ss.translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->translateBrowsePaths.call_count(), 1u);
}

TEST_F(ServiceSetTest, CallAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::CallResponse>([&](auto cb) { ss.call_async(ua::CallRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->call.call_count(), 1u);
}

TEST_F(ServiceSetTest, RegisterNodesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::RegisterNodesResponse>(
    [&](auto cb) { ss.register_nodes_async(ua::RegisterNodesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->registerNodes.call_count(), 1u);
}

TEST_F(ServiceSetTest, UnregisterNodesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::UnregisterNodesResponse>(
    [&](auto cb) { ss.unregister_nodes_async(ua::UnregisterNodesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->unregisterNodes.call_count(), 1u);
}

TEST_F(ServiceSetTest, HistoryReadAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::HistoryReadResponse>(
    [&](auto cb) { ss.history_read_async(ua::HistoryReadRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->historyRead.call_count(), 1u);
}

TEST_F(ServiceSetTest, HistoryUpdateAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::HistoryUpdateResponse>(
    [&](auto cb) { ss.history_update_async(ua::HistoryUpdateRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->historyUpdate.call_count(), 1u);
}

TEST_F(ServiceSetTest, QueryFirstAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::QueryFirstResponse>(
    [&](auto cb) { ss.query_first_async(ua::QueryFirstRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->queryFirst.call_count(), 1u);
}

TEST_F(ServiceSetTest, QueryNextAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::QueryNextResponse>(
    [&](auto cb) { ss.query_next_async(ua::QueryNextRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->queryNext.call_count(), 1u);
}

TEST_F(ServiceSetTest, AddNodesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result =
    await<ua::AddNodesResponse>([&](auto cb) { ss.add_nodes_async(ua::AddNodesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->addNodes.call_count(), 1u);
}

TEST_F(ServiceSetTest, AddReferencesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::AddReferencesResponse>(
    [&](auto cb) { ss.add_references_async(ua::AddReferencesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->addReferences.call_count(), 1u);
}

TEST_F(ServiceSetTest, DeleteNodesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::DeleteNodesResponse>(
    [&](auto cb) { ss.delete_nodes_async(ua::DeleteNodesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->deleteNodes.call_count(), 1u);
}

TEST_F(ServiceSetTest, DeleteReferencesAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result = await<ua::DeleteReferencesResponse>(
    [&](auto cb) { ss.delete_references_async(ua::DeleteReferencesRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->deleteReferences.call_count(), 1u);
}

TEST_F(ServiceSetTest, CancelAsyncForwardsToSession)
{
  auto ss = make_service_set();
  auto result =
    await<ua::CancelResponse>([&](auto cb) { ss.cancel_async(ua::CancelRequest{}, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->cancel.call_count(), 1u);
}

// --- Single-wrap: a bad downstream Result is returned unchanged (status + detail preserved). ---

// @verifies CL-DIAG-001
// @relation(CL-DIAG-001, scope=function)
TEST_F(ServiceSetTest, ReadAsyncPropagatesBadDownstreamResultUnchanged)
{
  // Script the tier-0 read to fail with a detail-carrying bad Result.
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied},
    ua::make_error_detail("Downstream", "scripted tier-0 failure", "test.downstream")});

  auto ss = make_service_set();
  auto result = await<ua::ReadResponse>([&](auto cb) { ss.read_async(ua::ReadRequest{}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value())
    << "the ServiceSet must return the downstream status verbatim (no substitution)";
  ASSERT_NE(result.shared_detail(), nullptr)
    << "the downstream ErrorDetail must survive the forward (no discard, CL-DIAG-001)";
}

// --- Sync / try_sync wrappers (section 7.0). ---

TEST_F(ServiceSetTest, TrySyncReturnsResult)
{
  auto ss = make_service_set();
  auto result = ss.try_read_sync(ua::ReadRequest{});
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mSession->read.call_count(), 2u);
}

TEST_F(ServiceSetTest, SyncThrowsOnServiceBad)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied}});
  auto ss = make_service_set();
  EXPECT_THROW((void)ss.read_sync(ua::ReadRequest{}), ua::UaException);
}

TEST_F(ServiceSetTest, SyncReturnsResponseOnGood)
{
  auto ss = make_service_set();
  EXPECT_NO_THROW((void)ss.write_sync(ua::WriteRequest{}));
  EXPECT_EQ(mSession->write.call_count(), 1u);
}

}  // namespace
