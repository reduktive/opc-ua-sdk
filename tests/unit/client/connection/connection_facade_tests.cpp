// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 public ua::client::Connection handle and its ua::client::Subscriptions
// sub-accessor (client design section 7.2 / section 7.4). Both are thin move-only value handles over the same
// strand-serialized ConnectionImpl.
//
// Pinned, over the FakeSessionOps tier-0 interface:
//   - Lifecycle: close_async forwards to the tier-0 session close and lands the Connection in Closed.
//   - State: state()/session_id()/namespace_table() read the ConnectionImpl cross-strand snapshot.
//   - Value sugar: read_value composes a single-node Value Read and decodes results[0]; write_value
//     composes a single Value Write and flattens the per-item status; the manufactured empty-results and
//     single-wrap (CL-DIAG-001) paths behave.
//   - namespace_table() exposes the published NamespaceTable snapshot (CL-ADDRSP-004).
//   - Subscriptions: create_async reaches the pipeline (CreateSubscription on the wire, a Publish follows -
//     CL-SUB-018) and list() enumerates the live ids.
//
// Falsifiability: a handle that dropped a call fails the call_count / state assertions; value sugar that
// composed the wrong attribute fails the attribute_id assertion; a facade that discarded the downstream
// ErrorDetail fails the CL-DIAG-001 assertion.

#include "ua_client_observers.h"
#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_create_subscription_response.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_response.h"

#include <boost/asio/post.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <mutex>
#include <thread>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::ConnectionState;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::Subscription;
using ua::client::SubscriptionConfig;
using ua::client::Subscriptions;
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

// Builds a WriteResponse with a single per-item status.
ua::WriteResponse make_write_response(ua::StatusCode itemStatus)
{
  ua::WriteResponse response;
  response.results().push_back(itemStatus);
  return response;
}

// A live Active ConnectionImpl plus the public Connection handle wrapping it.
class ConnectionFacadeTest : public ::testing::Test
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

    // Bootstrap consumes the fake's mandatory NamespaceArray + ServerArray response. Subsequent facade
    // Reads model ordinary one-node Value reads and therefore need exactly one result; retaining the
    // two-result bootstrap payload would correctly trip ConnectionImpl's response-cardinality guard.
    ua::ReadResponse valueResponse;
    valueResponse.results().push_back(ua::DataValue{});
    mSession->read.set_result(Result<ua::ReadResponse>{std::move(valueResponse)});
  }

  Connection make_connection()
  {
    return ConnectionHandleFactory::make_connection(mConnection);
  }

  Result<ua::DataValue> run_wrap_level(ua::client::ClientDiagnosticPolicy::WrapLevel level)
  {
    auto session = std::make_shared<FakeSessionOps>();
    ConnectionConfig config;
    config.diagnostics.wrapLevel = level;
    auto impl = TA::create_with_ops(mRuntime.executor(),
      session,
      std::move(config),
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    std::promise<VoidResult> started;
    auto startedFuture = started.get_future();
    impl->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    EXPECT_TRUE(startedFuture.get().is_good());

    session->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied},
      ua::make_error_detail("WireFailure", "scripted wire failure", "server.wire")});
    auto connection = ConnectionHandleFactory::make_connection(std::move(impl));
    return connection.try_read_value_sync(ua::NodeId{1, 7});
  }

  static Result<ua::ReadResponse> permissive_shape_response()
  {
    ua::ReadResponse response;
    response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{-2}}});
    response.results().push_back(ua::DataValue{});
    return Result<ua::ReadResponse>{std::move(response)};
  }

  void script_permissive_shape_metadata()
  {
    mSession->read.set_result_fn(
      [](const ua::ReadRequest&) -> Result<ua::ReadResponse> { return permissive_shape_response(); });
  }

  void script_checked_write_reads(ua::NodeId declaredDataType, std::uint32_t accessLevelEx)
  {
    mSession->read.set_result_fn(
      [declaredDataType = std::move(declaredDataType), accessLevelEx](
        const ua::ReadRequest& request) -> Result<ua::ReadResponse>
      {
        if (!request.nodes_to_read().empty() && request.nodes_to_read()[0].attribute_id() ==
                                                  static_cast<ua::IntegerId>(ua::AttributeId::ValueRank))
        {
          return permissive_shape_response();
        }
        ua::ReadResponse response;
        response.results().push_back(ua::DataValue{ua::Variant{declaredDataType}});
        response.results().push_back(ua::DataValue{ua::Variant{accessLevelEx}});
        return Result<ua::ReadResponse>{std::move(response)};
      });
  }

  void script_failed_preflight_then_shape()
  {
    mSession->read.set_result_fn(
      [](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
      {
        if (!request.nodes_to_read().empty() && request.nodes_to_read()[0].attribute_id() ==
                                                  static_cast<ua::IntegerId>(ua::AttributeId::ValueRank))
        {
          return permissive_shape_response();
        }
        return Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied}};
      });
  }
};

// --- Lifecycle ---

namespace
{

/// Counts the terminal disconnect notifications a Connection emits.
class DisconnectCounter final : public ua::client::ConnectionObserver
{
public:
  void on_disconnected(
    const Connection&, ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail>) override
  {
    std::lock_guard lock(mMutex);
    ++mCount;
    mReason = reason;
  }

  int count() const
  {
    std::lock_guard lock(mMutex);
    return mCount;
  }

  ua::StatusCode reason() const
  {
    std::lock_guard lock(mMutex);
    return mReason;
  }

private:
  mutable std::mutex mMutex;
  int mCount = 0;
  ua::StatusCode mReason{Status::Good};
};

/// Waits until @p predicate holds or 2 s pass.
template<typename Predicate>
bool eventually(Predicate predicate)
{
  for (int i = 0; i < 200 && !predicate(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  return predicate();
}

}  // namespace

// A Connection without automatic reconnect whose SecureChannel is lost has nothing to recover with, so the
// loss is terminal: Failed, and on_disconnected once with the cause (owner decision 2026-10-03, BR-19).
// Falsifiable: the former Connection ignored the loss and stayed Active, so the application was never told.
// @relation(AC-CL-SESS-021-A-SINGLE-SHOT-CONNECTION-REPORTS-A-LOST-CHANNEL, scope=function)
TEST_F(ConnectionFacadeTest, ASingleShotConnectionReportsALostChannelOnce)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto impl = ConnectionImpl::create_from_ops(mRuntime.executor(), session, ConnectionConfig{}, ua::Logger{});
  std::promise<VoidResult> started;
  auto startedFuture = started.get_future();
  impl->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_TRUE(startedFuture.get().is_good());
  auto connection = ConnectionHandleFactory::make_connection(impl);
  auto observer = std::make_shared<DisconnectCounter>();
  connection.set_connection_observer(observer);

  impl->on_channel_lost_async(ua::StatusCode{Status::BadConnectionClosed}, nullptr);
  ASSERT_TRUE(eventually([&] { return observer->count() > 0; })) << "the application is told";
  EXPECT_EQ(observer->reason(), ua::StatusCode{Status::BadConnectionClosed});
  EXPECT_TRUE(eventually([&] { return connection.state() == ConnectionState::Failed; }));

  impl->on_channel_lost_async(ua::StatusCode{Status::BadConnectionClosed}, nullptr);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(observer->count(), 1) << "reported once";
}

// A Connection with automatic reconnect ignores the hook: its keep-alive and Publish paths own drop handling.
// @relation(AC-CL-SESS-021-A-SINGLE-SHOT-CONNECTION-REPORTS-A-LOST-CHANNEL, scope=function)
TEST_F(ConnectionFacadeTest, AReconnectingConnectionIgnoresTheLostChannelHook)
{
  auto connection = make_connection();
  auto observer = std::make_shared<DisconnectCounter>();
  connection.set_connection_observer(observer);
  mConnection->on_channel_lost_async(ua::StatusCode{Status::BadConnectionClosed}, nullptr);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(observer->count(), 0);
  EXPECT_EQ(connection.state(), ConnectionState::Active);
}

// A loss that follows an intentional close is not a failure: the closed Connection reports nothing more.
// @relation(AC-CL-SESS-021-A-SINGLE-SHOT-CONNECTION-REPORTS-A-LOST-CHANNEL, scope=function)
TEST_F(ConnectionFacadeTest, ALostChannelAfterCloseIsNotReported)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto impl = ConnectionImpl::create_from_ops(mRuntime.executor(), session, ConnectionConfig{}, ua::Logger{});
  std::promise<VoidResult> started;
  auto startedFuture = started.get_future();
  impl->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_TRUE(startedFuture.get().is_good());
  auto connection = ConnectionHandleFactory::make_connection(impl);
  auto observer = std::make_shared<DisconnectCounter>();
  ASSERT_TRUE(connection.try_close_sync().is_good());
  const int afterClose = observer->count();
  connection.set_connection_observer(observer);
  impl->on_channel_lost_async(ua::StatusCode{Status::BadConnectionClosed}, nullptr);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(observer->count(), afterClose);
  EXPECT_EQ(connection.state(), ConnectionState::Closed);
}

TEST_F(ConnectionFacadeTest, CloseForwardsToSessionAndTransitionsClosed)
{
  auto connection = make_connection();
  ASSERT_EQ(connection.state(), ConnectionState::Active);

  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.close_async([&done](VoidResult result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  EXPECT_EQ(mSession->close.call_count(), 1u) << "close must reach the tier-0 session";
  EXPECT_EQ(connection.state(), ConnectionState::Closed);
}

TEST_F(ConnectionFacadeTest, TryCloseSyncReturnsGood)
{
  auto connection = make_connection();
  EXPECT_TRUE(connection.try_close_sync().is_good());
  EXPECT_EQ(mSession->close.call_count(), 1u);
}

// --- State snapshot accessors ---

TEST_F(ConnectionFacadeTest, StateReflectsActiveAfterBootstrap)
{
  auto connection = make_connection();
  EXPECT_EQ(connection.state(), ConnectionState::Active);
}

TEST_F(ConnectionFacadeTest, SessionIdReportsServerAssignedId)
{
  auto connection = make_connection();
  const auto sessionId = connection.session_id();
  ASSERT_TRUE(sessionId.is_good());
  // FakeSessionOps reports {1, 42}; ConnectionImpl snapshots it at bootstrap.
  EXPECT_EQ(sessionId.value(), (ua::NodeId{1, 42}));
}

// namespace_table() exposes the URI<->index mapping the published NamespaceTable snapshot carries, so users
// can translate persisted NodeIds without the SDK mutating user-held NodeIds.
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionFacadeTest, NamespaceTableExposesPublishedSnapshot)
{
  auto connection = make_connection();
  const auto table = connection.namespace_table();
  ASSERT_NE(table, nullptr) << "after bootstrap the public accessor exposes the NamespaceTable snapshot";
  EXPECT_EQ(table.get(), mConnection->namespace_table_snapshot().get())
    << "the accessor returns the SAME immutable snapshot ConnectionImpl published";
  EXPECT_EQ(table->size(), 2u) << "the default bootstrap NamespaceArray has two namespaces";
}

// --- URI-tagged ExpandedNodeId resolution (OPC 10000-3 section 5.2.2; OPEN-NSREMAP ruling) ---

// The client accepts a URI-carrying ExpandedNodeId and resolves the NamespaceIndex per-Session at send time
// (the user holds a stable URI-ref; the index is resolved against the CURRENT NamespaceArray). When the
// server renumbers the NamespaceArray between Sessions, the SAME persisted ExpandedNodeId resolves to the NEW
// index - the SDK never mutates the user's handle; it re-resolves each call. Falsifiable: resolving once and
// caching the index (or resolving against the bootstrap table) would keep the old index after the array
// change.
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionFacadeTest, RenumbersPersistedExpandedNodeIdAfterNamespaceArrayChange)
{
  auto connection = make_connection();
  const ua::ExpandedNodeId persisted{ua::NodeId{0, 5000}, "urn:example:ns_B"};

  // Session 1: NamespaceArray = [opc, ns_A, ns_B] -> ns_B is index 2.
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A", "urn:example:ns_B"})
                .is_good());
  {
    std::promise<Result<ua::DataValue>> done;
    auto future = done.get_future();
    connection.read_value_async(
      persisted, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }
  {
    const auto requests = mSession->read.requests();
    ASSERT_FALSE(requests.empty());
    ASSERT_EQ(requests.back().nodes_to_read().size(), 1u);
    EXPECT_EQ(requests.back().nodes_to_read()[0].node_id(), (ua::NodeId{2, 5000}))
      << "ns_B resolves to index 2 under the first NamespaceArray";
  }

  // Session 2 (reconnect re-read): NamespaceArray reordered to [opc, ns_B, ns_A] -> ns_B is now index 1.
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_B", "urn:example:ns_A"})
                .is_good());
  {
    std::promise<Result<ua::DataValue>> done;
    auto future = done.get_future();
    connection.read_value_async(
      persisted, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }
  {
    const auto requests = mSession->read.requests();
    ASSERT_FALSE(requests.empty());
    ASSERT_EQ(requests.back().nodes_to_read().size(), 1u);
    EXPECT_EQ(requests.back().nodes_to_read()[0].node_id(), (ua::NodeId{1, 5000}))
      << "the SAME persisted ExpandedNodeId re-resolves ns_B to index 1 after the array is reordered";
  }
}

// A persisted ExpandedNodeId whose NamespaceUri is absent from the current Session's NamespaceArray must fail
// LOCALLY with a rich ErrorDetail (Bad_NodeIdUnknown, source client.namespace_table, the unresolved URI
// preserved) and issue NO wire request. Falsifiable: silently stripping the URI and reading the index-0 node,
// or forwarding to the wire, would advance the read op and not surface uri_unresolved.
//
// Also pins "resolve against the CURRENT snapshot, not the bootstrap one": the bootstrap NamespaceArray HAD
// "urn:test:connection"; the reconnect re-read drops it. Resolving that URI must now fail - so a
// stale-snapshot resolver (one that never republished on re-read) would WRONGLY still resolve it and pass
// is_good().
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionFacadeTest, RejectsUnresolvedNamespaceUriAfterReconnect)
{
  auto connection = make_connection();
  // Sanity: the bootstrap snapshot DOES contain "urn:test:connection" (index 1) - resolving it succeeds now.
  {
    std::promise<Result<ua::DataValue>> warm;
    auto warmFuture = warm.get_future();
    connection.read_value_async(ua::ExpandedNodeId{ua::NodeId{0, 5000}, "urn:test:connection"},
      [&warm](Result<ua::DataValue> result) { warm.set_value(std::move(result)); });
    ASSERT_TRUE(warmFuture.get().is_good()) << "the bootstrap NamespaceArray carries urn:test:connection";
  }

  // Reconnect re-read: NamespaceArray is now {opc, ns_A} - both "urn:test:connection" AND ns_C are absent.
  ASSERT_TRUE(
    TA::apply_namespace_read(*mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A"}).is_good());

  for (std::string_view absentUri :
    {std::string_view{"urn:example:ns_C"}, std::string_view{"urn:test:connection"}})
  {
    const ua::ExpandedNodeId persisted{ua::NodeId{0, 5000}, absentUri};
    const std::size_t readsBefore = mSession->read.call_count();
    std::promise<Result<ua::DataValue>> done;
    auto future = done.get_future();
    connection.read_value_async(
      persisted, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
    const auto result = future.get();

    ASSERT_TRUE(result.is_bad()) << "URI '" << absentUri
                                 << "' absent from the CURRENT array must fail locally";
    EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadNodeIdUnknown}.value());
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->source, "client.namespace_table")
      << "the rich resolve_local ErrorDetail is propagated unchanged (single-wrap)";
    EXPECT_EQ(mSession->read.call_count(), readsBefore)
      << "an unresolved URI issues NO wire Read (local rejection before dispatch)";
  }
}

// The blocking sync wrappers surface a resolution failure too: try_*_sync returns the bad Result (never
// throws); the throwing *_sync raises. Guards the *_sync/try_*_sync ExpandedNodeId bridges (not just the
// async form).
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionFacadeTest, SyncWrappersSurfaceUnresolvedExpandedNodeId)
{
  auto connection = make_connection();
  ASSERT_TRUE(
    TA::apply_namespace_read(*mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A"}).is_good());
  const ua::ExpandedNodeId absent{ua::NodeId{0, 5000}, "urn:example:ns_C"};

  const std::size_t readsBefore = mSession->read.call_count();
  const auto readResult = connection.try_read_value_sync(absent);
  ASSERT_TRUE(readResult.is_bad());
  EXPECT_EQ(readResult.status_code().value(), ua::StatusCode{Status::BadNodeIdUnknown}.value());

  const auto writeResult = connection.try_write_value_sync(absent, ua::Variant{std::int32_t{1}});
  ASSERT_TRUE(writeResult.is_bad());
  EXPECT_EQ(writeResult.status_code().value(), ua::StatusCode{Status::BadNodeIdUnknown}.value());

  EXPECT_EQ(mSession->read.call_count(), readsBefore)
    << "no wire Read for an unresolved URI via the sync path";
  EXPECT_THROW(connection.read_value_sync(absent), ua::UaException)
    << "the throwing sync form raises on an unresolved URI";
}

// A non-zero ServerIndex names a node on a DIFFERENT Server; silently reading the local namespace would be
// incorrect (Part 4 section 5.10.2). With no cross-Server ConnectionRegistry configured, the public overload
// refuses locally with Bad_NotImplemented and issues NO wire request (the explicit CL-ATTR-029 default
// policy). Falsifiable: stripping the ServerIndex and reading local would advance the read op and return
// good.
// @verifies CL-ADDRSP-004
// @verifies CL-ATTR-029
// @relation(CL-ADDRSP-004, CL-ATTR-029, scope=function)
TEST_F(ConnectionFacadeTest, RejectsNonZeroServerIndexExpandedNodeId)
{
  auto connection = make_connection();
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A", "urn:example:ns_B"})
                .is_good());
  // serverIndex=3, URI resolvable locally - the URI resolving must NOT mask the cross-Server refusal.
  const ua::ExpandedNodeId remote{ua::NodeId{0, 5000}, "urn:example:ns_B", std::uint32_t{3}};

  const std::size_t readsBefore = mSession->read.call_count();
  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    remote, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadNotImplemented}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.resolve_expanded");
  EXPECT_EQ(mSession->read.call_count(), readsBefore) << "a cross-Server node issues NO local wire Read";
}

// The write path honours the same per-Session URI resolution: a URI-tagged ExpandedNodeId write resolves to
// the current index before the WriteValue reaches the wire.
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionFacadeTest, WriteResolvesExpandedNodeIdAgainstCurrentNamespaceTable)
{
  script_permissive_shape_metadata();
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A", "urn:example:ns_B"})
                .is_good());

  const ua::ExpandedNodeId persisted{ua::NodeId{0, 5000}, "urn:example:ns_B"};
  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(persisted,
    ua::Variant{std::int32_t{7}},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = mSession->write.requests();
  ASSERT_FALSE(requests.empty());
  ASSERT_EQ(requests.back().nodes_to_write().size(), 1u);
  EXPECT_EQ(requests.back().nodes_to_write()[0].node_id(), (ua::NodeId{2, 5000}))
    << "the write resolves ns_B to index 2 against the current NamespaceArray";
}

// --- CL-SESS-028: reconnect re-read republishes the snapshot; bare NodeIds are never rewritten ---

// On reconnect the client re-reads Server.NamespaceArray and republishes a fresh immutable snapshot with a
// bumped generation, so the cross-strand accessor (and per-Session ExpandedNodeId resolution) sees the new
// index space (Part 4 section 6.7 "reconnect without losing information"; Part 3 section 8.2 URI is the
// stable identifier). Falsifiable: without the republish at the re-read site the snapshot would keep the old
// generation + mapping.
// @verifies CL-SESS-028
// @relation(CL-SESS-028, scope=function)
TEST_F(ConnectionFacadeTest, ReconnectRereadNamespaceArrayRepublishesSnapshot)
{
  auto connection = make_connection();
  const auto before = connection.namespace_table();
  ASSERT_NE(before, nullptr);
  const std::uint64_t generationBefore = before->generation();
  EXPECT_EQ(before->lookup_index("urn:example:ns_B"), std::nullopt)
    << "the bootstrap array does not yet know ns_B";

  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A", "urn:example:ns_B"})
                .is_good());

  const auto after = connection.namespace_table();
  ASSERT_NE(after, nullptr);
  EXPECT_GT(after->generation(), generationBefore) << "the re-read bumps the generation";
  ASSERT_TRUE(after->lookup_index("urn:example:ns_B").has_value());
  EXPECT_EQ(*after->lookup_index("urn:example:ns_B"), 2u)
    << "the republished snapshot carries the new URI<->index mapping";
}

// A BARE NodeId carries no NamespaceUri, so the SDK must forward its index VERBATIM and never guess a remap
// across a namespace change (the OPEN-NSREMAP ruling: only URI-tagged ExpandedNodeIds are re-resolved; a bare
// NodeId records no URI to remap against). This is the "stable indices -> no rewriting" invariant.
// Falsifiable: a blanket index-remapper would rewrite the bare NodeId's index after the array reorder.
// @verifies CL-SESS-028
// @relation(CL-SESS-028, scope=function)
TEST_F(ConnectionFacadeTest, BareNodeIdNotRewrittenAcrossNamespaceChange)
{
  auto connection = make_connection();
  ASSERT_TRUE(TA::apply_namespace_read(
    *mConnection, {"http://opcfoundation.org/UA/", "urn:example:ns_A", "urn:example:ns_B"})
                .is_good());

  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{2, 5000}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = mSession->read.requests();
  ASSERT_FALSE(requests.empty());
  ASSERT_EQ(requests.back().nodes_to_read().size(), 1u);
  EXPECT_EQ(requests.back().nodes_to_read()[0].node_id(), (ua::NodeId{2, 5000}))
    << "a bare NodeId's index is forwarded verbatim - the SDK never remaps an index it cannot tie to a URI";
}

// --- read_value composition + decode ---

TEST_F(ConnectionFacadeTest, ReadValueComposesValueReadAndDecodesFirstResult)
{
  auto connection = make_connection();
  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{0, 42}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_good()) << "the default fake read yields a good DataValue";
  // The composed request must target the Value attribute of the requested node.
  const auto requests = mSession->read.requests();
  ASSERT_FALSE(requests.empty());
  const auto& lastRead = requests.back();
  ASSERT_EQ(lastRead.nodes_to_read().size(), 1u);
  EXPECT_EQ(lastRead.nodes_to_read()[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::Value));
}

// The tier-2 read composes a NULL DataEncoding, so the server falls back to the Session's negotiated
// encoding (UA Binary for a binary Session) and a built-in structured value decodes against it. The
// client must NOT pin a specific encoding name here -- doing so would override the Session default and
// could force an encoding the Session cannot decode. The end-to-end decode-correctness half is covered by
// the ClientReadEncoding.NullEncodingDefaultsToSessionEncoding integration row against a real server.
// [neg: the composed read hardcodes "Default Binary"/"Default XML" instead of leaving it null]
// @verifies CL-ATTR-014
// @verifies CL-ATTR-015
// @relation(CL-ATTR-014, CL-ATTR-015, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueComposesNullDataEncodingSoServerUsesSessionEncoding)
{
  auto connection = make_connection();
  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{0, 2256}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  (void)future.get();

  const auto requests = mSession->read.requests();
  ASSERT_FALSE(requests.empty());
  const auto& lastRead = requests.back();
  ASSERT_EQ(lastRead.nodes_to_read().size(), 1u);
  EXPECT_TRUE(lastRead.nodes_to_read()[0].data_encoding().is_null())
    << "the tier-2 read must leave DataEncoding null so the server uses the Session's default encoding "
       "(CL-ATTR-015); pinning an encoding name could force one the Session cannot decode";
}

// @verifies CL-DIAG-003
// @relation(CL-DIAG-003, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueManufacturesErrorOnEmptyResults)
{
  // A Good Read response with NO result element is a protocol anomaly the facade must surface.
  mSession->read.set_result(Result<ua::ReadResponse>{ua::ReadResponse{}});
  auto connection = make_connection();

  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{0, 7}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.read_value");
}

// read_value's own is_bad() branch forwards the downstream status + ErrorDetail unchanged (no re-wrap).
// @verifies CL-DIAG-001
// @relation(CL-DIAG-001, scope=function)
TEST_F(ConnectionFacadeTest, ReadValuePropagatesDownstreamErrorDetailUnchanged)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadUserAccessDenied},
    ua::make_error_detail("Downstream", "scripted tier-0 failure", "test.downstream")});
  auto connection = make_connection();

  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{0, 7}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value());
  ASSERT_NE(result.shared_detail(), nullptr) << "the downstream ErrorDetail must survive (CL-DIAG-001)";
}

// @verifies CL-DIAG-015
// @relation(CL-DIAG-015, scope=function)
TEST_F(ConnectionFacadeTest, WrapLevelMinimalSkipsTierBoundaryLinks)
{
  const auto result = run_wrap_level(ua::client::ClientDiagnosticPolicy::WrapLevel::Minimal);
  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "server.wire");
}

// @verifies CL-DIAG-015
// @relation(CL-DIAG-015, scope=function)
TEST_F(ConnectionFacadeTest, WrapLevelStandardAddsTierOneAndTierTwoWithImmediateContext)
{
  const auto result = run_wrap_level(ua::client::ClientDiagnosticPolicy::WrapLevel::Standard);
  ASSERT_TRUE(result.is_bad());
  const auto outer = result.shared_detail();
  ASSERT_NE(outer, nullptr);
  EXPECT_EQ(outer->source, "client.tier2.connection.read_value");
  ASSERT_NE(outer->cause, nullptr);
  EXPECT_EQ(outer->cause->source, "client.tier1.connection.read");
  ASSERT_NE(outer->cause->cause, nullptr);
  EXPECT_EQ(outer->cause->cause->source, "server.wire");
  ASSERT_EQ(outer->context.size(), 1u);
  EXPECT_EQ(outer->context[0].key, "node.id");
  EXPECT_EQ(outer->context[0].value, "ns=1;i=7");
}

// @verifies CL-DIAG-015
// @relation(CL-DIAG-015, scope=function)
TEST_F(ConnectionFacadeTest, WrapLevelVerboseAddsResolvedNamespaceUriContext)
{
  const auto result = run_wrap_level(ua::client::ClientDiagnosticPolicy::WrapLevel::Verbose);
  ASSERT_TRUE(result.is_bad());
  const auto outer = result.shared_detail();
  ASSERT_NE(outer, nullptr);
  EXPECT_EQ(outer->source, "client.tier2.connection.read_value");
  const auto uri = std::ranges::find_if(
    outer->context, [](const ua::NamedValue& fact) { return fact.key == "namespace.uri"; });
  ASSERT_NE(uri, outer->context.end());
  EXPECT_EQ(uri->value, "urn:test:connection");
}

// CL-ATTR-013: when the wire codec fails to decode a structured value (malformed/over-long body, mismatched
// TypeId, unknown encoding), it yields a Bad_DecodingError Result BELOW the SessionOps interface. The
// client's own obligation is to SURFACE that on the read Result chain - never swallow it into a Good/partial
// DataValue. This pins the client-side surfacing (the codec's emission is integration-verified end-to-end by
// ClientReadComplex.DecodeErrorsSurfaceBadDecodingError over a real MisbehavingServer). Falsifiable: a read
// path that manufactured a Good empty DataValue, or re-wrapped the status, would fail these assertions.
// @verifies CL-ATTR-013
// @relation(CL-ATTR-013, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueSurfacesCodecDecodingError)
{
  mSession->read.set_result(Result<ua::ReadResponse>{ua::StatusCode{Status::BadDecodingError},
    ua::make_error_detail("StructureDecodeFailed",
      "the ExtensionObject body did not match the registered Structure",
      "core.codec.binary.extension_object")});
  auto connection = make_connection();

  std::promise<Result<ua::DataValue>> done;
  auto future = done.get_future();
  connection.read_value_async(
    ua::NodeId{0, 7}, [&done](Result<ua::DataValue> result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad())
    << "a codec decode failure must not be swallowed into a Good/partial DataValue";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadDecodingError}.value());
  ASSERT_NE(result.shared_detail(), nullptr) << "the codec's field-naming ErrorDetail must reach the caller";
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.read_value");
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->source, "client.tier1.connection.read");
  ASSERT_NE(result.shared_detail()->cause->cause, nullptr);
  EXPECT_EQ(result.shared_detail()->cause->cause->source, "core.codec.binary.extension_object")
    << "Standard wrapping must retain the codec ErrorDetail as the terminal cause";
}

// --- CL-ADDRSP-009: abstract-DataType-checked read (read_value_checked_async) ---

// Builds a two-result ReadResponse: results[0] = the Value, results[1] = the declared DataType NodeId - the
// shape make_value_and_datatype_read expects.
Result<ua::ReadResponse> make_checked_read_response(ua::Variant value, ua::NodeId declaredDataType)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{std::move(value)});
  response.results().push_back(ua::DataValue{ua::Variant{std::move(declaredDataType)}});
  return Result<ua::ReadResponse>{std::move(response)};
}

// A concrete Int32 value satisfies a Variable declared with the abstract Number DataType (Int32 <: Number,
// from the seeded NS0 hierarchy) -> the checked read delivers the value.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueCheckedAcceptsConcreteSubtypeOfAbstractDeclared)
{
  mSession->read.set_result(
    make_checked_read_response(ua::Variant{std::int32_t{7}}, ua::NodeId{ua::DataTypeId::Number}));
  auto connection = make_connection();

  const auto result = connection.try_read_value_checked_sync(ua::NodeId{2, 42});
  ASSERT_TRUE(result.is_good()) << "Int32 <: Number must be accepted";
  const auto decoded = result.value().value().to<std::int32_t>();
  ASSERT_TRUE(decoded.is_good());
  EXPECT_EQ(decoded.value(), 7);
}

// A String value for a Variable declared with Number is a genuinely disjoint mismatch (String is not a
// subtype of Number) -> rejected locally with Bad_TypeMismatch + a source-tagged ErrorDetail, not delivered.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueCheckedRejectsValueNotSubtypeOfDeclared)
{
  mSession->read.set_result(
    make_checked_read_response(ua::Variant{ua::String{"x"}}, ua::NodeId{ua::DataTypeId::Number}));
  auto connection = make_connection();

  const auto result = connection.try_read_value_checked_sync(ua::NodeId{2, 42});
  ASSERT_TRUE(result.is_bad()) << "a String is not a subtype of Number";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.read_value_checked");
}

// An Int32 value for a Variable declared with an (undiscovered) enum DataType must FAIL OPEN - an enum wires
// as Int32, so the value could be a valid enum; the checked read delivers it rather than rejecting.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueCheckedFailsOpenForIntegerEncodedEnum)
{
  // NS0 NodeClass (i=257) is an Enumeration subtype; its edge is not in the seeded core, so the relation is
  // undecidable -> fail-open.
  mSession->read.set_result(
    make_checked_read_response(ua::Variant{std::int32_t{2}}, ua::NodeId{std::uint16_t{0}, 257U}));
  auto connection = make_connection();

  const auto result = connection.try_read_value_checked_sync(ua::NodeId{2, 42});
  ASSERT_TRUE(result.is_good()) << "an Int32-encoded enum value must not be rejected (fail-open)";
  EXPECT_TRUE(result.value().value().to<std::int32_t>().is_good());
}

// section 3.1 MEDIUM regression: a BAD-QUALITY Value must be delivered VERBATIM (its server status +
// ErrorDetail ride on the DataValue, the two-layer model) - NOT type-validated and replaced by a synthesised
// Bad_TypeMismatch, which would swallow the server's real failure (error_handling.md). Falsifiable:
// validating regardless would return a good outer Result with a manufactured Bad_TypeMismatch, losing
// Bad_OutOfService.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ConnectionFacadeTest, ReadValueCheckedDeliversBadQualityValueVerbatim)
{
  // A bad-quality Value whose (stale) type is disjoint from the declared Number - must NOT be rejected.
  ua::ReadResponse response;
  response.results().push_back(
    ua::DataValue{ua::Variant{ua::String{"x"}}, ua::StatusCode{Status::BadOutOfService}});
  response.results().push_back(ua::DataValue{ua::Variant{ua::NodeId{ua::DataTypeId::Number}}});
  mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});
  auto connection = make_connection();

  const auto result = connection.try_read_value_checked_sync(ua::NodeId{2, 42});
  ASSERT_TRUE(result.is_good()) << "the outer Result stays good; the bad quality rides on the DataValue";
  ASSERT_TRUE(result.value().status().has_value());
  EXPECT_EQ(result.value().status()->value(), ua::StatusCode{Status::BadOutOfService}.value())
    << "the server's original bad-quality StatusCode must be preserved, not replaced by Bad_TypeMismatch";
}

// --- CL-ATTR-025: NoSubDataTypes-checked write (write_value_checked_async) ---

// Builds the checked-write pre-flight response: results[0] = declared DataType, results[1] = AccessLevelEx.
Result<ua::ReadResponse> make_preflight_response(ua::NodeId declaredDataType, std::uint32_t accessLevelEx)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::move(declaredDataType)}});
  response.results().push_back(ua::DataValue{ua::Variant{accessLevelEx}});
  return Result<ua::ReadResponse>{std::move(response)};
}

constexpr std::uint32_t noSubDataTypesBit = 1u << 11;

// Writing an Int32 (a strict subtype of the declared Integer, from the seeded NS0 hierarchy) to a Variable
// with AccessLevelEx.NoSubDataTypes set is refused LOCALLY with Bad_TypeMismatch - no wire Write is issued.
// Falsifiable: a write that forwarded regardless would advance the write op and not surface Bad_TypeMismatch.
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueCheckedRefusesSubtypeToNoSubDataTypesTarget)
{
  mSession->read.set_result(make_preflight_response(ua::NodeId{ua::DataTypeId::Integer}, noSubDataTypesBit));
  auto connection = make_connection();

  const std::size_t writesBefore = mSession->write.call_count();
  const auto result =
    connection.try_write_value_checked_sync(ua::NodeId{2, 42}, ua::Variant{std::int32_t{7}});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.write_value_checked");
  EXPECT_EQ(mSession->write.call_count(), writesBefore) << "a refused subtype write issues NO wire Write";
}

// Writing the EXACT declared type to a NoSubDataTypes target is forwarded (only a strict SUBTYPE is refused).
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueCheckedForwardsExactTypeToNoSubDataTypesTarget)
{
  script_checked_write_reads(ua::NodeId{ua::DataTypeId::Int32}, noSubDataTypesBit);
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const std::size_t writesBefore = mSession->write.call_count();
  const auto result =
    connection.try_write_value_checked_sync(ua::NodeId{2, 42}, ua::Variant{std::int32_t{7}});
  EXPECT_TRUE(result.is_good()) << "the exact declared type is accepted";
  EXPECT_EQ(mSession->write.call_count(), writesBefore + 1) << "the exact-type write reaches the wire";
}

// A subtype write to a target WITHOUT NoSubDataTypes is forwarded (the server accepts subtypes by default).
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueCheckedForwardsSubtypeToNormalTarget)
{
  script_checked_write_reads(ua::NodeId{ua::DataTypeId::Integer}, /*accessLevelEx=*/0u);
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const std::size_t writesBefore = mSession->write.call_count();
  const auto result =
    connection.try_write_value_checked_sync(ua::NodeId{2, 42}, ua::Variant{std::int32_t{7}});
  EXPECT_TRUE(result.is_good()) << "a subtype write to a normal target is forwarded";
  EXPECT_EQ(mSession->write.call_count(), writesBefore + 1);
}

// A failed pre-flight must NOT block a legitimate write - the checked write fails OPEN and forwards (the
// server remains the authority).
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueCheckedForwardsWhenPreflightFails)
{
  script_failed_preflight_then_shape();
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const std::size_t writesBefore = mSession->write.call_count();
  const auto result =
    connection.try_write_value_checked_sync(ua::NodeId{2, 42}, ua::Variant{std::int32_t{7}});
  EXPECT_TRUE(result.is_good()) << "a failed pre-flight fails open - the write is forwarded";
  EXPECT_EQ(mSession->write.call_count(), writesBefore + 1);
}

// section 3.1 HIGH regression (use-after-move / lambdas.md sequencing): the pre-flight Read must target the
// ACTUAL node, not a moved-from NodeId. A STRING identifier exposes the bug - moving a string NodeId leaves
// it empty, so an indeterminately-sequenced make_...(node) + [node = std::move(node)] would pre-read a NULL
// node and silently defeat the check. A numeric NodeId masks it (a moved numeric identifier is intact).
// Falsifiable: the buggy code reads NodeId{2, ""} here.
// @verifies CL-ATTR-025
// @relation(CL-ATTR-025, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueCheckedPreflightsTheCorrectNodeForStringIdentifier)
{
  mSession->read.set_result(make_preflight_response(ua::NodeId{ua::DataTypeId::Integer}, noSubDataTypesBit));
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const ua::NodeId stringNode{std::uint16_t{2}, std::string_view{"MyStringVar"}};
  (void)connection.try_write_value_checked_sync(stringNode, ua::Variant{std::int32_t{7}});

  const auto reads = mSession->read.requests();
  ASSERT_FALSE(reads.empty());
  ASSERT_EQ(reads.back().nodes_to_read().size(), 2u) << "the pre-flight reads DataType + AccessLevelEx";
  EXPECT_EQ(reads.back().nodes_to_read()[0].node_id(), stringNode)
    << "the pre-flight must read the CORRECT node, not a use-after-move null NodeId";
}

// --- write_value composition + per-item flatten ---

// @verifies CL-ATTR-026
// @relation(CL-ATTR-026, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueForwardsSimpleTypeAsExactSupertypeVariant)
{
  script_permissive_shape_metadata();
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const ua::Duration duration = 2.5;
  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{duration},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_good());
  const auto requests = mSession->write.requests();
  ASSERT_FALSE(requests.empty());
  const auto& lastWrite = requests.back();
  ASSERT_EQ(lastWrite.nodes_to_write().size(), 1u);
  EXPECT_EQ(lastWrite.nodes_to_write()[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::Value));
  EXPECT_FALSE(lastWrite.nodes_to_write()[0].value().value().is_structure());
  const auto* wireValue = lastWrite.nodes_to_write()[0].value().value().try_as<double>();
  ASSERT_NE(wireValue, nullptr) << "Duration must retain its Double supertype representation";
  EXPECT_DOUBLE_EQ(*wireValue, duration);
}

// @verifies CL-ATTR-018
// @relation(CL-ATTR-018, scope=function)
TEST_F(ConnectionFacadeTest, GoodCompletesAsynchronouslyIsPreservedAtTierOneAndSucceedsAtTierTwo)
{
  script_permissive_shape_metadata();
  const ua::StatusCode asynchronousStatus{Status::GoodCompletesAsynchronously};
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(asynchronousStatus)});
  auto connection = make_connection();

  ua::WriteValue target;
  target.node_id() = ua::NodeId{0, 99};
  target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  target.value() = ua::DataValue{ua::Variant{std::int32_t{7}}};
  ua::WriteRequest request;
  request.nodes_to_write().push_back(std::move(target));

  std::promise<Result<ua::WriteResponse>> rawDone;
  auto rawFuture = rawDone.get_future();
  connection.service_requests().write_async(std::move(request),
    [&rawDone](Result<ua::WriteResponse> result) { rawDone.set_value(std::move(result)); });
  const auto rawResult = rawFuture.get();
  ASSERT_TRUE(rawResult.is_good());
  ASSERT_EQ(rawResult.value().results().size(), 1u);
  EXPECT_EQ(rawResult.value().results()[0], asynchronousStatus)
    << "the tier-1 service response must preserve the exact Good sub-code for applications that verify it";

  std::promise<VoidResult> convenienceDone;
  auto convenienceFuture = convenienceDone.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{std::int32_t{7}},
    [&convenienceDone](VoidResult result) { convenienceDone.set_value(std::move(result)); });
  EXPECT_TRUE(convenienceFuture.get().is_good())
    << "the tier-2 convenience must classify every Good-severity sub-code as success";

  EXPECT_NO_THROW(connection.write_value_sync(ua::NodeId{0, 99}, ua::Variant{std::int32_t{7}}));
  EXPECT_TRUE(connection.try_write_value_sync(ua::NodeId{0, 99}, ua::Variant{std::int32_t{7}}).is_good());
}

TEST_F(ConnectionFacadeTest, WriteValueFlattensBadPerItemStatus)
{
  script_permissive_shape_metadata();
  mSession->write.set_result(
    Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::BadUserAccessDenied})});
  auto connection = make_connection();

  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{std::int32_t{7}},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value())
    << "the per-item write status is flattened into the VoidResult";
}

// CL-ATTR-020: write_value must ACCEPT both a ByteString Variant and a Byte[] Variant and forward each to the
// wire VERBATIM - the client must never fabricate a local type rejection nor silently convert between the two
// wire-adjacent representations. The ByteStringByteArrayEquivalence integration row proves the end-to-end
// round-trip; this pins the client-side no-mangling guarantee on the OUTGOING request (a regression that
// special-cased either shape would drop the write or mutate the Variant's type). @verifies CL-ATTR-020
TEST_F(ConnectionFacadeTest, WriteValueForwardsByteStringAndByteArrayVariantsVerbatim)
{
  script_permissive_shape_metadata();
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();
  const std::vector<std::uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F};

  // A ByteString Variant must reach the wire STILL a ByteString (not converted to a Byte[]).
  {
    std::promise<VoidResult> done;
    auto future = done.get_future();
    connection.write_value_async(ua::NodeId{0, 99},
      ua::Variant{ua::ByteString{payload}},
      [&done](VoidResult result) { done.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
    const auto requests = mSession->write.requests();  // by value - must outlive the reference below
    ASSERT_FALSE(requests.empty());
    const auto& forwarded = requests.back().nodes_to_write()[0].value().value();
    const auto* asByteString = forwarded.try_as<ua::ByteString>();
    ASSERT_NE(asByteString, nullptr)
      << "a ByteString Variant must be forwarded as a ByteString, not converted";
    EXPECT_EQ((std::vector<std::uint8_t>{asByteString->begin(), asByteString->end()}), payload);
  }

  // A Byte[] Variant must reach the wire STILL a Byte[] (not converted to a ByteString).
  {
    ua::Array<std::uint8_t> byteArray;
    for (const std::uint8_t byte : payload)
    {
      byteArray.push_back(byte);
    }
    std::promise<VoidResult> done;
    auto future = done.get_future();
    connection.write_value_async(ua::NodeId{0, 99},
      ua::Variant{byteArray},
      [&done](VoidResult result) { done.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
    const auto requests = mSession->write.requests();  // by value - must outlive the reference below
    ASSERT_FALSE(requests.empty());
    const auto& forwarded = requests.back().nodes_to_write()[0].value().value();
    EXPECT_EQ(forwarded.try_as<ua::ByteString>(), nullptr)
      << "a Byte[] Variant must NOT be silently converted to a ByteString";
    const auto asVector = forwarded.to_vector<std::uint8_t>();
    ASSERT_TRUE(asVector.is_good()) << "the forwarded Byte[] must still decode as a byte array";
    EXPECT_EQ(asVector.value(), payload);
  }
}

// @verifies CL-ATTR-021
// write_value must forward a LocalizedText Variant VERBATIM, carrying each field faithfully - the locale and
// text survive with no field dropped, swapped, or fabricated. The LocalizedTextNullStringSemanticsPreserved
// integration row proves the per-field carriage end-to-end against a real server; this pins the client-side
// no-mangling guarantee on the outgoing request.
// @relation(CL-ATTR-021, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueForwardsLocalizedTextVariantVerbatim)
{
  script_permissive_shape_metadata();
  mSession->write.set_result(Result<ua::WriteResponse>{make_write_response(ua::StatusCode{Status::Good})});
  auto connection = make_connection();

  const ua::LocalizedText source{ua::LocaleId{"en"}, ua::String{"hello"}};
  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{source},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto requests = mSession->write.requests();  // by value - must outlive the reference below
  ASSERT_FALSE(requests.empty());
  const auto& forwarded = requests.back().nodes_to_write()[0].value().value();
  const auto* asLocalizedText = forwarded.try_as<ua::LocalizedText>();
  ASSERT_NE(asLocalizedText, nullptr) << "a LocalizedText Variant must be forwarded as a LocalizedText";
  EXPECT_EQ(std::string{asLocalizedText->locale()}, "en") << "the locale field must be carried verbatim";
  EXPECT_EQ(std::string{asLocalizedText->text()}, "hello") << "the text field must be carried verbatim";
}

// The tier-0 wire-op funnel returns the WriteResponse verbatim; the value facade must flatten a bad
// ResponseHeader.serviceResult into a bad Result rather than trusting a Good per-item result under it.
// @verifies CL-ATTR-017
// @relation(CL-ATTR-017, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueFlattensBadServiceResult)
{
  script_permissive_shape_metadata();
  auto response = make_write_response(ua::StatusCode{Status::Good});
  response.response_header().service_result() = ua::StatusCode{Status::BadTooManyOperations};
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});
  auto connection = make_connection();

  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{std::int32_t{7}},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad()) << "a bad serviceResult must not be swallowed under a Good per-item status";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTooManyOperations}.value());
}

// A single-node Write must return exactly one per-item status; any other count cannot be positionally
// mapped and must be rejected with Bad_UnexpectedError rather than indexed blindly.
// @verifies CL-ATTR-017
// @relation(CL-ATTR-017, scope=function)
TEST_F(ConnectionFacadeTest, WriteValueRejectsResultCountMismatch)
{
  script_permissive_shape_metadata();
  ua::WriteResponse response;  // zero per-item results for a single-node write
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(response)});
  auto connection = make_connection();

  std::promise<VoidResult> done;
  auto future = done.get_future();
  connection.write_value_async(ua::NodeId{0, 99},
    ua::Variant{std::int32_t{7}},
    [&done](VoidResult result) { done.set_value(std::move(result)); });
  const auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUnexpectedError}.value())
    << "a result count that is not exactly one must be rejected as Bad_UnexpectedError";
}

// --- Subscriptions sub-accessor ---

TEST_F(ConnectionFacadeTest, SubscriptionsCreateReachesSessionAndReturnsServerId)
{
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 42;
  mSession->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});

  auto connection = make_connection();
  auto subscriptions = connection.subscriptions();

  std::promise<Result<Subscription>> done;
  auto future = done.get_future();
  subscriptions.create_async(
    SubscriptionConfig{500.0}, [&done](Result<Subscription> result) { done.set_value(std::move(result)); });
  auto result = future.get();

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().server_subscription_id(), 42u);
  EXPECT_EQ(mSession->createSubscription.call_count(), 1u) << "create must reach the tier-0 session";
}

TEST_F(ConnectionFacadeTest, SubscriptionsListEnumeratesLiveIds)
{
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 42;
  mSession->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});

  auto connection = make_connection();
  auto subscriptions = connection.subscriptions();

  std::promise<Result<Subscription>> done;
  auto future = done.get_future();
  subscriptions.create_async(
    SubscriptionConfig{500.0}, [&done](Result<Subscription> result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  const auto live = subscriptions.list_sync();
  ASSERT_EQ(live.size(), 1u) << "the created Subscription must be enumerable";
  EXPECT_EQ(live.front().server_subscription_id(), 42u);
}

// API-4.3: on the Connection's executor, where observer callbacks run, list_async answers and the
// blocking form refuses with Bad_WouldBlock rather than waiting on the thread that would answer it.
TEST_F(ConnectionFacadeTest, SubscriptionsListAsyncAnswersOnTheExecutorWhereTheSyncFormRefuses)
{
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 42;
  mSession->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});
  auto connection = make_connection();
  auto subscriptions = connection.subscriptions();
  ASSERT_TRUE(subscriptions.try_create_sync(SubscriptionConfig{500.0}).is_good());

  std::promise<ua::StatusCode> refused;
  std::promise<Result<std::vector<Subscription>>> listed;
  boost::asio::post(mRuntime.executor(),
    [&subscriptions, &refused, &listed]
    {
      refused.set_value(subscriptions.try_list_sync().status_code());
      subscriptions.list_async(
        [&listed](Result<std::vector<Subscription>> result) { listed.set_value(std::move(result)); });
    });
  auto refusedFuture = refused.get_future();
  auto listedFuture = listed.get_future();
  ASSERT_EQ(refusedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "try_list_sync blocked the executor";
  EXPECT_EQ(refusedFuture.get(), ua::StatusCode{Status::BadWouldBlock});
  ASSERT_EQ(listedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "list_async never answered";
  auto live = listedFuture.get();
  ASSERT_TRUE(live.is_good()) << to_string(live.status_code());
  ASSERT_EQ(live.value().size(), 1u);
  EXPECT_EQ(live.value().front().server_subscription_id(), 42u);
}

TEST_F(ConnectionFacadeTest, SubscriptionsCreateSurfacesBadCreateStatus)
{
  mSession->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{ua::StatusCode{Status::BadTooManySubscriptions}});
  auto connection = make_connection();
  auto subscriptions = connection.subscriptions();

  std::promise<Result<Subscription>> done;
  auto future = done.get_future();
  subscriptions.create_async(
    SubscriptionConfig{500.0}, [&done](Result<Subscription> result) { done.set_value(std::move(result)); });
  auto result = future.get();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTooManySubscriptions}.value());
}

// A successful CreateSubscription starts the Publish pump: at least one Publish reaches the wire.
// @verifies CL-SUB-018
// @relation(CL-SUB-018, scope=function)
TEST_F(ConnectionFacadeTest, SubscriptionsCreateIssuesPublish)
{
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 42;
  mSession->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});
  // Hold Publish completions so the pump does not spin unbounded during the test.
  mSession->publish.set_hold(true);

  auto connection = make_connection();
  auto subscriptions = connection.subscriptions();

  std::promise<Result<Subscription>> done;
  auto future = done.get_future();
  subscriptions.create_async(
    SubscriptionConfig{500.0}, [&done](Result<Subscription> result) { done.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  // Barrier: list_sync() drains the pipeline strand (add_subscription + pump start ran), then a
  // connection-strand snapshot drains the posted send_publish -> the tier-0 Publish has been issued.
  (void)subscriptions.list_sync();
  (void)TA::snapshot(*mConnection);

  EXPECT_GE(mSession->publish.call_count(), 1u)
    << "a successful CreateSubscription must start the Publish pump (CL-SUB-018)";
}

// --- Null-pimpl handle safety (a handle wrapping no ConnectionImpl - e.g. moved-from). ---

// A handle with no underlying ConnectionImpl must degrade safely on every accessor rather than dereference
// a null pimpl.
TEST(ConnectionFacadeNullHandle, DegradesSafelyWithNoImpl)
{
  Connection connection = ConnectionHandleFactory::make_connection(nullptr);
  EXPECT_EQ(connection.state(), ConnectionState::Closed);
  EXPECT_TRUE(connection.session_id().is_bad());
  EXPECT_EQ(connection.namespace_table(), nullptr);

  bool closed = false;
  connection.close_async([&closed](VoidResult result) { closed = result.is_bad(); });
  EXPECT_TRUE(closed) << "close on a null handle fails fast (inline) with a bad Result, no crash";

  bool readFailed = false;
  connection.read_value_async(
    ua::NodeId{0, 1}, [&readFailed](Result<ua::DataValue> result) { readFailed = result.is_bad(); });
  EXPECT_TRUE(readFailed) << "read_value on a null handle fails fast with a bad Result";

  EXPECT_EQ(connection.subscriptions().try_list_sync().status_code(), ua::StatusCode{Status::BadInvalidState})
    << "listing through a null handle fails rather than reporting no Subscriptions";
}

}  // namespace
