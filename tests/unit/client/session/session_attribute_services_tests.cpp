// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionAttributeServices (Attribute Service Set forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. A missing
// guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
// Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"
#include "test_utilities.h"
#include "ua_session_service_helpers.h"

#include "ua_browse_request.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_session_attribute_services.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <condition_variable>
#include <cstdint>
#include <future>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;
using ua::client::guard_test::DeadSessionHarness;
using ua::client::test_capture::CaptureHarness;

TEST(SessionAttributeServicesGuard, ReadOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto attributes = harness.live().attributes();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  attributes.read_async(ReadRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionAttributeServicesGuard, HistoryReadOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto attributes = harness.live().attributes();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  attributes.history_read_async(HistoryReadRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

// @verifies CL-ATTR-001
// Part 4 section 5.10.2.2: "If maxAge is set to 0, the Server shall attempt to read a new value from the data
// source." The client obligation this underwrites is that read_async forwards the caller's maxAge verbatim
// and never silently substitutes a non-zero server-cache window in its place. We drive the real Read send
// path, capture the outgoing ReadRequest off the SecureChannel, and assert its MaxAge reaches the wire as
// exactly 0. Falsifies if read_async rewrites/bumps a maxAge=0 request to any non-zero value (which would
// turn a demanded fresh-from-source read into a cached read).
// @relation(CL-ATTR-001, scope=function)
TEST(SessionAttributeServicesRead, MaxAgeZeroPassesThroughToWireUnmodified)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    ReadRequest request;
    request.max_age() = 0.0;
    ReadValueId target;
    target.node_id() = NodeId{2, 4711};
    request.nodes_to_read().push_back(target);

    harness.session_handle().attributes().read_async(request, [](auto) {});

    ASSERT_TRUE(harness.wait_for_pending_request()) << "read_async must forward a Read to the channel";
    auto captured = harness.first_captured<ReadRequest>();
    ASSERT_TRUE(captured.has_value()) << "the ReadRequest must reach the SecureChannel send path";
    ASSERT_EQ(captured->nodes_to_read().size(), 1u)
      << "the caller's nodes_to_read must be forwarded (confirms the captured request is ours)";
    EXPECT_EQ(captured->nodes_to_read()[0].node_id(), NodeId(2, 4711));
    EXPECT_EQ(captured->max_age(), 0.0) << "maxAge=0 must reach the wire unmodified (fresh-from-source)";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-DIAG-004
// @relation(CL-DIAG-004, scope=function)
TEST(SessionAttributeServicesDiagnostics, Tier0RawByDefaultAndWrapsOnlyWhenOptedIn)
{
  boost::asio::thread_pool pool;
  auto originalDetail = std::shared_ptr<const ua::ErrorDetail>{
    ua::ErrorDetail::build("WireFailure", "Synthetic wire failure", "test.tier0.wire")};
  const ua::StatusCode originalStatus{ua::Status::BadNodeIdUnknown, originalDetail};

  const auto run = [&](bool wrapTier0)
  {
    auto harness = CaptureHarness::create_active(pool.get_executor(), {}, wrapTier0);
    std::promise<ua::Result<ua::ReadResponse>> received;
    auto receivedFuture = received.get_future();
    ua::ReadRequest request;
    request.nodes_to_read().push_back(ua::ReadValueId{});
    harness.session_handle().attributes().read_async(
      std::move(request), [&received](auto result) { received.set_value(std::move(result)); });
    EXPECT_TRUE(harness.wait_for_pending_request());
    EXPECT_TRUE(harness.inject_channel_failure(originalStatus));
    auto result = receivedFuture.get();
    harness.cleanup_sync();
    harness.release();
    return result;
  };

  const auto raw = run(false);
  ASSERT_TRUE(raw.is_bad());
  EXPECT_EQ(raw.status_code().as_uint32(), originalStatus.as_uint32());
  EXPECT_EQ(raw.status_code().shared_detail(), originalDetail)
    << "default tier-0 pass-through must preserve the exact incoming rich status";

  const auto wrapped = run(true);
  ASSERT_TRUE(wrapped.is_bad());
  EXPECT_EQ(wrapped.status_code().as_uint32(), originalStatus.as_uint32());
  const auto outer = wrapped.status_code().shared_detail();
  ASSERT_NE(outer, nullptr);
  EXPECT_EQ(outer->source, "client.tier0.session.service");
  EXPECT_EQ(outer->cause, originalDetail);

  ::ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-DIAG-011
// @relation(CL-DIAG-011, scope=function)
TEST(SessionAttributeServicesDiagnostics, ReturnDiagnosticsOverrideWinsIncludingExplicitZero)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  harness.sessionDeps->defaultReturnDiagnostics = 0x12u;

  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0), 0x12u);
  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0x34u), 0x34u)
    << "without a Connection override an explicit request value must remain authoritative";

  ua::client::SessionTestAccess::set_return_diagnostics_override(*harness.session, 0xFFFFu);
  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0), 0xFFFFu);
  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0x34u), 0xFFFFu)
    << "an engaged per-Connection policy must override every request";

  ua::client::SessionTestAccess::set_return_diagnostics_override(*harness.session, 0u);
  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0x34u), 0u)
    << "engaged zero must suppress diagnostics rather than mean no override";

  ua::client::SessionTestAccess::set_return_diagnostics_override(*harness.session, std::nullopt);
  EXPECT_EQ(ua::client::SessionTestAccess::return_diagnostics_for(*harness.session, 0), 0x12u);

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-AUDIT-001
// @relation(CL-AUDIT-001, scope=function)
TEST(SessionAttributeServicesAudit, ProviderPopulatesEmptyRequestHeaderBeforeSend)
{
  boost::asio::thread_pool pool;
  std::size_t providerCalls = 0;
  ua::client::SessionImpl::Config config;
  config.auditEntryIdProvider = [&providerCalls]
  {
    ++providerCalls;
    return ua::String{"audit-1234"};
  };
  auto harness = CaptureHarness::create_active(pool.get_executor(), std::move(config));
  const auto lifecycleProviderCalls = providerCalls;

  WriteRequest request;
  request.nodes_to_write().push_back(WriteValue{});
  harness.session_handle().attributes().write_async(std::move(request), [](auto) {});

  ASSERT_TRUE(harness.wait_for_pending_request());
  const auto captured = harness.first_captured<WriteRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->request_header().audit_entry_id(), ua::String{"audit-1234"});
  EXPECT_EQ(providerCalls, lifecycleProviderCalls + 1U);
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-AUDIT-001
// @relation(CL-AUDIT-001, scope=function)
TEST(SessionAttributeServicesAudit, DefaultIsEmptyAndPerCallOverrideWins)
{
  boost::asio::thread_pool pool;
  std::size_t providerCalls = 0;
  ua::client::SessionImpl::Config config;
  config.auditEntryIdProvider = [&providerCalls]
  {
    ++providerCalls;
    return ua::String{"provider-id"};
  };
  auto harness = CaptureHarness::create_active(pool.get_executor(), std::move(config));
  const auto lifecycleProviderCalls = providerCalls;

  WriteRequest request;
  request.request_header().audit_entry_id() = "per-call";
  request.nodes_to_write().push_back(WriteValue{});
  harness.session_handle().attributes().write_async(std::move(request), [](auto) {});

  ASSERT_TRUE(harness.wait_for_pending_request());
  const auto captured = harness.first_captured<WriteRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->request_header().audit_entry_id(), ua::String{"per-call"});
  EXPECT_EQ(providerCalls, lifecycleProviderCalls) << "a per-call override must not consume the provider";
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);

  boost::asio::thread_pool emptyPool;
  auto emptyHarness = CaptureHarness::create_active(emptyPool.get_executor());
  ReadRequest emptyRequest;
  emptyRequest.nodes_to_read().push_back(ReadValueId{});
  emptyHarness.session_handle().attributes().read_async(std::move(emptyRequest), [](auto) {});
  ASSERT_TRUE(emptyHarness.wait_for_pending_request());
  const auto emptyCaptured = emptyHarness.first_captured<ReadRequest>();
  ASSERT_TRUE(emptyCaptured.has_value());
  EXPECT_TRUE(emptyCaptured->request_header().audit_entry_id().empty());
  EXPECT_EQ(providerCalls, lifecycleProviderCalls);
  emptyHarness.cleanup_sync();
  emptyHarness.release();
  ua::test_utils::drain_with_timeout(emptyPool);
}

// @verifies CL-AUDIT-001
// @relation(CL-AUDIT-001, scope=function)
TEST(SessionAttributeServicesAudit, ThrowingProviderFailsRequestWithoutSending)
{
  boost::asio::thread_pool pool;
  bool armed = false;
  ua::client::SessionImpl::Config config;
  config.auditEntryIdProvider = [&armed]
  {
    if (!armed)
      return ua::String{};
    throw std::runtime_error{"audit provider failed"};
    return ua::String{};
  };
  auto harness = CaptureHarness::create_active(pool.get_executor(), std::move(config));
  armed = true;

  std::mutex mutex;
  std::condition_variable completed;
  std::optional<ua::Result<ua::WriteResponse>> outcome;
  WriteRequest request;
  request.nodes_to_write().push_back(WriteValue{});
  harness.session_handle().attributes().write_async(std::move(request),
    [&](auto result)
    {
      {
        std::lock_guard lock(mutex);
        outcome.emplace(std::move(result));
      }
      completed.notify_one();
    });

  {
    std::unique_lock lock(mutex);
    ASSERT_TRUE(completed.wait_for(lock, 2s, [&] { return outcome.has_value(); }));
  }
  ASSERT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code(), ua::StatusCode{ua::Status::BadInternalError});
  ASSERT_NE(outcome->shared_detail(), nullptr);
  EXPECT_EQ(outcome->shared_detail()->code, "RequestHeaderProviderException");
  EXPECT_FALSE(harness.first_captured<WriteRequest>().has_value())
    << "a provider exception must be converted before any request reaches the channel";
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-AUDIT-002
// @relation(CL-AUDIT-002, scope=function)
TEST(SessionAttributeServicesAudit, AuditableServiceMembershipMatchesPart4)
{
  using namespace ua::client::detail;
  EXPECT_TRUE(is_auditable_session_service_request<ua::CancelRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::AddNodesRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::AddReferencesRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::DeleteNodesRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::DeleteReferencesRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::WriteRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::HistoryUpdateRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::CallRequest>);
  EXPECT_TRUE(is_auditable_session_service_request<ua::TransferSubscriptionsRequest>);
  EXPECT_FALSE(is_auditable_session_service_request<ua::ReadRequest>);
  EXPECT_FALSE(is_auditable_session_service_request<ua::BrowseRequest>);
}

// @verifies CL-AUDIT-002
// @relation(CL-AUDIT-002, scope=function)
TEST(SessionAttributeServicesAudit, FailedAuditableInvocationWasStampedBeforeSend)
{
  boost::asio::thread_pool pool;
  std::size_t providerCalls = 0;
  ua::client::SessionImpl::Config config;
  config.auditEntryIdProvider = [&providerCalls]
  {
    ++providerCalls;
    return ua::String{"failed-write-audit"};
  };
  auto harness = CaptureHarness::create_active(pool.get_executor(), std::move(config));
  const auto lifecycleProviderCalls = providerCalls;

  std::mutex outcomeMutex;
  std::condition_variable outcomeReady;
  std::optional<ua::Result<ua::WriteResponse>> outcome;
  WriteRequest request;
  request.nodes_to_write().push_back(WriteValue{});
  harness.session_handle().attributes().write_async(std::move(request),
    [&](auto result)
    {
      {
        std::lock_guard lock(outcomeMutex);
        outcome.emplace(std::move(result));
      }
      outcomeReady.notify_one();
    });

  ASSERT_TRUE(harness.wait_for_pending_request());
  const auto captured = harness.first_captured<WriteRequest>();
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->request_header().audit_entry_id(), ua::String{"failed-write-audit"});
  EXPECT_EQ(providerCalls, lifecycleProviderCalls + 1U)
    << "the provider must run exactly once before the auditable request is sent";

  auto response = std::make_shared<ua::WriteResponse>();
  response->response_header().service_result() = ua::Status::BadNodeIdUnknown;
  ASSERT_TRUE(harness.inject_channel_response(std::move(response)));
  {
    std::unique_lock lock(outcomeMutex);
    ASSERT_TRUE(outcomeReady.wait_for(lock, 2s, [&] { return outcome.has_value(); }));
    ASSERT_TRUE(outcome->is_good());
    EXPECT_EQ(
      outcome->value().response_header().service_result(), ua::StatusCode{ua::Status::BadNodeIdUnknown});
  }

  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-ATTR-002
// Part 4 section 5.10.2.2: "If maxAge is set to the max Int32 value or greater, the Server shall attempt to
// get a cached value." The client must expose this in the API and not silently substitute a different value.
// We send Int32.max as the Duration maxAge, capture the outgoing ReadRequest, and assert the wire carries
// that exact value. Falsifies if read_async clamps/rewrites a large maxAge (e.g. to a smaller cache window),
// which would defeat the caller's explicit opt-in to a cached read.
// @relation(CL-ATTR-002, scope=function)
TEST(SessionAttributeServicesRead, MaxAgeInt32MaxPassesThroughUnclamped)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    const double requestedMaxAge = static_cast<double>(std::numeric_limits<int32_t>::max());
    ReadRequest request;
    request.max_age() = requestedMaxAge;

    harness.session_handle().attributes().read_async(request, [](auto) {});

    ASSERT_TRUE(harness.wait_for_pending_request()) << "read_async must forward a Read to the channel";
    auto captured = harness.first_captured<ReadRequest>();
    ASSERT_TRUE(captured.has_value()) << "the ReadRequest must reach the SecureChannel send path";
    EXPECT_EQ(captured->max_age(), requestedMaxAge)
      << "maxAge = Int32.max must reach the wire unclamped (caller opt-in to a cached read)";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-ATTR-002
// Same normative clause ("max Int32 value or greater"): a maxAge strictly above Int32.max must also pass
// through untouched. This pins the "or greater" half of the clause and, unlike the exactly-Int32.max case,
// falsifies specifically against a clamp-to-Int32.max implementation (which would leave the wire value at
// Int32.max rather than the larger requested value).
// @relation(CL-ATTR-002, scope=function)
TEST(SessionAttributeServicesRead, MaxAgeAboveInt32MaxPassesThroughUnclamped)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    const double requestedMaxAge = static_cast<double>(std::numeric_limits<int32_t>::max()) * 1000.0;
    ReadRequest request;
    request.max_age() = requestedMaxAge;

    harness.session_handle().attributes().read_async(request, [](auto) {});

    ASSERT_TRUE(harness.wait_for_pending_request()) << "read_async must forward a Read to the channel";
    auto captured = harness.first_captured<ReadRequest>();
    ASSERT_TRUE(captured.has_value()) << "the ReadRequest must reach the SecureChannel send path";
    EXPECT_EQ(captured->max_age(), requestedMaxAge)
      << "maxAge > Int32.max must not be clamped to Int32.max on the wire";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-ATTR-019
// Tier-1 write_async returns the raw WriteResponse with per-slot StatusCodes and emits no compensating
// write: a partial failure exposes each slot's result unchanged and never rolls back a successful slot. We
// drive a 2-node Write, inject a WriteResponse whose service result is Good but whose per-slot results are
// [Good, Bad_UserAccessDenied], and assert (a) both per-slot StatusCodes surface to the caller unmodified
// and (b) exactly one Write is sent - no second, compensating Write is emitted. Falsifies if the client
// collapses the mixed per-slot results into a single status, or if it issues a rollback Write to undo the
// slot that succeeded.
// @relation(CL-ATTR-019, scope=function)
TEST(SessionAttributeServicesWrite, PartialFailureExposesPerSlotStatusAndEmitsNoCompensatingWrite)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    WriteRequest request;
    WriteValue slotZero;
    slotZero.node_id() = NodeId{2, 1};
    WriteValue slotOne;
    slotOne.node_id() = NodeId{2, 2};
    request.nodes_to_write().push_back(slotZero);
    request.nodes_to_write().push_back(slotOne);

    std::mutex mx;
    std::condition_variable cv;
    bool fired{false};
    bool good{false};
    std::vector<StatusCode> perSlot;

    harness.session_handle().attributes().write_async(request,
      [&](auto result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          good = result.is_good();
          if (good)
          {
            const auto& results = result.value().results();
            for (size_t i = 0; i < results.size(); ++i)
            {
              perSlot.push_back(results[i]);
            }
          }
        }
        cv.notify_one();
      });

    ASSERT_TRUE(harness.wait_for_pending_request()) << "write_async must forward a Write to the channel";
    auto captured = harness.first_captured<WriteRequest>();
    ASSERT_TRUE(captured.has_value()) << "the WriteRequest must reach the SecureChannel send path";
    ASSERT_EQ(captured->nodes_to_write().size(), 2u) << "both write slots must be forwarded";

    auto response = std::make_shared<WriteResponse>();
    response->response_header().service_result() = Status::Good;
    response->results().push_back(StatusCode{Status::Good});
    response->results().push_back(StatusCode{Status::BadUserAccessDenied});
    ASSERT_TRUE(harness.inject_channel_response(response));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }

    ASSERT_TRUE(good) << "a WriteResponse with a Good service result must surface as a good Result";
    ASSERT_EQ(perSlot.size(), 2u) << "every per-slot StatusCode must be exposed to the caller";
    EXPECT_EQ(perSlot[0], StatusCode{Status::Good}) << "slot 0 result must pass through unmodified";
    EXPECT_EQ(perSlot[1], StatusCode{Status::BadUserAccessDenied})
      << "slot 1 (the failed write) must surface per-slot, not collapse the whole response";

    // No-rollback: a partial failure must NOT trigger a compensating Write to undo the successful slot.
    EXPECT_FALSE(harness.wait_for_pending_request(100ms))
      << "the client must not emit a compensating/rollback Write after a partial failure";
    EXPECT_EQ(harness.all_captured<WriteRequest>().size(), 1u)
      << "exactly one Write must be sent; a rollback would produce a second";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(SessionAttributeServicesGuard, WriteOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto attributes = harness.live().attributes();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  attributes.write_async(WriteRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionAttributeServicesGuard, HistoryUpdateOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto attributes = harness.live().attributes();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  attributes.history_update_async(HistoryUpdateRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}
