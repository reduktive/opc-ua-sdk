// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Regression pins for sub-phase 4.9 - session service-call ownership.
//
// These pins lock in the fix that re-keys the session's in-flight-service
// ownership map from the client-supplied RequestHandle to the server-assigned
// per-request id.
//
// THE BUG (pre-fix):
//   The session held its in-flight services in
//     unordered_multimap<RequestHandle, shared_ptr<Service>> mServiceCallsByRequestHandle.
//   The reference client sends request_header().request_handle() == 0 for EVERY
//   request, so concurrent requests collided on the same key. When one request
//   completed, response_received() did `mServiceCallsByRequestHandle.erase(handle)`
//   which erased EVERY entry sharing that handle - destroying the OTHER concurrent
//   request's still-in-flight Service. The destroyed service's completion never
//   fired, so its response was never sent and the client timed out (BadTimeout,
//   seen in DynamicTypeIntegration.SessionModelAccessChunkedDiscovery).
//
// THE FIX:
//   Re-key to unordered_map<requestId, shared_ptr<Service>> (requestId is unique
//   per in-flight request). response_received() now erases by requestId, so
//   completing one request leaves every other concurrent request untouched.
//   Cancel resolves handle -> {requestId...} via mRequestHandlesByRequestId so a
//   single Cancel still targets every in-flight request carrying that handle.
//
// WHY THESE PINS ARE FALSIFIABLE:
//   They register >= 2 in-flight services that SHARE one RequestHandle (0) but
//   have distinct requestIds, then drive the real production cleanup/cancel code
//   paths (Session::response_received / Session::cancel_outstanding_ops_effect).
//   - CompletingOneSharedHandleRequestLeavesTheOtherAlive FAILS on the old
//     handle-keyed code: erase(handle) destroys both services, so the surviving
//     service is gone (its alive-flag flips, its slot is missing) and it can
//     never route its response. It PASSES on the fixed code because erase is by
//     requestId.
//   - CancelTargetsAllInFlightSharingHandle would silently cancel only one (or
//     an arbitrary one) of the colliding multimap entries on the old code path;
//     the fix iterates the handle index so it cancels all of them.

#include <gtest/gtest.h>

#include <memory>

#include "fake_session_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_read_response.h"
#include "ua_server_session_test_access.h"
#include "ua_service.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

// Minimal in-flight Service test double.
//
// Stands in for a real ReadService/BrowseService/etc. that the session owns
// strongly in mServiceCallsByRequestId while its async chain is mid-flight. We
// use a double (rather than a real parked service) because the bug under test is
// in the SESSION's ownership/cleanup bookkeeping, not in any one service - and a
// double lets the test observe destruction deterministically and route a real
// Response through the production Session::response_received path.
class FakeInFlightService final : public ::ua::server::Service
{
public:
  static std::shared_ptr<FakeInFlightService> create(::ua::weak_ptr<::ua::server::Session> session,
    uint32_t requestId, ::ua::IntegerId requestHandle, std::shared_ptr<bool> aliveFlag)
  {
    return std::shared_ptr<FakeInFlightService>(
      new FakeInFlightService(session, requestId, requestHandle, std::move(aliveFlag)));
  }

  ~FakeInFlightService() override
  {
    if (mAliveFlag)
      *mAliveFlag = false;
  }

  // cancel_outstanding_ops_effect() invokes this from WITHIN the session strand.
  // A real service's cancel() posts its terminal ServiceFault ASYNCHRONOUSLY to
  // its own strand (non-blocking) - it never routes response_received inline. We
  // therefore only RECORD the cancel here: driving response_received via the
  // blocking on_strand() helper from within the strand would deadlock (on_strand
  // posts-and-blocks and is documented "never call from a strand"). That cancel
  // routes a ServiceFault is covered by the real-service cancel suite
  // (cancel_request_pin_test.cpp + the 29 cancel/in-flight tests). This pin's
  // required assertion is that the SESSION targets every in-flight request
  // sharing the handle - observed via cancel_count(), not fault routing.
  void abort(StatusCode /*reason*/) override
  {
    mCancelCount++;
  }

  // Drive a normal completion: route a ReadResponse through the production
  // Session::response_received path, exactly as the real service's completion
  // callback does. Idempotent via mFinished (see cancel()).
  void complete()
  {
    auto session = mSession.lock();
    if (!session || mFinished)
      return;
    mFinished = true;
    auto resp = ::std::make_shared<::ua::ReadResponse>();
    resp->response_header().service_result() = ::ua::Status::Good;
    ::ua::server::SessionTestAccess::on_strand(
      *session, [this, resp](auto& g) { g.response_received(::ua::Response{mRequestId, resp}); });
  }

  uint32_t cancel_count() const
  {
    return mCancelCount;
  }

private:
  FakeInFlightService(::ua::weak_ptr<::ua::server::Session> session, uint32_t requestId,
    ::ua::IntegerId requestHandle, std::shared_ptr<bool> aliveFlag)
    : ::ua::server::Service(requestHandle), mSession(std::move(session)), mRequestId(requestId),
      mAliveFlag(std::move(aliveFlag))
  {
    if (mAliveFlag)
      *mAliveFlag = true;
  }

  ::ua::weak_ptr<::ua::server::Session> mSession;
  uint32_t mRequestId;
  std::shared_ptr<bool> mAliveFlag;
  uint32_t mCancelCount{0};
  bool mFinished{false};
};

// Register a fake in-flight service into the session's ownership maps exactly as
// the production `*_request_received` methods do: strong owner in
// mServiceCallsByRequestId, the handle index in mRequestHandlesByRequestId, and
// the outstanding-handle set entry. This sets up the SAME preconditions the real
// dispatch path establishes, so the cleanup/cancel code under test runs against
// realistic state.
std::shared_ptr<FakeInFlightService> register_in_flight(SessionPinHarness& harness, uint32_t requestId,
  ::ua::IntegerId requestHandle, std::shared_ptr<bool> aliveFlag)
{
  auto service = FakeInFlightService::create(
    harness.session->weak_from_this(), requestId, requestHandle, std::move(aliveFlag));
  ::ua::server::SessionTestAccess::on_strand(*harness.session,
    [&](auto& g)
    {
      g.service_calls_by_request_id().emplace(requestId, service);
      g.request_handles_by_request_id()[requestId] = requestHandle;
      g.outstanding_request_handles().insert(requestHandle);
    });
  return service;
}

// Drive an activated session ready to accept service requests.
std::unique_ptr<SessionPinHarness> make_activated_harness()
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 1;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();
  return h;
}

struct TrackedRequestState
{
  bool subjectInFlight{false};
  bool unrelatedInFlight{false};
  bool subjectServiceOwned{false};
  bool unrelatedServiceOwned{false};
  bool subjectHandleIndexed{false};
  bool unrelatedHandleIndexed{false};
  bool subjectDiagnosticsOwned{false};
  bool unrelatedDiagnosticsOwned{false};
};

void seed_full_request_tracking(SessionPinHarness& harness, uint32_t requestId, ::ua::IntegerId requestHandle,
  std::shared_ptr<::ua::Structure> request, const std::shared_ptr<FakeInFlightService>& service)
{
  ::ua::server::SessionTestAccess::on_strand(*harness.session,
    [&](auto& guard)
    {
      guard.in_flight_requests()[requestId] = std::move(request);
      guard.service_calls_by_request_id()[requestId] = service;
      guard.request_handles_by_request_id()[requestId] = requestHandle;
      guard.outstanding_request_handles().insert(requestHandle);
      guard.return_diagnostics_by_request_id()[requestId] = 0x3ff;
    });
}

TrackedRequestState tracked_request_state(
  SessionPinHarness& harness, uint32_t subjectId, uint32_t unrelatedId)
{
  return ::ua::server::SessionTestAccess::on_strand(*harness.session,
    [&](auto& guard)
    {
      return TrackedRequestState{
        .subjectInFlight = guard.in_flight_requests().contains(subjectId),
        .unrelatedInFlight = guard.in_flight_requests().contains(unrelatedId),
        .subjectServiceOwned = guard.service_calls_by_request_id().contains(subjectId),
        .unrelatedServiceOwned = guard.service_calls_by_request_id().contains(unrelatedId),
        .subjectHandleIndexed = guard.request_handles_by_request_id().contains(subjectId),
        .unrelatedHandleIndexed = guard.request_handles_by_request_id().contains(unrelatedId),
        .subjectDiagnosticsOwned = guard.return_diagnostics_by_request_id().contains(subjectId),
        .unrelatedDiagnosticsOwned = guard.return_diagnostics_by_request_id().contains(unrelatedId),
      };
    });
}

class SessionServiceCallOwnershipPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// (a) THE CORE INVARIANT.
//
// Two in-flight services share RequestHandle 0 (distinct requestIds). Completing
// ONE must leave the OTHER alive and able to route its response.
//
// Falsifiability: on the old handle-keyed multimap, response_received() did
// mServiceCallsByRequestHandle.erase(0), destroying BOTH services. The survivor's
// alive-flag would be false and its completion would route nothing (the
// secure-channel sink would never see the second response). On the fixed code
// (erase by requestId) only the completed service is dropped.
// ---------------------------------------------------------------------------
TEST_F(SessionServiceCallOwnershipPin, CompletingOneSharedHandleRequestLeavesTheOtherAlive)
{
  auto h = make_activated_harness();

  auto aliveOne = std::make_shared<bool>(false);
  auto aliveTwo = std::make_shared<bool>(false);
  auto serviceOne = register_in_flight(*h, /*requestId=*/100, /*requestHandle=*/0, aliveOne);
  auto serviceTwo = register_in_flight(*h, /*requestId=*/101, /*requestHandle=*/0, aliveTwo);

  ASSERT_TRUE(*aliveOne);
  ASSERT_TRUE(*aliveTwo);

  // Complete request 100. On the buggy code this also erases request 101.
  serviceOne->complete();
  h->wait_for_responses(1);
  (void)h->take_response();

  // The survivor's session-held strong owner must still exist. We drop our own
  // local strong ref first so the session map is the ONLY remaining owner - if
  // the buggy erase-by-handle ran, the service is already destroyed and the slot
  // is gone.
  serviceTwo.reset();

  bool survivorStillOwned = ::ua::server::SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    { return g.service_calls_by_request_id().find(101) != g.service_calls_by_request_id().end(); });

  EXPECT_TRUE(survivorStillOwned)
    << "completing request 100 must NOT erase the concurrent request 101 sharing handle 0";
  EXPECT_TRUE(*aliveTwo) << "request 101's service must still be alive after request 100 completes";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// (a continued): the survivor can still route its response after the other
// completes. This is the externally-observable symptom the client saw
// (BadTimeout): the second response never reaching the wire.
// ---------------------------------------------------------------------------
TEST_F(SessionServiceCallOwnershipPin, SurvivorStillRoutesItsResponseAfterSiblingCompletes)
{
  auto h = make_activated_harness();

  auto aliveOne = std::make_shared<bool>(false);
  auto aliveTwo = std::make_shared<bool>(false);
  auto serviceOne = register_in_flight(*h, /*requestId=*/200, /*requestHandle=*/0, aliveOne);
  auto serviceTwo = register_in_flight(*h, /*requestId=*/201, /*requestHandle=*/0, aliveTwo);

  serviceOne->complete();
  h->wait_for_responses(1);
  auto first = h->take_response();
  EXPECT_EQ(first.first, 200u);

  // The survivor completes and must produce the second response.
  serviceTwo->complete();
  h->wait_for_responses(1);
  auto second = h->take_response();
  EXPECT_EQ(second.first, 201u)
    << "request 201 must still deliver its response after request 200 (same handle) completed";
  EXPECT_NE(dynamic_cast<ReadResponse*>(second.second.get()), nullptr);

  h->shutdown();
}

// Browse and BrowseNext use a special terminal-response handler so the Session can adopt continuation
// points before emitting the answer. That special path owes the same request-slot/owner release as the
// generic response path; otherwise a strictly sequential browse eventually reaches the in-flight cap.
// @relation(AC-COMP-SVR-SESSION-REQUEST-TRACKING-01-TERMINAL-CLEANUP, scope=function)
TEST(SessionRequestTracking, BrowseCompletionReleasesOnlyItsOwnRequestTracking)
{
  auto harness = make_activated_harness();
  constexpr uint32_t subjectId{300};
  constexpr uint32_t unrelatedId{301};

  auto subjectAlive = std::make_shared<bool>(false);
  auto unrelatedAlive = std::make_shared<bool>(false);
  auto subjectService =
    FakeInFlightService::create(harness->session->weak_from_this(), subjectId, 30, subjectAlive);
  auto unrelatedService =
    FakeInFlightService::create(harness->session->weak_from_this(), unrelatedId, 31, unrelatedAlive);
  seed_full_request_tracking(
    *harness, subjectId, 30, std::make_shared<::ua::BrowseRequest>(), subjectService);
  seed_full_request_tracking(
    *harness, unrelatedId, 31, std::make_shared<::ua::BrowseRequest>(), unrelatedService);
  subjectService.reset();
  unrelatedService.reset();

  ::ua::server::SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      auto response = std::make_shared<::ua::BrowseResponse>();
      ::ua::Response responseEnvelope{subjectId, std::move(response)};
      std::vector<::ua::server::BrowseContinuationPoint> continuationPoints;
      guard.browse_response_received(std::move(responseEnvelope), std::move(continuationPoints));
    });
  harness->wait_for_responses(1);
  EXPECT_EQ(harness->take_response().first, subjectId);

  const auto state = tracked_request_state(*harness, subjectId, unrelatedId);
  EXPECT_FALSE(state.subjectInFlight);
  EXPECT_FALSE(state.subjectServiceOwned);
  EXPECT_FALSE(state.subjectHandleIndexed);
  EXPECT_FALSE(state.subjectDiagnosticsOwned);
  EXPECT_FALSE(*subjectAlive) << "the Session must release the subject Service's final strong owner";
  EXPECT_TRUE(state.unrelatedInFlight);
  EXPECT_TRUE(state.unrelatedServiceOwned);
  EXPECT_TRUE(state.unrelatedHandleIndexed);
  EXPECT_TRUE(state.unrelatedDiagnosticsOwned);
  EXPECT_TRUE(*unrelatedAlive) << "completing the subject must not release an unrelated Service";

  harness->shutdown();
}

// HistoryRead has its own continuation-point adoption handler and therefore controls the sibling
// special path: fixing only Browse leaves the same permanent request-slot leak in a long-lived history
// Session.
// @relation(AC-COMP-SVR-SESSION-REQUEST-TRACKING-01-TERMINAL-CLEANUP, scope=function)
TEST(SessionRequestTracking, HistoryReadCompletionReleasesOnlyItsOwnRequestTracking)
{
  auto harness = make_activated_harness();
  constexpr uint32_t subjectId{400};
  constexpr uint32_t unrelatedId{401};

  auto subjectAlive = std::make_shared<bool>(false);
  auto unrelatedAlive = std::make_shared<bool>(false);
  auto subjectService =
    FakeInFlightService::create(harness->session->weak_from_this(), subjectId, 40, subjectAlive);
  auto unrelatedService =
    FakeInFlightService::create(harness->session->weak_from_this(), unrelatedId, 41, unrelatedAlive);
  seed_full_request_tracking(
    *harness, subjectId, 40, std::make_shared<::ua::HistoryReadRequest>(), subjectService);
  seed_full_request_tracking(
    *harness, unrelatedId, 41, std::make_shared<::ua::HistoryReadRequest>(), unrelatedService);
  subjectService.reset();
  unrelatedService.reset();

  ::ua::server::SessionTestAccess::on_strand(*harness->session,
    [&](auto& guard)
    {
      ::ua::server::HistoryReadService::HistoryReadServiceResponse completion{
        .response = {subjectId, std::make_shared<::ua::HistoryReadResponse>()},
        .continuationPoints = {},
      };
      guard.history_read_response_received(std::move(completion));
    });
  harness->wait_for_responses(1);
  EXPECT_EQ(harness->take_response().first, subjectId);

  const auto state = tracked_request_state(*harness, subjectId, unrelatedId);
  EXPECT_FALSE(state.subjectInFlight);
  EXPECT_FALSE(state.subjectServiceOwned);
  EXPECT_FALSE(state.subjectHandleIndexed);
  EXPECT_FALSE(state.subjectDiagnosticsOwned);
  EXPECT_FALSE(*subjectAlive) << "the Session must release the subject Service's final strong owner";
  EXPECT_TRUE(state.unrelatedInFlight);
  EXPECT_TRUE(state.unrelatedServiceOwned);
  EXPECT_TRUE(state.unrelatedHandleIndexed);
  EXPECT_TRUE(state.unrelatedDiagnosticsOwned);
  EXPECT_TRUE(*unrelatedAlive) << "completing the subject must not release an unrelated Service";

  harness->shutdown();
}

// ---------------------------------------------------------------------------
// (b) Cancel targets ALL in-flight services sharing a handle.
//
// Two in-flight services share handle 7. A single Cancel(handle=7) must cancel
// BOTH and report cancel_count == 2; each cancelled service must route a fault
// (not be silently dropped).
//
// Falsifiability: the fix iterates mRequestHandlesByRequestId to find every
// requestId carrying the target handle. A keyed-by-handle implementation that
// only handled one entry per handle (or relied on multimap iteration that the
// completion path could corrupt) would under-count and leave a service
// un-cancelled.
// ---------------------------------------------------------------------------
TEST_F(SessionServiceCallOwnershipPin, CancelTargetsAllInFlightSharingHandle)
{
  auto h = make_activated_harness();

  auto aliveOne = std::make_shared<bool>(false);
  auto aliveTwo = std::make_shared<bool>(false);
  auto serviceOne = register_in_flight(*h, /*requestId=*/300, /*requestHandle=*/7, aliveOne);
  auto serviceTwo = register_in_flight(*h, /*requestId=*/301, /*requestHandle=*/7, aliveTwo);

  uint32_t cancelCount = ::ua::server::SessionTestAccess::on_strand(
    *h->session, [&](auto& g) { return g.cancel_outstanding_ops_effect(7); });

  EXPECT_EQ(cancelCount, 2u) << "Cancel(handle=7) must target BOTH in-flight requests sharing handle 7";
  EXPECT_EQ(serviceOne->cancel_count(), 1u) << "request 300 must have been cancelled";
  EXPECT_EQ(serviceTwo->cancel_count(), 1u) << "request 301 must have been cancelled";

  // Load-bearing assertion above: the session targeted EVERY in-flight request
  // sharing handle 7 (the Part-4 semantic the requestId re-key preserves). That
  // cancel then routes a ServiceFault through response_received is covered by the
  // real-service cancel suite (real services post the fault async; the fake here
  // cannot route on-strand without re-entering the blocking on_strand helper).
  h->shutdown();
}

// ---------------------------------------------------------------------------
// (b continued): a Cancel that matches no in-flight handle reports zero and
// touches nothing.
// ---------------------------------------------------------------------------
TEST_F(SessionServiceCallOwnershipPin, CancelWithNoMatchingHandleReportsZero)
{
  auto h = make_activated_harness();

  auto alive = std::make_shared<bool>(false);
  auto service = register_in_flight(*h, /*requestId=*/400, /*requestHandle=*/7, alive);

  uint32_t cancelCount = ::ua::server::SessionTestAccess::on_strand(
    *h->session, [&](auto& g) { return g.cancel_outstanding_ops_effect(/*unmatched=*/99); });

  EXPECT_EQ(cancelCount, 0u);
  EXPECT_EQ(service->cancel_count(), 0u) << "non-matching Cancel must not touch in-flight services";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// (c) complete-then-cancel is a safe no-op.
//
// After a request completes (and the session releases ownership), a later Cancel
// targeting its handle must NOT re-touch the now-gone service (no double-erase,
// no use-after-free) and must report zero.
// ---------------------------------------------------------------------------
TEST_F(SessionServiceCallOwnershipPin, CancelAfterCompleteIsSafeNoOp)
{
  auto h = make_activated_harness();

  auto alive = std::make_shared<bool>(false);
  auto service = register_in_flight(*h, /*requestId=*/500, /*requestHandle=*/5, alive);

  service->complete();
  h->wait_for_responses(1);
  (void)h->take_response();

  // Session must have released its strong owner AND the handle index entry on
  // completion, so a later Cancel finds nothing.
  uint32_t cancelCount = ::ua::server::SessionTestAccess::on_strand(*h->session,
    [&](auto& g)
    {
      EXPECT_EQ(g.service_calls_by_request_id().find(500), g.service_calls_by_request_id().end());
      EXPECT_EQ(g.request_handles_by_request_id().find(500), g.request_handles_by_request_id().end());
      return g.cancel_outstanding_ops_effect(5);
    });

  EXPECT_EQ(cancelCount, 0u) << "Cancel after the request already completed must be a no-op";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Note: the cancel-then-complete idempotency case (cancel routes a fault, a late
// complete() then routes nothing) is intentionally NOT pinned here. It requires
// the fake's cancel() to route response_received from WITHIN the session strand,
// which the post-and-block test-access helper cannot do without deadlocking. That
// case is covered by the real-service cancel suite (cancel_request_pin_test.cpp
// and the 29 cancel/in-flight tests), where real services post their terminal
// fault asynchronously off the cancel call.

}  // namespace ua::test::pins_4_9
