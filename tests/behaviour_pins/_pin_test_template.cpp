// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour-pin test template.
//
// This file is illustrative. It is NOT linked into the test binary. Real pin tests live
// at tests/behaviour_pins/phase_<phase>_<sub-phase>_<flow>/<flow>_pin_test.cpp.
//
// Read historical runbook to see how a pin is referenced from a
// runbook.
//
// The patterns shown here cover the seven pin categories from the README:
//   1. Final Status on success.
//   2. Final Status + ErrorDetail content per failure mode.
//   3. ErrorDetail propagation through every Result<T> hand-off.
//   4. Single-flight rejection.
//   5. Threading affinity.
//   6. Concurrent-on-strand semantics.
//   7. Destructor-during-flight.
//
// The placeholder names <Component>, <flow>, <Args>, <Result>, <FailureMode>, etc.
// must be replaced with the concrete types from the flow being pinned. Includes are
// commented out for the same reason - uncomment and adapt when copying.

#include <atomic>
#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

// Concrete includes - replace with the component under test.
//
// #include "ua_<component>.h"
// #include <boost/asio/thread_pool.hpp>
// #include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

// #include "<component>_test_access.h"
// #include "fake_<collaborator>.h"

namespace ua::test::behaviour_pins
{

// =============================================================================
// Fixture
// =============================================================================
//
// Pin fixtures hold:
//   - A real boost::asio::thread_pool / Asio executor (no mocked strand or executor).
//   - The component under test, constructed with fake collaborators.
//   - Capture sinks for the user callback (status, error detail, thread id).
//
// The fixture is intentionally not a base class - pin tests are flow-specific and a
// shared base would tempt premature abstraction. Copy this skeleton per flow.

class FlowPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // mPool       = std::make_unique<boost::asio::thread_pool>(/*threads=*/2);
    // mStrand     = boost::asio::make_strand(mPool->get_executor());
    // mFakeCollab = std::make_shared<FakeCollaborator>(/*...*/);
    // mComponent  = std::make_shared<Component>(mStrand, mFakeCollab);
  }

  void TearDown() override
  {
    // Explicit boost::asio::thread_pool::stop() before locals reverse-destruct.
    // if (mPool) mPool->stop();
  }

  // Helpers --------------------------------------------------------------------

  // Block on the main test thread (only) for a callback to fire. Returns the result.
  template<class Result>
  Result wait_for_callback(std::future<Result>& f)
  {
    using namespace std::chrono_literals;
    EXPECT_EQ(f.wait_for(2s), std::future_status::ready)
      << "callback did not fire within 2s - is the flow stuck?";
    return f.get();
  }

  // std::unique_ptr<boost::asio::thread_pool>     mPool;
  // boost::asio::strand<boost::asio::any_io_executor>                          mStrand;
  // std::shared_ptr<FakeCollaborator>   mFakeCollab;
  // std::shared_ptr<Component>          mComponent;
};

// =============================================================================
// Pin 1: Final Status on success.
// =============================================================================
//
// The simplest pin: invoke the flow with a happy-path stimulus, assert the user
// callback receives Status::Good (or whatever the flow contracts).

TEST_F(FlowPin, SuccessYieldsExpectedStatus)
{
  // mFakeCollab->set_<step>_response(Result<...>{/*good response*/});
  //
  // std::promise<Result<X>> done;
  // mComponent-><flow>_async(/*args*/, [&](Result<X> r) { done.set_value(std::move(r)); });
  //
  // auto fut = done.get_future();
  // auto result = wait_for_callback(fut);
  //
  // EXPECT_TRUE(result.ok());
  // EXPECT_EQ(result.status_code(), Status::Good);
}

// =============================================================================
// Pin 2: Final Status + ErrorDetail content for each documented failure mode.
// =============================================================================
//
// One test per failure mode. The pin asserts both the status code AND the detail
// content (message, source, inner detail chain). Status alone is insufficient
// because the migration's biggest silent-regression risk is dropping ErrorDetail.

TEST_F(FlowPin, AuthorizerDeniesYieldsBadUserAccessDeniedWithDetail)
{
  // mFakeCollab->set_authorize_response(
  //   Result<bool>{Status::BadUserAccessDenied,
  //                make_error_detail("authorizer denied: <reason>")});
  //
  // std::promise<Result<X>> done;
  // mComponent-><flow>_async(/*args*/, [&](Result<X> r) { done.set_value(std::move(r)); });
  //
  // auto fut = done.get_future();
  // auto result = wait_for_callback(fut);
  //
  // EXPECT_FALSE(result.ok());
  // EXPECT_EQ(result.status_code(), Status::BadUserAccessDenied);
  // ASSERT_NE(result.shared_detail(), nullptr);
  // EXPECT_EQ(result.shared_detail()->message(), "authorizer denied: <reason>");
}

// One test per documented failure mode. Repeat the pattern.

// =============================================================================
// Pin 3: ErrorDetail propagation through every Result<T> hand-off.
// =============================================================================
//
// For each continuation that consumes a Result<T> from a collaborator and routes it
// onward, assert the detail survives every hand-off. The key property: the detail
// observed by the user callback is the SAME object (or pointer-identical via
// shared_ptr<const>) as the one the collaborator emitted. A copy-by-value detail
// passes status checks but fails identity checks.

TEST_F(FlowPin, InnerStepErrorDetailReachesUserCallbackUnchanged)
{
  // auto innerDetail = make_error_detail("inner failure source",
  //                                      Status::BadResourceUnavailable);
  // mFakeCollab->set_<step>_response(Result<...>{Status::BadResourceUnavailable, innerDetail});
  //
  // std::promise<Result<X>> done;
  // mComponent-><flow>_async(/*args*/, [&](Result<X> r) { done.set_value(std::move(r)); });
  //
  // auto fut = done.get_future();
  // auto result = wait_for_callback(fut);
  //
  // ASSERT_NE(result.shared_detail(), nullptr);
  // EXPECT_EQ(result.shared_detail().get(), innerDetail.get())
  //     << "ErrorDetail was copied/replaced at the boundary - should be lossless";
}

// =============================================================================
// Pin 4: Single-flight rejection.
// =============================================================================
//
// Only applicable to single-instance flows. A multi-instance flow (per-publish-request,
// per-service-request) is exempt and the runbook should explicitly justify it.

TEST_F(FlowPin, SecondInvocationWhilePendingReturnsBadInvalidState)
{
  // // First invocation: configure collaborator to NOT complete yet.
  // mFakeCollab->set_<step>_pending();
  //
  // std::promise<Result<X>> firstDone;
  // mComponent-><flow>_async(/*args*/,
  //   [&](Result<X> r) { firstDone.set_value(std::move(r)); });
  //
  // // Second invocation: should be rejected without disturbing the first.
  // std::promise<Result<X>> secondDone;
  // mComponent-><flow>_async(/*args*/,
  //   [&](Result<X> r) { secondDone.set_value(std::move(r)); });
  //
  // auto secondFut = secondDone.get_future();
  // auto secondResult = wait_for_callback(secondFut);
  // EXPECT_EQ(secondResult.status_code(), Status::BadInvalidState);
  //
  // // First invocation completes normally once we release the collaborator.
  // mFakeCollab->complete_<step>(Result<...>{/*good*/});
  // auto firstFut = firstDone.get_future();
  // auto firstResult = wait_for_callback(firstFut);
  // EXPECT_TRUE(firstResult.ok());
}

// =============================================================================
// Pin 5: Threading affinity.
// =============================================================================
//
// Capture the thread on which the user callback runs. The pin asserts the callback
// either runs on the component's strand (default per design section 11.4) or on the caller's
// strand if the design explicitly hops back. Use a strand-affinity counter rather than
// raw std::this_thread::get_id() comparisons - strands can be served by any pool thread.

TEST_F(FlowPin, UserCallbackFiresOnComponentStrand)
{
  // std::atomic<bool> calledOnStrand{false};
  // std::promise<Result<X>> done;
  //
  // mComponent-><flow>_async(/*args*/, [&](Result<X> r) {
  //   // Use the strand's running_in_this_thread() check (Asio strand contract).
  //   calledOnStrand = mStrand.running_in_this_thread();
  //   done.set_value(std::move(r));
  // });
  //
  // auto fut = done.get_future();
  // (void)wait_for_callback(fut);
  // EXPECT_TRUE(calledOnStrand)
  //     << "callback did not fire on the component's strand";
}

// =============================================================================
// Pin 6: Concurrent-on-strand semantics (service flows only).
// =============================================================================
//
// Applicable to service top-level flows that kick off N per-operation flows and
// aggregate. The current coroutine implementation runs each operation eagerly to its
// first await before starting the next; the post-flip implementation must preserve
// this. Sequential conversion ("op N+1 starts only after op N completes") is a
// silent throughput regression and the pin catches it.

TEST_F(FlowPin, OperationsKickOffEagerlyToFirstAwait)
{
  // // Configure the fake authorizer to count concurrent in-flight calls. Each
  // // call goes pending until the test releases it.
  // mFakeCollab->authorize_pending_count = 0;
  //
  // // Submit a request with N=3 items.
  // std::promise<<Response>Result> done;
  // mComponent->process_request(/*request with 3 items*/, [&](auto r) {
  //   done.set_value(std::move(r));
  // });
  //
  // // After kick-off, all 3 operations should be parked at the authorize step.
  // // Use a strand-posted poll loop to observe (do NOT sleep on the main thread
  // // and assume the work has run).
  // std::promise<int> observed;
  // boost::asio::post(mStrand.get_inner_executor(), [&]() {
  //   observed.set_value(mFakeCollab->authorize_pending_count.load());
  // });
  // auto fut = observed.get_future();
  // ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  // EXPECT_EQ(fut.get(), 3)
  //     << "operations did not interleave on the strand - flow has been silently serialised";
  //
  // // Release each authorizer call so the request completes cleanly.
  // mFakeCollab->complete_all_authorizers(/*ok*/);
  // auto reqFut = done.get_future();
  // (void)wait_for_callback(reqFut);
}

// =============================================================================
// Pin 7: Destructor-during-flight.
// =============================================================================
//
// Destroying the component while the flow is mid-flight must not UAF and must not
// dangle the user callback. Either the callback fires with a shutdown status, or it
// is dropped (both are acceptable; the design picks one
// per component, the pin asserts which).

TEST_F(FlowPin, DestructorDuringFlightFiresCallbackWithShutdownStatus)
{
  // mFakeCollab->set_<step>_pending();
  //
  // std::promise<Result<X>> done;
  // mComponent-><flow>_async(/*args*/,
  //   [&](Result<X> r) { done.set_value(std::move(r)); });
  //
  // // Drop the component while the flow is parked at <step>.
  // mComponent.reset();
  //
  // auto fut = done.get_future();
  // // Pick whichever the design specifies for this component:
  // //   (a) callback fires with BadShutdown:
  // auto result = wait_for_callback(fut);
  // EXPECT_EQ(result.status_code(), Status::BadShutdown);
  // //   (b) callback is dropped (future never readies; assert that):
  // // EXPECT_EQ(fut.wait_for(std::chrono::milliseconds(500)),
  // //           std::future_status::timeout);
}

// =============================================================================
// Pin 8 (optional): Wire-observable invariants.
// =============================================================================
//
// For flows that emit wire bytes (services, secure-channel encode/decode), capture
// the byte sequence and assert it is byte-identical pre- and post-flip. This is the
// strongest pin available and should be used wherever the flow's output is observable
// on the wire.

TEST_F(FlowPin, WireOutputIsByteIdenticalToReferenceCapture)
{
  // // 1. Run the flow with deterministic inputs.
  // // 2. Capture the bytes the fake transport observed in send_chunk().
  // // 3. Compare to a committed reference capture under
  // //    tests/behaviour_pins/phase_<...>/reference_captures/<name>.bin.
  // //
  // // Update the reference capture only when an authorised behaviour change lands;
  // // never as part of a flip PR.
}

}  // namespace ua::test::behaviour_pins
