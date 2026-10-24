// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::SessionMethodServices (the Method Service Set forwarder on a Session).
//
// Two groups live here:
//   * Absent-session guard tests. The Call method locks its weak_ptr<SessionImpl>; when the owning session
//     has been destroyed the guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling
//     pointer. Both the async and try_*_sync variants share the same guard, so both are exercised. A missing
//     guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
//     Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.
//   * Real-code-path Call tests. These drive Session::methods().call_async through a live SessionImpl over a
//     null-connection SecureChannel, capture the CallRequest the client actually sends, and inject synthetic
//     CallResponses to observe how per-operation results are surfaced. They pin the CL-METH-* wire and
//     consumer obligations against the forwarder that carries them.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"
#include "test_utilities.h"

#include "ua_session_method_services.h"

#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_node_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

using namespace ua;
using namespace ua::client;
using ua::client::guard_test::DeadSessionHarness;

TEST(SessionMethodServicesGuard, CallAsyncOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto methods = harness.live().methods();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  methods.call_async(CallRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionMethodServicesGuard, CallTrySyncOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto methods = harness.live().methods();
  ASSERT_TRUE(harness.kill());

  const auto result = methods.try_call_sync(CallRequest{});

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSessionIdInvalid});
}

// --- Real-code-path Call tests (capture harness) ---

namespace
{

using namespace std::chrono_literals;
using ua::client::test_capture::CaptureHarness;

/// Thread-safe sink for a Call outcome delivered on a pool worker thread.
struct CallOutcome
{
  std::mutex mx;
  std::condition_variable cv;
  int fireCount{0};
  bool good{false};
  ua::StatusCode status{ua::Status::Good};
  ua::CallResponse response;

  void set(ua::Result<ua::CallResponse> result)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      ++fireCount;
      good = result.is_good();
      status = result.status_code();
      if (good)
      {
        response = result.value();
      }
    }
    cv.notify_one();
  }

  bool wait(std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return fireCount > 0; });
  }
};

/// A CallRequest naming exactly one Method (object, method) with @p args as its positional input arguments.
ua::CallRequest make_call_request(ua::NodeId objectId, ua::NodeId methodId, std::vector<ua::Variant> args)
{
  ua::CallMethodRequest method;
  method.object_id() = std::move(objectId);
  method.method_id() = std::move(methodId);
  for (auto& arg : args)
  {
    method.input_arguments().push_back(std::move(arg));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));
  return request;
}

/// A service-level-good CallResponse carrying exactly one CallMethodResult.
std::shared_ptr<ua::CallResponse> make_call_response(ua::CallMethodResult result)
{
  auto response = std::make_shared<ua::CallResponse>();
  response->response_header().service_result() = ua::Status::Good;
  response->results().push_back(std::move(result));
  return response;
}

}  // namespace

// The Call service is the only Method invocation surface: call_async dispatches exactly one CallRequest that
// carries the requested Method, never zero (dropped) or many (duplicated), and no other request type.
// @verifies CL-METH-001
// @relation(CL-METH-001, scope=function)
TEST(SessionMethodServicesCall, CallDispatchesExactlyOneCallRequest)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request()) << "call_async must forward a request to the channel";
    auto calls = harness.all_captured<ua::CallRequest>();
    ASSERT_EQ(calls.size(), 1u) << "the Call service must dispatch exactly one CallRequest, not zero or many";
    ASSERT_EQ(calls[0].methods_to_call().size(), 1u);
    EXPECT_EQ(calls[0].methods_to_call()[0].method_id(), ua::NodeId(2, 20))
      << "the dispatched CallRequest must carry the requested Method as its only invocation surface";
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// objectId and methodId are context/target NodeIds that travel to the wire distinctly - the forwarder must
// not collapse them into one, swap them, or rewrite either.
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST(SessionMethodServicesCall, CallForwardsObjectAndMethodIdsDistinctly)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    const ua::NodeId objectId{2, 111};
    const ua::NodeId methodId{2, 222};
    methods.call_async(make_call_request(objectId, methodId, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto call = harness.first_captured<ua::CallRequest>();
    ASSERT_TRUE(call.has_value());
    ASSERT_EQ(call->methods_to_call().size(), 1u);
    EXPECT_EQ(call->methods_to_call()[0].object_id(), objectId)
      << "objectId must reach the wire verbatim (not collapsed onto methodId)";
    EXPECT_EQ(call->methods_to_call()[0].method_id(), methodId)
      << "methodId must reach the wire verbatim (not swapped with objectId)";
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// When the server reports Bad_MethodInvalid at the operation level (methodId is not a component of objectId),
// that per-operation StatusCode must reach the user in the CallMethodResult verbatim, not be dropped or
// coerced into the service-level status.
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST(SessionMethodServicesCall, CallSurfacesServerBadMethodInvalid)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    ua::CallMethodResult result;
    result.status_code() = ua::Status::BadMethodInvalid;
    ASSERT_TRUE(harness.inject_channel_response(make_call_response(std::move(result))));

    ASSERT_TRUE(sink->wait());
    EXPECT_TRUE(sink->good) << "a service-level-good CallResponse must surface as a good Result";
    ASSERT_EQ(sink->response.results().size(), 1u);
    EXPECT_EQ(sink->response.results()[0].status_code(), ua::StatusCode{ua::Status::BadMethodInvalid})
      << "the per-operation Bad_MethodInvalid must reach the user verbatim";
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// inputArguments are positional: the client must send them in the same order the caller supplied, with no
// reordering or normalization.
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST(SessionMethodServicesCall, CallPreservesInputArgumentOrderOnWire)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    std::vector<ua::Variant> args;
    args.emplace_back(uint32_t{11});
    args.emplace_back(uint32_t{22});
    args.emplace_back(uint32_t{33});
    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, std::move(args)),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto call = harness.first_captured<ua::CallRequest>();
    ASSERT_TRUE(call.has_value());
    const auto& wireArgs = call->methods_to_call()[0].input_arguments();
    ASSERT_EQ(wireArgs.size(), 3u);
    EXPECT_EQ(wireArgs[0], ua::Variant{uint32_t{11}}) << "argument order must be preserved on the wire";
    EXPECT_EQ(wireArgs[1], ua::Variant{uint32_t{22}});
    EXPECT_EQ(wireArgs[2], ua::Variant{uint32_t{33}});
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// An empty argument list must travel as a zero-length array - not padded, and not omitted.
// @verifies CL-METH-003
// @relation(CL-METH-003, scope=function)
TEST(SessionMethodServicesCall, CallEmptyInputArgumentsStayZeroLength)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto call = harness.first_captured<ua::CallRequest>();
    ASSERT_TRUE(call.has_value());
    ASSERT_EQ(call->methods_to_call().size(), 1u);
    EXPECT_EQ(call->methods_to_call()[0].input_arguments().size(), 0u)
      << "an empty input list must travel as a zero-length array, not be padded or omitted";
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A Method invocation always returns: the pending Call resolves exactly once when its response arrives
// (1:1 request-to-response pairing). A second response has no parked entry left to resolve.
// @verifies CL-METH-004
// @relation(CL-METH-004, scope=function)
TEST(SessionMethodServicesCall, CallResolvesExactlyOnceOnResponse)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    ua::CallMethodResult result;
    result.status_code() = ua::Status::Good;
    ASSERT_TRUE(harness.inject_channel_response(make_call_response(std::move(result))));

    ASSERT_TRUE(sink->wait()) << "the pending Call must resolve when its response arrives";
    EXPECT_TRUE(sink->good);
    // The pairing consumed the parked entry: a second response has nothing left to resolve.
    EXPECT_FALSE(harness.inject_channel_response(make_call_response(ua::CallMethodResult{})))
      << "the response must resolve the pending Call exactly once, leaving no parked entry";
    {
      std::lock_guard<std::mutex> lk(sink->mx);
      EXPECT_EQ(sink->fireCount, 1) << "the Call callback must fire exactly once";
    }
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A pending Call is bounded by channel teardown: when the channel drops while the Call is in flight, the
// pending Call must still return (with a bad status) rather than hang forever.
// @verifies CL-METH-004
// @relation(CL-METH-004, scope=function)
TEST(SessionMethodServicesCall, CallPendingFailsOnChannelTeardown)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, {}),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    // Tear the channel down while the Call is in flight.
    ua::client::SessionTestAccess::on_strand(
      *harness.session, [](auto& guard) { guard.inject_channel_error(ua::Status::BadConnectionClosed); });

    ASSERT_TRUE(sink->wait()) << "a pending Call must resolve (not hang) when the channel is torn down";
    EXPECT_TRUE(sink->status.is_bad()) << "channel teardown must fail the pending Call with a bad status";
    EXPECT_EQ(sink->status, ua::StatusCode{ua::Status::BadConnectionClosed});
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// NOTE (2026-07-14): CL-METH-005 (per-argument inputArgumentResults) and CL-METH-006 (drop
// outputArguments when the op status Severity is Bad) are NOT unit-coverable on this tier-1
// call_async path. That path is a wholesale struct-move forwarder with no per-argument or
// severity-conditional logic, so any test here is "assert-what-you-injected" (non-falsifiable) -
// the adversarial verify pass correctly rejected the three attempts. Per the requirement design,
// these obligations live on the tier-2 CallResult surface; cover them there (or via a
// MisbehavingServer integration row), not with a false citation here.

// A ByteString input argument must reach the wire as a ByteString - the client must not silently widen it to
// an array of Byte (no lossy ByteString <-> Byte[] coercion at the Variant boundary).
// @verifies CL-METH-008
// @relation(CL-METH-008, scope=function)
TEST(SessionMethodServicesCall, CallPassesByteStringArgVerbatim)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    std::vector<ua::Variant> args;
    args.emplace_back(ua::ByteString{0x01, 0x02, 0x03});
    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, std::move(args)),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto call = harness.first_captured<ua::CallRequest>();
    ASSERT_TRUE(call.has_value());
    ASSERT_EQ(call->methods_to_call()[0].input_arguments().size(), 1u);
    const auto& arg = call->methods_to_call()[0].input_arguments()[0];
    EXPECT_EQ(arg.get_built_in_type(), ua::BuiltInTypeId::ByteString)
      << "a ByteString argument must not be silently widened to an array of Byte";
    EXPECT_TRUE(arg.is_byte_string());
    EXPECT_FALSE(arg.is_array_of_uint8()) << "no lossy ByteString -> Byte[] coercion may occur";
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// When trailing optional arguments are omitted, the client forwards the short argument list verbatim: it must
// not null-pad the array up to the Method's declared length. Here a caller supplies only the two mandatory
// arguments of a notionally three-argument (one optional) Method.
// @verifies CL-METH-009
// @relation(CL-METH-009, scope=function)
TEST(SessionMethodServicesCall, CallForwardsShortArgumentListWithoutPadding)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto sessionHandle = harness.session_handle();
    auto methods = sessionHandle.methods();
    auto sink = std::make_shared<CallOutcome>();

    std::vector<ua::Variant> args;
    args.emplace_back(uint32_t{1});
    args.emplace_back(uint32_t{2});
    methods.call_async(make_call_request(ua::NodeId{2, 10}, ua::NodeId{2, 20}, std::move(args)),
      [sink](ua::Result<ua::CallResponse> result) { sink->set(std::move(result)); });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto call = harness.first_captured<ua::CallRequest>();
    ASSERT_TRUE(call.has_value());
    const auto& wireArgs = call->methods_to_call()[0].input_arguments();
    ASSERT_EQ(wireArgs.size(), 2u) << "a short argument list must not be null-padded to the declared length";
    EXPECT_EQ(wireArgs[0], ua::Variant{uint32_t{1}}) << "the supplied args must travel unchanged (no filler)";
    EXPECT_EQ(wireArgs[1], ua::Variant{uint32_t{2}});
  }
  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
