// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionDiscoveryServices (Discovery Service Set forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. A missing
// guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
// Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"
#include "test_utilities.h"

#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_session_discovery_services.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;
using ua::client::guard_test::DeadSessionHarness;
using ua::client::test_capture::CaptureHarness;

TEST(SessionDiscoveryServicesGuard, GetEndpointsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto discovery = harness.live().discovery();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  discovery.get_endpoints_async(GetEndpointsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionDiscoveryServicesGuard, FindServersOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto discovery = harness.live().discovery();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  discovery.find_servers_async(FindServersRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionDiscoveryServicesGuard, FindServersOnNetworkOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto discovery = harness.live().discovery();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  discovery.find_servers_on_network_async(FindServersOnNetworkRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionDiscoveryServicesGuard, RegisterServerOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto discovery = harness.live().discovery();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  discovery.register_server_async(RegisterServerRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionDiscoveryServicesGuard, RegisterServer2OnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto discovery = harness.live().discovery();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  discovery.register_server2_async(RegisterServer2Request{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

// --- Real-send-path forwarding tests (CL-DISC-007, CL-DISC-008) -----------------------------------
//
// These drive the tier-0 SessionDiscoveryServices forwarder over a live-but-null-connection Session
// (SessionImpl -> SecureChannel) using the shared capture harness. The harness installs an outgoing-
// request observer on the SecureChannel, so a test can decode exactly what the client sent, and lets a
// test resolve the parked request with a synthetic response. This exercises the real forwarding +
// send + response-decode code path rather than any hand-rolled request.

namespace
{

// Resolve the oldest parked channel request with a service-level failure, exactly as a per-request
// ServiceFault or timeout would surface it. This delivers a bad ServiceResponseResult to the single
// pending request WITHOUT signalling a channel-down event, so the session stays Active and a later
// discovery call can still be issued (send_request delivers the per-request result and does not
// transition session state on a bad response).
bool fail_oldest_pending(CaptureHarness& harness, Status status)
{
  return SecureChannelTestAccess::on_strand(*harness.channel,
    [status](auto& guard) -> bool
    {
      auto& pending = guard.pending_requests();
      if (pending.empty())
      {
        return false;
      }
      auto it = pending.begin();
      auto callback = std::move(it->second);
      pending.erase(it);
      callback(SecureChannelImpl::ServiceResponseResult{status});
      return true;
    });
}

// Drive one complete FindServers round-trip (send + good empty response) and report whether the
// caller callback surfaced a good Result.
bool find_servers_round_trip(CaptureHarness& harness)
{
  auto discovery = harness.session_handle().discovery();

  std::mutex mx;
  std::condition_variable cv;
  bool fired = false;
  bool good = false;
  discovery.find_servers_async(FindServersRequest{},
    [&](Result<FindServersResponse> result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        good = result.is_good();
        cv.notify_one();
      }
    });

  if (!harness.wait_for_pending_request())
  {
    return false;
  }
  auto response = std::make_shared<FindServersResponse>();
  response->response_header().service_result() = Status::Good;
  if (!harness.inject_channel_response(std::move(response)))
  {
    return false;
  }
  std::unique_lock<std::mutex> lk(mx);
  cv.wait_for(lk, 1000ms, [&]() { return fired; });
  return good;
}

// Drive one complete GetEndpoints round-trip (send + good response) and report success.
bool get_endpoints_round_trip(CaptureHarness& harness)
{
  auto discovery = harness.session_handle().discovery();

  std::mutex mx;
  std::condition_variable cv;
  bool fired = false;
  bool good = false;
  discovery.get_endpoints_async(GetEndpointsRequest{},
    [&](Result<GetEndpointsResponse> result)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        fired = true;
        good = result.is_good();
        cv.notify_one();
      }
    });

  if (!harness.wait_for_pending_request())
  {
    return false;
  }
  auto response = std::make_shared<GetEndpointsResponse>();
  response->response_header().service_result() = Status::Good;
  if (!harness.inject_channel_response(std::move(response)))
  {
    return false;
  }
  std::unique_lock<std::mutex> lk(mx);
  cv.wait_for(lk, 1000ms, [&]() { return fired; });
  return good;
}

}  // namespace

// CL-DISC-008 realises the "Client may supply serverUris filter" obligation: the caller-supplied
// serverUris must reach the wire verbatim. Driving find_servers_async and decoding the captured
// outgoing request proves the forwarder carries the filter unmodified through the real send path.
// Falsifies if the forwarder drops, rewrites, or fails to transmit serverUris.
// @verifies CL-DISC-008
// @relation(CL-DISC-008, scope=function)
TEST(SessionDiscoveryServices, FindServersForwardsCallerServerUrisFilterToWire)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto discovery = harness.session_handle().discovery();

    FindServersRequest request;
    request.server_uris().payload().push_back(String{"urn:A"});
    request.server_uris().payload().push_back(String{"urn:B"});

    std::mutex mx;
    std::condition_variable cv;
    bool fired = false;
    discovery.find_servers_async(std::move(request),
      [&](Result<FindServersResponse>)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          cv.notify_one();
        }
      });

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "find_servers must forward a FindServersRequest down the real send path";
    auto captured = harness.first_captured<FindServersRequest>();
    ASSERT_TRUE(captured.has_value())
      << "the FindServersRequest must travel the real Session -> SecureChannel path";
    ASSERT_EQ(captured->server_uris().payload().size(), 2u)
      << "the caller-supplied serverUris filter must reach the wire unmodified";
    EXPECT_EQ(captured->server_uris().payload()[0], String{"urn:A"});
    EXPECT_EQ(captured->server_uris().payload()[1], String{"urn:B"});

    auto response = std::make_shared<FindServersResponse>();
    response->response_header().service_result() = Status::Good;
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-DISC-008 realises the "shall handle empty result" obligation: a FindServers response with
// serviceResult=Good and an empty servers[] is a valid outcome, not an error. Falsifies if the client
// ever maps an empty (but Good) server list to a bad Result.
// @verifies CL-DISC-008
// @relation(CL-DISC-008, scope=function)
TEST(SessionDiscoveryServices, FindServersEmptyServerListWithGoodStatusIsNotAnError)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto discovery = harness.session_handle().discovery();

    std::mutex mx;
    std::condition_variable cv;
    bool fired = false;
    bool good = false;
    std::size_t serverCount = 999;
    discovery.find_servers_async(FindServersRequest{},
      [&](Result<FindServersResponse> result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          good = result.is_good();
          if (result.is_good())
          {
            serverCount = result.value().servers().payload().size();
          }
          cv.notify_one();
        }
      });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto response = std::make_shared<FindServersResponse>();
    response->response_header().service_result() = Status::Good;  // Good status, empty servers[]
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    EXPECT_TRUE(good) << "an empty server list with a Good serviceResult must surface a good Result";
    EXPECT_EQ(serverCount, 0u);
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-DISC-008: an empty serverUris means "return all known Servers"; the SDK must not substitute a
// default filter of its own. Falsifies if the forwarder injects any serverUris entry when the caller
// supplied none.
// @verifies CL-DISC-008
// @relation(CL-DISC-008, scope=function)
TEST(SessionDiscoveryServices, FindServersDefaultRequestCarriesNoServerUrisFilter)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto discovery = harness.session_handle().discovery();

    std::mutex mx;
    std::condition_variable cv;
    bool fired = false;
    discovery.find_servers_async(FindServersRequest{},
      [&](Result<FindServersResponse>)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          cv.notify_one();
        }
      });

    ASSERT_TRUE(harness.wait_for_pending_request());
    auto captured = harness.first_captured<FindServersRequest>();
    ASSERT_TRUE(captured.has_value());
    EXPECT_TRUE(captured->server_uris().payload().empty())
      << "an unfiltered FindServers call must not inject a default serverUris filter";

    auto response = std::make_shared<FindServersResponse>();
    response->response_header().service_result() = Status::Good;
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-DISC-007: discovery is repeatable. The SDK must not impose per-call state (a one-shot latch or
// memoised cache) that prevents a second find_servers call from running. Two identical calls each
// reach the wire independently. Falsifies if a cache/latch suppresses the second request.
// @verifies CL-DISC-007
// @relation(CL-DISC-007, scope=function)
TEST(SessionDiscoveryServices, FindServersIsRepeatableAcrossCalls)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    EXPECT_TRUE(find_servers_round_trip(harness)) << "first find_servers call must succeed";
    EXPECT_TRUE(find_servers_round_trip(harness)) << "second find_servers call must succeed";

    EXPECT_EQ(harness.all_captured<FindServersRequest>().size(), 2u)
      << "each find_servers call must send its own request (no memoised short-circuit)";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-DISC-007: a prior discovery failure must not poison later calls. After the first find_servers
// fails, a second call still succeeds. Falsifies if the SDK latches a sticky error that blocks
// re-invocation after a failed discovery attempt.
// @verifies CL-DISC-007
// @relation(CL-DISC-007, scope=function)
TEST(SessionDiscoveryServices, FindServersSecondCallAfterFirstFailureSucceeds)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    auto discovery = harness.session_handle().discovery();

    std::mutex mx;
    std::condition_variable cv;
    bool fired = false;
    bool firstGood = true;
    discovery.find_servers_async(FindServersRequest{},
      [&](Result<FindServersResponse> result)
      {
        {
          std::lock_guard<std::mutex> lk(mx);
          fired = true;
          firstGood = result.is_good();
          cv.notify_one();
        }
      });

    ASSERT_TRUE(harness.wait_for_pending_request());
    ASSERT_TRUE(fail_oldest_pending(harness, Status::BadInternalError));
    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return fired; }));
    }
    ASSERT_FALSE(firstGood) << "the first call must surface the injected failure";

    // The second call must not be blocked by any sticky error state left by the first.
    EXPECT_TRUE(find_servers_round_trip(harness))
      << "a discovery call after a prior failure must succeed (no sticky error state)";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-DISC-007: GetEndpoints is likewise repeatable (the requirement names both find_servers and
// get_endpoints). Two calls each reach the wire independently. Falsifies if a per-call cache/latch
// suppresses the second GetEndpoints request.
// @verifies CL-DISC-007
// @relation(CL-DISC-007, scope=function)
TEST(SessionDiscoveryServices, GetEndpointsIsRepeatableAcrossCalls)
{
  boost::asio::thread_pool tp;
  auto harness = CaptureHarness::create_active(tp.get_executor());
  {
    EXPECT_TRUE(get_endpoints_round_trip(harness)) << "first get_endpoints call must succeed";
    EXPECT_TRUE(get_endpoints_round_trip(harness)) << "second get_endpoints call must succeed";

    EXPECT_EQ(harness.all_captured<GetEndpointsRequest>().size(), 2u)
      << "each get_endpoints call must send its own request (no memoised short-circuit)";
  }

  harness.cleanup_sync();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
