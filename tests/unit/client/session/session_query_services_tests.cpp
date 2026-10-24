// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionQueryServices (Query Service Set forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. A missing
// guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
// Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "session_service_guard_fixture.h"

#include "ua_session_query_services.h"

using namespace ua;
using namespace ua::client;
using ua::client::guard_test::DeadSessionHarness;

TEST(SessionQueryServicesGuard, QueryFirstOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto query = harness.live().query();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  query.query_first_async(QueryFirstRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionQueryServicesGuard, QueryNextOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto query = harness.live().query();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  query.query_next_async(QueryNextRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}
