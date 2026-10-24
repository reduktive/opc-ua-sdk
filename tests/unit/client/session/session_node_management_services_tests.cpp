// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionNodeManagementServices (NodeManagement Service Set
// forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. A missing
// guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
// Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "session_service_guard_fixture.h"

#include "ua_session_node_management_services.h"

using namespace ua;
using namespace ua::client;
using ua::client::guard_test::DeadSessionHarness;

TEST(SessionNodeManagementServicesGuard, AddNodesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto nodes = harness.live().node_management();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  nodes.add_nodes_async(AddNodesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionNodeManagementServicesGuard, AddReferencesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto nodes = harness.live().node_management();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  nodes.add_references_async(AddReferencesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionNodeManagementServicesGuard, DeleteNodesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto nodes = harness.live().node_management();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  nodes.delete_nodes_async(DeleteNodesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionNodeManagementServicesGuard, DeleteReferencesOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto nodes = harness.live().node_management();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  nodes.delete_references_async(DeleteReferencesRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}
