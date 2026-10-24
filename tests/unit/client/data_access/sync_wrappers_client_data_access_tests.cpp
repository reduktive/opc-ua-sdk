// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 DataAccess facade's blocking wrappers (`*_sync` / `try_*_sync`).
//
// The facade shipped async-only, so every operation gained a promise/future bridge over its existing
// async entry point. These tests cover what a bridge can get wrong: returning the wrong Result,
// losing the status and ErrorDetail of a failure, throwing from the non-throwing form, failing to
// throw from the throwing form, and - the realistic defect in twenty-one mechanically written
// wrappers - arming a sibling's async instead of its own.
//
// The io_context is pumped by a worker thread, because that is the wrappers' contract: they block
// the calling thread until the completion runs, so the thread that runs the completion cannot be the
// one that is waiting. A fixture pumping from the test thread would hang, which is precisely the
// misuse each wrapper's documentation warns about.
//
// Falsifiability: a wrapper that drops the failure Result fails the *Failure* tests; one whose
// throwing form does not throw fails the *Throws* tests; one wired to the wrong async fails
// ResolversAreWiredToTheirOwnAsync, which leans on the fact that base_analog accepts a node carrying
// none of the analog Properties while analog_item, analog_unit and analog_unit_range all reject it.

#include "ua_data_access.h"

#include "fake_connection_ops.h"

#include "ua_data_access_state.h"
#include "ua_data_access_test_access.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

namespace
{

using ua::client::AnalogItemHandle;
using ua::client::DataAccessAccessor;
using ua::client::detail::DataAccessClientTestAccess;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{std::uint16_t{1}, identifier};
}

// Runs the io_context on a worker thread for the lifetime of the test, so a blocking wrapper called
// from the test thread has something to complete it.
struct SyncFixture : ::testing::Test
{
  boost::asio::io_context ctx;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard{ctx.get_executor()};
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();
  std::thread worker{[this]
    {
      ctx.run();
    }};

  DataAccessAccessor accessor()
  {
    return DataAccessClientTestAccess::make_accessor(wireOps, supportOps, ctx.get_executor());
  }

  ~SyncFixture() override
  {
    guard.reset();
    ctx.stop();
    if (worker.joinable())
    {
      worker.join();
    }
  }
};

// ===========================================================================
// The bridge itself: a result comes back, and it is the async operation's own
// ===========================================================================

// A node that exposes none of the analog Properties resolves as a BaseAnalogType, so this is the
// success path through the bridge: a real handle, returned to a blocked caller.
TEST_F(SyncFixture, TryResolveSyncReturnsTheHandleTheAsyncOperationProduced)
{
  const ua::Result<AnalogItemHandle> resolved = accessor().try_base_analog_sync(node(1));

  ASSERT_TRUE(resolved.is_good()) << ua::to_string(resolved.status_code());
  EXPECT_EQ(resolved.value().node_id(), node(1));
}

// The throwing form is `try_*_sync(...).value()`, so it must return the same handle rather than a
// default-constructed one.
TEST_F(SyncFixture, ResolveSyncReturnsTheHandleOnSuccess)
{
  AnalogItemHandle handle = accessor().base_analog_sync(node(2));

  EXPECT_EQ(handle.node_id(), node(2));
}

// AnalogItemType mandates EURange, which this node does not carry, so the async operation fails.
// The bridge must surface that failure verbatim rather than swallowing it or hanging.
TEST_F(SyncFixture, TryResolveSyncSurfacesTheAsyncFailure)
{
  const ua::Result<AnalogItemHandle> resolved = accessor().try_analog_item_sync(node(3));

  EXPECT_FALSE(resolved.is_good());
  EXPECT_TRUE(resolved.status_code().shared_detail())
    << "the failure reached the caller without the detail that explains it";
}

// The non-throwing form is noexcept: the same failure must arrive as a Result, never as an exception.
TEST_F(SyncFixture, TryResolveSyncDoesNotThrowOnFailure)
{
  EXPECT_NO_THROW({ (void)accessor().try_analog_item_sync(node(4)); });
}

// And the throwing form must actually throw, carrying the status the async operation reported.
TEST_F(SyncFixture, ResolveSyncThrowsOnFailure)
{
  const ua::StatusCode expected = accessor().try_analog_item_sync(node(5)).status_code();
  ASSERT_FALSE(expected.is_good());

  try
  {
    (void)accessor().analog_item_sync(node(5));
    FAIL() << "analog_item_sync returned a handle for a node that cannot resolve as an AnalogItemType";
  }
  catch (const ua::UaException& failure)
  {
    EXPECT_EQ(failure.status_code().as_status(), expected.as_status());
  }
}

// The defect a mechanically written family of wrappers actually has: one of them forwarding to a
// sibling's async. base_analog accepts a node with no analog Properties; analog_item, analog_unit
// and analog_unit_range each mandate a Property it does not carry. A wrapper wired to the wrong
// async therefore lands on the wrong side of this split.
TEST_F(SyncFixture, ResolversAreWiredToTheirOwnAsync)
{
  EXPECT_TRUE(accessor().try_base_analog_sync(node(10)).is_good())
    << "base_analog requires no Property, so it must accept this node";
  EXPECT_FALSE(accessor().try_analog_item_sync(node(10)).is_good())
    << "analog_item mandates EURange, so it must reject this node";
  EXPECT_FALSE(accessor().try_analog_unit_sync(node(10)).is_good())
    << "analog_unit mandates EngineeringUnits, so it must reject this node";
  EXPECT_FALSE(accessor().try_analog_unit_range_sync(node(10)).is_good())
    << "analog_unit_range mandates both, so it must reject this node";
}

// Every resolver must complete rather than hang, whatever it decides. A wrapper that never arms its
// async, or arms it twice, shows up here as a timeout rather than a failure, which is why the whole
// family is driven once.
TEST_F(SyncFixture, EveryResolverCompletes)
{
  DataAccessAccessor da = accessor();

  EXPECT_NO_THROW({
    (void)da.try_analog_item_sync(node(20));
    (void)da.try_base_analog_sync(node(20));
    (void)da.try_analog_unit_sync(node(20));
    (void)da.try_analog_unit_range_sync(node(20));
    (void)da.try_two_state_discrete_sync(node(20));
    (void)da.try_multi_state_discrete_sync(node(20));
    (void)da.try_multi_state_value_discrete_sync(node(20));
    (void)da.try_multi_state_dictionary_entry_sync(node(20));
  });
}

// ===========================================================================
// Handle operations
// ===========================================================================

// A handle's read is the same bridge over a different async, and it carries a value type rather than
// a handle, so it is covered on its own.
TEST_F(SyncFixture, HandleReadSyncCompletesThroughTheBridge)
{
  AnalogItemHandle handle = accessor().base_analog_sync(node(30));

  EXPECT_NO_THROW({ (void)handle.try_read_sync(); });
}

// A void-completing operation goes through the VoidResult overload of the bridge, which is a
// separate instantiation and can be wired wrongly on its own.
TEST_F(SyncFixture, HandleWriteSyncSurfacesTheScriptedOutcome)
{
  AnalogItemHandle handle = accessor().base_analog_sync(node(31));
  wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::BadUserAccessDenied});

  const ua::VoidResult written = handle.try_write_value_sync(ua::Variant{42.0});

  EXPECT_FALSE(written.is_good());
  EXPECT_EQ(written.status_code().as_status(), ua::Status::BadUserAccessDenied);
}

// refresh_properties re-runs the Property pre-flight rather than touching the Value, so it is a
// third shape and gets its own case.
TEST_F(SyncFixture, HandleRefreshPropertiesSyncCompletesThroughTheBridge)
{
  AnalogItemHandle handle = accessor().base_analog_sync(node(32));

  EXPECT_NO_THROW({ (void)handle.try_refresh_properties_sync(); });
}

}  // namespace
