// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5d - AttributeServiceSet (Read flow).
//
//
// Coverage (compact corpus targeting the synchronous header/pre-validation
// gates of the Read pipeline - properties that are observable through the
// existing fixture infrastructure without standing up FakeAsyncReadDelegate
// from runbook section 4.0.1):
//
//   RH-A ReadServiceRejectsEmptyNodesToReadWithBadNothingToDo
//   RH-B ReadServiceRejectsNegativeMaxAgeWithBadMaxAgeInvalid
//   RH-C ReadServiceRejectsTimestampsToReturnInvalidWithBadTimestampsToReturnInvalid
//   RH-D ReadServiceRejectsOperationCountExceedingLimitWithBadTooManyOperations
//   RP-AFF ReadServiceUserCallbackFiresOnServiceStrand
//   DISABLED_ReadServiceDestructorDuringFlightFiresShutdownCallback (D1, expected-fail
//     until matching {b} flip restructures lifetime to weak_from_this with
//     explicit destructor BadShutdown emission)
//
// Scope notes:
//   * Per-batch namespace-resolution pins (RB-A..G), per-attribute pins
//     (RP-A..R), correspondence pins (RP-CORR), concurrent-on-strand pin
//     (RP-CONC), and stack-protection pin (RB-TRAMP) are deferred - they require
//     an async address-space fake firing from a dedicated worker thread plus a
//     configurable authorizer. The shared fixture
//     (`attribute_service_pin_fixture.h/.cpp`) is in place and ready for that
//     extended corpus.
//   * The per-namespace Read/Write override delegates were removed in the interface
//     refactor - every namespace now resolves through the single authorized
//     default path (invariant I2), so there is no delegate-merge branch left to
//     pin. Default-path resolution, authorization and cancellation are covered
//     by batch_resolve_tests.cpp and read_service_default_path_tests.cpp.

#include <chrono>
#include <future>

#include <gtest/gtest.h>

#include "ua_diagnostic_bits.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_service_fault.h"
#include "ua_timestamps_to_return.h"

#include "attribute_service_pin_fixture.h"
#include "fake_namespace.h"
#include "ua_attribute_id.h"
#include "ua_namespace_array.h"

namespace ua::test::behaviour_pins::attribute
{
namespace
{

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// RH-A - Empty nodes_to_read yields ServiceFault.BadNothingToDo with detail.
//        Falsifiable bug: a {b} flip that drops the empty-list check at
//        ua_attribute_service_set.cpp:539-542.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceRejectsEmptyNodesToReadWithBadNothingToDo)
{
  ::ua::ReadRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Both;
  // nodes_to_read() left empty.

  auto resp = dispatch_read_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for empty nodes_to_read";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadNothingToDo);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value())
    << "service-level detail must propagate";
}

// ---------------------------------------------------------------------------
// RH-B - Negative max_age yields ServiceFault.BadMaxAgeInvalid with detail.
//        Falsifiable bug: a {b} flip that drops the max_age sign check at
//        ua_attribute_service_set.cpp:546-548.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceRejectsNegativeMaxAgeWithBadMaxAgeInvalid)
{
  ::ua::ReadRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Both;
  req.max_age() = ::ua::Duration{-1.0};
  req.nodes_to_read().resize(1);
  req.nodes_to_read()[0].node_id() = ::ua::NodeId{0u, 0u};
  req.nodes_to_read()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);

  auto resp = dispatch_read_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for negative max_age";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadMaxAgeInvalid);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// RH-C - TimestampsToReturn::Invalid yields ServiceFault.BadTimestampsToReturnInvalid.
//        Falsifiable bug: a {b} flip that drops the timestamps_to_return check
//        at ua_attribute_service_set.cpp:551-554.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceRejectsTimestampsToReturnInvalidWithBadTimestampsToReturnInvalid)
{
  ::ua::ReadRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Invalid;
  req.nodes_to_read().resize(1);
  req.nodes_to_read()[0].node_id() = ::ua::NodeId{0u, 0u};
  req.nodes_to_read()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);

  auto resp = dispatch_read_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for invalid timestamps_to_return";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTimestampsToReturnInvalid);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// RH-D - Operation count exceeds mMaxNodesPerRead -> ServiceFault.BadTooManyOperations.
//        Falsifiable bug: a {b} flip that drops the limits check at
//        ua_attribute_service_set.cpp:561-564.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceRejectsOperationCountExceedingLimitWithBadTooManyOperations)
{
  mSession->server_cfg().server_capabilities().operationLimits.maxNodesPerRead = 1;

  ::ua::ReadRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Both;
  req.nodes_to_read().resize(2);
  req.nodes_to_read()[0].node_id() = ::ua::NodeId{0u, 0u};
  req.nodes_to_read()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);
  req.nodes_to_read()[1].node_id() = ::ua::NodeId{0u, 1u};
  req.nodes_to_read()[1].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);

  auto resp = dispatch_read_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for over-limit nodes_to_read";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTooManyOperations);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// RP-AFF - User callback fires on the service strand pool thread (1-thread
//          pool means strand worker IS the pool worker). Falsifiable bug: a
//          {b} flip that fires the callback inline on the cancel/timeout path.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceUserCallbackFiresOnServiceStrand)
{
  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  ::ua::ReadRequest req;
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Both;
  // Empty nodes_to_read drives the synchronous BadNothingToDo path.

  auto svc = ::ua::server::AttributeServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(req),
    mExecutor,
    [&p](::ua::Response) { p.set_value(std::this_thread::get_id()); });
  (void)svc;

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto cbThread = fut.get();
  EXPECT_NE(cbThread, mMainThreadId) << "callback must not fire on the test main thread";
}

// ---------------------------------------------------------------------------
// D1 - destructor during in-flight Read fires BadShutdown.
//
// Authored against the {b} flip's restructured lifetime: weak_from_this everywhere,
// per-flow structs allocated on the strand, ~AttributeServiceSet gated by try_finish().
// Parks find_node_async on a FakeNamespace, waits for the
// parked count > 0, then drops the service's last shared_ptr. The destructor observes
// the per-op flow is still in flight, calls try_finish() (returns true), and fires
// Status::BadShutdown.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, ReadServiceDestructorDuringFlightFiresShutdownCallback)
{
  auto fakeNs = ::ua::test_helpers::FakeNamespace::create("urn:test:read-fake-ns");
  const uint16_t fakeIdx = mSession->address_space().add_namespace_sync(fakeNs);

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();

  ::ua::ReadRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.timestamps_to_return() = ::ua::TimestampsToReturn::Both;
  req.nodes_to_read().resize(1);
  req.nodes_to_read()[0].node_id() = ::ua::NodeId{fakeIdx, 1u};
  req.nodes_to_read()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);

  auto svc = ::ua::server::AttributeServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(req),
    mExecutor,
    [&p](::ua::Response r)
    {
      ::ua::StatusCode sc{::ua::Status::Good};
      if (auto* fault = dynamic_cast<::ua::ServiceFault*>(r.second.get()))
        sc = fault->response_header().service_result();
      p.set_value(sc);
    });

  for (int i = 0; i < 200 && fakeNs->pending_find_node_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_GE(fakeNs->pending_find_node_count(), 1u)
    << "expected find_node_async to be parked before destruction";

  svc.reset();

  ASSERT_EQ(fut.wait_for(500ms), std::future_status::ready)
    << "destructor must drive the user callback with BadShutdown";
  EXPECT_EQ(fut.get(), ::ua::Status::BadShutdown);
}

}  // namespace
}  // namespace ua::test::behaviour_pins::attribute
