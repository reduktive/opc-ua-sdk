// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5d - AttributeServiceSet (Write flow).
//
//
// Coverage (compact corpus targeting top-level synchronous gates of the Write
// pipeline; deeper coverage deferred per the read-side scope-note above):
//
//   WH-A WriteServiceRejectsEmptyNodesToWriteWithBadNothingToDo
//   WH-B WriteServiceRejectsOperationCountExceedingLimitWithBadTooManyOperations
//   DISABLED_WriteServiceDestructorDuringFlightFiresShutdownCallback (D1)

#include <chrono>
#include <future>

#include <gtest/gtest.h>

#include "ua_diagnostic_bits.h"
#include "ua_service_fault.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

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
// WH-A - Empty nodes_to_write yields ServiceFault.BadNothingToDo with detail.
//        Falsifiable bug: a {b} flip that drops the empty-list check at
//        ua_attribute_service_set.cpp:1264-1266.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, WriteServiceRejectsEmptyNodesToWriteWithBadNothingToDo)
{
  ::ua::WriteRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  // nodes_to_write() left empty.

  auto resp = dispatch_write_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for empty nodes_to_write";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadNothingToDo);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// WH-B - Operation count exceeds maxNodesPerWrite -> ServiceFault.BadTooManyOperations.
//        Falsifiable bug: a {b} flip that drops the limits check at
//        ua_attribute_service_set.cpp:1273-1276.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, WriteServiceRejectsOperationCountExceedingLimitWithBadTooManyOperations)
{
  mSession->server_cfg().server_capabilities().operationLimits.maxNodesPerWrite = 1;

  ::ua::WriteRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.nodes_to_write().resize(2);
  req.nodes_to_write()[0].node_id() = ::ua::NodeId{0u, 0u};
  req.nodes_to_write()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);
  req.nodes_to_write()[1].node_id() = ::ua::NodeId{0u, 1u};
  req.nodes_to_write()[1].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);

  auto resp = dispatch_write_raw(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for over-limit nodes_to_write";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTooManyOperations);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// D1 - destructor during in-flight Write fires BadShutdown.
//
// Symmetric to the read-side pin. Parks find_node_async on a FakeNamespace, waits
// for the parked count > 0, then drops the service's last shared_ptr.
// ---------------------------------------------------------------------------
TEST_F(AttributeServicePin, WriteServiceDestructorDuringFlightFiresShutdownCallback)
{
  auto fakeNs = ::ua::test_helpers::FakeNamespace::create("urn:test:write-fake-ns");
  const uint16_t fakeIdx = mSession->address_space().add_namespace_sync(fakeNs);

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();

  ::ua::WriteRequest req;
  req.request_header().return_diagnostics() = full_diagnostics_mask();
  req.nodes_to_write().resize(1);
  req.nodes_to_write()[0].node_id() = ::ua::NodeId{fakeIdx, 1u};
  req.nodes_to_write()[0].attribute_id() = ::ua::utils::to_underlying(::ua::AttributeId::Value);
  req.nodes_to_write()[0].value().value() = ::ua::Variant{int32_t{42}};

  auto svc = ::ua::server::AttributeServiceSet::create(mSession,
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
