// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5b - DiscoveryServiceSet<FindServersOnNetworkRequest> flow.
//
//
// AMENDED (server-as-LDS landing): FindServersOnNetwork is no longer a silent no-op. Per
// SVR-DISC-LDS-007 (Part 4 section 5.4.3.1 lines 1417-1418; common Table 182 section 7.39.2; Part 12
// section 4.2.2 line 1031), a server that is NOT an LDS-ME SHALL return Bad_ServiceUnsupported rather than
// leaving the request unanswered. `start_find_servers_on_network()` now synchronously emits a
// ServiceFault carrying Status::BadServiceUnsupported.
//
// The original pin documented the pre-implementation stub ("callback never fires"); it has been
// replaced in lockstep with the implementation. Falsifiable bug this guards: a regression that
// drops the ServiceUnsupported fault (reverting to the silent no-op) or returns a different
// status, either of which would leave a non-LDS-ME server out of spec.

#include <chrono>
#include <future>
#include <memory>

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_find_servers_on_network_request.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_discovery_dependencies.h"
#include "pin_certificate_store.h"
#include "ua_discovery_service_set.h"
#include "ua_service_fault.h"

namespace ua::test::behaviour_pins::discovery
{
namespace
{

using namespace std::chrono_literals;

class FindServersOnNetworkPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(/*noOfThreads=*/1);
    mCertStore = PinCertificateStore::create();
    mDeps = std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(mPool->executor());
    mDeps->set_default_application_group_certificate_store(mCertStore);
  }

  void TearDown() override
  {
    mDeps.reset();
    mCertStore.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::shared_ptr<PinCertificateStore> mCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mDeps;
  std::shared_ptr<::ua::server::DiscoveryServiceSet<::ua::FindServersOnNetworkRequest>> mService;
};

// ---------------------------------------------------------------------------
// FN-A - SVR-DISC-LDS-007: FindServersOnNetwork on a non-LDS-ME server SHALL return
//        Bad_ServiceUnsupported. The handler synchronously emits a ServiceFault
//        with that status. Falsifiable bug: a regression to the old silent
//        no-op (callback never fires) or a different status code.
// ---------------------------------------------------------------------------
// @verifies AC-SVR-DISC-LDS-007-NON-LDS-REFUSES-FSN
TEST_F(FindServersOnNetworkPin, FindServersOnNetworkReturnsServiceUnsupported)
{
  std::promise<::ua::Response> p;
  auto fut = p.get_future();
  ::ua::FindServersOnNetworkRequest req;
  mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersOnNetworkRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response r) { p.set_value(std::move(r)); });

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready)
    << "FindServersOnNetwork must now answer the request (Bad_ServiceUnsupported)";
  auto response = fut.get();
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected a ServiceFault for a non-LDS-ME server";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadServiceUnsupported);
}

}  // namespace
}  // namespace ua::test::behaviour_pins::discovery
