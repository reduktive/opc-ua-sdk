// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5d (AttributeServiceSet - Read/Write).
//
// Shared fixture: constructs a SessionInfo whose channel is "secured" (security
// mode is signed) AND whose ServerConfig grants Full diagnostic level so
// the per-item DiagnosticCollector path actually materialises ErrorDetail into
// the response. SessionInfoStub uses MessageSecurityMode::None which gates the
// collector to zero - those pins would be vacuously good.
//

#ifndef PHASE_4_5D_ATTRIBUTE_SERVICE_PIN_FIXTURE_H
#define PHASE_4_5D_ATTRIBUTE_SERVICE_PIN_FIXTURE_H

#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_diagnostic_bits.h"
#include "ua_diagnostic_policy.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server_configuration.h"
#include "ua_server_session_info.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_write_request.h"
#include "ua_write_response.h"

#include "access_control_test_support.h"
#include "ua_session_security.h"

namespace ua::test::behaviour_pins::attribute
{

// Test session that mirrors TestReadSessionInfo / TestWriteSessionInfo from the
// service unit tests, but with a *secured* channel and *Full* diagnostic policy
// so DiagnosticCollector actually emits operation-level diagnostics.
class PinSessionInfo final : public ua::server::SessionInfo, public ua::server::SessionSecurityContext
{
public:
  explicit PinSessionInfo(boost::asio::any_io_executor ex);

  // Configuration knobs (mutate before issuing a request).
  ua::server::ServerConfig& server_cfg()
  {
    return mServerCfg;
  }

  // SessionInfo overrides.
  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  ua::AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ua::ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ua::server::ServerConfig& server_configuration() const override
  {
    return mServerCfg;
  }

  // SessionSecurityContext overrides.
  ua::NodeId session_id() const override;

  std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const ua::server::UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const ua::AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  ua::server::DiagnosticSecurityContext diagnostic_security_context() const override;

  ua::Logger logger() const override
  {
    return {};
  }

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ua::ApplicationConfig> mAppCfg;
  ua::AddressSpace mAddressSpace;
  ua::server::ServerConfig mServerCfg;
  std::shared_ptr<const ua::server::EndpointSecurityContext> mSecurity;
  std::shared_ptr<const ua::server::UserIdentity> mUser;
  std::shared_ptr<const ua::AccessIdentity> mAccessIdentity;
};

// Shared GTest fixture. Each test constructs its own request and dispatches via
// AttributeServiceSet::create - the fixture only owns the pool, session, and
// allow-all authorizer.
class AttributeServicePin : public ::testing::Test
{
protected:
  void SetUp() override;
  void TearDown() override;

  // Populate request_header.return_diagnostics() with full op + service masks
  // so DiagnosticCollector emits per-item DiagnosticInfo into the response.
  static uint32_t full_diagnostics_mask();

  // Helpers - block on the main test thread ("no blocking on pool";
  // these helpers are only called from the test main thread).
  ua::ReadResponse dispatch_read(ua::ReadRequest req);
  ua::WriteResponse dispatch_write(ua::WriteRequest req);

  // Variant that also returns the ServiceFault (when the response is a fault rather
  // than a Read/Write response). Returns nullptr in the structure if the actual
  // response was a Read/Write response.
  ua::Response dispatch_read_raw(ua::ReadRequest req);
  ua::Response dispatch_write_raw(ua::WriteRequest req);

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<PinSessionInfo> mSession;

  // Captured during SetUp: the test's main thread id. Used by affinity pins to
  // assert the user callback fires on a *different* thread (i.e. on the pool).
  std::thread::id mMainThreadId;
};

}  // namespace ua::test::behaviour_pins::attribute

#endif  // PHASE_4_5D_ATTRIBUTE_SERVICE_PIN_FIXTURE_H
