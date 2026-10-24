// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "attribute_service_pin_fixture.h"

#include "ua_crypto_types.h"
#include "ua_guid.h"
#include "ua_message_security_mode.h"

namespace ua::test::behaviour_pins::attribute
{

PinSessionInfo::PinSessionInfo(boost::asio::any_io_executor ex)
  : mExecutor(ex),
    mAppCfg(std::make_shared<const ua::ApplicationConfig>(ua::ApplicationConfig::load_default())),
    mAddressSpace(ua::AddressSpace::create("urn:test:pin:4_5d", mExecutor))
{
  // Secure the channel so DiagnosticSecurityContext::securedChannel == true,
  // which is what allows the collector to emit per-item DiagnosticInfo.
  auto security = std::make_shared<ua::server::EndpointSecurityContext>();
  security->endpointPolicyId = "Pin/Sign";
  security->messageSecurityMode = ua::MessageSecurityMode::Sign;
  security->securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  mSecurity = std::move(security);

  auto user = std::make_shared<ua::server::UserIdentity>();
  user->userId = "pin-user";
  user->displayName = "Pin User";
  user->kind = ua::server::UserTokenKind::Anonymous;
  mUser = std::move(user);

  // Full diagnostic level so the collector materialises symbolic_id, additional_info,
  // and source - needed to assert per-item ErrorDetail propagation lands on the response.
  mServerCfg.diagnosticPolicy.defaultLevel = ua::server::ServerConfig::DiagnosticPolicy::Level::Full;

  mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
}

ua::NodeId PinSessionInfo::session_id() const
{
  return ua::NodeId{1, ua::Guid::create_and_generate()};
}

ua::server::DiagnosticSecurityContext PinSessionInfo::diagnostic_security_context() const
{
  return ua::server::detail::make_diagnostic_security_context(
    *mSecurity, *mUser, mServerCfg.diagnosticPolicy);
}

void AttributeServicePin::SetUp()
{
  mMainThreadId = std::this_thread::get_id();
  mExecutor = mPool.get_executor();
  mSession = std::make_shared<PinSessionInfo>(mExecutor);
}

void AttributeServicePin::TearDown()
{
  // Drop the session before stopping the pool so any tear-down work it triggers
  // can drain. Explicit stop() before locals reverse-destruct.
  mSession.reset();
  mPool.join();
}

uint32_t AttributeServicePin::full_diagnostics_mask()
{
  // Service-level + operation-level: every bit set so the collector emits
  // every projected field. The runbook requires per-item ErrorDetail observable
  // on the response (DiagnosticCollector path), and the symbolic_id / namespace_uri
  // / additional_info projections are how that lands on the wire.
  return ua::server::diag::serviceLevelMask | ua::server::diag::operationLevelMask;
}

ua::Response AttributeServicePin::dispatch_read_raw(ua::ReadRequest req)
{
  std::promise<ua::Response> promise;
  auto fut = promise.get_future();
  auto svc = ua::server::AttributeServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/1,
    std::move(req),
    mExecutor,
    [&promise](ua::Response r) { promise.set_value(std::move(r)); });
  (void)svc;

  // Block on the main thread only. The pool services the strand; never block the pool.
  if (fut.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
  {
    ADD_FAILURE() << "Read service did not complete within 2s";
    return {};
  }
  return fut.get();
}

ua::Response AttributeServicePin::dispatch_write_raw(ua::WriteRequest req)
{
  std::promise<ua::Response> promise;
  auto fut = promise.get_future();
  auto svc = ua::server::AttributeServiceSet::create(mSession,
    /*requestId=*/1,
    std::move(req),
    mExecutor,
    [&promise](ua::Response r) { promise.set_value(std::move(r)); });
  (void)svc;

  if (fut.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
  {
    ADD_FAILURE() << "Write service did not complete within 2s";
    return {};
  }
  return fut.get();
}

ua::ReadResponse AttributeServicePin::dispatch_read(ua::ReadRequest req)
{
  auto resp = dispatch_read_raw(std::move(req));
  auto* readResp = dynamic_cast<ua::ReadResponse*>(resp.second.get());
  if (readResp)
  {
    return std::move(*readResp);
  }
  // Fall through: a ServiceFault was returned. Lift its response_header into a
  // ReadResponse so the caller can still inspect service_result + service_diagnostics.
  ua::ReadResponse out;
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get()))
  {
    out.response_header() = fault->response_header();
  }
  return out;
}

ua::WriteResponse AttributeServicePin::dispatch_write(ua::WriteRequest req)
{
  auto resp = dispatch_write_raw(std::move(req));
  auto* writeResp = dynamic_cast<ua::WriteResponse*>(resp.second.get());
  if (writeResp)
  {
    return std::move(*writeResp);
  }
  ua::WriteResponse out;
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get()))
  {
    out.response_header() = fault->response_header();
  }
  return out;
}

}  // namespace ua::test::behaviour_pins::attribute
