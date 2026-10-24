// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_secure_channel_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_server_secure_channel_info.h"

namespace ua::test::behaviour_pins::phase_4_7
{

FakeSecureChannelDependencies::FakeSecureChannelDependencies(::boost::asio::any_io_executor executor)
  : mExecutor(executor), mAppCfg(::ua::ApplicationConfig::load_default()),
    mObserver(std::make_shared<RecordingServerObserver>()),
    mInFlightDiscovery(std::make_shared<std::atomic<uint32_t>>(0)),
    mInFlightRequests(std::make_shared<std::atomic<uint32_t>>(0))
{}

::ua::weak_ptr<::ua::server::DiscoveryDependencies> FakeSecureChannelDependencies::discovery_dependencies()
{
  return {};
}

::boost::asio::any_io_executor FakeSecureChannelDependencies::executor()
{
  return mExecutor;
}

::ua::shared_ptr<const ::ua::Crypto> FakeSecureChannelDependencies::crypto()
{
  if (!mCrypto)
    mCrypto = ::ua::create_default_crypto();
  return mCrypto;
}

::ua::WeakAddressSpace FakeSecureChannelDependencies::address_space()
{
  return {};
}

const ::ua::ApplicationConfig& FakeSecureChannelDependencies::configuration()
{
  return mAppCfg;
}

const ::ua::server::ServerConfig& FakeSecureChannelDependencies::server_configuration()
{
  return mServerCfg;
}

::ua::shared_ptr<::ua::CertificateStore>
  FakeSecureChannelDependencies::default_application_group_certificate_store()
{
  return nullptr;
}

uint32_t FakeSecureChannelDependencies::get_next_secure_channel_id()
{
  return 1;
}

void FakeSecureChannelDependencies::create_session(
  ::ua::server::SecureChannelInfo secureChannelInfo, uint32_t requestId, ::ua::CreateSessionRequest&& request)
{
  (void)request;
  {
    std::lock_guard<std::mutex> lock{mMutex};
    mCreateSessionCalled = true;
    mCreateSessionRequestId = requestId;
    mCreateSessionEndpointPolicyId = secureChannelInfo.endpoint_policy_id();
  }
  mCv.notify_all();
}

::ua::StructureFactory& FakeSecureChannelDependencies::structure_factory()
{
  // Pin tests use `inject_decoded_request_for_tests` which bypasses UA Binary decoding;
  // the factory is therefore unreachable in this corpus. Throwing here would catch any
  // accidental wire-decode path slipping into a pin.
  throw ::ua::UaException{::ua::Status::BadInternalError,
    ::ua::make_error_detail("FakeSecureChannelDependencies",
      "structure_factory not used by phase_4_7 pin corpus",
      "FakeSecureChannelDependencies")};
}

std::vector<::ua::server::ServerEndpointConfig> FakeSecureChannelDependencies::endpoints(
  ::ua::server::ListenerHandle)
{
  return mEndpoints;
}

std::shared_ptr<::ua::server::ServerObserver> FakeSecureChannelDependencies::observer()
{
  return mObserver;
}

::ua::Logger FakeSecureChannelDependencies::logger()
{
  if (!logSink)
  {
    return {};
  }
  return ::ua::Logger{
    logSink, std::make_shared<std::atomic<::ua::LogLevel>>(::ua::LogLevel::Trace), "secure_channel"};
}

std::shared_ptr<std::atomic<uint32_t>> FakeSecureChannelDependencies::in_flight_discovery_requests()
{
  return mInFlightDiscovery;
}

std::shared_ptr<std::atomic<uint32_t>> FakeSecureChannelDependencies::in_flight_requests()
{
  return mInFlightRequests;
}

void FakeSecureChannelDependencies::remove_secure_channel(
  const ::ua::shared_ptr<::ua::server::SecureChannel>&)
{
  {
    std::lock_guard<std::mutex> lock{mMutex};
    ++mRemoveCallCount;
  }
  mCv.notify_all();
}

void FakeSecureChannelDependencies::activate_session_on_channel(
  ::ua::server::SecureChannelInfo newChannelInfo, uint32_t requestId, ::ua::ActivateSessionRequest&&)
{
  {
    std::lock_guard<std::mutex> lock{mMutex};
    mActivateSessionOnChannelCalled = true;
    mActivateSessionRequestId = requestId;
    mActivateSessionChannelId = newChannelInfo.channel_id();
  }
  mCv.notify_all();
}

void FakeSecureChannelDependencies::set_endpoints(std::vector<::ua::server::ServerEndpointConfig> endpoints)
{
  mEndpoints = std::move(endpoints);
}

bool FakeSecureChannelDependencies::wait_create_session_called(std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lock{mMutex};
  return mCv.wait_for(lock, timeout, [this]() { return mCreateSessionCalled; });
}

bool FakeSecureChannelDependencies::wait_activate_session_on_channel_called(std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lock{mMutex};
  return mCv.wait_for(lock, timeout, [this]() { return mActivateSessionOnChannelCalled; });
}

bool FakeSecureChannelDependencies::wait_remove_called(std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lock{mMutex};
  return mCv.wait_for(lock, timeout, [this]() { return mRemoveCallCount > 0; });
}

uint32_t FakeSecureChannelDependencies::create_session_request_id() const
{
  std::lock_guard<std::mutex> lock{mMutex};
  return mCreateSessionRequestId;
}

std::string FakeSecureChannelDependencies::create_session_endpoint_policy_id() const
{
  std::lock_guard<std::mutex> lock{mMutex};
  return mCreateSessionEndpointPolicyId;
}

uint32_t FakeSecureChannelDependencies::activate_session_request_id() const
{
  std::lock_guard<std::mutex> lock{mMutex};
  return mActivateSessionRequestId;
}

uint32_t FakeSecureChannelDependencies::activate_session_channel_id() const
{
  std::lock_guard<std::mutex> lock{mMutex};
  return mActivateSessionChannelId;
}

size_t FakeSecureChannelDependencies::remove_call_count() const
{
  std::lock_guard<std::mutex> lock{mMutex};
  return mRemoveCallCount;
}

}  // namespace ua::test::behaviour_pins::phase_4_7
