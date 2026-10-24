// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.7a (Server SecureChannel) - OPN failure paths.
//
// (OF-A through OF-N). This file pins the synchronous pre-await rejection points in
// `handle_open_secure_channel`. Each pin asserts the produced ServiceFault status AND a
// non-null `shared_detail()` carrying the source-code site name (per the highest-priority
// "ErrorDetail propagation" rule).
//
// Pins implemented at HEAD (using the `inject_decoded_request_for_tests` injection path
// and the `set_validation_failure_observer` test hook to capture the rich StatusCode
// at the SDK boundary, before wire encoding strips its detail):
//   OF-A  AuthTokenNotNull            (BadInvalidArgument, "AuthTokenNotNull")
//   OF-B  ProtocolVersionMismatch     (BadProtocolVersionUnsupported, "ProtocolVersionMismatch")
//   OF-C  DuplicateIssue              (BadInvalidState, "DuplicateIssue")
//   OF-D  RenewOnClosed               (BadInvalidState, "RenewOnClosed")
//   OF-E  SecurityModeRejected        (BadSecurityModeRejected, "SecurityModeRejected")
//   OF-F  SecurityModeChanged         (BadSecurityModeRejected, "SecurityModeChanged")
//   OF-G  NonceEmpty                  (BadNonceInvalid, "NonceEmpty")
//   OF-H  NonceTooShort               (BadNonceInvalid, "NonceTooShort")
//   OF-J  NonceReused                 (BadNonceInvalid, "NonceReused")
//
// Pins NOT covered here and why:
//   OF-I  NonceWrongSize    - Requires an ECC SecurityPolicy with nonce_length() > 32. The
//                             default fixture's `set_minimal_context_authenticated` accepts a
//                             SecurityPolicyId but ECC policies are not registered without a
//                             crypto provider. Flagged as an infra gap (needs an ECC fixture
//                             or a fake SecurityPolicy override).
//   OF-K  EntropyGenerationFailure  - Requires `FakeAsyncCrypto` (planned by 4.3a) to
//                                     deferring entropy generation and inject a bad Result.
//                                     Flagged as an infra gap.
//   OF-L  EphemeralKeyGenerationFailure - Same gap as OF-K plus ECC.
//   OF-M / OF-N  observer fired on OPN/Renew failure - These need `mContext` not to be
//                "uninitialised" so the observer fires (see :958, :1003). The minimal-
//                context helper sets policy + mode but leaves `mState=Uninitialised`.
//                Flagged for resolution: pre-condition the channel's `mContext` state via a
//                helper that flips State::Open without an active token.

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_secure_channel_dependencies.h"
#include "ua_log_format.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"

#include "ua_byte_string.h"
#include "ua_defines.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_open_secure_channel_request.h"
#include "ua_response_header.h"
#include "ua_crypto_types.h"
#include "ua_security_policy.h"
#include "ua_security_token_request_type.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_service_fault.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins::phase_4_7
{
namespace
{

using namespace std::chrono_literals;
using SCTA = ::ua::server::SecureChannelTestAccess;

// Pin observer - captures (status, detail) at the SDK boundary
// (`SecureChannel::send_service_fault_with_hooks` entry, before wire encoding strips the
// detail). Updated under a mutex; the main test thread waits via condition variable.
//
// ErrorDetail does NOT survive wire encoding: `ResponseHeader::shared_detail()` /
// `DiagnosticInfo::shared_detail()` do not exist. The validation_failure_observer test
// hook captures the pre-encoding tuple and is the canonical observation point for these
// rejection-path pins.
struct FaultCapture
{
  std::mutex mutex;
  std::condition_variable cv;
  bool gotFault{false};
  ::ua::StatusCode faultStatus{::ua::Status::Good};
  std::shared_ptr<const ::ua::ErrorDetail> detail;

  bool wait(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock{mutex};
    return cv.wait_for(lock, timeout, [this]() { return gotFault; });
  }

  void on_validation_failure(::ua::StatusCode status)
  {
    {
      std::lock_guard<std::mutex> lock{mutex};
      // First failure wins - pin assertions describe a single rejection.
      if (gotFault)
        return;
      gotFault = true;
      detail = status.shared_detail();
      faultStatus = std::move(status);
    }
    cv.notify_all();
  }
};

}  // namespace

// =============================================================================
// Fixture
// =============================================================================
//
// Each pin constructs a 1-thread `boost::asio::thread_pool`, a `FakeSecureChannelDependencies`, and a
// `SecureChannel` with `nullptr` connection (test-injection path). Following the
// explicit-thread_pool::stop()-in-test-teardown rule, the fixture's TearDown joins the pool
// before any other locals destruct.

/// Collects rendered log lines so a test can assert on what the channel actually logged.
class CapturingLogSink : public ::ua::LogSink
{
public:
  void log(const ::ua::LogEntry& entry) override
  {
    std::string line = ::ua::detail::format_log_line(entry);
    const std::lock_guard<std::mutex> lock{mMutex};
    mText += line;
  }

  std::string text() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mText;
  }

private:
  mutable std::mutex mMutex;
  std::string mText;
};

class OpenSecureChannelFailurePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeSecureChannelDependencies>(mPool->executor());
    mChannel = ::ua::server::SecureChannel::create(
      mDeps, nullptr, ::ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");
    mCapture = std::make_shared<FaultCapture>();
  }

  void TearDown() override
  {
    mChannel.reset();
    mDeps.reset();
    if (mPool)
    {
      mPool->stop();
      mPool.reset();
    }
  }

  // Configure the channel with a SecurityPolicy::None context.
  void configure_none_policy()
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard)
      {
        guard.set_minimal_context_none(mPool->executor(), "L/None");
        guard.set_validation_failure_observer([cap = mCapture](::ua::StatusCode status) mutable
          { cap->on_validation_failure(std::move(status)); });
      });
  }

  // Configure the channel with an authenticated SecurityPolicy (Basic256Sha256). Used
  // for nonce-validation paths that only fire on `is_authenticated() == true`.
  void configure_basic256sha256_policy()
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard)
      {
        guard.set_minimal_context_authenticated(mPool->executor(),
          "L/Basic256Sha256",
          ::ua::SecurityPolicyId::Basic256Sha256,
          ::ua::MessageSecurityMode::SignAndEncrypt);
        guard.set_validation_failure_observer([cap = mCapture](::ua::StatusCode status) mutable
          { cap->on_validation_failure(std::move(status)); });
      });
  }

  // Mark the channel state as Open without going through a real OPN flow. Used by
  // OF-C ("DuplicateIssue") and OF-F ("SecurityModeChanged") which require the channel
  // to already be Open.
  void force_channel_state_open(::ua::MessageSecurityMode mode = ::ua::MessageSecurityMode::None)
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard)
      {
        guard.channel_state() = SCTA::ChannelState::Open;
        // Update the security mode in the context to match.
        guard.context()->messageSecurityMode = mode;
      });
  }

  // Inject a decoded OpenSecureChannelRequest with the given fields populated.
  void inject_opn(uint32_t requestId, std::shared_ptr<::ua::OpenSecureChannelRequest> request)
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard) { guard.inject_decoded_request(requestId, std::move(request), ::ua::NodeId{}); });
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeSecureChannelDependencies> mDeps;
  std::shared_ptr<::ua::server::SecureChannel> mChannel;
  std::shared_ptr<FaultCapture> mCapture;
};

// ============================================================================
// OF-A - Non-null AuthenticationToken on OPN is rejected with BadInvalidArgument.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:479-489. Spec: Part 6 - OPN's RequestHeader must
// have a null authentication token. The detail's source is "AuthTokenNotNull".

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsNonNullAuthenticationToken)
{
  configure_none_policy();

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  // Non-null authentication token (any non-default NodeId).
  request->request_header().authentication_token() = ::ua::NodeId{1, uint32_t{42}};
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::None;

  inject_opn(/*requestId=*/100, request);

  ASSERT_TRUE(mCapture->wait(2s)) << "channel did not emit a ServiceFault for non-null auth token";
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadInvalidArgument});
  ASSERT_NE(mCapture->detail, nullptr) << "OF-A failure must carry an ErrorDetail";
  EXPECT_EQ(mCapture->detail->code, "AuthTokenNotNull");
}

// ============================================================================
// OF-B - A client protocol version differing from the Hello's is rejected with
// BadProtocolVersionUnsupported (Part 6 6.7.4). RATIFIED CHANGE (group L, review B1-10): any non-zero
// version was rejected with BadTcpMessageTypeInvalid ("UnsupportedProtocolVersion"); the Hello now
// negotiates down and the OPN is held to the version the Hello named.
// ============================================================================
//
// Source: SecureChannel::handle_open_secure_channel_async. Detail code "ProtocolVersionMismatch".

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsAProtocolVersionOtherThanTheHellos)
{
  configure_none_policy();

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 1;  // the Hello named 0 (the channel's default)
  request->security_mode() = ::ua::MessageSecurityMode::None;

  inject_opn(/*requestId=*/101, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadProtocolVersionUnsupported});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "ProtocolVersionMismatch");
}

// ============================================================================
// OF-C - Issue on already-open channel is rejected with BadInvalidState.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:506-516. Detail source "DuplicateIssue".

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsIssueOnAlreadyOpenChannel)
{
  configure_none_policy();
  force_channel_state_open();

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::None;

  inject_opn(/*requestId=*/102, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadInvalidState});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "DuplicateIssue");
}

// ============================================================================
// OF-D - Renew on closed channel is rejected with BadInvalidState.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:517-526. Detail source "RenewOnClosed".

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsRenewOnClosedChannel)
{
  configure_none_policy();
  // Channel state is `Closed` by default.

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Renew;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::None;

  inject_opn(/*requestId=*/103, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadInvalidState});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "RenewOnClosed");
}

// ============================================================================
// OF-E - Unsupported security mode (no matching endpoint, non-None policy) is rejected.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:534-557. Detail source "SecurityModeRejected".
//
// Path: `select_security_mode(requestedMode)` returns false because the FakeDeps's
// `endpoints()` is empty. The "always-accept" override at :537-544 fires when the
// channel's policy is None AND the requested mode is None - to bypass that override and
// reach the rejection branch we configure an authenticated policy.

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsUnsupportedSecurityMode)
{
  configure_basic256sha256_policy();
  // Endpoints list is empty (FakeDeps default), so select_security_mode returns false
  // for any non-None mode + non-None policy combo.

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  // Provide a valid 32-byte client nonce so we don't trip OF-G/H first.
  std::vector<uint8_t> nonce(32, 0xAB);
  request->client_nonce() = ::ua::ByteString{std::move(nonce)};

  inject_opn(/*requestId=*/104, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadSecurityModeRejected});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "SecurityModeRejected");
}

// The observer asserted on above is TEST-ONLY. In a running server a pre-authentication reject
// has no public observer (on_secure_channel_open_failed is guarded on the channel having left
// Uninitialised) and the wire strips the detail, so the log is the only production-visible
// record of WHY the channel was refused. Pin that the reject context actually reaches it -
// without this the SDK builds a structured detail and then discards it.
TEST_F(OpenSecureChannelFailurePin, UnsupportedSecurityModeRejectionIsLoggedWithItsContext)
{
  auto sink = std::make_shared<CapturingLogSink>();
  mDeps->set_log_sink(sink);
  configure_basic256sha256_policy();

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  std::vector<uint8_t> nonce(32, 0xAB);
  request->client_nonce() = ::ua::ByteString{std::move(nonce)};

  inject_opn(/*requestId=*/114, request);

  ASSERT_TRUE(mCapture->wait(2s));
  const std::string logged = sink->text();
  EXPECT_NE(logged.find("SecurityModeRejected"), std::string::npos)
    << "the symbolic reject id must reach the log; logged: " << logged;
  EXPECT_NE(logged.find("security.mode"), std::string::npos)
    << "the reject's context key must reach the log; logged: " << logged;
}

// ============================================================================
// OF-F - Renew with changed security mode is rejected.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:561-571. Detail source "SecurityModeChanged".
// Channel was opened with mode X; renew arrives requesting mode Y.

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRenewRejectsChangedSecurityMode)
{
  configure_basic256sha256_policy();
  // Pretend the channel was opened with SignAndEncrypt.
  force_channel_state_open(::ua::MessageSecurityMode::SignAndEncrypt);

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Renew;
  request->client_protocol_version() = 0;
  // Renew arrives requesting Sign (different from the open's SignAndEncrypt).
  request->security_mode() = ::ua::MessageSecurityMode::Sign;
  std::vector<uint8_t> nonce(32, 0xCD);
  request->client_nonce() = ::ua::ByteString{std::move(nonce)};

  inject_opn(/*requestId=*/105, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadSecurityModeRejected});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "SecurityModeChanged");
}

// ============================================================================
// OF-G - Empty client nonce on authenticated policy is rejected.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:575-585. Detail source "NonceEmpty".

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsEmptyClientNonceOnAuthenticatedPolicy)
{
  configure_basic256sha256_policy();
  // Endpoints empty -> security mode would be rejected; we need `select_security_mode`
  // to accept the mode before reaching the nonce check. Configure a single endpoint.
  ::ua::server::ServerEndpointConfig ep;
  ep.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  ep.securityPolicyId = ::ua::SecurityPolicyId::Basic256Sha256;
  ep.messageSecurityMode = ::ua::MessageSecurityMode::SignAndEncrypt;
  ep.name = "EP";
  mDeps->set_endpoints({ep});

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  // Empty client nonce - triggers the NonceEmpty rejection.
  request->client_nonce() = ::ua::ByteString{};

  inject_opn(/*requestId=*/106, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadNonceInvalid});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "NonceEmpty");
}

// ============================================================================
// OF-H - Too-short client nonce on authenticated policy is rejected.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:590-599. Detail source "NonceTooShort".
// `client_nonce().size() < 32`.

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRejectsTooShortClientNonce)
{
  configure_basic256sha256_policy();
  ::ua::server::ServerEndpointConfig ep;
  ep.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  ep.securityPolicyId = ::ua::SecurityPolicyId::Basic256Sha256;
  ep.messageSecurityMode = ::ua::MessageSecurityMode::SignAndEncrypt;
  ep.name = "EP";
  mDeps->set_endpoints({ep});

  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  // 16-byte nonce - below the 32-byte minimum.
  std::vector<uint8_t> shortNonce(16, 0x77);
  request->client_nonce() = ::ua::ByteString{std::move(shortNonce)};

  inject_opn(/*requestId=*/107, request);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadNonceInvalid});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "NonceTooShort");
}

// ============================================================================
// OF-J - Reused client nonce on Renew is rejected.
// ============================================================================
//
// Source: ua_server_secure_channel.cpp:615-624. Detail source "NonceReused".
// Pre-condition: channel is Open AND `mLastClientNonce` matches the renew's nonce.

TEST_F(OpenSecureChannelFailurePin, OpenSecureChannelRenewRejectsReusedClientNonce)
{
  configure_basic256sha256_policy();
  // Channel opened with SignAndEncrypt mode.
  force_channel_state_open(::ua::MessageSecurityMode::SignAndEncrypt);

  // Endpoint match so the security-mode check passes.
  ::ua::server::ServerEndpointConfig ep;
  ep.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  ep.securityPolicyId = ::ua::SecurityPolicyId::Basic256Sha256;
  ep.messageSecurityMode = ::ua::MessageSecurityMode::SignAndEncrypt;
  ep.name = "EP";
  mDeps->set_endpoints({ep});

  // Seed mLastClientNonce directly via test access - represents a previously-accepted
  // client nonce. The OF-J check compares `request.client_nonce() == mLastClientNonce`
  // and rejects on equality.
  std::vector<uint8_t> nonceBytes(32, 0xEE);
  ::ua::ByteString nonce{nonceBytes};
  SCTA::on_strand(*mChannel, [&](auto& guard) { guard.last_client_nonce() = nonce; });

  // Renew with the SAME nonce - should be rejected with NonceReused.
  auto renew = std::make_shared<::ua::OpenSecureChannelRequest>();
  renew->request_type() = ::ua::SecurityTokenRequestType::Renew;
  renew->client_protocol_version() = 0;
  renew->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  renew->client_nonce() = nonce;
  inject_opn(/*requestId=*/108, renew);

  ASSERT_TRUE(mCapture->wait(2s));
  EXPECT_EQ(mCapture->faultStatus, ::ua::StatusCode{::ua::Status::BadNonceInvalid});
  ASSERT_NE(mCapture->detail, nullptr);
  EXPECT_EQ(mCapture->detail->code, "NonceReused");
}

}  // namespace ua::test::behaviour_pins::phase_4_7
