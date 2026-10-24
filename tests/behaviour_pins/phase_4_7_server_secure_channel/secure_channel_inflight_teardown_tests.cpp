// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Regression: server SecureChannel weak-only self-capture in async collaborator callbacks.
//
// Bug (confirmed UAF on teardown): `handle_open_secure_channel_async` and the OPN/encode/decode
// continuations captured a STRONG `auto self = shared_from_this()` into the callbacks handed to
// async collaborators (crypto entropy/ephemeral keys, certificate store, security-policy
// encode/decode) and re-captured that strong `self` into a `dispatch_to_strand` post onto the
// channel's own pool-backed strand. If an async op was in flight when the server shut down and
// the channel registry dropped its only strong ref, the in-flight completion kept the channel
// alive via a queued task on a thread_pool worker. `~SecureChannel` then ran on the pool worker
// and synchronously fired observer events back into a tearing-down ServerImpl - a heap race.
//
// The fix converts every collaborator-callback self-capture to weak (`weak_from_this()` +
// `lock()` in BOTH the collaborator lambda and the dispatched-to-strand lambda), matching the
// client SecureChannel and the section 7.5 weak-only self-capture rule.
//
// This test proves the fix DETERMINISTICALLY (the bug is not reliably reproducible by stress):
//   1. Drive the channel into the OPN entropy step with a crypto fake that PARKS
//      `get_entropy_async` (stores the completion instead of invoking it). The entropy
//      completion is now the only in-flight async op.
//   2. Drop the only external strong ref to the channel (simulating complete_shutdown's
//      registry-vector release), keeping a weak_ptr to observe.
//   3. PROOF: with weak capture, the parked completion holds NO strong ref, so the channel is
//      destroyed at step 2 (weak_ptr expires). Pre-fix the strong `self` in the parked callback
//      would keep it alive past step 2 - the leak that becomes the UAF.
//   4. Fire the parked crypto completion and assert it is a safe no-op (the `on_entropy_received`
//      continuation is NOT entered: it would, on a bad result, drive `fail_open` and fire the
//      validation-failure observer; with the channel gone the outer `weak.lock()` returns null
//      and the continuation never runs) and does not crash.

#include <chrono>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_crypto.h"
#include "fake_secure_channel_dependencies.h"

#include "ua_byte_string.h"
#include "ua_crypto_types.h"
#include "ua_defines.h"
#include "ua_message_security_mode.h"
#include "ua_open_secure_channel_request.h"
#include "ua_security_policy.h"
#include "ua_security_token_request_type.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins::phase_4_7
{
namespace
{

using namespace std::chrono_literals;
using SCTA = ::ua::server::SecureChannelTestAccess;

// Poll-wait helper: spin until `pred()` is true or the deadline elapses. The strand runs on a
// 1-thread pool, so polling from the test thread observes the parked op once the strand task
// that kicked off entropy generation has returned.
template<typename Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
      return true;
    std::this_thread::sleep_for(1ms);
  }
  return pred();
}

}  // namespace

class SecureChannelInflightTeardown : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(1);
    mDeps = std::make_shared<FakeSecureChannelDependencies>(mPool->executor());
    mCrypto = ::ua::test_helpers::FakeAsyncCrypto::create();
    // Park every async crypto op: get_entropy_async stores its completion instead of firing.
    mCrypto->set_park_async(true);

    mChannel = ::ua::server::SecureChannel::create(
      mDeps, nullptr, ::ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");
  }

  void TearDown() override
  {
    mChannel.reset();
    mDeps.reset();
    mCrypto.reset();
    if (mPool)
    {
      mPool->stop();
      mPool.reset();
    }
  }

  // Configure an authenticated (Basic256Sha256) context whose crypto is the PARKED fake, and
  // register a matching endpoint so the OPN flow clears select_security_mode and reaches the
  // entropy step. nonce_length() for Basic256Sha256 is 32 (> 0, not ECC) -> get_entropy_async.
  void configure_authenticated_with_parked_crypto()
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard)
      {
        guard.set_minimal_context_authenticated(mPool->executor(),
          "L/Basic256Sha256",
          ::ua::SecurityPolicyId::Basic256Sha256,
          ::ua::MessageSecurityMode::SignAndEncrypt);
        // The test-access context helper does not seed mCrypto; install the parked fake so the
        // OPN entropy step parks against it (the real constructor seeds mCrypto from deps, but
        // set_minimal_context_* replaces the whole context).
        guard.context()->crypto = mCrypto;
      });

    ::ua::server::ServerEndpointConfig ep;
    ep.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
    ep.securityPolicyId = ::ua::SecurityPolicyId::Basic256Sha256;
    ep.messageSecurityMode = ::ua::MessageSecurityMode::SignAndEncrypt;
    ep.name = "EP";
    mDeps->set_endpoints({ep});
  }

  void inject_opn(uint32_t requestId, std::shared_ptr<::ua::OpenSecureChannelRequest> request)
  {
    SCTA::on_strand(*mChannel,
      [&](auto& guard) { guard.inject_decoded_request(requestId, std::move(request), ::ua::NodeId{}); });
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::shared_ptr<FakeSecureChannelDependencies> mDeps;
  std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto> mCrypto;
  std::shared_ptr<::ua::server::SecureChannel> mChannel;
};

// =============================================================================
// In-flight entropy op must NOT keep the channel alive across registry release.
// =============================================================================
TEST_F(SecureChannelInflightTeardown, ParkedEntropyCompletionDoesNotKeepChannelAlive)
{
  configure_authenticated_with_parked_crypto();

  // Valid 32-byte client nonce so the synchronous nonce checks (OF-G/H/I) pass and the flow
  // reaches the entropy step.
  auto request = std::make_shared<::ua::OpenSecureChannelRequest>();
  request->request_type() = ::ua::SecurityTokenRequestType::Issue;
  request->client_protocol_version() = 0;
  request->security_mode() = ::ua::MessageSecurityMode::SignAndEncrypt;
  std::vector<uint8_t> nonce(32, 0xAB);
  request->client_nonce() = ::ua::ByteString{std::move(nonce)};

  inject_opn(/*requestId=*/200, request);

  // Step 2 (pre): the OPN flow parked exactly one get_entropy_async completion.
  ASSERT_TRUE(wait_until([&] { return mCrypto->pending_get_entropy_count() == 1; }, 2s))
    << "OPN flow did not reach the parked get_entropy_async step";

  // The fake records the parked completion before the strand turn that called get_entropy_async
  // returns. Drain that turn so its temporary weak.lock() owner cannot be mistaken for ownership by
  // the parked callback itself (the distinction becomes visible under sanitizer instrumentation).
  SCTA::strand_barrier(*mChannel);

  // Observe the channel via a weak_ptr, then drop the only external strong ref - this simulates
  // complete_shutdown's registry-vector release while the entropy op is in flight.
  std::weak_ptr<::ua::server::SecureChannel> weakChannel = mChannel;
  mChannel.reset();

  // THE PROOF: with weak self-capture, the parked completion holds no strong ref to the channel,
  // so dropping mChannel destroys it now. Pre-fix the strong `self` captured into the parked
  // get_entropy_async callback would keep the channel alive here (weak_ptr still valid) - the
  // leak that, on a pool worker, becomes the teardown UAF.
  EXPECT_TRUE(weakChannel.expired())
    << "channel survived registry release while an async op was in flight - a strong self-capture "
       "is still keeping it alive (pre-fix behaviour / regression)";

  // Step 4: firing the parked crypto completion after the channel is gone must be a safe no-op.
  // The continuation (on_entropy_received) is never entered because the outer weak.lock() fails;
  // there must be no crash and no use-after-free.
  ASSERT_EQ(mCrypto->pending_get_entropy_count(), 1u);
  std::vector<uint8_t> entropy(32, 0x11);
  mCrypto->complete_pending_get_entropy(0, ::ua::ByteString{std::move(entropy)});

  // Give the (no-op) completion a moment in case it posts; the channel stays dead.
  EXPECT_TRUE(wait_until([&] { return weakChannel.expired(); }, 500ms));
  EXPECT_EQ(mCrypto->pending_get_entropy_count(), 0u);
}

}  // namespace ua::test::behaviour_pins::phase_4_7
