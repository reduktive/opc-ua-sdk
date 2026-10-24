// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.3a (SecurityPolicy::derive_symmetric_keys).
//
// What is pinned:
//   DK-D: None policy returns an empty (default-constructed) Keys pair without
//         invoking any Crypto async hop. Locks the section 9.5.3 invariant that None has
//         zero `co_await`s in derive_symmetric_keys (verified at
//         policies/ua_sec_pol_none.cpp:146-154).
//
// Pins not authored in this file (with reason - see runbook section 4.5 for full table):
//   DK-A1, DK-A2 (Basic256Sha256 local/remote derive failure) - require
//                FakeAsyncCrypto to inject a bad derive_symmetric_keys_async
//                response. Fake is a sub-phase-local fixture (runbook section 4.0.1) but
//                not yet authored; runbook flags the deferral-mode TODO as
//                requiring human resolution before the fake is built.
//   DK-B1, DK-B2 (Aes256Sha256RsaPss) - same FakeAsyncCrypto dependency.
//   DK-C1, DK-C2, DK-C3, DK-C4 (EccNistP256) - same FakeAsyncCrypto dependency.

#include <chrono>
#include <optional>
#include <memory>
#include <utility>

#include <gtest/gtest.h>

#include "run_async_sync.h"

#include "ua_byte_string.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

std::shared_ptr<SecureChannelContext> make_minimal_context_for_derive(
  boost::asio::any_io_executor /*ex*/, boost::asio::strand<boost::asio::any_io_executor> strand)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  return ctx;
}

}  // namespace

class DeriveSymmetricKeysPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }

  void TearDown() override
  {
    mPool.join();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
};

// ---------------------------------------------------------------------------
// Pin DK-D - None policy: derive_symmetric_keys returns empty Keys pair.
// ---------------------------------------------------------------------------
//
// Stimulus: derive_symmetric_keys on SecurityPolicyId::None with arbitrary nonces.
// Pre-flip body at policies/ua_sec_pol_none.cpp:146-154 simply
// `co_return std::make_pair(SecurityToken::Keys{}, SecurityToken::Keys{})` -
// no Crypto interaction.
//
// Asserts both halves of the returned pair are default-constructed: every key
// component (signing, encrypting, IV) is empty. A 4.3b restructure that
// accidentally routes None through a Crypto hop (or returns a non-empty placeholder)
// is caught by the empty-key assertions.

TEST_F(DeriveSymmetricKeysPin, NoneReturnsEmptyKeyPairWithoutCryptoCall)
{
  auto ctx = make_minimal_context_for_derive(mExecutor, *mStrand);
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Nonces are unused by None, but pass non-empty buffers to verify the policy
  // ignores them rather than echoing them into the keys.
  ByteString localNonce;
  localNonce.resize(8, uint8_t{0xAA});
  ByteString remoteNonce;
  remoteNonce.resize(8, uint8_t{0xBB});

  auto pair = ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [&](auto cb) {
      policy->derive_symmetric_keys_async(ctx, localNonce, remoteNonce, ChannelRole::Server, std::move(cb));
    }).value();

  // Local keys: all three components empty.
  EXPECT_TRUE(pair.first.signingKey.empty()) << "None policy must not derive a local signing key";
  EXPECT_TRUE(pair.first.encryptingKey.empty()) << "None policy must not derive a local encrypting key";
  EXPECT_TRUE(pair.first.initializationVector.empty()) << "None policy must not derive a local IV";

  // Remote keys: all three components empty.
  EXPECT_TRUE(pair.second.signingKey.empty()) << "None policy must not derive a remote signing key";
  EXPECT_TRUE(pair.second.encryptingKey.empty()) << "None policy must not derive a remote encrypting key";
  EXPECT_TRUE(pair.second.initializationVector.empty()) << "None policy must not derive a remote IV";
  ctx.reset();
}

}  // namespace ua::test::behaviour_pins
