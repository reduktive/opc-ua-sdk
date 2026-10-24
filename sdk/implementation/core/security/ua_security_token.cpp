// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_security_token.h"
#include "ua_security_policy_internal.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token_request_type.h"
#include "ua_secure_memory.h"
#include "ua_to_result.h"

namespace ua
{

SecurityToken::Keys& SecurityToken::Keys::operator=(const Keys& other)
{
  if (this != &other)
  {
    scrub();
    signingKey = other.signingKey;
    encryptingKey = other.encryptingKey;
    initializationVector = other.initializationVector;
  }
  return *this;
}

SecurityToken::Keys& SecurityToken::Keys::operator=(Keys&& other) noexcept
{
  if (this != &other)
  {
    scrub();
    signingKey = std::move(other.signingKey);
    encryptingKey = std::move(other.encryptingKey);
    initializationVector = std::move(other.initializationVector);
  }
  return *this;
}

SecurityToken::Keys::~Keys()
{
  scrub();
}

void SecurityToken::Keys::scrub() noexcept
{
  security::secure_clear(signingKey);
  security::secure_clear(encryptingKey);
  security::secure_clear(initializationVector);
}

SecurityToken::SecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys,
  Keys remoteKeys, uint32_t id, std::chrono::milliseconds revisedLifetime,
  TokenTimeoutCallback tokenTimeoutCallback)
  : mId(id), mLocalKeys(std::move(localKeys)), mRemoteKeys(std::move(remoteKeys)),
    mCreatedAt(DateTime::now()), mRevisedLifetime(revisedLifetime),
    mExpiresAt(std::chrono::steady_clock::now() + revisedLifetime)
{
  mTimeoutTimer = Timer::schedule_after(std::move(strand),
    revisedLifetime,
    [cb = std::move(tokenTimeoutCallback)](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      cb();
    });
}

uint32_t SecurityToken::id() const
{
  return mId;
}

const SecurityToken::Keys& SecurityToken::local_keys() const
{
  return mLocalKeys;
}

const SecurityToken::Keys& SecurityToken::remote_keys() const
{
  return mRemoteKeys;
}

DateTime SecurityToken::created_at() const
{
  return mCreatedAt;
}

std::chrono::milliseconds SecurityToken::revised_lifetime() const
{
  return mRevisedLifetime;
}

bool SecurityToken::has_expired() const
{
  return std::chrono::steady_clock::now() >= mExpiresAt;
}

void SecurityToken::create_async(SecurityTokenRequestType requestType,
  shared_ptr<SecureChannelContext> context, uint32_t id, std::chrono::milliseconds revisedLifetime,
  ByteString localNonce, ByteString remoteNonce, ChannelRole role, TokenTimeoutCallback tokenTimeoutCallback,
  std::function<void(CreateResult)> callback)
{
  check(context);

  // Part 6 6.8.1 Step 2 chains a renewal's key material to the token it renews; an Issue starts a channel,
  // so it starts a new chain.
  if (requestType == SecurityTokenRequestType::Issue)
  {
    security::secure_clear(context->keyAgreementIkm);
  }

  context->securityPolicy->derive_symmetric_keys_async(context,
    std::move(localNonce),
    std::move(remoteNonce),
    role,

    [requestType,
      ctx = context,
      id,
      revisedLifetime,
      tokenCb = std::move(tokenTimeoutCallback),
      callback = std::move(callback)](SecurityPolicy::DeriveSymmetricKeysResult deriveResult) mutable
    {
      if (!deriveResult.is_good())
      {
        callback(CreateResult{ua::security_internal::not_good_answer(
          deriveResult.status_code(), Status::BadInternalError, "SecurityToken")});
        return;
      }

      try
      {
        auto [fst, snd] = std::move(deriveResult).value();

        class Wrapper : public SecurityToken
        {
        public:
          Wrapper(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
            uint32_t id, std::chrono::milliseconds revisedLifetime, TokenTimeoutCallback tokenTimeoutCallback)
            : SecurityToken(strand, localKeys, remoteKeys, id, revisedLifetime, tokenTimeoutCallback)
          {}
        };

        auto token = std::make_unique<Wrapper>(
          *ctx->boundStrand, std::move(fst), std::move(snd), id, revisedLifetime, std::move(tokenCb));

        SecurityToken* raw = nullptr;
        if (requestType == SecurityTokenRequestType::Issue)
        {
          ctx->activeSecurityToken = std::move(token);
          raw = ctx->activeSecurityToken.get();
        }
        else
        {
          ctx->pendingSecurityToken = std::move(token);
          raw = ctx->pendingSecurityToken.get();
        }
        callback(CreateResult{raw});
      }
      catch (...)
      {
        auto er = ::ua::exception_to_status_code(std::current_exception());
        callback(CreateResult{er, er.shared_detail()});
      }
    });
}

}  // namespace ua
