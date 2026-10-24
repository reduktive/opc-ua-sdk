// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "server_chunk_forge.h"

#include <stdexcept>

#include "fake_certificate_store.h"
#include "run_async_sync.h"

#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_date_time.h"
#include "ua_encoding_limits.h"
#include "ua_open_secure_channel_response.h"
#include "ua_read_response.h"
#include "ua_security_token.h"
#include "ua_service_fault.h"
#include "ua_security_token_request_type.h"
#include "ua_x509_certificate.h"

namespace ua::test_helpers
{

namespace
{

ua::EncodingLimits forge_encoding_limits()
{
  return ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

}  // namespace

ServerChunkForge::ServerChunkForge(boost::asio::any_io_executor executor,
  std::shared_ptr<const ua::Crypto> crypto, std::shared_ptr<const ua::X509Certificate> serverCert,
  std::shared_ptr<const ua::AsymmetricKeyPair> serverKeys,
  std::shared_ptr<const ua::X509Certificate> clientCert, ua::MessageSecurityMode mode,
  ua::SecurityPolicyId policyId)
  : mExecutor(std::move(executor)), mCertStore(FakeCertificateStore::create()),
    mSecurityPolicy(ua::SecurityPolicy::create(policyId)),
    mContext(std::make_shared<ua::SecureChannelContext>())
{
  // Server-role context: the forge is the server, so its local material is the server's and its
  // remote material is the client's. Lifted from the server-role decrypt context in
  // client_secure_channel_crypto_tests.cpp, extended with the send-side fields the encode path needs.
  mContext->boundStrand = boost::asio::make_strand(mExecutor);
  mContext->crypto = std::move(crypto);
  mContext->certStore = mCertStore;
  mContext->securityPolicy = mSecurityPolicy;
  mContext->messageSecurityMode = mode;
  mContext->localCertificate = std::move(serverCert);
  mContext->localKeyPair = std::move(serverKeys);
  mContext->remoteCertificate = std::move(clientCert);
  mContext->encodingLimits = forge_encoding_limits();
  mContext->namespaceIndexCallback = [](ua::string_view)
  {
    return uint16_t{0};
  };
  mContext->state = ua::SecureChannelContext::State::Open;

  // Ample transport limits so a small response ships as a single final chunk.
  mContext->negotiatedLimits.receiveBufferSize = 65536;
  mContext->negotiatedLimits.sendBufferSize = 65536;
  mContext->negotiatedLimits.sendMaxChunkCount = 0;
  mContext->negotiatedLimits.sendMaxMessageSize = 0;
}

ServerChunkForge::~ServerChunkForge() = default;

void ServerChunkForge::set_local_issuer_certificates(
  std::vector<std::shared_ptr<const ua::X509Certificate>> issuers)
{
  // The production asymmetric encoder appends localIssuerCertificates after the leaf (decision 24).
  mContext->localIssuerCertificates = std::move(issuers);
}

void ServerChunkForge::set_token_from_nonces(ua::ByteString clientNonce, ua::ByteString serverNonce,
  uint32_t tokenId, std::chrono::milliseconds lifetime)
{
  // Server derives the complementary key set: local = serverNonce, remote = clientNonce,
  // ChannelRole::Server. create_async installs the token as the active token on the context.
  auto result = ua::test_helpers::run_async_callback_sync<ua::SecurityToken::CreateResult>(
    [&](auto cb)
    {
      ua::SecurityToken::create_async(
        ua::SecurityTokenRequestType::Issue,
        mContext,
        tokenId,
        lifetime,
        std::move(serverNonce),
        std::move(clientNonce),
        ua::ChannelRole::Server,
        []() {},
        std::move(cb));
    });
  // A forged token is usable only after its key derivation completed successfully.
  (void)result.value();
}

void ServerChunkForge::set_pending_token(ua::ByteString clientNonce, ua::ByteString serverNonce,
  uint32_t tokenId, std::chrono::milliseconds lifetime)
{
  // A Renew request installs the derived token as the PENDING token on the context (see
  // SecurityToken::create_async). Same server-role nonce ordering as the active token.
  auto result = ua::test_helpers::run_async_callback_sync<ua::SecurityToken::CreateResult>(
    [&](auto cb)
    {
      ua::SecurityToken::create_async(
        ua::SecurityTokenRequestType::Renew,
        mContext,
        tokenId,
        lifetime,
        std::move(serverNonce),
        std::move(clientNonce),
        ua::ChannelRole::Server,
        []() {},
        std::move(cb));
    });
  (void)result.value();
}

std::vector<ua::byte> ServerChunkForge::encode_symmetric_response(
  const SymMsgParams& params, std::shared_ptr<ua::Structure> response)
{
  mContext->secureChannelId = params.secureChannelId;
  // encode stamps ++lastTxSequenceNumber, so seed one below the desired number. Valid sequence
  // numbers start at 1; guard the underflow so a 0 request degrades to "start at 1" rather than wrap.
  mContext->lastTxSequenceNumber = params.sequenceNumber > 0 ? params.sequenceNumber - 1 : 0;
  // The forge produces whatever number a test asks for, replays included; the per-token reuse record
  // (CRY-4) is the sender's own protection and is cleared so it does not refuse the forgery.
  mContext->txUseUnderToken = {};

  // The production encode path secures the chunk with the ACTIVE token. To stamp/secure with the
  // pending token, swap it into the active slot for the (synchronous) encode and restore afterwards.
  if (params.usePendingToken)
  {
    std::swap(mContext->activeSecurityToken, mContext->pendingSecurityToken);
  }

  std::vector<ua::ByteString> chunks;
  ua::SecurityPolicy::SendMessageChunk sink = [&chunks](ua::ByteString chunk)
  {
    chunks.push_back(std::move(chunk));
  };

  auto result = ua::test_helpers::run_async_callback_sync<ua::VoidResult>([&](auto cb)
    { mSecurityPolicy->encode_message_async(mContext, params.requestId, response, sink, std::move(cb)); });

  if (params.usePendingToken)
  {
    std::swap(mContext->activeSecurityToken, mContext->pendingSecurityToken);
  }

  result.value();

  if (chunks.size() != 1)
  {
    throw std::runtime_error("ServerChunkForge::encode_symmetric_response expected a single chunk");
  }

  ua::span<const ua::byte> bytes = chunks.front();
  return std::vector<ua::byte>{bytes.begin(), bytes.end()};
}

std::vector<ua::byte> ServerChunkForge::build_symmetric_msg(const SymMsgParams& params)
{
  return encode_symmetric_response(params, std::make_shared<ua::ReadResponse>());
}

std::vector<ua::byte> ServerChunkForge::build_symmetric_service_fault(
  const SymMsgParams& params, ua::StatusCode serviceResult)
{
  auto fault = std::make_shared<ua::ServiceFault>();
  fault->response_header().service_result() = serviceResult;
  return encode_symmetric_response(params, std::move(fault));
}

void ServerChunkForge::record_open_secure_channel_request(ua::span<const ua::byte> requestChunk)
{
  if (!mSecurityPolicy->secure_channel_enhancements())
  {
    return;
  }
  const size_t signatureSize = mSecurityPolicy->asymmetric_signature_size(mContext->remoteCertificate.get());
  if (signatureSize == 0 || requestChunk.size() < signatureSize)
  {
    throw std::runtime_error(
      "ServerChunkForge::record_open_secure_channel_request: the chunk holds no Signature");
  }
  mContext->openSecureChannelRequestSignature =
    ua::ByteString{requestChunk.subspan(requestChunk.size() - signatureSize)};
}

std::vector<ua::byte> ServerChunkForge::build_opn_response(const OpnRespParams& params)
{
  mContext->secureChannelId = params.secureChannelId;
  // encode stamps ++lastTxSequenceNumber, so seed one below the desired number. Valid sequence
  // numbers start at 1; guard the underflow so a 0 request degrades to "start at 1" rather than wrap.
  mContext->lastTxSequenceNumber = params.sequenceNumber > 0 ? params.sequenceNumber - 1 : 0;
  // The forge produces whatever number a test asks for, replays included; the per-token reuse record
  // (CRY-4) is the sender's own protection and is cleared so it does not refuse the forgery.
  mContext->txUseUnderToken = {};

  auto response = std::make_shared<ua::OpenSecureChannelResponse>();
  response->response_header().request_handle() = params.requestHandle;
  response->response_header().service_result() = ua::StatusCode{ua::Status::Good};
  response->server_protocol_version() = params.serverProtocolVersion;
  response->server_nonce() = params.serverNonce;
  response->security_token().channel_id() = params.secureChannelId;
  response->security_token().token_id() = params.tokenId;
  response->security_token().created_at() = ua::DateTime::now();
  response->security_token().revised_lifetime() = params.revisedLifetimeMs;

  std::vector<ua::ByteString> chunks;
  ua::SecurityPolicy::SendMessageChunk sink = [&chunks](ua::ByteString chunk)
  {
    chunks.push_back(std::move(chunk));
  };

  // encode_message_async routes an OpenSecureChannelResponse through the asymmetric encoder, which
  // signs with the server (local) key and encrypts to the client (remote) cert on the server-role
  // context - producing a fully-framed OPN response, never a hand-encoded one.
  auto result = ua::test_helpers::run_async_callback_sync<ua::VoidResult>([&](auto cb)
    { mSecurityPolicy->encode_message_async(mContext, params.requestId, response, sink, std::move(cb)); });

  result.value();

  if (chunks.size() != 1)
  {
    throw std::runtime_error("ServerChunkForge::build_opn_response expected a single chunk");
  }

  ua::span<const ua::byte> bytes = chunks.front();
  return std::vector<ua::byte>{bytes.begin(), bytes.end()};
}

}  // namespace ua::test_helpers
