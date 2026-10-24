// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_SERVER_CHUNK_FORGE_H
#define UA_TEST_HELPERS_SERVER_CHUNK_FORGE_H

// Test-only helper that synthesises server->client UASC wire chunks and feeds them (via the caller)
// into the REAL client SecureChannelImpl decode path, so client-side inbound-verification
// requirements can be unit-tested.
//
// The forge owns a SERVER-ROLE SecureChannelContext (localCertificate = serverCert,
// localKeyPair = serverKeys, mRemoteCertificate = clientCert) and its own throwaway strand on the
// executor passed in. It uses the production SecurityPolicy encode path to produce fully-framed,
// signed/encrypted chunks - it never hand-encodes length prefixes or signatures.
//
// Each build_* method BLOCKS the calling thread (via run_async_callback_sync) while the pool runs
// the crypto, and returns one complete chunk. Call the build_* methods from the gtest main thread,
// never from inside an on_strand handler.

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include "ua_byte_string.h"
#include "ua_message_security_mode.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"

namespace ua
{
class Crypto;
class X509Certificate;
class AsymmetricKeyPair;
class CertificateStore;
class Structure;
}  // namespace ua

namespace ua::test_helpers
{

/// Synthesises server->client secure-channel chunks against a server-role SecureChannelContext.
class ServerChunkForge
{
public:
  /// Constructs the forge with the peer material of an already-wired client channel.
  ///
  /// @param executor   Executor whose pool runs the crypto (the client's test thread pool).
  /// @param crypto     Crypto provider (same instance the client uses).
  /// @param serverCert Server (sender) certificate the forged chunks are signed with.
  /// @param serverKeys Server key pair matching @p serverCert.
  /// @param clientCert Client (receiver) certificate the forged chunks encrypt to.
  /// @param mode       Message security mode of the channel being forged against.
  /// @param policyId   Security policy of the channel being forged against.
  ServerChunkForge(boost::asio::any_io_executor executor, std::shared_ptr<const ua::Crypto> crypto,
    std::shared_ptr<const ua::X509Certificate> serverCert,
    std::shared_ptr<const ua::AsymmetricKeyPair> serverKeys,
    std::shared_ptr<const ua::X509Certificate> clientCert, ua::MessageSecurityMode mode,
    ua::SecurityPolicyId policyId);

  ServerChunkForge(const ServerChunkForge&) = delete;
  ServerChunkForge& operator=(const ServerChunkForge&) = delete;
  ServerChunkForge(ServerChunkForge&&) = delete;
  ServerChunkForge& operator=(ServerChunkForge&&) = delete;
  ~ServerChunkForge();

  /// Sets the issuer chain the forged OPN response presents after the server certificate (the
  /// AsymmetricSecurityHeader SenderCertificate chain, OPC 10000-6 section 6.2.6). Empty by default.
  ///
  /// @param issuers The certificates that follow the leaf, nearest issuer first.
  void set_local_issuer_certificates(std::vector<std::shared_ptr<const ua::X509Certificate>> issuers);

  /// Derives the MIRROR symmetric token and installs it as the active token on the server context.
  ///
  /// The client derives its token from (clientNonce, serverNonce) with ChannelRole::Client; the
  /// server (this forge) derives the complementary key set from the same pair with
  /// ChannelRole::Server, so the forge's local sending keys equal the client's remote receiving keys.
  ///
  /// @param clientNonce The client's nonce (the client's own last_client_nonce).
  /// @param serverNonce The server nonce the client was opened with.
  /// @param tokenId     Token id stamped into forged symmetric chunks.
  /// @param lifetime    Token lifetime; large enough that it never expires during the test.
  void set_token_from_nonces(ua::ByteString clientNonce, ua::ByteString serverNonce, uint32_t tokenId,
    std::chrono::milliseconds lifetime);

  /// Derives a MIRROR token and installs it as the PENDING token on the server context.
  ///
  /// Models a renewal in flight: the forge can then stamp chunks with either the active (old) token
  /// id or this pending (new) token id (see @ref SymMsgParams::usePendingToken).
  ///
  /// @param clientNonce The client's nonce for the renewed generation.
  /// @param serverNonce The server nonce for the renewed generation.
  /// @param tokenId     Token id of the pending (renewed) token.
  /// @param lifetime    Token lifetime; large enough that it never expires during the test.
  void set_pending_token(ua::ByteString clientNonce, ua::ByteString serverNonce, uint32_t tokenId,
    std::chrono::milliseconds lifetime);

  /// Parameters for a forged symmetric (established-channel) response chunk.
  struct SymMsgParams
  {
    /// SecureChannelId stamped into the message header. The client rejects a mismatch pre-crypto.
    uint32_t secureChannelId{0};
    /// Token id the chunk claims. Informational: the stamped id is that of the token the chunk is
    /// secured with (active by default; pending when @ref usePendingToken is set).
    uint32_t tokenId{0};
    /// Request id stamped into the sequence header; must match a pending client request to deliver.
    uint32_t requestId{0};
    /// Sequence number stamped into the sequence header (a full override). The client accepts
    /// strictly +1 per chunk, starting from 1; a gap or a replay is rejected.
    uint32_t sequenceNumber{1};
    /// When true, the chunk is stamped/secured with the PENDING token (see @ref set_pending_token)
    /// rather than the active token. Used to drive the client's token rotation on renewal.
    bool usePendingToken{false};
  };

  /// Builds one symmetric ReadResponse chunk secured with the active token.
  ///
  /// @param params Header/sequence values to stamp (see @ref SymMsgParams).
  /// @return The complete single chunk, ready to hand to receive_message_chunk.
  std::vector<ua::byte> build_symmetric_msg(const SymMsgParams& params);

  /// Builds one symmetric ServiceFault chunk (secured with the active token) whose ResponseHeader
  /// carries @p serviceResult - models a server fault delivered for a specific request id (e.g. a
  /// Bad_RequestCancelledByClient fault for a cancelled outstanding request).
  ///
  /// @param params        Header/sequence values to stamp (requestId must match a pending request).
  /// @param serviceResult The ServiceResult status stamped into the fault's ResponseHeader.
  /// @return The complete single chunk, ready to hand to receive_message_chunk.
  std::vector<ua::byte> build_symmetric_service_fault(
    const SymMsgParams& params, ua::StatusCode serviceResult);

  /// Parameters for a forged asymmetric OpenSecureChannel (Issue) response chunk.
  struct OpnRespParams
  {
    /// SecureChannelId stamped into both the message header and the response body's SecurityToken.
    uint32_t secureChannelId{1};
    /// Token id carried in the response body's SecurityToken (the id the client will adopt).
    uint32_t tokenId{1};
    /// Request id stamped into the sequence header.
    uint32_t requestId{1};
    /// Sequence number stamped into the sequence header (a full override; the encode path stamps
    /// ++lastTxSequenceNumber, so the forge seeds one below this value).
    uint32_t sequenceNumber{1};
    /// Server nonce carried in the response body. For a non-None policy its length must match the
    /// policy's nonce length so the client's symmetric key derivation succeeds.
    ua::ByteString serverNonce;
    /// Revised token lifetime (ms) carried in the response body; large enough to avoid expiry mid-test.
    uint32_t revisedLifetimeMs{600000};
    /// RequestHandle echoed in the response header.
    uint32_t requestHandle{0};
    /// ServerProtocolVersion carried in the response body (Part 6 6.7.4: the Acknowledge's version, 0).
    uint32_t serverProtocolVersion{0};
  };

  /// Builds one asymmetric OpenSecureChannel response chunk (Issue), signed with the server key and
  /// encrypted to the client cert, using the production asymmetric encode path.
  ///
  /// `encode_message_async` routes an `OpenSecureChannelResponse` through the asymmetric encoder
  /// (ua_security_policy.cpp), so the produced chunk is a fully-framed, signed and encrypted OPN
  /// response ready to feed into the client's `receive_message_chunk` decode interface.
  ///
  /// @param params Header/token/nonce values to stamp (see @ref OpnRespParams).
  /// @return The complete single chunk, ready to hand to receive_message_chunk.
  std::vector<ua::byte> build_opn_response(const OpnRespParams& params);

  /// Records the Signature that ends the client's OpenSecureChannel request @p requestChunk, as a server
  /// records it before answering: under a policy with SecureChannelEnhancements the first response is
  /// signed over the response followed by that Signature (OPC 10000-6 6.7.5), and the policy refuses to
  /// sign one without it. The request is signed but not encrypted under such a policy, so the Signature is
  /// the chunk's last bytes, sized by the client certificate. Does nothing for any other policy.
  void record_open_secure_channel_request(ua::span<const ua::byte> requestChunk);

private:
  /// Shared symmetric-encode path: stamps the header/sequence values from @p params and secures the
  /// serialized @p response with the active (or pending) token via the production encode path.
  std::vector<ua::byte> encode_symmetric_response(
    const SymMsgParams& params, std::shared_ptr<ua::Structure> response);

  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<ua::CertificateStore> mCertStore;
  std::shared_ptr<ua::SecurityPolicy> mSecurityPolicy;
  std::shared_ptr<ua::SecureChannelContext> mContext;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_SERVER_CHUNK_FORGE_H
