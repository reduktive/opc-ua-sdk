// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-connection secure-channel state shared across the UASC pipeline.
/// @ingroup security

#ifndef UA_SECURE_CHANNEL_CONTEXT_H
#define UA_SECURE_CHANNEL_CONTEXT_H

#include "ua_exceptions.h"
#include "ua_includes.h"
#include "ua_logger.h"
#include "ua_message_security_mode.h"
#include "ua_timer.h"
#include "ua_connection_protocol.h"
#include "ua_crypto.h"
#include "ua_encoding_limits.h"
#include "ua_codec_namespace_context.h"
#include "ua_channel_role.h"
#include "ua_secure_memory.h"

#include <functional>
#include <limits>

namespace ua
{
class SecurityPolicy;

class X509Certificate;
class AsymmetricKeyPair;
class AddressSpace;
class SecurityToken;
class CertificateStore;
struct CertificateValidationRequest;

/// Mutable per-connection state of a single UASC secure channel.
///
/// Aggregates the cryptographic material, negotiated parameters, security tokens, and in-flight
/// message state that the secure-channel state machine reads and mutates as a channel is opened,
/// renewed, and closed. One instance backs one transport connection for its lifetime.
///
/// All access is serialized through the channel's @ref boundStrand - members are mutated and read only
/// from within that strand, so the struct itself carries no internal locking.
///
/// @ingroup security
struct SecureChannelContext
{
  SecureChannelContext() = default;
  /// Declared because the destructor would otherwise suppress it: a context can be built and returned by
  /// value.
  SecureChannelContext(SecureChannelContext&&) = default;
  SecureChannelContext(const SecureChannelContext&) = delete;
  SecureChannelContext& operator=(const SecureChannelContext&) = delete;
  SecureChannelContext& operator=(SecureChannelContext&&) = delete;

  /// Scrubs the key-agreement secrets: a context is released by whichever holder lets go last, which may
  /// be an operation that outlived the channel.
  ~SecureChannelContext()
  {
    release_key_agreement_secrets();
  }

  /// Scrubs the key-agreement secrets this channel holds: the chained input keying material and the
  /// ephemeral private key. The owning channel calls it when the channel closes. A renewal still deriving
  /// its keys then commits nothing into the context (@ref keyAgreementReleased).
  void release_key_agreement_secrets() noexcept
  {
    keyAgreementReleased = true;
    security::secure_clear(keyAgreementIkm);
    security::secure_clear(localEphemeralPrivateKey);
  }

  /// Establish the policy-specific initial sequence state for a newly negotiated channel.
  /// Legacy policies number their first chunk 1; current policies number it 0.
  ///
  /// @param legacy `true` for a policy whose first chunk is numbered 1, which is expressed by
  ///        seeding the last-sent number with 0. `false` seeds it with `UINT32_MAX` so the
  ///        pre-increment wraps to 0 for the first chunk.
  void initialise_sequence_numbers(bool legacy)
  {
    lastTxSequenceNumber = legacy ? 0u : std::numeric_limits<uint32_t>::max();
    txChunkSent = false;
    lastRxSequenceNumber = legacy ? optional<uint32_t>{0u} : std::nullopt;
    txUseUnderToken = {};
    rxUseUnderToken = {};
  }

  /// Advances @ref lastTxSequenceNumber to the number of the next chunk to send and returns it. Every
  /// chunk sent takes its number here.
  ///
  /// @return The SequenceNumber of the chunk about to be sent.
  uint32_t next_tx_sequence_number() noexcept
  {
    txChunkSent = true;
    return ++lastTxSequenceNumber;
  }

  /// The LastSequenceNumber of Part 6 6.8.1 Table 69 for the next chunk to send: the number of the
  /// previous chunk sent in this direction, or 0 when none has been sent. Before the first chunk of a
  /// current policy @ref lastTxSequenceNumber holds 0xFFFFFFFF (so that the first increment gives 0),
  /// which after a wrap is also a real previous number; @ref txChunkSent tells the two apart.
  ///
  /// @return The previous SequenceNumber sent, or 0.
  uint32_t last_tx_sequence_number() const noexcept
  {
    return (!txChunkSent && lastTxSequenceNumber == std::numeric_limits<uint32_t>::max())
             ? 0u
             : lastTxSequenceNumber;
  }

  /// Part 6 6.7.2.4: a SequenceNumber may not be reused under one TokenId. The first number used
  /// under the current token is remembered per direction; a number that returns to it under the
  /// same token is a reuse (2^32 chunks without a renewal), which the receiver treats as a transport
  /// error and the sender refuses to produce (CRY-4).
  struct SequenceUseUnderToken
  {
    optional<uint32_t> tokenId;
    optional<uint32_t> firstSequenceNumber;
    optional<uint32_t> lastSequenceNumber;
  };

  /// Records `sequenceNumber` as used under `tokenId` in one direction.
  ///
  /// The numbers used under a token run from its first number upwards, so a number is a reuse when
  /// it returns to the first one, or when the sequence wraps (a number below the last one, which
  /// the legacy policies allow anywhere below 1024) onto a value at or above the first one: every
  /// number from the first to the last was used under this token.
  ///
  /// @return `false` when the number would be a reuse under that token.
  static bool note_sequence_number_under_token(
    SequenceUseUnderToken& use, uint32_t tokenId, uint32_t sequenceNumber)
  {
    if (!use.tokenId || *use.tokenId != tokenId)
    {
      use.tokenId = tokenId;
      use.firstSequenceNumber = sequenceNumber;
      use.lastSequenceNumber = sequenceNumber;
      return true;
    }
    const bool returnsToFirst = use.firstSequenceNumber && *use.firstSequenceNumber == sequenceNumber;
    const bool wrapsOntoUsed = use.lastSequenceNumber && use.firstSequenceNumber &&
                               sequenceNumber < *use.lastSequenceNumber &&
                               sequenceNumber >= *use.firstSequenceNumber;
    if (returnsToFirst || wrapsOntoUsed)
      return false;
    use.lastSequenceNumber = sequenceNumber;
    return true;
  }

  SequenceUseUnderToken txUseUnderToken;  ///< Sent chunks under the current token (CRY-4).
  SequenceUseUnderToken rxUseUnderToken;  ///< Received chunks under the current token (CRY-4).

  /// Lifecycle phase of the secure channel.
  enum class State
  {
    Uninitialised,  ///< No OpenSecureChannel has completed yet; no usable token.
    Open,  ///< Channel is established and an active security token is in force.
    Closed  ///< Channel has been torn down and must not carry further messages.
  };

  /// Returns true while the channel has not yet completed its initial open.
  ///
  /// @return `true` while no OpenSecureChannel has completed and the channel holds no usable token.
  bool is_uninitialised() const
  {
    return (state == State::Uninitialised);
  }

  /// Returns true while the channel is open and able to carry secured messages.
  ///
  /// @return `true` while the channel is open and can carry secured messages.
  bool is_open() const
  {
    return (state == State::Open);
  }

  /// The strand every access to this context is serialized on.
  ///
  /// @ref boundStrand is engaged the moment a channel binds this context to an executor - the server
  /// channel's constructor does it five lines after building the context, the client assigns its
  /// own - and neither ever resets it. A bound channel therefore always has one, and this binds
  /// that invariant behind an explicit precondition instead of letting a disengaged optional
  /// silently run the work on whatever thread happened to call: the shape no coroutine can
  /// survive, because a body's own suspension state would then be written from two threads.
  ///
  /// @return The channel strand.
  /// @throws UaException `BadInvalidState` when the context is not yet bound to an executor.
  const boost::asio::strand<boost::asio::any_io_executor>& strand() const
  {
    if (!boundStrand.has_value())
    {
      throw_empty_optional_check(Status::BadInvalidState, UA_CURRENT_LOCATION);
    }
    return *boundStrand;
  }

  /// Strand serializing all access to this context; engaged once the channel is bound to its
  /// executor. Empty until then.
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> boundStrand;
  /// Logger for the security-policy async work serialized on @ref boundStrand, seeded by the owning
  /// channel where it binds the strand. A value handle that survives teardown; passed into the post
  /// helpers / guarded at each call site alongside @ref boundStrand.
  ua::Logger logger;
  /// Crypto provider for the negotiated security policy; shared, immutable. Null until negotiated.
  shared_ptr<const Crypto> crypto;
  /// Certificate store used to validate the peer chain; weak to avoid extending its lifetime.
  std::weak_ptr<CertificateStore> certStore;
  /// Resolves namespace URIs to runtime indices when (de)serializing channel-level messages.
  NamespaceIndexResolver namespaceIndexCallback;
  /// Current lifecycle phase of the channel.
  State state{State::Uninitialised};
  /// Which side of the channel this participant is. Set once at construction and never changed.
  ///
  /// Used to report an over-size outgoing message with the status the standard names for THAT
  /// direction: OPC 10000-4 section 5.3 gives the Server `Bad_ResponseTooLarge` for an oversized response,
  /// and the Client Communication Stack `Bad_RequestTooLarge` for an oversized request. The check
  /// itself is shared, so without this the same status was reported both ways and a caller whose
  /// REQUEST was too large read "response too large".
  ChannelRole role{ChannelRole::Server};
  /// Negotiated security policy (signing/encryption algorithms). Null until negotiated.
  shared_ptr<SecurityPolicy> securityPolicy;
  /// Negotiated message security mode (None, Sign, or SignAndEncrypt).
  MessageSecurityMode messageSecurityMode{MessageSecurityMode::Invalid};
  /// Server-assigned identifier of this secure channel.
  uint32_t secureChannelId{0};
  /// Sequence number of the most recently received message; empty before the first message.
  optional<uint32_t> lastRxSequenceNumber{0};
  /// Sequence number of the most recently transmitted message.
  uint32_t lastTxSequenceNumber{0};
  /// Set once a chunk has taken a number from @ref next_tx_sequence_number.
  bool txChunkSent{false};
  /// Token currently in force for securing traffic. Null until the channel opens.
  unique_ptr<SecurityToken> activeSecurityToken;
  /// Token issued by a renewal but not yet activated by the peer. Null when no renewal is pending.
  unique_ptr<SecurityToken> pendingSecurityToken;
  /// Client only: the token a renew response replaced. Nothing is sent under it; it still decodes chunks
  /// the Server secured with it (a Server answers under the old token until it receives a message under the
  /// new one), until it expires or a chunk under the active token is accepted (OPC 10000-6 6.7.4, 1.05.06).
  /// Null otherwise.
  unique_ptr<SecurityToken> retiredSecurityToken;
  /// Transport limits agreed during the HEL/ACK handshake (buffer/message/chunk sizes).
  connection_protocol::NegotiatedLimits negotiatedLimits;
  /// Encoding limits applied to messages on this channel (nesting depth, array/string sizes).
  ua::EncodingLimits encodingLimits;
  /// This endpoint's own certificate presented during channel setup. Null if unused.
  shared_ptr<const X509Certificate> localCertificate;
  /// Private/public key pair matching @ref localCertificate. Null if unused.
  shared_ptr<const AsymmetricKeyPair> localKeyPair;
  /// Issuer chain of @ref localCertificate (nearest issuer first, leaf excluded), sent after the leaf in
  /// the OPN SenderCertificate (OPC 10000-6 section 6.2.6). Empty when the own certificate has none.
  std::vector<shared_ptr<const X509Certificate>> localIssuerCertificates;
  /// Called with the exact request the peer certificate was validated with, each time that validation
  /// succeeds (presented issuers, policy, endpoint URL). The client retains it so a later revalidation
  /// resubmits the same request against current trust material. Empty: not called.
  std::function<void(const CertificateValidationRequest&)> onRemoteCertificateValidated;
  /// Called with the validated request and the errors the validation suppressed (OPC 10000-4 section
  /// 6.1.3, owner decision 22.6) each time the peer certificate is accepted with at least one suppressed
  /// error. The server reports them through ServerObserver::on_certificate_error_suppressed; the client
  /// logs a warning each. Empty: not called.
  std::function<void(const CertificateValidationRequest&, const std::vector<StatusCode>&)>
    onRemoteCertificateErrorsSuppressed;
  /// Peer's certificate received during channel setup. Null if unused.
  shared_ptr<const X509Certificate> remoteCertificate;
  /// Peer's issuer (intermediate/CA) chain accompanying @ref remoteCertificate.
  std::vector<shared_ptr<const X509Certificate>> remoteIssuerCertificates;
  /// Endpoint URL this channel was opened against.
  std::string endpointUrl;
  /// When set the remote certificate is validated without the HostName binding to @ref endpointUrl (a client
  /// that relaxed it; CreateSession reports the mismatch instead).
  bool relaxHostNameCheck{false};

  /// Ephemeral private key for ECC key agreement on this channel; empty for non-ECC policies.
  ByteString localEphemeralPrivateKey;

  /// Part 6 6.8.1 Step 2: the input keying material of the most recently derived token. A renewal's IKM is
  /// its shared secret XOR this value, so every token's keys depend on every earlier exchange. Empty before
  /// the first derivation, after an Issue starts a new chain, and for a policy without key agreement.
  ByteString keyAgreementIkm;

  /// Set by @ref release_key_agreement_secrets when the channel closes, and never cleared: a derivation that
  /// completes afterwards answers Bad_SecureChannelClosed instead of putting new key material into the
  /// context.
  bool keyAgreementReleased{false};

  /// Part 6 6.7.5: the Signature of the first OpenSecureChannel request, which the Signature of the first
  /// response also covers under a policy with SecureChannelEnhancements. The server records the request
  /// it verified and the client the request it sent, each only until @ref channelThumbprint is set.
  ByteString openSecureChannelRequestSignature;

  /// Part 6 6.7.5: the ChannelThumbprint, the Signature on the first OpenSecureChannel response. The
  /// server sets it when it signs that response and the client when it verifies it. A renewal does not
  /// change it. Empty under a policy without SecureChannelEnhancements.
  ByteString channelThumbprint;

  /// Reassembled body of the message currently being processed.
  ByteString receivedMessageBody;
  /// Request id of the message currently being processed, correlating request and response.
  uint32_t receivedRequestId{};
  /// Number of chunks accumulated into @ref receivedMessageBody for the message currently being
  /// reassembled. Bounded against the negotiated MaxChunkCount and reset at each message boundary so a
  /// peer cannot stream unbounded Intermediate chunks (defensive inbound limit; see copy_message_body).
  uint32_t receivedChunkCount{0};

  /// Set by the decode finalizers when an abort chunk (IsFinal='A', Part 6 6.7.3) is received:
  /// {RequestId, decoded Error StatusCode}. The owning channel consumes and clears it after each
  /// decoded chunk to fail that one request without closing the channel.
  std::optional<std::pair<uint32_t, ua::StatusCode>> receivedAbort;
};

}  // namespace ua

#endif  // UA_SECURE_CHANNEL_CONTEXT_H
