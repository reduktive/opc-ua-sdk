// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STACK_UTILITIES_H
#define UA_STACK_UTILITIES_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_encoding_limits.h"
#include "ua_includes.h"
#include "ua_user_token_policy.h"
#include <algorithm>
#include <optional>

namespace ua
{

class RequestHeader;
class ResponseHeader;
class ServiceFault;
class X509Certificate;
class UaBinaryEncoder;
class UaBinaryDecoder;

namespace stack_utils
{

struct UaCpMessageHeader
{
  enum class MessageType
  {
    Hello,
    Acknowledge,
    Error,
    ReverseHello
  };

  MessageType messageType{MessageType::Hello};
  uint32_t messageSize{0};

  static constexpr size_t sizeInBytes{8};

  void encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const;
  void decode(const EncodingLimits& limits, UaBinaryDecoder& decoder);
};

struct UaScMessageHeader
{
  enum class MessageType
  {
    Message,
    Open,
    Close
  };

  enum class IsFinal
  {
    Intermediate,
    Final,
    Aborted
  };

  MessageType messageType{MessageType::Message};
  IsFinal isFinal{IsFinal::Intermediate};
  uint32_t messageChunkSize{0};
  uint32_t secureChannelId{0};

  static constexpr size_t sizeInBytes{12};

  void encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const;
  void decode(const EncodingLimits& limits, UaBinaryDecoder& decoder);
};

struct AsymmetricSecurityHeader
{
  std::string securityPolicyUri;
  shared_ptr<const X509Certificate> senderCertificate;
  std::vector<shared_ptr<const X509Certificate>> issuerCertificates;
  ByteString receiverCertificateThumbprint;

  // Decode metadata used for spec validations.
  // These are populated by `decode()`.
  size_t decodedSecurityPolicyUriSize{0};
  size_t decodedSenderCertificatesSize{0};
  size_t decodedReceiverThumbprintSize{0};

  size_t encoded_size(const EncodingLimits& limits) const;

  void encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const;
  /// Decodes the header and parses the SenderCertificate field into the leaf and its issuers. With
  /// @p receiveBufferSize, Part 6 section 6.7.2.3 is checked first: the SenderCertificate with its chain
  /// must fit one chunk and leave room for the SequenceHeader and one body byte, else Bad_DecodingError,
  /// before any certificate is parsed.
  void decode(const EncodingLimits& limits, UaBinaryDecoder& decoder, const Crypto& crypto,
    std::optional<size_t> receiveBufferSize = std::nullopt);
};

struct SymmetricSecurityHeader
{
  uint32_t tokenId{0};

  static constexpr size_t sizeInBytes{4};

  void encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const;
  void decode(const EncodingLimits& limits, UaBinaryDecoder& decoder);
};

struct SequenceHeader
{
  uint32_t sequenceNumber{0};
  uint32_t requestId{0};

  static constexpr size_t sizeInBytes{8};

  void encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const;
  void decode(const EncodingLimits& limits, UaBinaryDecoder& decoder);
};

bool test_and_set_sequence_no(uint32_t& previous, uint32_t received);
bool legacy_test_and_set_sequence_no(uint32_t& previous, uint32_t received);

CertificateStore::ApplicationCertificate get_local_cert_and_keys(
  span<CertificateStore::ApplicationCertificate> applicationCertificates, SecurityPolicyId securityPolicyId);

/// Resolves which server certificate type should be used for an endpoint.
/// For authenticated channels, returns the channel policy's certificate type.
/// For None channels, inspects user token policies to determine which certificate
/// the server needs to present (for password encryption, X509 token signatures, etc.).
/// Returns nullopt if no certificate is needed (pure anonymous endpoint on None channel).
optional<CertificateType> resolve_certificate_type_for_endpoint(
  SecurityPolicyId channelPolicyId, span<const UserTokenPolicy> userTokenPolicies);

/// Resolves the certificate type an endpoint presents, from the certificates the application holds. For an
/// authenticated channel this is the channel policy's type. For a None channel the certificate encrypts or
/// verifies the user tokens of every UserTokenPolicy that names a SecurityPolicy (OPC 10000-4 7.41.4 Table
/// 193), and one EndpointDescription carries one certificate, which "shall" be valid for all of them (OPC
/// 10000-6 6.8.3): the first held certificate that complies with every such policy is chosen, the type-only
/// resolution above preferred. Returns nullopt when no certificate is needed, or when none complies with
/// every policy (the server refuses that configuration at start).
optional<CertificateType> resolve_certificate_type_for_endpoint(SecurityPolicyId channelPolicyId,
  span<const UserTokenPolicy> userTokenPolicies,
  span<const CertificateStore::ApplicationCertificate> heldCertificates);

/// OPC 10000-4 1.05.07 sections 5.7.2 and 5.7.3: a Session nonce - the CreateSession clientNonce and the
/// CreateSession and ActivateSession serverNonce - "shall have a length between 32 and 128 bytes inclusive",
/// and the receiver checks it.
inline constexpr size_t minimumSessionNonceLength = 32;
inline constexpr size_t maximumSessionNonceLength = 128;

/// The Session nonce length over a channel whose SecureChannelNonceLength is @p channelNonceLength: that
/// length kept within the Session range. Only Basic128Rsa15 (16, owner decision 11) and RSA_DH (384, the
/// ffdhe3072 public value) differ from their channel nonce.
constexpr size_t session_nonce_length(size_t channelNonceLength) noexcept
{
  return std::clamp(channelNonceLength, minimumSessionNonceLength, maximumSessionNonceLength);
}

/// Resolves the Session nonce length for an endpoint.
/// For authenticated channels, returns @ref session_nonce_length of the channel policy's nonce length.
/// For None channels, returns @ref session_nonce_length of the longest nonce length across the
/// authenticated user token policies. Returns 0 if no authenticated token policies exist.
size_t resolve_nonce_length_for_endpoint(
  SecurityPolicyId channelPolicyId, span<const UserTokenPolicy> userTokenPolicies);

void prepare_response_header(const RequestHeader& requestHeader, ResponseHeader& responseHeader);

shared_ptr<ServiceFault> create_service_fault(const RequestHeader* requestHeader, StatusCode statusCode);

}  // namespace stack_utils

}  // namespace ua

#endif  // UA_STACK_UTILITIES_H
