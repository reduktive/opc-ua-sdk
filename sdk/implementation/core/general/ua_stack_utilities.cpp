// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_stack_utilities.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "ua_certificate_validation_paths.h"
#include "ua_connection_protocol_limits.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_null_stream.h"
#include "ua_security_policy.h"
#include "ua_resource_budgets.h"
#include "ua_application_configuration.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"
#include "ua_request_header.h"
#include "ua_response_header.h"
#include "ua_service_fault.h"

#include <algorithm>

namespace ua
{

namespace
{
static const std::array<byte, ua::connection_protocol::messageTypeSize> helMessageType{
  std::byte{'H'}, std::byte{'E'}, std::byte{'L'}};
static const std::array<byte, ua::connection_protocol::messageTypeSize> ackMessageType{
  std::byte{'A'}, std::byte{'C'}, std::byte{'K'}};
static const std::array<byte, ua::connection_protocol::messageTypeSize> errMessageType{
  std::byte{'E'}, std::byte{'R'}, std::byte{'R'}};
static const std::array<byte, ua::connection_protocol::messageTypeSize> rheMessageType{
  std::byte{'R'}, std::byte{'H'}, std::byte{'E'}};

static const std::array<byte, ua::connection_protocol::messageTypeSize> opnMessageType{
  std::byte{'O'}, std::byte{'P'}, std::byte{'N'}};
static const std::array<byte, ua::connection_protocol::messageTypeSize> cloMessageType{
  std::byte{'C'}, std::byte{'L'}, std::byte{'O'}};
static const std::array<byte, ua::connection_protocol::messageTypeSize> msgMessageType{
  std::byte{'M'}, std::byte{'S'}, std::byte{'G'}};
}  // namespace

namespace stack_utils
{

void UaCpMessageHeader::encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const
{
  const std::array<byte, ua::connection_protocol::messageTypeSize>* type = nullptr;

  switch (messageType)
  {
  case MessageType::Hello:
    type = &helMessageType;
    break;

  case MessageType::Acknowledge:
    type = &ackMessageType;
    break;

  case MessageType::Error:
    type = &errMessageType;
    break;

  case MessageType::ReverseHello:
    type = &rheMessageType;
    break;

  default:
    throw UaException{Status::BadInvalidArgument,
      make_error_detail(
        "InvalidMessageType", "Unknown CP message type in UaCpMessageHeader::encode", "StackUtilities")};
    break;
  }

  encoder.stream().write_all(*type);

  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, uint8_t{'F'});
  encoder.encode(limit, messageSize);
}

void UaCpMessageHeader::decode(const EncodingLimits& limits, UaBinaryDecoder& decoder)
{
  std::array<byte, ua::connection_protocol::messageTypeSize> wireType{};
  decoder.stream().read_all(wireType);

  if (std::ranges::equal(wireType, helMessageType))
  {
    messageType = MessageType::Hello;
  }
  else if (std::ranges::equal(wireType, ackMessageType))
  {
    messageType = MessageType::Acknowledge;
  }
  else if (std::ranges::equal(wireType, errMessageType))
  {
    messageType = MessageType::Error;
  }
  else if (std::ranges::equal(wireType, rheMessageType))
  {
    messageType = MessageType::ReverseHello;
  }
  else
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidMessageType", "Unrecognized CP message type in UaCpMessageHeader::decode", "StackUtilities")
        .context(ua::ContextKeys::actual,
          std::string(reinterpret_cast<const char*>(wireType.data()), wireType.size()))};
  }

  const StackDepth limit = limits.stack_depth();
  uint8_t reserved{0};
  decoder.decode(limit, reserved);

  decoder.decode(limit, messageSize);
}

void UaScMessageHeader::encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const
{
  const std::array<byte, ua::connection_protocol::messageTypeSize>* type = nullptr;

  switch (messageType)
  {
  case MessageType::Open:
    type = &opnMessageType;
    break;

  case MessageType::Message:
    type = &msgMessageType;
    break;

  case MessageType::Close:
    type = &cloMessageType;
    break;

  default:
    throw UaException{Status::BadInvalidArgument,
      make_error_detail(
        "InvalidMessageType", "Unknown SC message type in UaScMessageHeader::encode", "StackUtilities")};
    break;
  }

  uint8_t wireIsFinal{0};
  switch (isFinal)
  {
  case IsFinal::Final:
    wireIsFinal = 'F';
    break;

  case IsFinal::Intermediate:
    wireIsFinal = 'C';
    break;

  case IsFinal::Aborted:
    wireIsFinal = 'A';
    break;

  default:
    throw UaException{Status::BadInvalidArgument,
      make_error_detail(
        "InvalidIsFinalFlag", "Unknown IsFinal flag in UaScMessageHeader::encode", "StackUtilities")};
    break;
  }

  encoder.stream().write_all(*type);

  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, wireIsFinal);
  encoder.encode(limit, messageChunkSize);
  encoder.encode(limit, secureChannelId);
}

void UaScMessageHeader::decode(const EncodingLimits& limits, UaBinaryDecoder& decoder)
{
  std::array<byte, ua::connection_protocol::messageTypeSize> wireType{};
  decoder.stream().read_all(wireType);

  if (std::ranges::equal(wireType, opnMessageType))
  {
    messageType = MessageType::Open;
  }
  else if (std::ranges::equal(wireType, msgMessageType))
  {
    messageType = MessageType::Message;
  }
  else if (std::ranges::equal(wireType, cloMessageType))
  {
    messageType = MessageType::Close;
  }
  else
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidMessageType", "Unrecognized SC message type in UaScMessageHeader::decode", "StackUtilities")
        .context(ua::ContextKeys::actual,
          std::string(reinterpret_cast<const char*>(wireType.data()), wireType.size()))};
  }

  const StackDepth limit = limits.stack_depth();
  uint8_t wireIsFinal{0};
  decoder.decode(limit, wireIsFinal);
  if (wireIsFinal == 'F')
  {
    isFinal = IsFinal::Final;
  }
  else if (wireIsFinal == 'C')
  {
    isFinal = IsFinal::Intermediate;
  }
  else if (wireIsFinal == 'A')
  {
    isFinal = IsFinal::Aborted;
  }
  else
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidIsFinalFlag", "Unrecognized IsFinal flag in UaScMessageHeader::decode", "StackUtilities")
        .context(ua::ContextKeys::actual, std::to_string(wireIsFinal))};
  }

  decoder.decode(limit, messageChunkSize);
  decoder.decode(limit, secureChannelId);
}

size_t AsymmetricSecurityHeader::encoded_size(const EncodingLimits& limits) const
{
  NullStream stream;
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encode(limits, encoder);
  return stream.get_position();
}

void AsymmetricSecurityHeader::encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const
{
  const StackDepth limit = limits.stack_depth();

  encoder.encode(limit, securityPolicyUri);

  if (senderCertificate)
  {
    std::vector<shared_ptr<const X509Certificate>> certificates;
    certificates.push_back(senderCertificate);
    certificates.insert(certificates.end(), issuerCertificates.begin(), issuerCertificates.end());

    ByteString certs;
    for (auto& cert : certificates)
    {
      check(cert);
      auto der = cert->der_encoding();

      auto& certsPayload = certs.payload();
      certsPayload.insert(certsPayload.end(), der.begin(), der.end());
    }

    encoder.encode(limit, certs);
  }
  else
  {
    encoder.encode(limit, ByteString{});
  }

  encoder.encode(limit, receiverCertificateThumbprint);
}

void AsymmetricSecurityHeader::decode(const EncodingLimits& limits, UaBinaryDecoder& decoder,
  const Crypto& crypto, std::optional<size_t> receiveBufferSize)
{
  const StackDepth limit = limits.stack_depth();

  decoder.decode(limit, securityPolicyUri);

  // Part 6 requires SecurityPolicyUriLength <= 255 bytes.
  // We enforce this based on the decoded UTF-8 string length.
  decodedSecurityPolicyUriSize = securityPolicyUri.size();
  check_true(decodedSecurityPolicyUriSize <= 255, Status::BadDecodingError);

  ByteString senderCertificates;
  decoder.decode(limit, senderCertificates);
  decodedSenderCertificatesSize = senderCertificates.size();

  decoder.decode(limit, receiverCertificateThumbprint);
  decodedReceiverThumbprintSize = receiverCertificateThumbprint.size();

  // Part 6 section 6.7.2.3: the SenderCertificate, including its chain, fits one chunk with room for the
  // SequenceHeader and at least one body byte. Checked on the field's length before anything is parsed.
  if (receiveBufferSize)
  {
    const size_t overhead = UaScMessageHeader::sizeInBytes + sizeof(int32_t) + decodedSecurityPolicyUriSize +
                            sizeof(int32_t) + sizeof(int32_t) + decodedReceiverThumbprintSize +
                            SequenceHeader::sizeInBytes + 1;
    check_true(*receiveBufferSize > overhead, Status::BadDecodingError);
    check_true(decodedSenderCertificatesSize <= *receiveBufferSize - overhead, Status::BadDecodingError);
  }

  if (!senderCertificates.empty())
  {
    // The one chain parser for OPC UA certificate fields (leaf first, then the presented issuers).
    auto parsed = ua::detail::parse_certificate_field(crypto, senderCertificates);
    if (!parsed.is_good())
    {
      throw UaException{parsed.status_code()};
    }
    issuerCertificates = std::move(parsed).value();
    senderCertificate = issuerCertificates.front();
    issuerCertificates.erase(issuerCertificates.begin());
  }
}

void SymmetricSecurityHeader::encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const
{
  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, tokenId);
}

void SymmetricSecurityHeader::decode(const EncodingLimits& limits, UaBinaryDecoder& decoder)
{
  const StackDepth limit = limits.stack_depth();
  decoder.decode(limit, tokenId);
}

void SequenceHeader::encode(const EncodingLimits& limits, UaBinaryEncoder& encoder) const
{
  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, sequenceNumber);
  encoder.encode(limit, requestId);
}

void SequenceHeader::decode(const EncodingLimits& limits, UaBinaryDecoder& decoder)
{
  const StackDepth limit = limits.stack_depth();
  decoder.decode(limit, sequenceNumber);
  decoder.decode(limit, requestId);
}

bool test_and_set_sequence_no(uint32_t& previous, uint32_t received)
{
  auto expected = previous + 1;
  auto pass = (expected == received);
  if (pass)
  {
    previous = received;
  }

  return pass;
}

bool legacy_test_and_set_sequence_no(uint32_t& previous, uint32_t received)
{
  constexpr uint32_t low{1024};
  constexpr uint32_t high{std::numeric_limits<uint32_t>::max() - low};

  auto expected = previous + 1;
  if (previous <= high)
  {
    if (received == expected)
    {
      previous = received;
      return true;
    }
    else
    {
      return false;
    }
  }
  else
  {
    // Can wrap around at any time
    if ((received == expected) || (received < low))
    {
      previous = received;
      return true;
    }
    else
    {
      return false;
    }
  }
}

CertificateStore::ApplicationCertificate get_local_cert_and_keys(
  span<CertificateStore::ApplicationCertificate> applicationCertificates, SecurityPolicyId securityPolicyId)
{
  auto securityPolicy = SecurityPolicy::create(securityPolicyId);

  for (auto& cert : applicationCertificates)
  {
    if (cert.certificateType == securityPolicy->certificate_type())
    {
      check(cert.certificate);
      check(cert.keys);

      return cert;
    }
  }
  throw UaException{Status::BadNotFound,
    ErrorDetail::build("CertificateTypeNotFound",
      "Requested certificate type not found for the given security policy",
      "StackUtilities")
      .context(ua::ContextKeys::securityPolicy, utils::get_security_policy_uri(securityPolicyId))};
}

namespace
{

// Certificate compatibility family - policies within a family can coexist on one endpoint.
enum class CertFamily
{
  None,
  Rsa,
  NistEcc,
  BrainpoolEcc,
  Ed25519,
  Ed448
};

CertFamily classify_certificate_type(CertificateType certType)
{
  switch (certType)
  {
  case CertificateType::RsaMinApplication:
  case CertificateType::RsaSha256Application:
    return CertFamily::Rsa;
  case CertificateType::EccNistP256Application:
  case CertificateType::EccNistP384Application:
    return CertFamily::NistEcc;
  case CertificateType::EccBrainpoolP256r1Application:
  case CertificateType::EccBrainpoolP384r1Application:
    return CertFamily::BrainpoolEcc;
  case CertificateType::EccCurve25519Application:
    return CertFamily::Ed25519;
  case CertificateType::EccCurve448Application:
    return CertFamily::Ed448;
  default:
    return CertFamily::None;
  }
}

// Within a family, resolve to the preferred (strongest) certificate type.
CertificateType resolve_within_family(CertFamily family, bool hasP384OrHigher)
{
  switch (family)
  {
  case CertFamily::Rsa:
    return CertificateType::RsaSha256Application;
  case CertFamily::NistEcc:
    return hasP384OrHigher ? CertificateType::EccNistP384Application
                           : CertificateType::EccNistP256Application;
  case CertFamily::BrainpoolEcc:
    return hasP384OrHigher ? CertificateType::EccBrainpoolP384r1Application
                           : CertificateType::EccBrainpoolP256r1Application;
  case CertFamily::Ed25519:
    return CertificateType::EccCurve25519Application;
  case CertFamily::Ed448:
    return CertificateType::EccCurve448Application;
  default:
    return CertificateType::Invalid;
  }
}

bool is_p384_or_higher(CertificateType certType)
{
  return certType == CertificateType::EccNistP384Application ||
         certType == CertificateType::EccBrainpoolP384r1Application;
}

}  // namespace

optional<CertificateType> resolve_certificate_type_for_endpoint(
  SecurityPolicyId channelPolicyId, span<const UserTokenPolicy> userTokenPolicies)
{
  auto channelPolicy = SecurityPolicy::create(channelPolicyId);
  if (channelPolicy->is_authenticated())
    return channelPolicy->certificate_type();

  // None channel: scan user token policies for authenticated security policies.
  CertFamily resolvedFamily = CertFamily::None;
  bool hasP384 = false;

  for (const auto& tokenPolicy : userTokenPolicies)
  {
    const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
    if (tokenPolicyUri.empty())
      continue;

    auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
    if (tokenPolicyId == SecurityPolicyId::None || tokenPolicyId == SecurityPolicyId::Invalid)
      continue;

    auto policy = SecurityPolicy::create(tokenPolicyId);
    auto certType = policy->certificate_type();
    auto family = classify_certificate_type(certType);
    if (family == CertFamily::None)
      continue;

    if (resolvedFamily == CertFamily::None)
    {
      resolvedFamily = family;
    }
    // If families differ, the validation step should have rejected this config already.
    // But be defensive: use whichever family we saw first.

    if (is_p384_or_higher(certType))
      hasP384 = true;
  }

  if (resolvedFamily == CertFamily::None)
    return std::nullopt;

  return resolve_within_family(resolvedFamily, hasP384);
}

optional<CertificateType> resolve_certificate_type_for_endpoint(SecurityPolicyId channelPolicyId,
  span<const UserTokenPolicy> userTokenPolicies,
  span<const CertificateStore::ApplicationCertificate> heldCertificates)
{
  auto channelPolicy = SecurityPolicy::create(channelPolicyId);
  if (channelPolicy->is_authenticated())
    return channelPolicy->certificate_type();

  // The SecurityPolicies the user tokens of this endpoint are secured with (Table 193: the token policy's
  // own, the channel's None meaning no protection).
  std::vector<std::shared_ptr<const SecurityPolicy>> tokenPolicies;
  for (const auto& tokenPolicy : userTokenPolicies)
  {
    const auto& uri = tokenPolicy.security_policy_uri();
    if (uri.empty())
      continue;
    const auto id = utils::get_security_policy_id(uri);
    if (id == SecurityPolicyId::None || id == SecurityPolicyId::Invalid)
      continue;
    if (std::ranges::none_of(tokenPolicies, [id](const auto& known) { return known->id() == id; }))
      tokenPolicies.push_back(SecurityPolicy::create(id));
  }
  if (tokenPolicies.empty())
    return std::nullopt;

  const auto compliesWithEveryTokenPolicy = [&](const CertificateStore::ApplicationCertificate& held)
  {
    if (!held.certificate)
      return false;
    const X509Certificate& signer = held.issuerCertificates.empty() || !held.issuerCertificates.front()
                                      ? *held.certificate
                                      : *held.issuerCertificates.front();
    return std::ranges::all_of(tokenPolicies,
      [&](const auto& policy)
      {
        try
        {
          return policy
            ->check_certificate_compliance(*held.certificate, signer, CertificateChainPosition::EndEntity)
            .is_good();
        }
        catch (...)
        {
          return false;
        }
      });
  };

  // The type-only resolution is the preferred certificate; any other held certificate valid for every token
  // policy is the alternative.
  const auto preferred = resolve_certificate_type_for_endpoint(channelPolicyId, userTokenPolicies);
  if (preferred)
  {
    const auto entry = std::ranges::find(
      heldCertificates, *preferred, &CertificateStore::ApplicationCertificate::certificateType);
    if (entry != heldCertificates.end() && compliesWithEveryTokenPolicy(*entry))
      return preferred;
  }
  for (const auto& held : heldCertificates)
  {
    if (compliesWithEveryTokenPolicy(held))
      return held.certificateType;
  }
  return std::nullopt;
}

size_t resolve_nonce_length_for_endpoint(
  SecurityPolicyId channelPolicyId, span<const UserTokenPolicy> userTokenPolicies)
{
  auto channelPolicy = SecurityPolicy::create(channelPolicyId);
  // Session nonces are 32 to 128 bytes whatever the channel's SecureChannelNonceLength (Part 4 1.05.07
  // 5.7.2, 5.7.3).
  if (channelPolicy->is_authenticated())
    return session_nonce_length(channelPolicy->nonce_length());

  // None channel: max nonce length across authenticated user token policies, floor of 32.
  size_t maxNonce = 0;

  for (const auto& tokenPolicy : userTokenPolicies)
  {
    const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
    if (tokenPolicyUri.empty())
      continue;

    auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
    if (tokenPolicyId == SecurityPolicyId::None || tokenPolicyId == SecurityPolicyId::Invalid)
      continue;

    auto policy = SecurityPolicy::create(tokenPolicyId);
    maxNonce = std::max(maxNonce, policy->nonce_length());
  }

  if (maxNonce == 0)
    return 0;

  return session_nonce_length(maxNonce);
}

void prepare_response_header(const RequestHeader& requestHeader, ResponseHeader& responseHeader)
{
  responseHeader.timestamp() = DateTime::now();
  responseHeader.request_handle() = requestHeader.request_handle();
}

shared_ptr<ServiceFault> create_service_fault(const RequestHeader* requestHeader, StatusCode statusCode)
{
  auto serviceFault = make_shared<ServiceFault>();
  if (requestHeader)
  {
    prepare_response_header(*requestHeader, serviceFault->response_header());
  }
  serviceFault->response_header().service_result() = statusCode;
  return serviceFault;
}

}  // namespace stack_utils

}  // namespace ua
