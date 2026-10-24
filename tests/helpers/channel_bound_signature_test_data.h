// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_CHANNEL_BOUND_SIGNATURE_TEST_DATA_H
#define UA_TESTS_HELPERS_CHANNEL_BOUND_SIGNATURE_TEST_DATA_H

#include "ua_byte_string.h"
#include "ua_channel_bound_signature_data.h"
#include "ua_crypto.h"
#include "ua_security_policy.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <iterator>
#include <memory>

namespace ua::test_helpers
{

/// The DER of @p certificate, or nothing for a null one.
inline ByteString der_or_empty(const std::shared_ptr<const X509Certificate>& certificate)
{
  return certificate ? certificate->der_encoding() : ByteString{};
}

/// The data a session signature signs (OPC 10000-4 section 6.1.8 Table 101), assembled here from
/// @p crypto's synchronous digest rather than by the SDK's builder, which the checked-in vectors cover
/// (ChannelBoundSignatureData.*). HASH is @p decidingPolicy's CertificateThumbprintAlgorithm; an empty
/// certificate hashes to nothing.
inline ByteString channel_bound_data(const Crypto& crypto, const SecurityPolicy& decidingPolicy,
  ChannelBoundSignature signature, const ChannelBoundSignatureInputs& inputs)
{
  ByteString data;
  const auto append = [&data](const ByteString& bytes)
  {
    std::ranges::copy(bytes, std::back_inserter(data));
  };
  const auto appendHash = [&](const ByteString& certificate)
  {
    if (!certificate.empty())
      append(crypto.calculate_digest_sync(decidingPolicy.certificate_thumbprint_algorithm(), certificate));
  };
  switch (signature)
  {
  case ChannelBoundSignature::Server:
    append(inputs.channelThumbprint);
    append(inputs.clientNonce);
    appendHash(inputs.serverChannelCertificate);
    appendHash(inputs.clientChannelCertificate);
    append(inputs.serverNonce);
    break;
  case ChannelBoundSignature::Client:
    append(inputs.channelThumbprint);
    append(inputs.serverNonce);
    appendHash(inputs.serverCertificate);
    appendHash(inputs.serverChannelCertificate);
    appendHash(inputs.clientChannelCertificate);
    append(inputs.clientNonce);
    break;
  case ChannelBoundSignature::UserToken:
    append(inputs.channelThumbprint);
    append(inputs.serverNonce);
    appendHash(inputs.serverCertificate);
    appendHash(inputs.serverChannelCertificate);
    appendHash(inputs.clientCertificate);
    appendHash(inputs.clientChannelCertificate);
    append(inputs.clientNonce);
    break;
  case ChannelBoundSignature::UserTokenOverNone:
    append(inputs.serverNonce);
    appendHash(inputs.serverCertificate);
    append(inputs.clientNonce);
    break;
  }
  return data;
}

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_CHANNEL_BOUND_SIGNATURE_TEST_DATA_H
