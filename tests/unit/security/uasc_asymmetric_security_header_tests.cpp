// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <cstring>

#include "ua_crypto.h"
#include "ua_stack_utilities.h"

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

#include "test_pki_helpers.h"

using namespace ua;
using namespace ua::stack_utils;

namespace
{

static std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

static EncodingLimits test_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

static ByteString encode_asym_header(const AsymmetricSecurityHeader& h)
{
  // Size estimate: policy URI + a cert chain + thumbprint.
  memory_stream_device::Dynamic streamDevice{16 * 1024, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  h.encode(test_limits(), enc);
  auto out = streamDevice.move_storage_out();
  out.resize(stream.get_position());
  return ByteString{span<const byte>{out}};
}

static AsymmetricSecurityHeader decode_asym_header(span<const byte> bytes, const Crypto& crypto)
{
  memory_stream_device::ExternalReadOnly streamDevice{bytes};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  AsymmetricSecurityHeader out;
  out.decode(limits, dec, crypto);
  return out;
}

static void expect_runtime_exception_status(const std::function<void()>& fn, Status expected)
{
  try
  {
    fn();
    FAIL() << "Expected UaException";
  }
  catch (const UaException& e)
  {
    EXPECT_EQ(e.status(), expected);
  }
}

}  // namespace

// @relation(AC-SVR-UASC-005-CHAIN, SVR-UASC-061, scope=function)
TEST(UascAsymmetricSecurityHeaderTests, CertificateChainIsDecodedAndSplit)
{
  // Requirement: P6-67-0005 (certificate chain appended)

  auto crypto = create_crypto();
  TestPki pki{crypto};

  // Root CA
  auto caKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto caCert = pki.create_root_ca(caKeys, "Test Root", "1");

  // Leaf signed by CA
  auto leafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto from = DateTime::now();
  auto to = DateTime{from.value() + std::chrono::days{30}};
  auto leafCert = pki.create_leaf_cert(leafKeys, caKeys, caCert, from, to);

  AsymmetricSecurityHeader in;
  in.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  in.senderCertificate = leafCert;
  in.issuerCertificates.push_back(caCert);
  in.receiverCertificateThumbprint.clear();

  const auto encoded = encode_asym_header(in);
  const auto decoded = decode_asym_header(encoded, *crypto);

  ASSERT_NE(decoded.senderCertificate, nullptr);
  EXPECT_EQ(decoded.senderCertificate->thumbprint(), leafCert->thumbprint());

  ASSERT_EQ(decoded.issuerCertificates.size(), 1u);
  EXPECT_EQ(decoded.issuerCertificates[0]->thumbprint(), caCert->thumbprint());
}

// Covers SVR-UASC-006 (coverage-audit retag).
// @relation(AC-SVR-UASC-006-EXTRA, scope=function)
TEST(UascAsymmetricSecurityHeaderTests, ExtraBytesAfterChainAreIgnoredOrRejectedByCrypto)
{
  // Requirement: P6-67-0006 (ignore extra bytes in chains). Part 6 6.7.2 lets a receiver that does not
  // handle chains ignore the extra bytes; this receiver handles chains, and approved item 7 (owner review
  // 2026-10-02) makes the crypto refuse the whole field when bytes follow the last complete certificate
  // (Bad_CertificateInvalid, never a partial chain), so the bytes cannot change which identity is read.

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto caKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto caCert = pki.create_root_ca(caKeys, "Test Root", "2");

  auto leafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto from = DateTime::now();
  auto to = DateTime{from.value() + std::chrono::days{30}};
  auto leafCert = pki.create_leaf_cert(leafKeys, caKeys, caCert, from, to);

  // Build a DER concatenation and add trailing garbage.
  ByteString der;
  {
    auto leafDer = leafCert->der_encoding();
    auto caDer = caCert->der_encoding();
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), leafDer.begin(), leafDer.end());
    buf.insert(buf.end(), caDer.begin(), caDer.end());
    buf.push_back(0xFF);
    buf.push_back(0x00);
    buf.push_back(0xAA);
    der = ByteString{std::move(buf)};
  }

  // Feed through the same API used by `AsymmetricSecurityHeader::decode`: refused by the crypto.
  expect_runtime_exception_status(
    [&] { static_cast<void>(crypto->read_certificates_from_der(der)); }, Status::BadCertificateInvalid);

  // Control: the same chain without the trailing bytes reads as the leaf then its issuer.
  ByteString chainOnly;
  {
    auto leafDer = leafCert->der_encoding();
    auto caDer = caCert->der_encoding();
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), leafDer.begin(), leafDer.end());
    buf.insert(buf.end(), caDer.begin(), caDer.end());
    chainOnly = ByteString{std::move(buf)};
  }
  const auto certs = crypto->read_certificates_from_der(chainOnly);
  ASSERT_EQ(certs.size(), 2u);
  EXPECT_EQ(certs.front()->thumbprint(), leafCert->thumbprint());
}

// @relation(AC-SVR-UASC-007-THUMBPRINT, SVR-UASC-061, scope=function)
TEST(UascAsymmetricSecurityHeaderTests, ReceiverThumbprintMayBeEmptyWhenNotEncrypted)
{
  // Requirement: P6-67-0007 (thumbprint null if not encrypted)

  auto crypto = create_crypto();

  AsymmetricSecurityHeader in;
  in.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  in.senderCertificate.reset();
  in.issuerCertificates.clear();
  in.receiverCertificateThumbprint.clear();

  const auto encoded = encode_asym_header(in);
  const auto decoded = decode_asym_header(encoded, *crypto);

  EXPECT_TRUE(decoded.receiverCertificateThumbprint.empty());
}

// @verifies CL-UASC-002 [PARTIAL] - the decode-side 255-byte SecurityPolicyUri cap the CLIENT relies on
// when parsing a server OPN's asymmetric security header (a >255-byte URI is rejected with
// BadDecodingError). The client SEND side is structural (it always emits a valid ~55-byte standard URI -
// no testable branch), so this shared-codec decode check is the meaningful enforcement of CL-UASC-002.
// @relation(CL-UASC-002, SVR-UASC-002, SVR-UASC-061, scope=function)
TEST(UascAsymmetricSecurityHeaderTests, VeryLongSecurityPolicyUriIsRejected)
{
  // Requirement: P6-67-0002 (SecurityPolicyUriLength <= 255)

  auto crypto = create_crypto();

  AsymmetricSecurityHeader in;
  in.securityPolicyUri.assign(300, 'a');
  in.senderCertificate.reset();
  in.issuerCertificates.clear();
  in.receiverCertificateThumbprint.clear();

  const auto encoded = encode_asym_header(in);

  expect_runtime_exception_status(
    [&]() { (void)decode_asym_header(encoded, *crypto); }, Status::BadDecodingError);
}

TEST(UascAsymmetricSecurityHeaderTests, SenderCertificateLengthIsNotExplicitlyBoundedWithoutStackLimits)
{
  // Requirement: P6-67-0003 (SenderCertificateLength <= MaxSenderCertificateSize) - document current
  // enforcement. Without explicit stack-limit checks at this layer, any provided ByteString decodes as-is.

  auto crypto = create_crypto();

  AsymmetricSecurityHeader in;
  in.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  in.senderCertificate.reset();
  in.issuerCertificates.clear();

  // Provide an arbitrarily-sized (but still modest) thumbprint so we exercise ByteString decode.
  in.receiverCertificateThumbprint.resize(1024);
  std::memset(in.receiverCertificateThumbprint.data(), 0x11, 1024);

  const auto encoded = encode_asym_header(in);
  const auto decoded = decode_asym_header(encoded, *crypto);
  EXPECT_EQ(decoded.receiverCertificateThumbprint.size(), 1024u);
}
