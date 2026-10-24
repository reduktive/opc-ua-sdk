// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_key_rules.h"

#include <algorithm>
#include <string>

#include "ua_x509_certificate.h"

namespace ua
{

namespace
{

bool is_eddsa_key(CertificateKeyAlgorithm algorithm)
{
  return algorithm == CertificateKeyAlgorithm::EccCurve25519 ||
         algorithm == CertificateKeyAlgorithm::EccCurve448;
}

bool is_ecdsa_key(CertificateKeyAlgorithm algorithm)
{
  return algorithm != CertificateKeyAlgorithm::Invalid && algorithm != CertificateKeyAlgorithm::Rsa &&
         !is_eddsa_key(algorithm);
}

std::optional<CertificateRuleViolation> check(const RsaCertificateRules& rules,
  const X509Certificate& certificate, const X509Certificate& /*signer*/,
  CertificateChainPosition /*position*/)
{
  // Part 6 section 6.1: MinAsymmetricKeyLength and MaxAsymmetricKeyLength apply to every certificate of
  // the chain, issuers included, and so does the CertificateSignatureAlgorithm. The algorithm names the
  // signer's key family, so the signer itself is not consulted.
  if (certificate.key_algorithm() != CertificateKeyAlgorithm::Rsa)
  {
    return CertificateRuleViolation{"CertificateKeyFamilyNotPermitted",
      "the certificate key is not an RSA key, which this RSA security policy requires"};
  }
  const auto bits = certificate.public_key_bit_length();
  if (bits < rules.minKeyLength || bits > rules.maxKeyLength)
  {
    return CertificateRuleViolation{"CertificateKeyLengthOutOfRange",
      "the RSA key length " + std::to_string(bits) + " lies outside [" + std::to_string(rules.minKeyLength) +
        ", " + std::to_string(rules.maxKeyLength) + "] bits"};
  }
  // An unclassified (Invalid) algorithm is never in the permitted set, so it is refused, not skipped.
  const auto algorithm = certificate.signature_algorithm();
  if (std::find(rules.signatureAlgorithms.begin(), rules.signatureAlgorithms.end(), algorithm) ==
      rules.signatureAlgorithms.end())
  {
    return CertificateRuleViolation{"CertificateSignatureAlgorithmNotPermitted",
      "the certificate signature algorithm (" + std::to_string(static_cast<int>(algorithm)) +
        ") is not a CertificateSignatureAlgorithm this security policy permits"};
  }
  return std::nullopt;
}

std::optional<CertificateRuleViolation> check(const EccCertificateRules& rules,
  const X509Certificate& certificate, const X509Certificate& signer, CertificateChainPosition position)
{
  const auto key = certificate.key_algorithm();
  const bool keyPermitted =
    key == rules.curve || (position == CertificateChainPosition::HigherCa && key == rules.higherCaCurve);
  if (!keyPermitted)
  {
    return CertificateRuleViolation{"CertificateKeyNotPermitted",
      "the certificate key is not on a curve this security policy permits at this chain position"};
  }

  const auto algorithm = certificate.signature_algorithm();
  const auto signerKey = signer.key_algorithm();
  if (is_eddsa_key(rules.curve))
  {
    // EdDSA: the signer is on the policy curve and the signature is PureEdDSA of that curve.
    const auto expected = rules.curve == CertificateKeyAlgorithm::EccCurve25519
                            ? CertificateSignatureAlgorithm::PureEdDsa25519
                            : CertificateSignatureAlgorithm::PureEdDsa448;
    if (signerKey != rules.curve || algorithm != expected)
    {
      return CertificateRuleViolation{"CertificateSignatureAlgorithmNotPermitted",
        "the certificate is not signed with PureEdDSA on this security policy's curve"};
    }
    return std::nullopt;
  }

  // ECDSA: the hash follows the size of the SIGNING key's curve - SHA-256 up to 256 bits, SHA-384 up to
  // 384 bits, SHA-512 above.
  if (!is_ecdsa_key(signerKey))
  {
    return CertificateRuleViolation{"CertificateSignatureAlgorithmNotPermitted",
      "the certificate is not signed with an ECDSA key, which this security policy requires"};
  }
  const auto signerBits = signer.public_key_bit_length();
  const auto expected = signerBits <= 256   ? CertificateSignatureAlgorithm::EcDsaSha2256
                        : signerBits <= 384 ? CertificateSignatureAlgorithm::EcDsaSha2384
                                            : CertificateSignatureAlgorithm::EcDsaSha2512;
  if (algorithm != expected)
  {
    return CertificateRuleViolation{"CertificateSignatureAlgorithmNotPermitted",
      "the certificate's ECDSA hash does not match the size of its signer's curve"};
  }
  return std::nullopt;
}

}  // namespace

std::optional<CertificateRuleViolation> check_certificate_key_rules(const CertificateKeyRules& rules,
  const X509Certificate& certificate, const X509Certificate& signer, CertificateChainPosition position)
{
  return std::visit([&](const auto& family) { return check(family, certificate, signer, position); }, rules);
}

CertificateKeyAlgorithm end_entity_key_algorithm(const CertificateKeyRules& rules) noexcept
{
  if (const auto* ecc = std::get_if<EccCertificateRules>(&rules))
  {
    return ecc->curve;
  }
  return CertificateKeyAlgorithm::Rsa;
}

}  // namespace ua
