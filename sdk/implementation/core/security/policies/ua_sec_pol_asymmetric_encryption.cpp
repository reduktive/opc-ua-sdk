// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_asymmetric_encryption.h"

#include "ua_certificate_key_rules.h"

namespace ua
{

bool SecPolAsymmetricEncryption::is_rsa() const
{
  return true;
}

bool SecPolAsymmetricEncryption::is_ecc() const
{
  return false;
}

VoidResult SecPolAsymmetricEncryption::check_certificate_compliance(
  const X509Certificate& certificate, const X509Certificate& signer, CertificateChainPosition position) const
{
  const CertificateKeyRules rules{RsaCertificateRules{
    min_asymmetric_key_length(), max_asymmetric_key_length(), certificate_signature_algorithms()}};
  if (const auto violation = check_certificate_key_rules(rules, certificate, signer, position))
  {
    return certificate_policy_refusal(violation->rule, violation->summary, certificate, position);
  }
  return {};
}

}  // namespace ua
