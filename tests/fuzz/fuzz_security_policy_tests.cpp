// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fuzz_security_policy.h"
#include "ua_security_policy.h"

#include <gtest/gtest.h>

namespace
{

// The decorator stands in for the policy it wraps, so every query a caller classifies or sizes a policy by
// must give the wrapped policy's answer (the certificate-dependent sizes need a certificate and are not
// asked). Key agreement is classified by ephemeral_key_algorithm(): a decorator that answered Invalid would
// send a random nonce on an ephemeral-key channel instead of a public key.
// @relation(AC-COMP-SECPOL-ROWS-WRAPPER-CLASSIFIES-AS-THE-WRAPPED-POLICY, scope=function)
TEST(FuzzSecurityPolicy, AnswersEveryClassificationQueryAsTheWrappedPolicy)
{
  for (const auto policyId : ua::SecurityPolicy::supported_policy_ids())
  {
    SCOPED_TRACE(static_cast<int>(policyId));
    auto inner = ua::SecurityPolicy::create(policyId);
    ASSERT_NE(inner, nullptr);
    const opcua_fuzzer::FuzzSecurityPolicy fuzz{inner};

    EXPECT_EQ(fuzz.id(), inner->id());
    EXPECT_EQ(fuzz.uri(), inner->uri());
    EXPECT_EQ(fuzz.certificate_type(), inner->certificate_type());
    EXPECT_EQ(fuzz.is_authenticated(), inner->is_authenticated());
    EXPECT_EQ(fuzz.is_rsa(), inner->is_rsa());
    EXPECT_EQ(fuzz.is_ecc(), inner->is_ecc());
    EXPECT_EQ(fuzz.uses_legacy_sequence_no(), inner->uses_legacy_sequence_no());
    EXPECT_EQ(fuzz.is_deprecated(), inner->is_deprecated());
    EXPECT_EQ(fuzz.ephemeral_key_algorithm(), inner->ephemeral_key_algorithm());
    EXPECT_EQ(fuzz.secure_channel_enhancements(), inner->secure_channel_enhancements());
    EXPECT_EQ(fuzz.certificate_thumbprint_algorithm(), inner->certificate_thumbprint_algorithm());
    EXPECT_EQ(fuzz.nonce_length(), inner->nonce_length());
    EXPECT_EQ(fuzz.symmetric_plaintext_block_size(), inner->symmetric_plaintext_block_size());
    EXPECT_EQ(fuzz.symmetric_ciphertext_block_size(), inner->symmetric_ciphertext_block_size());
    EXPECT_EQ(fuzz.symmetric_signature_size(), inner->symmetric_signature_size());
    EXPECT_EQ(fuzz.symmetric_signature_key_size(), inner->symmetric_signature_key_size());
    EXPECT_EQ(fuzz.symmetric_encryption_key_size(), inner->symmetric_encryption_key_size());
    EXPECT_EQ(fuzz.symmetric_iv_size(), inner->symmetric_iv_size());
    EXPECT_EQ(fuzz.min_asymmetric_key_length(), inner->min_asymmetric_key_length());
    EXPECT_EQ(fuzz.max_asymmetric_key_length(), inner->max_asymmetric_key_length());
    EXPECT_EQ(fuzz.asymmetric_encryption_algorithm(), inner->asymmetric_encryption_algorithm());
    EXPECT_EQ(fuzz.asymmetric_signature_algorithm(), inner->asymmetric_signature_algorithm());
    EXPECT_EQ(fuzz.asymmetric_signature_algorithm_uri(), inner->asymmetric_signature_algorithm_uri());
    EXPECT_EQ(fuzz.symmetric_encryption_algorithm(), inner->symmetric_encryption_algorithm());
    EXPECT_EQ(fuzz.symmetric_signature_algorithm(), inner->symmetric_signature_algorithm());
  }
}

}  // namespace
