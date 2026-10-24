// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ua_crypto.h"

using namespace ua;

TEST(GeneralTests, Padding)
{
  // CryptoOpenSsl crypto{[]()
  //   {
  //     return SecureString{"password"};
  //   }};
  //
  // size_t keyLengthInBytes{64};
  // auto keyPair = crypto.create_asymmetric_key_pair(CertificateKeyAlgorithm::Rsa, keyLengthInBytes *
  // CHAR_BIT);
  //
  // std::vector<byte> plaintext;
  // plaintext.resize(50);
  // crypto.get_entropy(plaintext);
  //
  // std::vector<byte> signature;
  // signature.resize(128);
  //
  // span<byte> sig{signature};
  //
  // EXPECT_NO_THROW(
  //   crypto.asymmetric_sign(AsymmetricSignatureAlgorithm::RsaPssSha2_256, keyPair, plaintext, sig));
}
