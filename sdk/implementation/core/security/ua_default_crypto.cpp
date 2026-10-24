// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_crypto.h"

#include "ua_crypto_openssl.h"

namespace ua
{

shared_ptr<const Crypto> create_default_crypto()
{
  return CryptoOpenSsl::create();
}

shared_ptr<const Crypto> create_default_crypto(
  Crypto::PrivateKeyCredentialCallback privateKeyCredentialCallback)
{
  return CryptoOpenSsl::create(std::move(privateKeyCredentialCallback));
}

}  // namespace ua
