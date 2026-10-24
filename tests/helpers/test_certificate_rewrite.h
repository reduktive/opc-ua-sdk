// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Certificates the SDK refuses to create, made for tests by editing one the SDK created.

#ifndef UA_TEST_HELPERS_TEST_CERTIFICATE_REWRITE_H
#define UA_TEST_HELPERS_TEST_CERTIFICATE_REWRITE_H

#include "ua_crypto.h"

#include <memory>

namespace ua::test_certificates
{

/// @p certificate with its BasicConstraints changed to cA FALSE (the extension's criticality kept) and signed
/// again by @p issuerKeys with the digest of its own signature; every other field, keyCertSign among them, is
/// kept. The result is an issuer that is not a CA. `Crypto::create_certificate` refuses keyCertSign with cA
/// FALSE on a certificate that is not self-signed (OPC 10000-6 6.2.2 asks for keyCertSign with cA FALSE only
/// on a self-signed certificate), so a test that needs such an issuer makes it here. Throws on any OpenSSL
/// failure.
std::shared_ptr<const X509Certificate> resign_with_ca_false(
  const Crypto& crypto, const X509Certificate& certificate, const AsymmetricKeyPair& issuerKeys);

}  // namespace ua::test_certificates

#endif  // UA_TEST_HELPERS_TEST_CERTIFICATE_REWRITE_H
