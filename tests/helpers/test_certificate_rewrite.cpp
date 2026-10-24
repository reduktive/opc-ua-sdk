// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "test_certificate_rewrite.h"

#include "ua_x509_certificate.h"

#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace ua::test_certificates
{

std::shared_ptr<const X509Certificate> resign_with_ca_false(
  const Crypto& crypto, const X509Certificate& certificate, const AsymmetricKeyPair& issuerKeys)
{
  const auto der = certificate.der_encoding();
  const unsigned char* in = der.data();
  std::unique_ptr<X509, decltype(&X509_free)> edited{
    d2i_X509(nullptr, &in, static_cast<long>(der.size())), &X509_free};
  if (!edited)
    throw std::runtime_error{"d2i_X509 failed"};

  int critical = 1;
  if (const int at = X509_get_ext_by_NID(edited.get(), NID_basic_constraints, -1); at >= 0)
  {
    critical = X509_EXTENSION_get_critical(X509_get_ext(edited.get(), at));
    X509_EXTENSION_free(X509_delete_ext(edited.get(), at));
  }
  std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> constraints{
    BASIC_CONSTRAINTS_new(), &BASIC_CONSTRAINTS_free};
  if (!constraints)
    throw std::runtime_error{"BASIC_CONSTRAINTS_new failed"};
  constraints->ca = 0;
  if (X509_add1_ext_i2d(
        edited.get(), NID_basic_constraints, constraints.get(), critical, X509V3_ADD_DEFAULT) != 1)
    throw std::runtime_error{"replacing the BasicConstraints failed"};

  const auto pem = issuerKeys.private_key_pem();
  std::unique_ptr<BIO, decltype(&BIO_free)> bio{
    BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
  char passphrase[] = "password";
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
    PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, passphrase), &EVP_PKEY_free};
  if (!key)
    throw std::runtime_error{"reading the issuer's private key failed"};

  // The digest of the certificate's own signature algorithm. EdDSA signs without a separate digest, so it has
  // none and X509_sign takes a null one.
  int digestNid = NID_undef;
  if (OBJ_find_sigid_algs(X509_get_signature_nid(edited.get()), &digestNid, nullptr) != 1)
    throw std::runtime_error{"the certificate's signature algorithm is unknown"};
  const EVP_MD* digest = digestNid == NID_undef ? nullptr : EVP_get_digestbynid(digestNid);
  const int keyType = EVP_PKEY_id(key.get());
  if (digest == nullptr && keyType != EVP_PKEY_ED25519 && keyType != EVP_PKEY_ED448)
    throw std::runtime_error{"the certificate's signature has no digest the issuer's key can sign with"};
  if (X509_sign(edited.get(), key.get(), digest) <= 0)
    throw std::runtime_error{"signing the cA FALSE certificate failed"};

  unsigned char* out = nullptr;
  const int length = i2d_X509(edited.get(), &out);
  if (length <= 0)
    throw std::runtime_error{"i2d_X509 failed"};
  std::vector<byte> bytes(reinterpret_cast<const byte*>(out), reinterpret_cast<const byte*>(out) + length);
  OPENSSL_free(out);
  return crypto.read_certificate_from_der(span<const byte>{bytes});
}

}  // namespace ua::test_certificates
