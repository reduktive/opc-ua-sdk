// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Certificate validation matrices U7 (security-policy deviations) and U6 (certificate errors), from
// the certificate-validation test plan.
//
// Every expected status in this file comes from an ORACLE function or table below that encodes the
// specification and calls no SDK code: for U7 the OPC Foundation profile database entries of each
// SecurityPolicy (CertificateSignatureAlgorithm, MinAsymmetricKeyLength, MaxAsymmetricKeyLength and the
// curve rules) with OPC 10000-6 section 6.1 (the rules apply to every certificate of the chain, and an
// issuer has a key at least as long and an algorithm of at least the priority of what it issues); for U6
// OPC 10000-4 Table 106 with the oracle corrections and owner decisions recorded in the plan. A case the code
// disagrees with is a defect in the code, not in the expectation.
//
// Every certificate here is built directly with OpenSSL (the SDK's certificate factory cannot produce most of
// the deviations), then parsed with Crypto::read_certificate_from_der so the SDK sees exactly the bytes a
// peer would send.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "certificate_validation_request_helpers.h"
#include "certificate_store_test_backends.h"
#include "run_async_sync.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_certificate_store_files.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_exceptions.h"
#include "ua_security_policy.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

namespace fs = std::filesystem;
using namespace ua;

namespace
{

// ---------------------------------------------------------------------------------------------------------
// OpenSSL certificate and CRL construction (test-local; no SDK code).
// ---------------------------------------------------------------------------------------------------------

template<typename T, void (*Free)(T*)>
struct OpenSslDeleter
{
  void operator()(T* p) const
  {
    Free(p);
  }
};

using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, &X509_free>>;
using X509CrlPtr = std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, &X509_CRL_free>>;
using X509NamePtr = std::unique_ptr<X509_NAME, OpenSslDeleter<X509_NAME, &X509_NAME_free>>;
using X509ExtensionPtr =
  std::unique_ptr<X509_EXTENSION, OpenSslDeleter<X509_EXTENSION, &X509_EXTENSION_free>>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, &BN_free>>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, OpenSslDeleter<ASN1_INTEGER, &ASN1_INTEGER_free>>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, OpenSslDeleter<ASN1_TIME, &ASN1_TIME_free>>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, OpenSslDeleter<ASN1_OBJECT, &ASN1_OBJECT_free>>;
using Asn1OctetStringPtr =
  std::unique_ptr<ASN1_OCTET_STRING, OpenSslDeleter<ASN1_OCTET_STRING, &ASN1_OCTET_STRING_free>>;
using Asn1EnumeratedPtr =
  std::unique_ptr<ASN1_ENUMERATED, OpenSslDeleter<ASN1_ENUMERATED, &ASN1_ENUMERATED_free>>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, OpenSslDeleter<EVP_MD_CTX, &EVP_MD_CTX_free>>;
using PKey = std::shared_ptr<EVP_PKEY>;
using Der = std::vector<unsigned char>;

void require(bool condition, const char* what)
{
  if (!condition)
  {
    ERR_clear_error();
    throw std::runtime_error{std::string{"test PKI construction failed: "} + what};
  }
}

/// A key family, and for ECC and EdDSA the curve.
enum class KeyKind
{
  Rsa,
  P256,
  P384,
  P521,
  Bp256,
  Bp384,
  Bp512,
  Ed25519,
  Ed448,
};

struct KeySpec
{
  KeyKind kind = KeyKind::Rsa;
  int rsaBits = 2048;  ///< Only for KeyKind::Rsa.
};

KeySpec rsa_key(int bits)
{
  KeySpec spec;
  spec.kind = KeyKind::Rsa;
  spec.rsaBits = bits;
  return spec;
}

KeySpec curve_key(KeyKind kind)
{
  KeySpec spec;
  spec.kind = kind;
  spec.rsaBits = 0;
  return spec;
}

bool is_ecdsa_key(KeyKind kind)
{
  return kind == KeyKind::P256 || kind == KeyKind::P384 || kind == KeyKind::P521 || kind == KeyKind::Bp256 ||
         kind == KeyKind::Bp384 || kind == KeyKind::Bp512;
}

/// The key length in bits as OPC 10000-7 counts it (Ed448 is 456 bits).
int key_bits(const KeySpec& key)
{
  switch (key.kind)
  {
  case KeyKind::Rsa:
    return key.rsaBits;
  case KeyKind::P256:
  case KeyKind::Bp256:
  case KeyKind::Ed25519:
    return 256;
  case KeyKind::P384:
  case KeyKind::Bp384:
    return 384;
  case KeyKind::P521:
    return 521;
  case KeyKind::Bp512:
    return 512;
  case KeyKind::Ed448:
    return 456;
  }
  return 0;
}

std::string key_label(const KeySpec& key)
{
  switch (key.kind)
  {
  case KeyKind::Rsa:
    return "Rsa" + std::to_string(key.rsaBits);
  case KeyKind::P256:
    return "NistP256";
  case KeyKind::P384:
    return "NistP384";
  case KeyKind::P521:
    return "NistP521";
  case KeyKind::Bp256:
    return "BrainpoolP256r1";
  case KeyKind::Bp384:
    return "BrainpoolP384r1";
  case KeyKind::Bp512:
    return "BrainpoolP512r1";
  case KeyKind::Ed25519:
    return "Ed25519";
  case KeyKind::Ed448:
    return "Ed448";
  }
  return "Unknown";
}

/// The shared test key cache's name for @p spec.
test_keys::KeyType key_type(const KeySpec& spec)
{
  switch (spec.kind)
  {
  case KeyKind::Rsa:
    switch (spec.rsaBits)
    {
    case 512:
      return test_keys::KeyType::Rsa512;
    case 1024:
      return test_keys::KeyType::Rsa1024;
    case 1025:
      return test_keys::KeyType::Rsa1025;
    case 1500:
      return test_keys::KeyType::Rsa1500;
    case 2048:
      return test_keys::KeyType::Rsa2048;
    case 2049:
      return test_keys::KeyType::Rsa2049;
    case 3000:
      return test_keys::KeyType::Rsa3000;
    case 3072:
      return test_keys::KeyType::Rsa3072;
    case 4096:
      return test_keys::KeyType::Rsa4096;
    case 8192:
      return test_keys::KeyType::Rsa8192;
    default:
      throw std::logic_error{"the test key cache has no RSA " + std::to_string(spec.rsaBits) + " key type"};
    }
  case KeyKind::P256:
    return test_keys::KeyType::P256;
  case KeyKind::P384:
    return test_keys::KeyType::P384;
  case KeyKind::P521:
    return test_keys::KeyType::P521;
  case KeyKind::Bp256:
    return test_keys::KeyType::Bp256;
  case KeyKind::Bp384:
    return test_keys::KeyType::Bp384;
  case KeyKind::Bp512:
    return test_keys::KeyType::Bp512;
  case KeyKind::Ed25519:
    return test_keys::KeyType::Ed25519;
  case KeyKind::Ed448:
    return test_keys::KeyType::Ed448;
  }
  throw std::logic_error{"unknown key kind"};
}

/// The key in @p slot of @p spec's type, from the shared test key cache (generated once per machine, so
/// RSA 8192 costs its generation once). A slot names the chain position, so no two certificates of one chain
/// share a key. Null when this OpenSSL build cannot create the key type.
PKey cached_key(const KeySpec& spec, unsigned slot)
{
  return PKey{test_keys::new_evp_pkey(key_type(spec), slot), &EVP_PKEY_free};
}

/// The digest of a certificate signature. None is a pure EdDSA signature.
enum class Digest
{
  Sha1,
  Sha224,
  Sha256,
  Sha384,
  Sha512,
  None,
};

const EVP_MD* evp_md(Digest digest)
{
  switch (digest)
  {
  case Digest::Sha1:
    return EVP_sha1();
  case Digest::Sha224:
    return EVP_sha224();
  case Digest::Sha256:
    return EVP_sha256();
  case Digest::Sha384:
    return EVP_sha384();
  case Digest::Sha512:
    return EVP_sha512();
  case Digest::None:
    return nullptr;
  }
  return nullptr;
}

std::string digest_label(Digest digest)
{
  switch (digest)
  {
  case Digest::Sha1:
    return "Sha1";
  case Digest::Sha224:
    return "Sha224";
  case Digest::Sha256:
    return "Sha256";
  case Digest::Sha384:
    return "Sha384";
  case Digest::Sha512:
    return "Sha512";
  case Digest::None:
    return "PureEdDsa";
  }
  return "Unknown";
}

/// What a test certificate carries. Every field has a value that yields a conformant certificate; a case
/// changes the one field its defect is about.
struct CertSpec
{
  std::string commonName = "Test Certificate";
  bool emptySubject = false;
  long version = 3;
  std::string serialHex = "1000";
  bool negativeSerial = false;
  long notBeforeOffsetSeconds = -3600;
  long notAfterOffsetSeconds = 30L * 24 * 60 * 60;
  std::string notBeforeText;  ///< When set, an RFC 5280 time string used instead of the offset.
  std::string notAfterText;
  std::string rawNotBefore;  ///< When set, written into the UTCTime as-is (a malformed time).
  std::string rawNotAfter;
  bool hasBasicConstraints = true;
  bool ca = false;
  std::optional<long> pathLength;
  std::string keyUsage;  ///< OpenSSL configuration syntax; empty omits the extension.
  std::string extendedKeyUsage;
  std::string subjectAltName;
  std::string subjectKeyIdentifier = "hash";  ///< "hash" or a colon-separated hex value.
  bool authorityKeyIdentifier = true;  ///< Added to a certificate a CA issues.
  bool duplicateBasicConstraints = false;
  bool unknownCriticalExtension = false;
};

constexpr const char* rsaLeafKeyUsage =
  "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment";
constexpr const char* eccLeafKeyUsage = "critical,digitalSignature,nonRepudiation";
constexpr const char* caKeyUsage = "critical,digitalSignature,keyCertSign,cRLSign";
constexpr const char* leafExtendedKeyUsage = "serverAuth,clientAuth";

CertSpec ca_spec(const std::string& commonName, const std::string& serialHex)
{
  CertSpec spec;
  spec.commonName = commonName;
  spec.serialHex = serialHex;
  spec.ca = true;
  spec.keyUsage = caKeyUsage;
  spec.notAfterOffsetSeconds = 365L * 24 * 60 * 60;
  return spec;
}

CertSpec leaf_spec(const std::string& commonName, const std::string& serialHex, KeyKind keyKind,
  const std::string& subjectAltName)
{
  CertSpec spec;
  spec.commonName = commonName;
  spec.serialHex = serialHex;
  spec.ca = false;
  spec.keyUsage = keyKind == KeyKind::Rsa ? rsaLeafKeyUsage : eccLeafKeyUsage;
  spec.extendedKeyUsage = leafExtendedKeyUsage;
  spec.subjectAltName = subjectAltName;
  return spec;
}

void set_time(ASN1_TIME* time, long offsetSeconds, const std::string& text, const std::string& raw)
{
  if (!raw.empty())
  {
    require(X509_gmtime_adj(time, 0) != nullptr, "X509_gmtime_adj");
    require(ASN1_STRING_set(time, raw.data(), static_cast<int>(raw.size())) == 1, "ASN1_STRING_set time");
    return;
  }
  if (!text.empty())
  {
    require(ASN1_TIME_set_string_X509(time, text.c_str()) == 1, "ASN1_TIME_set_string_X509");
    return;
  }
  require(X509_gmtime_adj(time, offsetSeconds) != nullptr, "X509_gmtime_adj");
}

void add_extension(X509* certificate, X509* issuer, int nid, const std::string& value)
{
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer != nullptr ? issuer : certificate, certificate, nullptr, nullptr, 0);
  X509ExtensionPtr extension{X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str())};
  require(extension != nullptr, "X509V3_EXT_conf_nid");
  require(X509_add_ext(certificate, extension.get(), -1) == 1, "X509_add_ext");
}

void sign_certificate(X509* certificate, EVP_PKEY* signerKey, Digest digest, bool pss)
{
  if (pss)
  {
    EvpMdCtxPtr mdCtx{EVP_MD_CTX_new()};
    require(mdCtx != nullptr, "EVP_MD_CTX_new");
    EVP_PKEY_CTX* pkeyCtx = nullptr;
    require(EVP_DigestSignInit(mdCtx.get(), &pkeyCtx, evp_md(digest), nullptr, signerKey) == 1,
      "EVP_DigestSignInit");
    require(EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) > 0, "set PSS padding");
    require(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) > 0, "set PSS salt length");
    require(X509_sign_ctx(certificate, mdCtx.get()) > 0, "X509_sign_ctx");
    return;
  }
  // An EdDSA signer signs without a separate digest.
  const bool pure = EVP_PKEY_id(signerKey) == EVP_PKEY_ED25519 || EVP_PKEY_id(signerKey) == EVP_PKEY_ED448;
  require(X509_sign(certificate, signerKey, pure ? nullptr : evp_md(digest)) > 0, "X509_sign");
}

/// Builds a certificate for @p subjectKey. @p issuer null means self-signed (named by its own subject);
/// otherwise the certificate is named as issued by @p issuer and signed with @p signerKey, which is normally
/// the issuer's key and is a different key only to forge an issuer.
X509Ptr build_certificate(const CertSpec& spec, EVP_PKEY* subjectKey, X509* issuer, EVP_PKEY* signerKey,
  Digest digest, bool pss = false)
{
  X509Ptr certificate{X509_new()};
  require(certificate != nullptr, "X509_new");
  require(X509_set_version(certificate.get(), spec.version - 1) == 1, "X509_set_version");

  BIGNUM* rawSerial = nullptr;
  require(BN_hex2bn(&rawSerial, spec.serialHex.c_str()) > 0, "BN_hex2bn");
  BignumPtr serialNumber{rawSerial};
  if (spec.negativeSerial)
  {
    BN_set_negative(serialNumber.get(), 1);
  }
  Asn1IntegerPtr serial{BN_to_ASN1_INTEGER(serialNumber.get(), nullptr)};
  require(serial != nullptr && X509_set_serialNumber(certificate.get(), serial.get()) == 1, "serial");

  X509NamePtr name{X509_NAME_new()};
  require(name != nullptr, "X509_NAME_new");
  if (!spec.emptySubject)
  {
    require(X509_NAME_add_entry_by_txt(name.get(),
              "CN",
              MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>(spec.commonName.c_str()),
              -1,
              -1,
              0) == 1,
      "CN");
    require(
      X509_NAME_add_entry_by_txt(
        name.get(), "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("reduktive test"), -1, -1, 0) ==
        1,
      "O");
  }
  require(X509_set_subject_name(certificate.get(), name.get()) == 1, "subject");
  require(X509_set_issuer_name(
            certificate.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name.get()) == 1,
    "issuer");

  set_time(X509_getm_notBefore(certificate.get()),
    spec.notBeforeOffsetSeconds,
    spec.notBeforeText,
    spec.rawNotBefore);
  set_time(
    X509_getm_notAfter(certificate.get()), spec.notAfterOffsetSeconds, spec.notAfterText, spec.rawNotAfter);
  require(X509_set_pubkey(certificate.get(), subjectKey) == 1, "X509_set_pubkey");

  if (spec.hasBasicConstraints)
  {
    std::string value = spec.ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
    if (spec.pathLength)
    {
      value += ",pathlen:" + std::to_string(*spec.pathLength);
    }
    add_extension(certificate.get(), issuer, NID_basic_constraints, value);
    if (spec.duplicateBasicConstraints)
    {
      add_extension(certificate.get(), issuer, NID_basic_constraints, value);
    }
  }
  if (!spec.keyUsage.empty())
  {
    add_extension(certificate.get(), issuer, NID_key_usage, spec.keyUsage);
  }
  if (!spec.extendedKeyUsage.empty())
  {
    add_extension(certificate.get(), issuer, NID_ext_key_usage, spec.extendedKeyUsage);
  }
  if (!spec.subjectAltName.empty())
  {
    add_extension(certificate.get(), issuer, NID_subject_alt_name, spec.subjectAltName);
  }
  add_extension(certificate.get(), issuer, NID_subject_key_identifier, spec.subjectKeyIdentifier);
  if (issuer != nullptr && spec.authorityKeyIdentifier)
  {
    add_extension(certificate.get(), issuer, NID_authority_key_identifier, "keyid:always");
  }
  if (spec.unknownCriticalExtension)
  {
    Asn1ObjectPtr oid{OBJ_txt2obj("1.3.6.1.4.1.55555.1.1", 1)};
    Asn1OctetStringPtr value{ASN1_OCTET_STRING_new()};
    const unsigned char derNull[] = {0x05, 0x00};
    require(oid != nullptr && value != nullptr && ASN1_OCTET_STRING_set(value.get(), derNull, 2) == 1,
      "unknown extension value");
    X509ExtensionPtr extension{X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 1, value.get())};
    require(extension != nullptr && X509_add_ext(certificate.get(), extension.get(), -1) == 1,
      "unknown critical extension");
  }

  sign_certificate(certificate.get(), signerKey, digest, pss);
  return certificate;
}

Der der_of(X509* certificate)
{
  const int length = i2d_X509(certificate, nullptr);
  require(length > 0, "i2d_X509 length");
  Der der(static_cast<std::size_t>(length));
  unsigned char* out = der.data();
  require(i2d_X509(certificate, &out) == length, "i2d_X509");
  return der;
}

std::vector<ua::byte> to_ua_bytes(const Der& der)
{
  std::vector<ua::byte> bytes(der.size());
  std::transform(
    der.begin(), der.end(), bytes.begin(), [](unsigned char c) { return static_cast<ua::byte>(c); });
  return bytes;
}

/// The SDK's view of the bytes: what a peer's certificate becomes when it is read off the wire.
std::shared_ptr<const X509Certificate> to_sdk_certificate(const Crypto& crypto, const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return crypto.read_certificate_from_der(span<const ua::byte>{bytes});
}

std::string skid_hex(X509* certificate)
{
  const ASN1_OCTET_STRING* skid = X509_get0_subject_key_id(certificate);
  require(skid != nullptr, "subject key identifier");
  char* hex = OPENSSL_buf2hexstr(ASN1_STRING_get0_data(skid), ASN1_STRING_length(skid));
  require(hex != nullptr, "OPENSSL_buf2hexstr");
  std::string value{hex};
  OPENSSL_free(hex);
  return value;
}

/// One revoked entry of a CRL; @c reason below zero leaves the reasonCode extension out.
struct CrlEntry
{
  std::string serialHex;
  int reason = -1;
};

Der build_crl(X509* issuer, EVP_PKEY* issuerKey, const std::vector<CrlEntry>& entries,
  long lastUpdateOffsetSeconds = -3600, long nextUpdateOffsetSeconds = 7L * 24 * 60 * 60)
{
  X509CrlPtr crl{X509_CRL_new()};
  require(crl != nullptr, "X509_CRL_new");
  require(X509_CRL_set_version(crl.get(), 1) == 1, "X509_CRL_set_version");
  require(X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) == 1, "CRL issuer");
  Asn1TimePtr lastUpdate{ASN1_TIME_new()};
  Asn1TimePtr nextUpdate{ASN1_TIME_new()};
  require(lastUpdate != nullptr && nextUpdate != nullptr, "ASN1_TIME_new");
  require(X509_gmtime_adj(lastUpdate.get(), lastUpdateOffsetSeconds) != nullptr, "lastUpdate");
  require(X509_gmtime_adj(nextUpdate.get(), nextUpdateOffsetSeconds) != nullptr, "nextUpdate");
  require(X509_CRL_set1_lastUpdate(crl.get(), lastUpdate.get()) == 1, "set lastUpdate");
  require(X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get()) == 1, "set nextUpdate");

  for (const auto& entry : entries)
  {
    X509_REVOKED* revoked = X509_REVOKED_new();
    require(revoked != nullptr, "X509_REVOKED_new");
    BIGNUM* rawSerial = nullptr;
    require(BN_hex2bn(&rawSerial, entry.serialHex.c_str()) > 0, "revoked serial");
    BignumPtr serialNumber{rawSerial};
    Asn1IntegerPtr serial{BN_to_ASN1_INTEGER(serialNumber.get(), nullptr)};
    Asn1TimePtr revocationDate{ASN1_TIME_new()};
    require(serial != nullptr && revocationDate != nullptr &&
              X509_gmtime_adj(revocationDate.get(), -1800) != nullptr &&
              X509_REVOKED_set_serialNumber(revoked, serial.get()) == 1 &&
              X509_REVOKED_set_revocationDate(revoked, revocationDate.get()) == 1,
      "revoked entry");
    if (entry.reason >= 0)
    {
      Asn1EnumeratedPtr reason{ASN1_ENUMERATED_new()};
      require(reason != nullptr && ASN1_ENUMERATED_set(reason.get(), entry.reason) == 1 &&
                X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, reason.get(), 0, 0) == 1,
        "reasonCode");
    }
    require(X509_CRL_add0_revoked(crl.get(), revoked) == 1, "X509_CRL_add0_revoked");
  }

  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, nullptr, nullptr, crl.get(), 0);
  X509ExtensionPtr akid{X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always")};
  require(akid != nullptr && X509_CRL_add_ext(crl.get(), akid.get(), -1) == 1, "CRL authorityKeyIdentifier");
  Asn1IntegerPtr crlNumber{ASN1_INTEGER_new()};
  require(crlNumber != nullptr && ASN1_INTEGER_set(crlNumber.get(), 1) == 1 &&
            X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, crlNumber.get(), 0, 0) == 1,
    "CRL number");
  require(X509_CRL_sort(crl.get()) == 1, "X509_CRL_sort");
  require(X509_CRL_sign(crl.get(), issuerKey, EVP_sha256()) > 0, "X509_CRL_sign");

  const int length = i2d_X509_CRL(crl.get(), nullptr);
  require(length > 0, "i2d_X509_CRL length");
  Der der(static_cast<std::size_t>(length));
  unsigned char* out = der.data();
  require(i2d_X509_CRL(crl.get(), &out) == length, "i2d_X509_CRL");
  return der;
}

// ---------------------------------------------------------------------------------------------------------
// U7: the oracle. The OPC Foundation profile database entries and
// OPC 10000-6 section 6.1. Written from the specification only.
// ---------------------------------------------------------------------------------------------------------

enum class PolicyFamily
{
  Rsa,
  Ecc,
  EdDsa,
};

/// One SecurityPolicy's certificate requirements as the profile database states them.
struct PolicyRule
{
  SecurityPolicyId id = SecurityPolicyId::Invalid;
  const char* name = "";
  PolicyFamily family = PolicyFamily::Rsa;
  int minRsaBits = 0;  ///< RSA: MinAsymmetricKeyLength.
  int maxRsaBits = 0;  ///< RSA: MaxAsymmetricKeyLength.
  bool sha1Permitted = false;  ///< RSA: "RSA-PKCS15-SHA1, and SHA2 224/256/384/512 may be used instead".
  KeyKind endEntityCurve = KeyKind::Rsa;  ///< ECC/EdDSA: the end entity and the CA that issues it.
  KeyKind otherCaCurve = KeyKind::Rsa;  ///< ECC: the larger curve other CAs may use.
};

PolicyRule rsa_rule(SecurityPolicyId id, const char* name, int minBits, int maxBits, bool sha1Permitted)
{
  PolicyRule rule;
  rule.id = id;
  rule.name = name;
  rule.family = PolicyFamily::Rsa;
  rule.minRsaBits = minBits;
  rule.maxRsaBits = maxBits;
  rule.sha1Permitted = sha1Permitted;
  return rule;
}

PolicyRule curve_rule(
  SecurityPolicyId id, const char* name, PolicyFamily family, KeyKind endEntity, KeyKind otherCa)
{
  PolicyRule rule;
  rule.id = id;
  rule.name = name;
  rule.family = family;
  rule.endEntityCurve = endEntity;
  rule.otherCaCurve = otherCa;
  return rule;
}

/// Every SecurityPolicy the SDK implements that validates a certificate (sdk/implementation/core/security/
/// policies), with the profile database's rules.
std::vector<PolicyRule> implemented_policy_rules()
{
  return {
    rsa_rule(SecurityPolicyId::Basic128Rsa15, "Basic128Rsa15", 1024, 2048, true),
    rsa_rule(SecurityPolicyId::Basic256, "Basic256", 1024, 2048, true),
    rsa_rule(SecurityPolicyId::Basic256Sha256, "Basic256Sha256", 2048, 4096, false),
    rsa_rule(SecurityPolicyId::Aes128Sha256RsaOaep, "Aes128Sha256RsaOaep", 2048, 4096, false),
    rsa_rule(SecurityPolicyId::Aes256Sha256RsaPss, "Aes256Sha256RsaPss", 2048, 4096, false),
    curve_rule(
      SecurityPolicyId::EccNistP256AesGcm, "EccNistP256", PolicyFamily::Ecc, KeyKind::P256, KeyKind::P384),
    curve_rule(
      SecurityPolicyId::EccNistP384AesGcm, "EccNistP384", PolicyFamily::Ecc, KeyKind::P384, KeyKind::P521),
    curve_rule(SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      "EccBrainpoolP256r1",
      PolicyFamily::Ecc,
      KeyKind::Bp256,
      KeyKind::Bp384),
    curve_rule(SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      "EccBrainpoolP384r1",
      PolicyFamily::Ecc,
      KeyKind::Bp384,
      KeyKind::Bp512),
    curve_rule(SecurityPolicyId::EccCurve25519ChaChaPoly,
      "EccCurve25519",
      PolicyFamily::EdDsa,
      KeyKind::Ed25519,
      KeyKind::Ed25519),
    curve_rule(SecurityPolicyId::EccCurve448ChaChaPoly,
      "EccCurve448",
      PolicyFamily::EdDsa,
      KeyKind::Ed448,
      KeyKind::Ed448),
    // The other AEAD of each curve has the same certificate rules in the profile database, and RSA_DH
    // those of the SHA-2 RSA policies (the profile of each row is cited in
    // ua_sec_pol_ephemeral_key_rows.cpp).
    curve_rule(SecurityPolicyId::EccNistP256ChaChaPoly,
      "EccNistP256ChaChaPoly",
      PolicyFamily::Ecc,
      KeyKind::P256,
      KeyKind::P384),
    curve_rule(SecurityPolicyId::EccNistP384ChaChaPoly,
      "EccNistP384ChaChaPoly",
      PolicyFamily::Ecc,
      KeyKind::P384,
      KeyKind::P521),
    curve_rule(SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      "EccBrainpoolP256r1ChaChaPoly",
      PolicyFamily::Ecc,
      KeyKind::Bp256,
      KeyKind::Bp384),
    curve_rule(SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      "EccBrainpoolP384r1ChaChaPoly",
      PolicyFamily::Ecc,
      KeyKind::Bp384,
      KeyKind::Bp512),
    curve_rule(SecurityPolicyId::EccCurve25519AesGcm,
      "EccCurve25519AesGcm",
      PolicyFamily::EdDsa,
      KeyKind::Ed25519,
      KeyKind::Ed25519),
    curve_rule(SecurityPolicyId::EccCurve448AesGcm,
      "EccCurve448AesGcm",
      PolicyFamily::EdDsa,
      KeyKind::Ed448,
      KeyKind::Ed448),
    rsa_rule(SecurityPolicyId::RsaDhAesGcm, "RsaDhAesGcm", 2048, 4096, false),
    rsa_rule(SecurityPolicyId::RsaDhChaChaPoly, "RsaDhChaChaPoly", 2048, 4096, false),
  };
}

/// One certificate of a chain: its key, and the signature its issuer (itself, for the root) put on it.
struct ChainNode
{
  KeySpec key;
  Digest digest = Digest::Sha256;
  bool pss = false;
};

ChainNode chain_node(const KeySpec& key, Digest digest, bool pss = false)
{
  ChainNode node;
  node.key = key;
  node.digest = digest;
  node.pss = pss;
  return node;
}

/// The profile database's ECDSA rule: the hash follows the size of the SIGNING key's curve. "SHA2-256 if the
/// key is 256 bits or less, SHA2-384 if 257 to 384 bits, SHA2-512 above."
Digest ecdsa_digest_for(int signingKeyBits)
{
  if (signingKeyBits <= 256)
  {
    return Digest::Sha256;
  }
  if (signingKeyBits <= 384)
  {
    return Digest::Sha384;
  }
  return Digest::Sha512;
}

/// The order of increasing priority in which a CertificateSignatureAlgorithm lists its algorithms
/// (OPC 10000-6 section 6.1): SHA-1 first, then SHA-2 by length.
int digest_priority(Digest digest)
{
  switch (digest)
  {
  case Digest::Sha1:
    return 1;
  case Digest::Sha224:
    return 2;
  case Digest::Sha256:
    return 3;
  case Digest::Sha384:
    return 4;
  case Digest::Sha512:
    return 5;
  case Digest::None:
    return 0;
  }
  return 0;
}

/// @param position The index in the chain: 0 the leaf, 1 the CA that issued it, 2 and above every CA above
/// the issuing CA up to and including the self-signed root.
bool key_complies(const PolicyRule& rule, const KeySpec& key, std::size_t position)
{
  switch (rule.family)
  {
  case PolicyFamily::Rsa:
    return key.kind == KeyKind::Rsa && key.rsaBits >= rule.minRsaBits && key.rsaBits <= rule.maxRsaBits;
  case PolicyFamily::Ecc:
    // "An end entity Certificate shall use <curve>. A CA that issues end entity Certificates shall use
    // <curve>. Other CAs may use <larger>." Other CAs are every CA above the issuing CA, the root included.
    if (position < 2)
    {
      return key.kind == rule.endEntityCurve;
    }
    return key.kind == rule.endEntityCurve || key.kind == rule.otherCaCurve;
  case PolicyFamily::EdDsa:
    return key.kind == rule.endEntityCurve;
  }
  return false;
}

bool signature_complies(const PolicyRule& rule, const KeySpec& signerKey, const ChainNode& node)
{
  switch (rule.family)
  {
  case PolicyFamily::Rsa:
    // RSASSA-PKCS1-v1_5 only: never PSS, ECDSA or EdDSA.
    if (signerKey.kind != KeyKind::Rsa || node.pss)
    {
      return false;
    }
    if (rule.sha1Permitted)
    {
      return node.digest != Digest::None;
    }
    return node.digest == Digest::Sha256 || node.digest == Digest::Sha384 || node.digest == Digest::Sha512;
  case PolicyFamily::Ecc:
    return is_ecdsa_key(signerKey.kind) && !node.pss && node.digest == ecdsa_digest_for(key_bits(signerKey));
  case PolicyFamily::EdDsa:
    return signerKey.kind == rule.endEntityCurve;
  }
  return false;
}

/// OPC 10000-4 Table 106 step 4 for the chain chain[0] (the leaf) <- chain[1] (the issuing CA) <- ... <-
/// chain.back() (the self-signed root): every certificate's key and signature comply with the policy (the
/// signature on chain[i] is judged against the key of its signer chain[i + 1], the root's against its own
/// key), and on every edge the issuer's key is at least as long as the key of the certificate it issued and
/// the issuer's algorithm is of at least the priority of that certificate's (OPC 10000-6 section 6.1).
/// Bad_CertificatePolicyCheckFailed has no issuer variant, and the check is never suppressed (owner decision
/// 22.3).
Status policy_oracle(const PolicyRule& rule, const std::vector<ChainNode>& chain)
{
  for (std::size_t position = 0; position < chain.size(); ++position)
  {
    const auto& node = chain[position];
    const bool isRoot = position + 1 == chain.size();
    const auto& signer = isRoot ? node : chain[position + 1];
    if (!key_complies(rule, node.key, position) || !signature_complies(rule, signer.key, node))
    {
      return Status::BadCertificatePolicyCheckFailed;
    }
    if (!isRoot)
    {
      if (key_bits(node.key) > key_bits(signer.key))
      {
        return Status::BadCertificatePolicyCheckFailed;
      }
      if (digest_priority(node.digest) > digest_priority(signer.digest))
      {
        return Status::BadCertificatePolicyCheckFailed;
      }
    }
  }
  return Status::Good;
}

// ---------------------------------------------------------------------------------------------------------
// U7: the cases. Every chain is chain[0] the leaf, chain[1] the issuing CA, chain[2..] the CAs above it and
// chain.back() the self-signed root, for chains of 3, 4 and 5 certificates. Arms are generated per position
// and per edge, not as a cross product.
// ---------------------------------------------------------------------------------------------------------

constexpr std::size_t chainLengths[] = {3, 4, 5};

/// Completeness review C7: the short chains. Length 1 is a self-signed leaf (it is its own root); length 2 is
/// leaf <- root, where the root is the issuing CA and so is held to the end-entity rules (profile database:
/// "A CA that issues end entity Certificates shall use <curve>"). Generated by add_short_chain_cases with the
/// arms that exist at these lengths; the oracle is the same policy_oracle.
constexpr std::size_t shortChainLengths[] = {1, 2};

struct PolicyCase
{
  PolicyRule rule;
  std::string arm;
  std::vector<ChainNode> chain;
};

PolicyCase policy_case(const PolicyRule& rule, const std::string& arm, std::vector<ChainNode> chain)
{
  PolicyCase c;
  c.rule = rule;
  c.arm = "Chain" + std::to_string(chain.size()) + "_" + arm;
  c.chain = std::move(chain);
  return c;
}

/// The name of a chain position: Leaf, IssuingCa, Ca2 (the first CA above the issuing CA), Ca3, Root.
std::string position_name(std::size_t position, std::size_t length)
{
  if (position == 0)
  {
    return "Leaf";
  }
  if (position + 1 == length)
  {
    return "Root";
  }
  if (position == 1)
  {
    return "IssuingCa";
  }
  return "Ca" + std::to_string(position);
}

/// The signature a signer with @p signerKey puts on a certificate when the arm is not about the signature:
/// ECDSA with the hash the profile database pairs with the signing curve, pure EdDSA, or RSA with SHA-256.
Digest natural_digest(const KeySpec& signerKey)
{
  if (is_ecdsa_key(signerKey.kind))
  {
    return ecdsa_digest_for(key_bits(signerKey));
  }
  if (signerKey.kind == KeyKind::Ed25519 || signerKey.kind == KeyKind::Ed448)
  {
    return Digest::None;
  }
  return Digest::Sha256;
}

/// A chain of the keys @p keys, each certificate signed by the next one's key (the root by its own) with
/// natural_digest.
std::vector<ChainNode> signed_chain(const std::vector<KeySpec>& keys)
{
  std::vector<ChainNode> chain;
  for (std::size_t i = 0; i < keys.size(); ++i)
  {
    chain.push_back(chain_node(keys[i], natural_digest(keys[std::min(i + 1, keys.size() - 1)])));
  }
  return chain;
}

/// The RSA key lengths of a chain of @p length certificates with @p bits at @p position and every other
/// position at its baseline (the leaf at the minimum, every CA at the maximum), adjusted so that every edge
/// stays monotonic: a certificate below the position is no longer than @p bits, an issuer above it no
/// shorter. Only the length range is then under test.
std::vector<int> rsa_bits_at(const PolicyRule& rule, std::size_t length, std::size_t position, int bits)
{
  std::vector<int> result;
  for (std::size_t i = 0; i < length; ++i)
  {
    const int baseline = i == 0 ? rule.minRsaBits : rule.maxRsaBits;
    if (i < position)
    {
      result.push_back(std::min(baseline, bits));
    }
    else if (i == position)
    {
      result.push_back(bits);
    }
    else
    {
      result.push_back(std::max(baseline, bits));
    }
  }
  return result;
}

/// An RSA chain with the key lengths @p bits: the leaf signed with SHA-256 and every CA with SHA-512, the
/// highest priority every RSA policy permits. A signer below 1024 bits signs with SHA-256: a 512-bit modulus
/// cannot carry a SHA-512 PKCS#1 v1.5 signature.
std::vector<ChainNode> rsa_chain(const std::vector<int>& bits)
{
  std::vector<ChainNode> chain;
  for (std::size_t i = 0; i < bits.size(); ++i)
  {
    const int signerBits = bits[std::min(i + 1, bits.size() - 1)];
    const auto digest = i == 0 || signerBits < 1024 ? Digest::Sha256 : Digest::Sha512;
    chain.push_back(chain_node(rsa_key(bits[i]), digest));
  }
  return chain;
}

/// The lower-priority of two digests.
Digest lower_priority(Digest a, Digest b)
{
  return digest_priority(a) <= digest_priority(b) ? a : b;
}

void add_rsa_policy_cases(const PolicyRule& rule, std::size_t length, std::vector<PolicyCase>& cases)
{
  const int minBits = rule.minRsaBits;
  const int maxBits = rule.maxRsaBits;
  // Realistic sizes either side of the range: 1023 and 4097 are not generable key lengths.
  const int belowMin = minBits == 1024 ? 512 : 1024;
  const int aboveMax = maxBits == 2048 ? 3072 : 8192;
  const auto baseline = rsa_chain(rsa_bits_at(rule, length, 0, minBits));

  cases.push_back(policy_case(rule, "Compliant", baseline));

  struct Algorithm
  {
    const char* label;
    Digest digest;
    bool pss;
  };

  const Algorithm algorithms[] = {
    {"RsaPkcs15Sha1", Digest::Sha1, false},
    {"RsaPkcs15Sha224", Digest::Sha224, false},
    {"RsaPkcs15Sha256", Digest::Sha256, false},
    {"RsaPkcs15Sha384", Digest::Sha384, false},
    {"RsaPkcs15Sha512", Digest::Sha512, false},
    {"RsaPssSha256", Digest::Sha256, true},
  };

  for (std::size_t position = 0; position < length; ++position)
  {
    const auto name = position_name(position, length);

    // MinAsymmetricKeyLength / MaxAsymmetricKeyLength, min-1 / min / max / max+1, on every certificate
    // (OPC 10000-6 6.1: "apply to all Certificates (including Issuers in the chain)"). A key above the
    // maximum keeps the issuers above it as long, so the arm breaks the range and not monotonicity.
    for (const int bits : {belowMin, minBits, maxBits, aboveMax})
    {
      cases.push_back(policy_case(
        rule, name + "KeyRsa" + std::to_string(bits), rsa_chain(rsa_bits_at(rule, length, position, bits))));
    }
    // Sizes inside the range that are not one of Part 12's CertificateType sizes: the Security Policy Check
    // is a range check (Table 106 cites only MinAsymmetricKeyLength / MaxAsymmetricKeyLength; the Part 12
    // lists govern the certificates an application manages or requests), so these comply.
    // Held for the loop: the array behind a std::initializer_list temporary in the range expression ends with
    // that full-expression, before the body runs.
    const std::array<int, 2> insideTheRange =
      minBits == 1024 ? std::array<int, 2>{1025, 1500} : std::array<int, 2>{2049, 3000};
    for (const int bits : insideTheRange)
    {
      cases.push_back(policy_case(rule,
        name + "KeyRsa" + std::to_string(bits) + "InsideTheRange",
        rsa_chain(rsa_bits_at(rule, length, position, bits))));
    }

    // CertificateSignatureAlgorithm on the certificate at this position, the issuers above it signing with
    // the highest-priority algorithm. The certificates below it are signed with no higher priority, so only
    // this certificate's algorithm is under test.
    for (const auto& algorithm : algorithms)
    {
      auto chain = baseline;
      chain[position].digest = algorithm.digest;
      chain[position].pss = algorithm.pss;
      for (std::size_t below = 0; below < position; ++below)
      {
        chain[below].digest = lower_priority(chain[below].digest, algorithm.digest);
      }
      cases.push_back(policy_case(rule, name + "Signature" + algorithm.label, std::move(chain)));
    }
    // An ECDSA signature on an RSA certificate needs an ECC signer: the issuer above, or the root itself.
    {
      auto chain = baseline;
      const auto signer = std::min(position + 1, length - 1);
      chain[signer].key = curve_key(KeyKind::P256);
      chain[position].digest = Digest::Sha256;
      for (std::size_t below = 0; below < position; ++below)
      {
        chain[below].digest = lower_priority(chain[below].digest, Digest::Sha256);
      }
      cases.push_back(policy_case(rule, name + "SignatureEcdsaSha256", std::move(chain)));
    }
  }

  // A chain signed with SHA-1 throughout: the deprecated policies' CertificateSignatureAlgorithm.
  {
    auto chain = baseline;
    for (auto& node : chain)
    {
      node.digest = Digest::Sha1;
    }
    cases.push_back(policy_case(rule, "ChainSignedWithSha1", std::move(chain)));
  }

  // Key type mismatch: an ECC or EdDSA certificate on an RSA policy.
  for (const auto kind : {KeyKind::P256, KeyKind::Ed25519})
  {
    auto chain = baseline;
    chain[0].key = curve_key(kind);
    cases.push_back(policy_case(rule, "LeafKey" + key_label(curve_key(kind)), std::move(chain)));
  }

  // Monotonicity (OPC 10000-6 section 6.1) on every edge, the algorithm arm with the control that differs
  // only in the issued certificate's algorithm.
  for (std::size_t issued = 0; issued + 1 < length; ++issued)
  {
    const auto lower = position_name(issued, length);
    const auto upper = position_name(issued + 1, length);

    auto bits = rsa_bits_at(rule, length, 0, minBits);
    bits[issued] = maxBits;
    bits[issued + 1] = minBits;
    cases.push_back(policy_case(rule, lower + "KeyLongerThan" + upper, rsa_chain(bits)));

    auto higher = baseline;
    higher[issued].digest = Digest::Sha512;
    higher[issued + 1].digest = Digest::Sha256;
    cases.push_back(policy_case(rule, lower + "AlgorithmHigherThan" + upper, std::move(higher)));

    auto equal = baseline;
    for (std::size_t i = 0; i <= issued + 1; ++i)
    {
      equal[i].digest = Digest::Sha256;
    }
    cases.push_back(policy_case(rule, lower + "AlgorithmEqualTo" + upper, std::move(equal)));
  }
}

KeyKind same_size_other_family(KeyKind kind)
{
  switch (kind)
  {
  case KeyKind::P256:
    return KeyKind::Bp256;
  case KeyKind::P384:
    return KeyKind::Bp384;
  case KeyKind::Bp256:
    return KeyKind::P256;
  case KeyKind::Bp384:
    return KeyKind::P384;
  default:
    return kind;
  }
}

/// The next larger curve of the same family, beyond the one a policy lets other CAs use; none if the family
/// has no larger curve in this matrix.
std::optional<KeyKind> curve_beyond(KeyKind kind)
{
  switch (kind)
  {
  case KeyKind::P384:
    return KeyKind::P521;
  case KeyKind::Bp384:
    return KeyKind::Bp512;
  default:
    return std::nullopt;
  }
}

/// The next smaller curve of the same family; none for the smallest.
std::optional<KeyKind> curve_smaller(KeyKind kind)
{
  switch (kind)
  {
  case KeyKind::P384:
    return KeyKind::P256;
  case KeyKind::Bp384:
    return KeyKind::Bp256;
  default:
    return std::nullopt;
  }
}

/// The keys of a chain of @p length with the leaf and the issuing CA on @p endEntity and every CA above the
/// issuing CA on @p higher.
std::vector<KeySpec> curve_keys(std::size_t length, const KeySpec& endEntity, const KeySpec& higher)
{
  std::vector<KeySpec> keys(length, higher);
  keys[0] = endEntity;
  keys[1] = endEntity;
  return keys;
}

void add_ecc_policy_cases(const PolicyRule& rule, std::size_t length, std::vector<PolicyCase>& cases)
{
  const auto ee = curve_key(rule.endEntityCurve);
  const auto other = curve_key(rule.otherCaCurve);
  // Every CA above the issuing CA on the larger curve the profile allows them; each signs with its hash.
  const auto larger = curve_keys(length, ee, other);
  const auto policyCurve = curve_keys(length, ee, ee);

  cases.push_back(policy_case(rule, "CompliantHigherCasOnLargerCurve", signed_chain(larger)));
  cases.push_back(policy_case(rule, "CompliantHigherCasOnPolicyCurve", signed_chain(policyCurve)));

  for (std::size_t position = 2; position < length; ++position)
  {
    const auto name = position_name(position, length);

    // One CA above the issuing CA on the larger curve, the others on the policy's curve. The curve rule
    // permits it; below a CA on the policy's curve the edge to that CA breaks key-length monotonicity, so
    // only the root's arm complies.
    auto alone = policyCurve;
    alone[position] = other;
    cases.push_back(policy_case(rule, name + "AloneOnLargerCurve", signed_chain(alone)));

    // The larger curve from this CA up to the root, the CAs below it on the policy's curve: compliant.
    if (position > 2 && position + 1 < length)
    {
      auto fromHere = policyCurve;
      std::fill(fromHere.begin() + static_cast<std::ptrdiff_t>(position), fromHere.end(), other);
      cases.push_back(policy_case(rule, "CompliantLargerCurveFrom" + name + "Up", signed_chain(fromHere)));
    }

    // A curve beyond the one other CAs may use, on this CA alone.
    if (const auto beyond = curve_beyond(rule.otherCaCurve))
    {
      auto keys = larger;
      keys[position] = curve_key(*beyond);
      cases.push_back(policy_case(rule, name + "On" + key_label(curve_key(*beyond)), signed_chain(keys)));
    }

    // Key type mismatch on a CA above the issuing CA.
    for (const auto& wrong : {rsa_key(2048), curve_key(KeyKind::Ed25519)})
    {
      auto keys = larger;
      keys[position] = wrong;
      cases.push_back(policy_case(rule, name + "Key" + key_label(wrong), signed_chain(keys)));
    }
  }

  {
    auto keys = larger;
    keys[1] = other;
    cases.push_back(policy_case(rule, "IssuingCaOnLargerCurve", signed_chain(keys)));
  }
  {
    auto keys = larger;
    keys[0] = other;
    cases.push_back(policy_case(rule, "LeafOnLargerCurve", signed_chain(keys)));
  }
  if (const auto smaller = curve_smaller(rule.endEntityCurve))
  {
    auto keys = larger;
    keys[0] = curve_key(*smaller);
    cases.push_back(policy_case(rule, "LeafOnSmaller" + key_label(curve_key(*smaller)), signed_chain(keys)));
  }
  {
    auto keys = larger;
    keys[0] = curve_key(same_size_other_family(rule.endEntityCurve));
    cases.push_back(policy_case(rule, "LeafOnOtherFamilyCurve" + key_label(keys[0]), signed_chain(keys)));
  }

  // Key type mismatch on the leaf and on the issuing CA.
  for (const auto& wrong : {rsa_key(2048), curve_key(KeyKind::Ed25519)})
  {
    auto keys = larger;
    keys[0] = wrong;
    cases.push_back(policy_case(rule, "LeafKey" + key_label(wrong), signed_chain(keys)));
  }
  {
    auto keys = larger;
    keys[1] = rsa_key(2048);
    cases.push_back(policy_case(rule, "IssuingCaKeyRsa2048", signed_chain(keys)));
  }

  // The ECDSA hash must match the size of the signing key's curve, on every certificate including the root's
  // self-signature.
  const auto compliant = signed_chain(larger);
  for (std::size_t position = 0; position < length; ++position)
  {
    const auto label =
      position_name(position, length) + (position + 1 == length ? "SelfSignature" : "Signature");
    for (const auto digest : {Digest::Sha256, Digest::Sha384, Digest::Sha512})
    {
      if (digest != compliant[position].digest)
      {
        auto chain = compliant;
        chain[position].digest = digest;
        cases.push_back(policy_case(rule, label + "Ecdsa" + digest_label(digest), std::move(chain)));
      }
    }
  }
}

void add_eddsa_policy_cases(const PolicyRule& rule, std::size_t length, std::vector<PolicyCase>& cases)
{
  const auto ee = curve_key(rule.endEntityCurve);
  const auto otherEd = curve_key(rule.endEntityCurve == KeyKind::Ed25519 ? KeyKind::Ed448 : KeyKind::Ed25519);
  const std::vector<KeySpec> compliant(length, ee);

  cases.push_back(policy_case(rule, "Compliant", signed_chain(compliant)));
  for (std::size_t position = 0; position < length; ++position)
  {
    const auto name = position_name(position, length);
    auto keys = compliant;
    keys[position] = otherEd;
    cases.push_back(policy_case(rule, name + "On" + key_label(otherEd), signed_chain(keys)));
    for (const auto& wrong : {curve_key(KeyKind::P256), rsa_key(2048)})
    {
      keys[position] = wrong;
      cases.push_back(policy_case(rule, name + "Key" + key_label(wrong), signed_chain(keys)));
    }
  }
}

void add_short_chain_cases(const PolicyRule& rule, std::size_t length, std::vector<PolicyCase>& cases)
{
  switch (rule.family)
  {
  case PolicyFamily::Rsa:
  {
    const int belowMin = rule.minRsaBits == 1024 ? 512 : 1024;
    const auto baseline = rsa_chain(rsa_bits_at(rule, length, 0, rule.minRsaBits));
    cases.push_back(policy_case(rule, "Compliant", baseline));
    // The leaf below MinAsymmetricKeyLength (self-signed at length 1: RSA 1024 on Basic256Sha256).
    cases.push_back(policy_case(
      rule, "LeafKeyRsa" + std::to_string(belowMin), rsa_chain(rsa_bits_at(rule, length, 0, belowMin))));
    // Every certificate signed with SHA-1: refused unless the policy permits SHA-1.
    auto sha1 = baseline;
    for (auto& node : sha1)
    {
      node.digest = Digest::Sha1;
    }
    cases.push_back(policy_case(rule, "ChainSignedWithSha1", std::move(sha1)));
    if (length == 2)
    {
      // The root (the issuing CA) below the minimum; the leaf no longer than it.
      cases.push_back(policy_case(
        rule, "RootKeyRsa" + std::to_string(belowMin), rsa_chain(rsa_bits_at(rule, length, 1, belowMin))));
    }
    break;
  }
  case PolicyFamily::Ecc:
  {
    const auto ee = curve_key(rule.endEntityCurve);
    const auto other = curve_key(rule.otherCaCurve);
    cases.push_back(policy_case(rule, "Compliant", signed_chain(std::vector<KeySpec>(length, ee))));
    if (rule.otherCaCurve != rule.endEntityCurve)
    {
      // Length 1: a self-signed leaf on the larger curve (P-384 on nistP256). Length 2: the root issuing the
      // leaf on the larger curve (a P-384 root issuing a P-256 leaf) - the issuing CA must use the
      // end-entity curve, so both are PolicyCheckFailed.
      auto keys = std::vector<KeySpec>(length, ee);
      keys.back() = other;
      cases.push_back(policy_case(
        rule, length == 1 ? "SelfSignedLeafOnLargerCurve" : "IssuingRootOnLargerCurve", signed_chain(keys)));
    }
    break;
  }
  case PolicyFamily::EdDsa:
    cases.push_back(policy_case(
      rule, "Compliant", signed_chain(std::vector<KeySpec>(length, curve_key(rule.endEntityCurve)))));
    break;
  }
}

std::vector<PolicyCase> all_policy_cases()
{
  std::vector<PolicyCase> cases;
  for (const auto& rule : implemented_policy_rules())
  {
    for (const auto length : shortChainLengths)
    {
      add_short_chain_cases(rule, length, cases);
    }
    for (const auto length : chainLengths)
    {
      switch (rule.family)
      {
      case PolicyFamily::Rsa:
        add_rsa_policy_cases(rule, length, cases);
        break;
      case PolicyFamily::Ecc:
        add_ecc_policy_cases(rule, length, cases);
        break;
      case PolicyFamily::EdDsa:
        add_eddsa_policy_cases(rule, length, cases);
        break;
      }
    }
  }
  return cases;
}

std::string policy_case_name(const ::testing::TestParamInfo<PolicyCase>& info)
{
  return std::string{info.param.rule.name} + "_" + info.param.arm;
}

std::string describe_chain(const std::vector<ChainNode>& chain)
{
  std::string text;
  for (std::size_t i = 0; i < chain.size(); ++i)
  {
    text += (i == 0 ? "" : ", ") + position_name(i, chain.size()) + " " + key_label(chain[i].key) + "/" +
            (chain[i].pss ? "Pss" : "") + digest_label(chain[i].digest);
  }
  return text;
}

class CertificatePolicyDeviationMatrix : public ::testing::TestWithParam<PolicyCase>
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sCrypto = BackendOpenSslFiles::create_crypto();
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sThreadPool);
    sThreadPool.reset();
    sCrypto.reset();
  }

protected:
  void SetUp() override
  {
    ASSERT_NE(sCrypto, nullptr);
    mRootPath = test_utils::unique_temp_path("cert_policy_matrix");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sThreadPool->get_executor(), sCrypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  static std::shared_ptr<const Crypto> sCrypto;

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
};

std::shared_ptr<const Crypto> CertificatePolicyDeviationMatrix::sCrypto;

// The policy check driven through the single validator (owner review 2026-10-02, items 2 and 3): a
// CertificateValidationRequest carrying the peer's certificate (the leaf), the issuer certificates it
// presented with it (every CA but the root, issuing CA first) and policyId = id, given
// to the certificate store (the root in its trusted list). Step 4 runs inside the validator for every
// certificate of the chain, so the case and the oracle are unchanged from the SecurityPolicy entry point.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-09-POLICY-KEY, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-10-POLICY-SIGNATURE-ALGORITHM, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-11-POLICY-CURVE, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-12-POLICY-MONOTONICITY, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-88-SHORT-CHAINS, scope=function)
TEST_P(CertificatePolicyDeviationMatrix, ThePolicyCheckReturnsTheSpecifiedStatus)
{
  const auto& c = GetParam();
  const auto length = c.chain.size();

  const std::shared_ptr<const SecurityPolicy> policy = SecurityPolicy::create(c.rule.id);
  ASSERT_NE(policy, nullptr) << c.rule.name;

  // A key slot per position, so no two certificates of one chain share a key.
  std::vector<PKey> keys;
  for (std::size_t i = 0; i < length; ++i)
  {
    keys.push_back(cached_key(c.chain[i].key, static_cast<unsigned>(i)));
    ASSERT_TRUE(keys.back()) << "no key for position " << i << " of " << describe_chain(c.chain);
  }

  // Built from the root down, each CA issuing the certificate below it.
  std::vector<X509Ptr> certificates(length);
  for (std::size_t i = length; i-- > 0;)
  {
    const bool isRoot = i + 1 == length;
    const auto serial = "7" + std::to_string(i) + "00";
    const auto spec =
      i == 0 ? leaf_spec("U7 Leaf", serial, c.chain[i].key.kind, "URI:urn:reduktive:u7:leaf,DNS:localhost")
             : ca_spec("U7 " + position_name(i, length), serial);
    certificates[i] = build_certificate(spec,
      keys[i].get(),
      isRoot ? nullptr : certificates[i + 1].get(),
      isRoot ? keys[i].get() : keys[i + 1].get(),
      c.chain[i].digest,
      c.chain[i].pss);
  }

  std::vector<std::shared_ptr<const X509Certificate>> sdkCertificates;
  try
  {
    for (const auto& certificate : certificates)
    {
      sdkCertificates.push_back(to_sdk_certificate(*sCrypto, der_of(certificate.get())));
    }
  }
  catch (const UaException& e)
  {
    FAIL() << "the SDK refused to read a well-formed certificate: " << to_string(e.status());
  }
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sdkCertificates.back()).is_good());

  // Every CA but the root; none for a self-signed leaf (length 1) or a leaf issued by the root (length 2).
  const std::vector<std::shared_ptr<const X509Certificate>> presentedIssuers =
    length > 2 ? std::vector<std::shared_ptr<const X509Certificate>>(sdkCertificates.begin() + 1,
                   sdkCertificates.begin() + static_cast<std::ptrdiff_t>(length - 1))
               : std::vector<std::shared_ptr<const X509Certificate>>{};
  const auto request = ua::test::make_validation_request_for(
    sdkCertificates.front(), presentedIssuers, CertificateUse::ApplicationInstance, policy->id());

  const auto result = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto callback) { mStore->validate_certificate_async(request, std::move(callback)); });
  const auto expected = policy_oracle(c.rule, c.chain);
  EXPECT_EQ(result.status_code().as_status(), expected)
    << c.rule.name << " " << c.arm << ": expected " << to_string(expected) << ", got "
    << to_string(result.status_code().as_status()) << " (" << describe_chain(c.chain) << ")";
}

INSTANTIATE_TEST_SUITE_P(
  AllPolicies, CertificatePolicyDeviationMatrix, ::testing::ValuesIn(all_policy_cases()), policy_case_name);

// ---------------------------------------------------------------------------------------------------------
// U6: the oracle. OPC 10000-4 Table 106 with the plan's oracle corrections and owner decisions. Written from
// the specification only.
// ---------------------------------------------------------------------------------------------------------

/// Every defect of the U6 matrix. The name says where the defect is: on the leaf, the intermediate or the
/// root of leaf <- intermediate <- root, or a property of the chain.
enum class Defect
{
  // Table 106 step 1, Certificate Structure.
  LeafTruncatedDer,
  LeafTrailingBytesInsideTheOuterSequence,
  LeafVersion1WithExtensions,
  LeafVersion2WithExtensions,
  LeafMalformedNotBefore,
  LeafMalformedNotAfter,
  IntermediateEmptySubject,
  LeafDuplicateExtension,
  IntermediateDuplicateExtension,
  LeafUnknownCriticalExtension,
  IntermediateUnknownCriticalExtension,
  LeafUndecodablePublicKey,
  LeafZeroLengthSerial,
  LeafSerialLongerThan20Octets,
  LeafNegativeSerial,
  // Step 3, Signature.
  LeafSignatureBroken,
  IntermediateSignatureBroken,
  RootSignatureBroken,
  LeafSignatureAlgorithmFieldsDisagree,
  LeafSignedByAnImpostorWithTheIssuersName,
  IntermediateSignedByAnImpostorWithTheIssuersName,
  // Step 6, Validity Period.
  LeafNotBeforeAfterNotAfter,
  IntermediateNotBeforeAfterNotAfter,
  LeafNotAfterInYear9999,
  LeafNotBeforeInYear2100,
  IntermediateNotBeforeInYear2100,
  // Steps 7 and 8, Host Name and URI.
  LeafWithoutSubjectAltNameAgainstAnApplicationUri,
  LeafWithoutSubjectAltNameAgainstAnEndpointUrl,
  LeafSubjectAltNameWithoutAUri,
  LeafWithTwoUrisTheSecondMatching,
  LeafUriDifferingInCase,
  LeafUriWithATrailingSlash,
  LeafIpv4AddressMatchingTheEndpoint,
  LeafIpv4AddressNotMatchingTheEndpoint,
  LeafHostNameOnlyInTheCommonName,
  // Step 9, Certificate Usage (OPC 10000-6 Tables 43 to 45).
  RsaLeafWithoutKeyEncipherment,
  RsaLeafWithoutDataEncipherment,
  RsaLeafWithoutNonRepudiation,
  RsaLeafWithoutDigitalSignature,
  RsaLeafWithoutExtendedKeyUsage,
  EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage,
  EccLeafWithoutDigitalSignature,
  SelfSignedLeafWithoutKeyCertSign,
  SelfSignedLeafCaTrueWithPathLength1,
  SelfSignedLeafCaTrueWithoutPathLength,
  CaIssuedLeafCaTrue,
  IntermediateWithoutKeyCertSign,
  IntermediateWithoutCrlSignRevocationOff,
  IntermediateWithoutCrlSignRevocationOn,
  UserLeafCaTrue,
  UserLeafWithPathLength,
  UserLeafWithoutTheApplicationInstanceKeyUsage,
  ApplicationLeafWithoutTheApplicationInstanceKeyUsage,
  // Steps 10 and 11, Find Revocation List and Revocation Check (offline checking on).
  IntermediateCrlMalformed,
  IntermediateCrlFromAnotherIssuer,
  CrlOfAnotherIssuerListingTheLeafSerial,
  IntermediateCrlExpired,
  IntermediateCrlNotYetValid,
  IntermediateCrlSignatureBroken,
  RootCrlExpired,
  LeafRevokedWithReasonKeyCompromise,
  IntermediateRevokedWithReasonCaCompromise,
  // Chain anomalies (step 2, Build Certificate Chain).
  IssuerCycle,
  TwoIssuersWithTheSameNameOnlyOneVerifying,
  DuplicateCertificatesInThePresentedChain,
};

struct DefectName
{
  Defect defect;
  const char* name;
};

constexpr DefectName defects[] = {
  {Defect::LeafTruncatedDer, "LeafTruncatedDer"},
  {Defect::LeafTrailingBytesInsideTheOuterSequence, "LeafTrailingBytesInsideTheOuterSequence"},
  {Defect::LeafVersion1WithExtensions, "LeafVersion1WithExtensions"},
  {Defect::LeafVersion2WithExtensions, "LeafVersion2WithExtensions"},
  {Defect::LeafMalformedNotBefore, "LeafMalformedNotBefore"},
  {Defect::LeafMalformedNotAfter, "LeafMalformedNotAfter"},
  {Defect::IntermediateEmptySubject, "IntermediateEmptySubject"},
  {Defect::LeafDuplicateExtension, "LeafDuplicateExtension"},
  {Defect::IntermediateDuplicateExtension, "IntermediateDuplicateExtension"},
  {Defect::LeafUnknownCriticalExtension, "LeafUnknownCriticalExtension"},
  {Defect::IntermediateUnknownCriticalExtension, "IntermediateUnknownCriticalExtension"},
  {Defect::LeafUndecodablePublicKey, "LeafUndecodablePublicKey"},
  {Defect::LeafZeroLengthSerial, "LeafZeroLengthSerial"},
  {Defect::LeafSerialLongerThan20Octets, "LeafSerialLongerThan20Octets"},
  {Defect::LeafNegativeSerial, "LeafNegativeSerial"},
  {Defect::LeafSignatureBroken, "LeafSignatureBroken"},
  {Defect::IntermediateSignatureBroken, "IntermediateSignatureBroken"},
  {Defect::RootSignatureBroken, "RootSignatureBroken"},
  {Defect::LeafSignatureAlgorithmFieldsDisagree, "LeafSignatureAlgorithmFieldsDisagree"},
  {Defect::LeafSignedByAnImpostorWithTheIssuersName, "LeafSignedByAnImpostorWithTheIssuersName"},
  {Defect::IntermediateSignedByAnImpostorWithTheIssuersName,
    "IntermediateSignedByAnImpostorWithTheIssuersName"},
  {Defect::LeafNotBeforeAfterNotAfter, "LeafNotBeforeAfterNotAfter"},
  {Defect::IntermediateNotBeforeAfterNotAfter, "IntermediateNotBeforeAfterNotAfter"},
  {Defect::LeafNotAfterInYear9999, "LeafNotAfterInYear9999"},
  {Defect::LeafNotBeforeInYear2100, "LeafNotBeforeInYear2100"},
  {Defect::IntermediateNotBeforeInYear2100, "IntermediateNotBeforeInYear2100"},
  {Defect::LeafWithoutSubjectAltNameAgainstAnApplicationUri,
    "LeafWithoutSubjectAltNameAgainstAnApplicationUri"},
  {Defect::LeafWithoutSubjectAltNameAgainstAnEndpointUrl, "LeafWithoutSubjectAltNameAgainstAnEndpointUrl"},
  {Defect::LeafSubjectAltNameWithoutAUri, "LeafSubjectAltNameWithoutAUri"},
  {Defect::LeafWithTwoUrisTheSecondMatching, "LeafWithTwoUrisTheSecondMatching"},
  {Defect::LeafUriDifferingInCase, "LeafUriDifferingInCase"},
  {Defect::LeafUriWithATrailingSlash, "LeafUriWithATrailingSlash"},
  {Defect::LeafIpv4AddressMatchingTheEndpoint, "LeafIpv4AddressMatchingTheEndpoint"},
  {Defect::LeafIpv4AddressNotMatchingTheEndpoint, "LeafIpv4AddressNotMatchingTheEndpoint"},
  {Defect::LeafHostNameOnlyInTheCommonName, "LeafHostNameOnlyInTheCommonName"},
  {Defect::RsaLeafWithoutKeyEncipherment, "RsaLeafWithoutKeyEncipherment"},
  {Defect::RsaLeafWithoutDataEncipherment, "RsaLeafWithoutDataEncipherment"},
  {Defect::RsaLeafWithoutNonRepudiation, "RsaLeafWithoutNonRepudiation"},
  {Defect::RsaLeafWithoutDigitalSignature, "RsaLeafWithoutDigitalSignature"},
  {Defect::RsaLeafWithoutExtendedKeyUsage, "RsaLeafWithoutExtendedKeyUsage"},
  {Defect::EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage,
    "EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage"},
  {Defect::EccLeafWithoutDigitalSignature, "EccLeafWithoutDigitalSignature"},
  {Defect::SelfSignedLeafWithoutKeyCertSign, "SelfSignedLeafWithoutKeyCertSign"},
  {Defect::SelfSignedLeafCaTrueWithPathLength1, "SelfSignedLeafCaTrueWithPathLength1"},
  {Defect::SelfSignedLeafCaTrueWithoutPathLength, "SelfSignedLeafCaTrueWithoutPathLength"},
  {Defect::CaIssuedLeafCaTrue, "CaIssuedLeafCaTrue"},
  {Defect::IntermediateWithoutKeyCertSign, "IntermediateWithoutKeyCertSign"},
  {Defect::IntermediateWithoutCrlSignRevocationOff, "IntermediateWithoutCrlSignRevocationOff"},
  {Defect::IntermediateWithoutCrlSignRevocationOn, "IntermediateWithoutCrlSignRevocationOn"},
  {Defect::UserLeafCaTrue, "UserLeafCaTrue"},
  {Defect::UserLeafWithPathLength, "UserLeafWithPathLength"},
  {Defect::UserLeafWithoutTheApplicationInstanceKeyUsage, "UserLeafWithoutTheApplicationInstanceKeyUsage"},
  {Defect::ApplicationLeafWithoutTheApplicationInstanceKeyUsage,
    "ApplicationLeafWithoutTheApplicationInstanceKeyUsage"},
  {Defect::IntermediateCrlMalformed, "IntermediateCrlMalformed"},
  {Defect::IntermediateCrlFromAnotherIssuer, "IntermediateCrlFromAnotherIssuer"},
  {Defect::CrlOfAnotherIssuerListingTheLeafSerial, "CrlOfAnotherIssuerListingTheLeafSerial"},
  {Defect::IntermediateCrlExpired, "IntermediateCrlExpired"},
  {Defect::IntermediateCrlNotYetValid, "IntermediateCrlNotYetValid"},
  {Defect::IntermediateCrlSignatureBroken, "IntermediateCrlSignatureBroken"},
  {Defect::RootCrlExpired, "RootCrlExpired"},
  {Defect::LeafRevokedWithReasonKeyCompromise, "LeafRevokedWithReasonKeyCompromise"},
  {Defect::IntermediateRevokedWithReasonCaCompromise, "IntermediateRevokedWithReasonCaCompromise"},
  {Defect::IssuerCycle, "IssuerCycle"},
  {Defect::TwoIssuersWithTheSameNameOnlyOneVerifying, "TwoIssuersWithTheSameNameOnlyOneVerifying"},
  {Defect::DuplicateCertificatesInThePresentedChain, "DuplicateCertificatesInThePresentedChain"},
};

std::string defect_name(Defect defect)
{
  for (const auto& entry : defects)
  {
    if (entry.defect == defect)
    {
      return entry.name;
    }
  }
  return "Unknown";
}

/// The Table 106 outcome of a defect: its code, and the Part 12 Table 31 bit that suppresses it, if any.
struct ErrorRule
{
  Status status = Status::Good;
  std::optional<TrustListValidationOptions::Bit> suppressedBy;
};

ErrorRule error_rule(
  Status status, std::optional<TrustListValidationOptions::Bit> suppressedBy = std::nullopt)
{
  ErrorRule rule;
  rule.status = status;
  rule.suppressedBy = suppressedBy;
  return rule;
}

/// OPC 10000-4 Table 106 (oracle corrections, 2026-10-01; owner decisions, section 22):
/// - 1 Structure and 3 Signature: Bad_CertificateInvalid, never suppressed.
/// - 2 Build Certificate Chain: Bad_CertificateChainIncomplete, never suppressed.
/// - 6 Validity Period: Bad_CertificateTimeInvalid (SuppressCertificateExpired) on the certificate under
/// test,
///   Bad_CertificateIssuerTimeInvalid (SuppressIssuerCertificateExpired) on an issuer.
/// - 7 Host Name: Bad_CertificateHostNameInvalid (SuppressHostNameInvalid). 8 URI: Bad_CertificateUriInvalid,
///   never suppressed (Part 4; owner decision 22.3).
/// - 9 Certificate Usage: Bad_CertificateUseNotAllowed / Bad_CertificateIssuerUseNotAllowed, never
/// suppressed.
/// - 10 Find Revocation List: Bad_CertificateRevocationUnknown (SuppressRevocationStatusUnknown) /
///   Bad_CertificateIssuerRevocationUnknown (SuppressIssuerRevocationStatusUnknown). An out-of-date, foreign
///   or forged CRL is no usable CRL (labelled interpretation in the plan).
/// - 11 Revocation Check: Bad_CertificateRevoked / Bad_CertificateIssuerRevoked, never suppressed.
/// The rows that cite a Table 43 to 45 clause or RFC 5280 say so.
ErrorRule error_oracle(Defect defect)
{
  using Bit = TrustListValidationOptions::Bit;
  switch (defect)
  {
  case Defect::LeafTruncatedDer:
  case Defect::LeafTrailingBytesInsideTheOuterSequence:
  case Defect::LeafVersion1WithExtensions:  // RFC 5280 4.1.2.1: extensions require v3.
  case Defect::LeafVersion2WithExtensions:
  case Defect::LeafMalformedNotBefore:
  case Defect::LeafMalformedNotAfter:
  case Defect::IntermediateEmptySubject:  // RFC 5280 4.1.2.6: a CA's subject is non-empty; Table 45 CN.
  case Defect::LeafDuplicateExtension:  // RFC 5280 4.2: at most one instance of an extension.
  case Defect::IntermediateDuplicateExtension:
  case Defect::LeafUnknownCriticalExtension:  // RFC 5280 4.2: reject an unrecognised critical extension.
  case Defect::IntermediateUnknownCriticalExtension:
  case Defect::LeafUndecodablePublicKey:
  case Defect::LeafZeroLengthSerial:  // RFC 5280 4.1.2.2: a positive integer of at most 20 octets.
  case Defect::LeafSerialLongerThan20Octets:
    return error_rule(Status::BadCertificateInvalid);
  // RFC 5280 4.1.2.2: "Non-conforming CAs may issue certificates with serial numbers that are negative or
  // zero. Certificate users SHOULD be prepared to gracefully handle such certificates." A negative serial
  // is accepted (oracle correction, triage round 1 O1).
  case Defect::LeafNegativeSerial:
    return error_rule(Status::Good);

  case Defect::LeafSignatureBroken:
  case Defect::IntermediateSignatureBroken:
  case Defect::RootSignatureBroken:
  case Defect::LeafSignatureAlgorithmFieldsDisagree:  // RFC 5280 4.1.1.2: the two fields MUST be identical.
  case Defect::LeafSignedByAnImpostorWithTheIssuersName:
  case Defect::IntermediateSignedByAnImpostorWithTheIssuersName:
    return error_rule(Status::BadCertificateInvalid);

  case Defect::LeafNotBeforeAfterNotAfter:
  case Defect::LeafNotBeforeInYear2100:
    return error_rule(Status::BadCertificateTimeInvalid, Bit::SuppressCertificateExpired);
  case Defect::IntermediateNotBeforeAfterNotAfter:
  case Defect::IntermediateNotBeforeInYear2100:
    return error_rule(Status::BadCertificateIssuerTimeInvalid, Bit::SuppressIssuerCertificateExpired);
  case Defect::LeafNotAfterInYear9999:  // RFC 5280 4.1.2.5: 99991231235959Z means no expiry.
    return error_rule(Status::Good);

  // Host Name: the endpoint's host must be a dNSName or iPAddress of the subjectAltName (Table 43); the
  // subject's CN is not consulted.
  case Defect::LeafWithoutSubjectAltNameAgainstAnEndpointUrl:
  case Defect::LeafIpv4AddressNotMatchingTheEndpoint:
  case Defect::LeafHostNameOnlyInTheCommonName:
    return error_rule(Status::BadCertificateHostNameInvalid, Bit::SuppressHostNameInvalid);
  case Defect::LeafIpv4AddressMatchingTheEndpoint:
    return error_rule(Status::Good);
  // URI: "Shall include a uniformResourceIdentifier which is equal to the applicationUri" (Table 43).
  case Defect::LeafWithoutSubjectAltNameAgainstAnApplicationUri:
  case Defect::LeafSubjectAltNameWithoutAUri:
  case Defect::LeafUriDifferingInCase:
  case Defect::LeafUriWithATrailingSlash:
    return error_rule(Status::BadCertificateUriInvalid);
  case Defect::LeafWithTwoUrisTheSecondMatching:  // It includes one equal to the applicationUri.
    return error_rule(Status::Good);

  // Table 43 keyUsage: "For RSA keys ... digitalSignature, nonRepudiation, keyEncipherment and
  // dataEncipherment"; extendedKeyUsage "For RSA keys ... shall specify serverAuth and/or clientAuth"; "For
  // ECC keys, the keyUsage shall include digitalSignature" and the extendedKeyUsage "may" be given.
  case Defect::RsaLeafWithoutKeyEncipherment:
  case Defect::RsaLeafWithoutDataEncipherment:
  case Defect::RsaLeafWithoutNonRepudiation:
  case Defect::RsaLeafWithoutDigitalSignature:
  case Defect::RsaLeafWithoutExtendedKeyUsage:
  case Defect::EccLeafWithoutDigitalSignature:
  case Defect::ApplicationLeafWithoutTheApplicationInstanceKeyUsage:
    return error_rule(Status::BadCertificateUseNotAllowed);
  case Defect::EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage:
    return error_rule(Status::Good);
  // Table 43: "Self-signed Certificates shall also include keyCertSign" - applied where cA is TRUE, the only
  // form in which RFC 5280 4.2.1.9 permits keyCertSign (a cA FALSE self-signed certificate cannot carry it);
  // "If the CA flag is TRUE for self-signed ApplicationInstance Certificates, then the pathLength shall be
  // 0" - an explicit pathLength above 0 is refused, while an ABSENT pathLength is accepted because the same
  // row says "TRUE shall be accepted to ensure backward interoperability" and legacy cA TRUE certificates
  // carry none (owner decision 25); "The cA flag shall be FALSE for ApplicationInstance Certificates issued
  // by a CA".
  case Defect::SelfSignedLeafWithoutKeyCertSign:
  case Defect::SelfSignedLeafCaTrueWithPathLength1:
  case Defect::CaIssuedLeafCaTrue:
    return error_rule(Status::BadCertificateUseNotAllowed);
  case Defect::SelfSignedLeafCaTrueWithoutPathLength:
    return error_rule(Status::Good);
  // Table 45 with RFC 5280 4.2.1.3: an issuer whose keyUsage omits keyCertSign cannot have signed a
  // certificate.
  case Defect::IntermediateWithoutKeyCertSign:
    return error_rule(Status::BadCertificateIssuerUseNotAllowed);
  // cRLSign matters only when a CRL is used: without revocation checking nothing is wrong; with it, the CRL
  // the CA signed is not a usable CRL for the certificates it issued (RFC 5280 4.2.1.3).
  case Defect::IntermediateWithoutCrlSignRevocationOff:
    return error_rule(Status::Good);
  case Defect::IntermediateWithoutCrlSignRevocationOn:
    return error_rule(Status::BadCertificateRevocationUnknown, Bit::SuppressRevocationStatusUnknown);
  // Table 44: "The cA flag shall be FALSE for User Certificates. The pathLength shall not be present." Table
  // 43's keyUsage and extendedKeyUsage rows do not apply to a User Certificate.
  case Defect::UserLeafCaTrue:
  case Defect::UserLeafWithPathLength:
    return error_rule(Status::BadCertificateUseNotAllowed);
  case Defect::UserLeafWithoutTheApplicationInstanceKeyUsage:
    return error_rule(Status::Good);

  case Defect::IntermediateCrlMalformed:
  case Defect::IntermediateCrlFromAnotherIssuer:
  case Defect::IntermediateCrlExpired:
  case Defect::IntermediateCrlNotYetValid:
  case Defect::IntermediateCrlSignatureBroken:
    return error_rule(Status::BadCertificateRevocationUnknown, Bit::SuppressRevocationStatusUnknown);
  case Defect::RootCrlExpired:
    return error_rule(
      Status::BadCertificateIssuerRevocationUnknown, Bit::SuppressIssuerRevocationStatusUnknown);
  case Defect::CrlOfAnotherIssuerListingTheLeafSerial:  // A CRL lists the serials of ITS issuer's
                                                        // certificates.
    return error_rule(Status::Good);
  case Defect::LeafRevokedWithReasonKeyCompromise:
    return error_rule(Status::BadCertificateRevoked);
  case Defect::IntermediateRevokedWithReasonCaCompromise:
    return error_rule(Status::BadCertificateIssuerRevoked);

  // OPC 10000-6 6.2.6: the chain ends with a self-signed certificate; a cycle never reaches one. A chain that
  // exists is found whatever else is offered with it.
  case Defect::IssuerCycle:
    return error_rule(Status::BadCertificateChainIncomplete);
  case Defect::TwoIssuersWithTheSameNameOnlyOneVerifying:
  case Defect::DuplicateCertificatesInThePresentedChain:
    return error_rule(Status::Good);
  }
  return error_rule(Status::BadInternalError);
}

/// With every suppression bit set, a suppressible fault is suppressed and the others still decide.
Status expected_error_status(Defect defect, bool allSuppressionBits)
{
  const auto rule = error_oracle(defect);
  if (allSuppressionBits && rule.suppressedBy)
  {
    return Status::Good;
  }
  return rule.status;
}

// ---------------------------------------------------------------------------------------------------------
// U6: the scenarios. Each defect is built twice, with and without the defect, from the same keys and specs.
// ---------------------------------------------------------------------------------------------------------

constexpr const char* u6Uri = "urn:reduktive:u6:leaf";
constexpr const char* u6San = "URI:urn:reduktive:u6:leaf,DNS:u6-leaf.example,IP:192.0.2.10";
constexpr const char* u6Endpoint = "opc.tcp://u6-leaf.example:4840";
constexpr const char* u6Ipv4Endpoint = "opc.tcp://192.0.2.10:4840";

/// The two length octets of a DER SEQUENCE header 30 82 hi lo.
void adjust_der_length(Der& der, std::size_t at, long delta)
{
  const long length = (static_cast<long>(der[at]) << 8) + static_cast<long>(der[at + 1]) + delta;
  require(length > 0 && length < 0x10000, "DER length");
  der[at] = static_cast<unsigned char>((length >> 8) & 0xFF);
  der[at + 1] = static_cast<unsigned char>(length & 0xFF);
}

/// A certificate between 256 and 65535 bytes: Certificate SEQUENCE at 0, TBSCertificate SEQUENCE at 4.
void require_certificate_layout(const Der& der)
{
  require(der.size() > 32 && der[0] == 0x30 && der[1] == 0x82 && der[4] == 0x30 && der[5] == 0x82,
    "certificate DER layout");
}

Der truncated(Der der)
{
  der.resize(der.size() - 10);
  return der;
}

Der with_trailing_bytes_inside_the_outer_sequence(Der der)
{
  require_certificate_layout(der);
  der.push_back(0x05);  // An ASN.1 NULL after signatureValue, inside the Certificate SEQUENCE.
  der.push_back(0x00);
  adjust_der_length(der, 2, 2);
  return der;
}

Der with_zero_length_serial(Der der)
{
  require_certificate_layout(der);
  // TBSCertificate content: [0] { INTEGER 2 } = A0 03 02 01 02, then serialNumber 02 len value.
  require(der[8] == 0xA0 && der[9] == 0x03 && der[13] == 0x02 && der[14] < 0x80, "serial layout");
  const long serialLength = der[14];
  der.erase(der.begin() + 15, der.begin() + 15 + serialLength);
  der[14] = 0x00;
  adjust_der_length(der, 2, -serialLength);
  adjust_der_length(der, 6, -serialLength);
  return der;
}

Der with_undecodable_rsa_public_key(Der der)
{
  // AlgorithmIdentifier rsaEncryption, NULL parameters, then the BIT STRING 03 82 hi lo 00 holding
  // RSAPublicKey, a SEQUENCE (30). Turning that SEQUENCE into a SET leaves a key no RSA decoder accepts.
  const unsigned char prefix[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82};
  const auto found = std::search(der.begin(), der.end(), std::begin(prefix), std::end(prefix));
  require(found != der.end(), "rsaEncryption SubjectPublicKeyInfo");
  const auto keyTag = static_cast<std::size_t>(found - der.begin()) + 18;
  require(keyTag < der.size() && der[keyTag - 1] == 0x00 && der[keyTag] == 0x30, "RSAPublicKey SEQUENCE");
  der[keyTag] = 0x31;
  return der;
}

Der with_disagreeing_signature_algorithm(Der der)
{
  // The last sha256WithRSAEncryption OID is the outer signatureAlgorithm; the TBS copy stays sha256.
  const unsigned char sha256WithRsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
  const auto found =
    std::find_end(der.begin(), der.end(), std::begin(sha256WithRsa), std::end(sha256WithRsa));
  require(found != der.end(), "sha256WithRSAEncryption");
  *(found + 8) = 0x0C;  // sha384WithRSAEncryption.
  return der;
}

/// A DER length header for @p length.
Der der_length(std::size_t length)
{
  if (length < 0x80)
    return {static_cast<unsigned char>(length)};
  if (length < 0x100)
    return {0x81, static_cast<unsigned char>(length)};
  return {0x82, static_cast<unsigned char>(length >> 8), static_cast<unsigned char>(length & 0xFF)};
}

/// The certificate with its version field written as [0] { INTEGER @p version - 1 } (@p version 1 or 2) and
/// signed again with @p signer (SHA-256), so the version is its only defect. Whether OpenSSL encodes the
/// version that was set or makes a certificate that carries extensions version 3 depends on the release, and
/// a version 1 set is encoded by omitting the field, its DEFAULT; the field is therefore written after
/// signing, inserted where it is absent, so the certificate is the same whichever release made it.
Der with_version_resigned(const Der& der, long version, EVP_PKEY* signer)
{
  require_certificate_layout(der);
  // TBSCertificate at 4 (30 82 hi lo); its contents start with the version, A0 03 02 01 n, or, with the
  // version omitted, with the serialNumber INTEGER.
  const std::size_t tbsEnd = 8 + ((static_cast<std::size_t>(der[6]) << 8) | der[7]);
  Der contents(der.begin() + 8, der.begin() + static_cast<std::ptrdiff_t>(tbsEnd));
  const bool hasVersion = contents.size() > 5 && contents[0] == 0xA0 && contents[1] == 0x03 &&
                          contents[2] == 0x02 && contents[3] == 0x01;
  if (!hasVersion)
  {
    require(!contents.empty() && contents[0] == 0x02, "TBSCertificate version or serialNumber");
    const unsigned char versionField[] = {0xA0, 0x03, 0x02, 0x01, 0x00};
    contents.insert(contents.begin(), std::begin(versionField), std::end(versionField));
  }
  contents[4] = static_cast<unsigned char>(version - 1);
  Der tbs{0x30};
  const auto tbsLength = der_length(contents.size());
  tbs.insert(tbs.end(), tbsLength.begin(), tbsLength.end());
  tbs.insert(tbs.end(), contents.begin(), contents.end());
  // signatureAlgorithm follows the TBSCertificate: a short-form SEQUENCE.
  require(der[tbsEnd] == 0x30 && der[tbsEnd + 1] < 0x80, "signatureAlgorithm layout");
  const Der algorithm(der.begin() + static_cast<std::ptrdiff_t>(tbsEnd),
    der.begin() + static_cast<std::ptrdiff_t>(tbsEnd + 2 + der[tbsEnd + 1]));

  const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
  require(context && EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, signer) == 1,
    "EVP_DigestSignInit");
  std::size_t signatureLength = 0;
  require(EVP_DigestSign(context.get(), nullptr, &signatureLength, tbs.data(), tbs.size()) == 1, "size");
  Der signature(signatureLength);
  require(EVP_DigestSign(context.get(), signature.data(), &signatureLength, tbs.data(), tbs.size()) == 1,
    "EVP_DigestSign");
  signature.resize(signatureLength);

  Der bitString{0x03};
  const auto bitLength = der_length(signature.size() + 1);
  bitString.insert(bitString.end(), bitLength.begin(), bitLength.end());
  bitString.push_back(0x00);
  bitString.insert(bitString.end(), signature.begin(), signature.end());

  Der body = tbs;
  body.insert(body.end(), algorithm.begin(), algorithm.end());
  body.insert(body.end(), bitString.begin(), bitString.end());
  Der out{0x30};
  const auto outerLength = der_length(body.size());
  out.insert(out.end(), outerLength.begin(), outerLength.end());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

Der with_last_byte_flipped(Der der)
{
  der.back() ^= 0x5A;  // Inside the trailing signatureValue BIT STRING.
  return der;
}

struct ErrorScenario
{
  std::shared_ptr<const X509Certificate> leaf;
  std::vector<std::shared_ptr<const X509Certificate>> trusted;
  std::vector<std::shared_ptr<const X509Certificate>> issuers;
  std::vector<std::shared_ptr<const X509Certificate>> presented;
  std::vector<std::shared_ptr<const X509Crl>> trustedCrls;
  std::vector<std::shared_ptr<const X509Crl>> issuerCrls;
  std::optional<std::string> applicationUri;
  std::optional<std::string> endpointUrl;
  CertificateUse purpose = CertificateUse::ApplicationInstance;
  bool checkRevocation = false;
  Status parseRefusal = Status::Good;  ///< The SDK refused to read one of the certificates.
};

bool needs_revocation_checking(Defect defect)
{
  switch (defect)
  {
  case Defect::IntermediateWithoutCrlSignRevocationOn:
  case Defect::IntermediateCrlMalformed:
  case Defect::IntermediateCrlFromAnotherIssuer:
  case Defect::CrlOfAnotherIssuerListingTheLeafSerial:
  case Defect::IntermediateCrlExpired:
  case Defect::IntermediateCrlNotYetValid:
  case Defect::IntermediateCrlSignatureBroken:
  case Defect::RootCrlExpired:
  case Defect::LeafRevokedWithReasonKeyCompromise:
  case Defect::IntermediateRevokedWithReasonCaCompromise:
    return true;
  default:
    return false;
  }
}

constexpr long day = 24L * 60 * 60;

ErrorScenario build_error_scenario(const Crypto& crypto, Defect defect, bool withDefect)
{
  ErrorScenario s;
  s.checkRevocation = needs_revocation_checking(defect);

  const auto rootKey = cached_key(rsa_key(2048), 10);
  const auto intermediateKey = cached_key(rsa_key(2048), 11);
  const auto leafRsaKey = cached_key(rsa_key(2048), 12);
  const auto leafEccKey = cached_key(curve_key(KeyKind::P256), 12);
  const auto otherCaKey = cached_key(rsa_key(2048), 13);
  const auto impostorKey = cached_key(rsa_key(2048), 14);
  const auto cycleKeyA = cached_key(rsa_key(2048), 15);
  const auto cycleKeyB = cached_key(rsa_key(2048), 16);
  require(rootKey && intermediateKey && leafRsaKey && leafEccKey && otherCaKey && impostorKey && cycleKeyA &&
            cycleKeyB,
    "U6 keys");

  auto rootSpec = ca_spec("U6 Root CA", "6100");
  auto intermediateSpec = ca_spec("U6 Intermediate CA", "6200");
  auto leafSpec = leaf_spec("U6 Leaf", "6300", KeyKind::Rsa, u6San);
  EVP_PKEY* leafKey = leafRsaKey.get();
  EVP_PKEY* leafSigner = intermediateKey.get();
  EVP_PKEY* intermediateSigner = rootKey.get();
  bool selfSignedLeaf = false;
  std::vector<CrlEntry> rootCrlEntries;
  std::vector<CrlEntry> intermediateCrlEntries;

  // What the defect and its control share.
  switch (defect)
  {
  case Defect::LeafWithoutSubjectAltNameAgainstAnApplicationUri:
  case Defect::LeafSubjectAltNameWithoutAUri:
  case Defect::LeafWithTwoUrisTheSecondMatching:
  case Defect::LeafUriDifferingInCase:
    s.applicationUri = u6Uri;
    break;
  case Defect::LeafUriWithATrailingSlash:
    leafSpec.subjectAltName = "URI:http://u6.example/leaf,DNS:u6-leaf.example";
    s.applicationUri = "http://u6.example/leaf";
    break;
  case Defect::LeafWithoutSubjectAltNameAgainstAnEndpointUrl:
  case Defect::LeafHostNameOnlyInTheCommonName:
    s.endpointUrl = u6Endpoint;
    break;
  case Defect::LeafIpv4AddressMatchingTheEndpoint:
  case Defect::LeafIpv4AddressNotMatchingTheEndpoint:
    s.endpointUrl = u6Ipv4Endpoint;
    break;
  case Defect::EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage:
  case Defect::EccLeafWithoutDigitalSignature:
    leafKey = leafEccKey.get();
    leafSpec = leaf_spec("U6 ECC Leaf", "6300", KeyKind::P256, u6San);
    break;
  case Defect::SelfSignedLeafWithoutKeyCertSign:
  case Defect::SelfSignedLeafCaTrueWithPathLength1:
  case Defect::SelfSignedLeafCaTrueWithoutPathLength:
    // The conformant self-signed form both Table 43 and RFC 5280 4.2.1.3 accept: cA TRUE, pathLength 0,
    // keyCertSign.
    selfSignedLeaf = true;
    leafSpec.ca = true;
    leafSpec.pathLength = 0;
    leafSpec.keyUsage = std::string{rsaLeafKeyUsage} + ",keyCertSign";
    break;
  case Defect::UserLeafCaTrue:
  case Defect::UserLeafWithPathLength:
  case Defect::UserLeafWithoutTheApplicationInstanceKeyUsage:
    s.purpose = CertificateUse::User;
    break;
  default:
    break;
  }

  // The defect itself, where it is a property of how the certificate is built.
  if (withDefect)
  {
    switch (defect)
    {
    case Defect::LeafVersion1WithExtensions:
      leafSpec.version = 1;
      break;
    case Defect::LeafVersion2WithExtensions:
      leafSpec.version = 2;
      break;
    case Defect::LeafMalformedNotBefore:
      leafSpec.rawNotBefore = "261399999999Z";
      break;
    case Defect::LeafMalformedNotAfter:
      leafSpec.rawNotAfter = "991332000000Z";
      break;
    case Defect::IntermediateEmptySubject:
      intermediateSpec.emptySubject = true;
      break;
    case Defect::LeafDuplicateExtension:
      leafSpec.duplicateBasicConstraints = true;
      break;
    case Defect::IntermediateDuplicateExtension:
      intermediateSpec.duplicateBasicConstraints = true;
      break;
    case Defect::LeafUnknownCriticalExtension:
      leafSpec.unknownCriticalExtension = true;
      break;
    case Defect::IntermediateUnknownCriticalExtension:
      intermediateSpec.unknownCriticalExtension = true;
      break;
    case Defect::LeafSerialLongerThan20Octets:
      leafSpec.serialHex = "7F" + std::string(40, 'A');  // 21 octets.
      break;
    case Defect::LeafNegativeSerial:
      leafSpec.negativeSerial = true;
      break;
    case Defect::LeafSignedByAnImpostorWithTheIssuersName:
      leafSigner = impostorKey.get();
      break;
    case Defect::IntermediateSignedByAnImpostorWithTheIssuersName:
      intermediateSigner = impostorKey.get();
      break;
    case Defect::LeafNotBeforeAfterNotAfter:
      leafSpec.notBeforeOffsetSeconds = -1 * day;
      leafSpec.notAfterOffsetSeconds = -2 * day;
      break;
    case Defect::IntermediateNotBeforeAfterNotAfter:
      intermediateSpec.notBeforeOffsetSeconds = -1 * day;
      intermediateSpec.notAfterOffsetSeconds = -2 * day;
      break;
    case Defect::LeafNotAfterInYear9999:
      leafSpec.notAfterText = "99991231235959Z";
      break;
    case Defect::LeafNotBeforeInYear2100:
      leafSpec.notBeforeText = "21000101000000Z";
      leafSpec.notAfterText = "21010101000000Z";
      break;
    case Defect::IntermediateNotBeforeInYear2100:
      intermediateSpec.notBeforeText = "21000101000000Z";
      intermediateSpec.notAfterText = "21010101000000Z";
      break;
    case Defect::LeafWithoutSubjectAltNameAgainstAnApplicationUri:
    case Defect::LeafWithoutSubjectAltNameAgainstAnEndpointUrl:
      leafSpec.subjectAltName.clear();
      break;
    case Defect::LeafSubjectAltNameWithoutAUri:
      leafSpec.subjectAltName = "DNS:u6-leaf.example,IP:192.0.2.10";
      break;
    case Defect::LeafWithTwoUrisTheSecondMatching:
      leafSpec.subjectAltName = "URI:urn:reduktive:u6:other,URI:urn:reduktive:u6:leaf,DNS:u6-leaf.example";
      break;
    case Defect::LeafUriDifferingInCase:
      leafSpec.subjectAltName = "URI:urn:reduktive:u6:LEAF,DNS:u6-leaf.example";
      break;
    case Defect::LeafUriWithATrailingSlash:
      leafSpec.subjectAltName = "URI:http://u6.example/leaf/,DNS:u6-leaf.example";
      break;
    case Defect::LeafIpv4AddressMatchingTheEndpoint:
      leafSpec.subjectAltName = "URI:urn:reduktive:u6:leaf,IP:192.0.2.10";
      break;
    case Defect::LeafIpv4AddressNotMatchingTheEndpoint:
      leafSpec.subjectAltName = "URI:urn:reduktive:u6:leaf,IP:192.0.2.99";
      break;
    case Defect::LeafHostNameOnlyInTheCommonName:
      leafSpec.commonName = "u6-leaf.example";
      leafSpec.subjectAltName = "URI:urn:reduktive:u6:leaf";
      break;
    case Defect::RsaLeafWithoutKeyEncipherment:
      leafSpec.keyUsage = "critical,digitalSignature,nonRepudiation,dataEncipherment";
      break;
    case Defect::RsaLeafWithoutDataEncipherment:
      leafSpec.keyUsage = "critical,digitalSignature,nonRepudiation,keyEncipherment";
      break;
    case Defect::RsaLeafWithoutNonRepudiation:
      leafSpec.keyUsage = "critical,digitalSignature,keyEncipherment,dataEncipherment";
      break;
    case Defect::RsaLeafWithoutDigitalSignature:
      leafSpec.keyUsage = "critical,nonRepudiation,keyEncipherment,dataEncipherment";
      break;
    case Defect::RsaLeafWithoutExtendedKeyUsage:
      leafSpec.extendedKeyUsage.clear();
      break;
    case Defect::EccLeafWithOnlyDigitalSignatureAndNoExtendedKeyUsage:
      leafSpec.keyUsage = "critical,digitalSignature";
      leafSpec.extendedKeyUsage.clear();
      break;
    case Defect::EccLeafWithoutDigitalSignature:
      leafSpec.keyUsage = "critical,nonRepudiation";
      break;
    case Defect::SelfSignedLeafWithoutKeyCertSign:
      leafSpec.keyUsage = rsaLeafKeyUsage;
      break;
    case Defect::SelfSignedLeafCaTrueWithPathLength1:
      leafSpec.pathLength = 1;
      break;
    case Defect::SelfSignedLeafCaTrueWithoutPathLength:
      leafSpec.pathLength = std::nullopt;
      break;
    case Defect::CaIssuedLeafCaTrue:
    case Defect::UserLeafCaTrue:
      leafSpec.ca = true;
      break;
    case Defect::UserLeafWithPathLength:
      leafSpec.pathLength = 0;
      break;
    case Defect::UserLeafWithoutTheApplicationInstanceKeyUsage:
    case Defect::ApplicationLeafWithoutTheApplicationInstanceKeyUsage:
      leafSpec.keyUsage = "critical,digitalSignature";
      leafSpec.extendedKeyUsage.clear();
      break;
    case Defect::IntermediateWithoutKeyCertSign:
      intermediateSpec.keyUsage = "critical,digitalSignature,cRLSign";
      break;
    case Defect::IntermediateWithoutCrlSignRevocationOff:
    case Defect::IntermediateWithoutCrlSignRevocationOn:
      intermediateSpec.keyUsage = "critical,digitalSignature,keyCertSign";
      break;
    case Defect::LeafRevokedWithReasonKeyCompromise:
      intermediateCrlEntries.push_back(CrlEntry{"6300", 1});
      break;
    case Defect::IntermediateRevokedWithReasonCaCompromise:
      rootCrlEntries.push_back(CrlEntry{"6200", 2});
      break;
    default:
      break;
    }
  }

  const auto root = build_certificate(rootSpec, rootKey.get(), nullptr, rootKey.get(), Digest::Sha256);
  const auto intermediate = build_certificate(
    intermediateSpec, intermediateKey.get(), root.get(), intermediateSigner, Digest::Sha256);
  const auto leaf = selfSignedLeaf
                      ? build_certificate(leafSpec, leafKey, nullptr, leafKey, Digest::Sha256)
                      : build_certificate(leafSpec, leafKey, intermediate.get(), leafSigner, Digest::Sha256);

  Der rootDer = der_of(root.get());
  Der intermediateDer = der_of(intermediate.get());
  Der leafDer = der_of(leaf.get());

  // The defect itself, where it is byte surgery on a certificate that was well formed.
  if (withDefect)
  {
    switch (defect)
    {
    case Defect::LeafTruncatedDer:
      leafDer = truncated(leafDer);
      break;
    case Defect::LeafTrailingBytesInsideTheOuterSequence:
      leafDer = with_trailing_bytes_inside_the_outer_sequence(leafDer);
      break;
    case Defect::LeafUndecodablePublicKey:
      leafDer = with_undecodable_rsa_public_key(leafDer);
      break;
    case Defect::LeafZeroLengthSerial:
      leafDer = with_zero_length_serial(leafDer);
      break;
    case Defect::LeafVersion1WithExtensions:
    case Defect::LeafVersion2WithExtensions:
      require(!selfSignedLeaf, "a version defect on an issued leaf");
      leafDer = with_version_resigned(leafDer, leafSpec.version, leafSigner);
      break;
    case Defect::LeafSignatureBroken:
      leafDer = with_last_byte_flipped(leafDer);
      break;
    case Defect::IntermediateSignatureBroken:
      intermediateDer = with_last_byte_flipped(intermediateDer);
      break;
    case Defect::RootSignatureBroken:
      rootDer = with_last_byte_flipped(rootDer);
      break;
    case Defect::LeafSignatureAlgorithmFieldsDisagree:
      leafDer = with_disagreeing_signature_algorithm(leafDer);
      break;
    default:
      break;
    }
  }

  const auto parse = [&crypto, &s](const Der& der) -> std::shared_ptr<const X509Certificate>
  {
    try
    {
      return to_sdk_certificate(crypto, der);
    }
    catch (const UaException& e)
    {
      if (s.parseRefusal == Status::Good)
      {
        s.parseRefusal = e.status();
      }
      return nullptr;
    }
  };
  const auto parseCrl = [&crypto](const Der& der) -> std::shared_ptr<const X509Crl>
  {
    try
    {
      const auto bytes = to_ua_bytes(der);
      return crypto.read_crl_from_der(span<const ua::byte>{bytes});
    }
    catch (const UaException&)
    {
      return nullptr;  // A CRL the SDK cannot read is a CRL that is not there.
    }
  };

  const auto sdkRoot = parse(rootDer);
  const auto sdkIntermediate = parse(intermediateDer);
  s.leaf = parse(leafDer);

  if (selfSignedLeaf)
  {
    s.trusted = {s.leaf};
    return s;
  }

  s.trusted = {sdkRoot};
  s.issuers = {sdkIntermediate};

  if (defect == Defect::IssuerCycle && withDefect)
  {
    // A signed by B and B signed by A; the leaf is issued by A. A is trusted, B is chain material, and no
    // self-signed certificate is reachable. A0 only lends A's name and key identifier to B.
    const auto a0 = build_certificate(
      ca_spec("U6 Cycle CA A", "6501"), cycleKeyA.get(), nullptr, cycleKeyA.get(), Digest::Sha256);
    const auto b = build_certificate(
      ca_spec("U6 Cycle CA B", "6502"), cycleKeyB.get(), a0.get(), cycleKeyA.get(), Digest::Sha256);
    const auto a = build_certificate(
      ca_spec("U6 Cycle CA A", "6503"), cycleKeyA.get(), b.get(), cycleKeyB.get(), Digest::Sha256);
    const auto cycleLeaf = build_certificate(leafSpec, leafKey, a.get(), cycleKeyA.get(), Digest::Sha256);
    s.trusted = {parse(der_of(a.get()))};
    s.issuers = {parse(der_of(b.get()))};
    s.leaf = parse(der_of(cycleLeaf.get()));
  }
  if (defect == Defect::TwoIssuersWithTheSameNameOnlyOneVerifying)
  {
    // The genuine intermediate is presented with the leaf; with the defect, the issuer list also holds a CA
    // with the same name and key identifier but another key, which root genuinely issued.
    s.issuers.clear();
    s.presented = {sdkIntermediate};
    if (withDefect)
    {
      auto twinSpec = ca_spec("U6 Intermediate CA", "6201");
      twinSpec.subjectKeyIdentifier = skid_hex(intermediate.get());
      const auto twin =
        build_certificate(twinSpec, impostorKey.get(), root.get(), rootKey.get(), Digest::Sha256);
      s.issuers = {parse(der_of(twin.get()))};
    }
  }
  if (defect == Defect::DuplicateCertificatesInThePresentedChain)
  {
    s.issuers.clear();
    s.presented = {sdkIntermediate};
    if (withDefect)
    {
      s.presented.push_back(sdkIntermediate);
    }
  }

  if (s.checkRevocation)
  {
    // Every CA's current CRL, the root's in the trusted CRLs and the intermediate's in the issuer CRLs.
    Der rootCrl = build_crl(root.get(), rootKey.get(), rootCrlEntries);
    Der intermediateCrl = build_crl(intermediate.get(), intermediateKey.get(), intermediateCrlEntries);
    if (withDefect)
    {
      switch (defect)
      {
      case Defect::IntermediateCrlMalformed:
        intermediateCrl.resize(intermediateCrl.size() / 2);
        break;
      case Defect::IntermediateCrlFromAnotherIssuer:
      case Defect::CrlOfAnotherIssuerListingTheLeafSerial:
      {
        const auto otherCa = build_certificate(
          ca_spec("U6 Other CA", "6400"), otherCaKey.get(), nullptr, otherCaKey.get(), Digest::Sha256);
        s.trusted.push_back(parse(der_of(otherCa.get())));
        const auto otherCrl = build_crl(otherCa.get(), otherCaKey.get(), {CrlEntry{"6300", 1}});
        if (defect == Defect::IntermediateCrlFromAnotherIssuer)
        {
          intermediateCrl = otherCrl;
        }
        else
        {
          s.issuerCrls.push_back(parseCrl(otherCrl));
        }
        break;
      }
      case Defect::IntermediateCrlExpired:
        intermediateCrl = build_crl(intermediate.get(), intermediateKey.get(), {}, -2 * day, -1 * day);
        break;
      case Defect::IntermediateCrlNotYetValid:
        intermediateCrl = build_crl(intermediate.get(), intermediateKey.get(), {}, 1 * day, 8 * day);
        break;
      case Defect::IntermediateCrlSignatureBroken:
        intermediateCrl.back() ^= 0x5A;
        break;
      case Defect::RootCrlExpired:
        rootCrl = build_crl(root.get(), rootKey.get(), {}, -2 * day, -1 * day);
        break;
      default:
        break;
      }
    }
    s.trustedCrls.push_back(parseCrl(rootCrl));
    s.issuerCrls.push_back(parseCrl(intermediateCrl));
  }
  return s;
}

struct ErrorCase
{
  Defect defect = Defect::LeafTruncatedDer;
  bool allSuppressionBits = false;
};

std::vector<ErrorCase> all_error_cases()
{
  std::vector<ErrorCase> cases;
  for (const auto& entry : defects)
  {
    for (const bool suppressed : {false, true})
    {
      ErrorCase c;
      c.defect = entry.defect;
      c.allSuppressionBits = suppressed;
      cases.push_back(c);
    }
  }
  return cases;
}

std::string error_case_name(const ::testing::TestParamInfo<ErrorCase>& info)
{
  return defect_name(info.param.defect) +
         (info.param.allSuppressionBits ? "_AllSuppressionBits" : "_NoSuppression");
}

TrustListValidationOptions error_case_options(bool checkRevocation, bool allSuppressionBits)
{
  using Bit = TrustListValidationOptions::Bit;
  if (allSuppressionBits)
  {
    return checkRevocation ? TrustListValidationOptions{Bit::SuppressCertificateExpired,
                               Bit::SuppressHostNameInvalid,
                               Bit::SuppressRevocationStatusUnknown,
                               Bit::SuppressIssuerCertificateExpired,
                               Bit::SuppressIssuerRevocationStatusUnknown,
                               Bit::CheckRevocationStatusOffline}
                           : TrustListValidationOptions{Bit::SuppressCertificateExpired,
                               Bit::SuppressHostNameInvalid,
                               Bit::SuppressRevocationStatusUnknown,
                               Bit::SuppressIssuerCertificateExpired,
                               Bit::SuppressIssuerRevocationStatusUnknown};
  }
  return checkRevocation ? TrustListValidationOptions{Bit::CheckRevocationStatusOffline}
                         : TrustListValidationOptions{};
}

class CertificateErrorMatrix : public ::testing::TestWithParam<ErrorCase>
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sCrypto = BackendOpenSslFiles::create_crypto();
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sThreadPool);
    sThreadPool.reset();
    sCrypto.reset();
  }

protected:
  /// Validates the scenario's leaf through a fresh store of the scenario's list purpose, the store entry
  /// point both sides' secure channels use (the presented certificates as the additional issuer
  /// certificates).
  Status validate(const ErrorScenario& s, bool allSuppressionBits)
  {
    const auto rootPath = test_utils::unique_temp_path("cert_error_matrix");
    fs::remove_all(rootPath);
    Status status = Status::BadInternalError;
    {
      const auto store = CertificateStoreFiles::create(sThreadPool->get_executor(),
        sCrypto,
        {.trustListPath = rootPath, .storeRejectedCertificates = false, .use = s.purpose});
      EXPECT_NE(store, nullptr);
      if (store)
      {
        for (const auto& certificate : s.trusted)
        {
          if (certificate)
          {
            EXPECT_TRUE(store->try_add_to_trusted_certificates_sync(certificate).is_good());
          }
        }
        for (const auto& certificate : s.issuers)
        {
          if (certificate)
          {
            EXPECT_TRUE(store->try_add_to_issuer_certificates_sync(certificate).is_good());
          }
        }
        // A CRL the store refuses to hold is a CRL that is not there; the verdict is what is under test.
        for (const auto& crl : s.trustedCrls)
        {
          if (crl)
          {
            static_cast<void>(store->try_add_to_trusted_crls_sync(crl));
          }
        }
        for (const auto& crl : s.issuerCrls)
        {
          if (crl)
          {
            static_cast<void>(store->try_add_to_issuer_crls_sync(crl));
          }
        }
        std::vector<std::shared_ptr<const X509Certificate>> presented;
        for (const auto& certificate : s.presented)
        {
          if (certificate)
          {
            presented.push_back(certificate);
          }
        }
        status = store
                   ->try_validate_certificate_sync(ua::test::make_validation_request(s.leaf,
                     presented,
                     error_case_options(s.checkRevocation, allSuppressionBits),
                     s.applicationUri,
                     s.endpointUrl))
                   .status_code()
                   .as_status();
      }
    }
    std::error_code ignored;
    fs::remove_all(rootPath, ignored);
    return status;
  }

  static std::shared_ptr<const Crypto> sCrypto;

  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
};

std::shared_ptr<const Crypto> CertificateErrorMatrix::sCrypto;

// Each defect through CertificateStore::validate_certificate_async, with a control built from the same keys
// and specs that differs only in the defect and passes. A certificate the SDK refuses to read is refused at
// the Certificate Structure step: the refusal's status is the observation.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-13-ERROR-STRUCTURE, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-14-ERROR-SIGNATURE, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-15-ERROR-VALIDITY, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-16-ERROR-HOST-NAME-AND-URI, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-17-ERROR-USAGE, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-18-ERROR-REVOCATION-LIST, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-19-ERROR-CHAIN-ANOMALY, scope=function)
TEST_P(CertificateErrorMatrix, TheStoreReturnsTheSpecifiedStatusAndTheControlPasses)
{
  const auto& c = GetParam();
  ASSERT_NE(sCrypto, nullptr);

  const auto control = build_error_scenario(*sCrypto, c.defect, false);
  ASSERT_EQ(control.parseRefusal, Status::Good) << "the control must be readable";
  ASSERT_NE(control.leaf, nullptr);
  const auto controlStatus = validate(control, c.allSuppressionBits);
  EXPECT_EQ(controlStatus, Status::Good)
    << defect_name(c.defect) << " control: expected Good, got " << to_string(controlStatus);

  const auto faulty = build_error_scenario(*sCrypto, c.defect, true);
  const auto observed =
    faulty.parseRefusal != Status::Good ? faulty.parseRefusal : validate(faulty, c.allSuppressionBits);
  const auto expected = expected_error_status(c.defect, c.allSuppressionBits);
  EXPECT_EQ(observed, expected) << defect_name(c.defect) << ": expected " << to_string(expected) << ", got "
                                << to_string(observed)
                                << (faulty.parseRefusal != Status::Good ? " (refused when read)" : "");
}

INSTANTIATE_TEST_SUITE_P(
  AllDefects, CertificateErrorMatrix, ::testing::ValuesIn(all_error_cases()), error_case_name);

}  // namespace
