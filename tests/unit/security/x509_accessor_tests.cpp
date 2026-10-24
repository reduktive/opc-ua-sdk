// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// U13 (certificate coverage review): every accessor of the OpenSSL certificate and CRL classes, and the
// four DER parsers. Every fixture is built DIRECTLY WITH OPENSSL in this file (X509_new, X509V3 extensions,
// X509_sign), so the expected value is what the test put into the encoding, known without the class under
// test. The certificate under test is always read the way a production caller reads a peer's certificate:
// Crypto::read_certificate_from_der over the DER bytes.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "test_key_cache.h"
#include "certificate_store_test_backends.h"
#include "ua_crypto.h"
#include "ua_exceptions.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

using namespace ua;

namespace
{

// ---------------------------------------------------------------------------------------------------------
// OpenSSL construction (test-local; no SDK code).
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
using Asn1OctetStringPtr =
  std::unique_ptr<ASN1_OCTET_STRING, OpenSslDeleter<ASN1_OCTET_STRING, &ASN1_OCTET_STRING_free>>;
using Asn1EnumeratedPtr =
  std::unique_ptr<ASN1_ENUMERATED, OpenSslDeleter<ASN1_ENUMERATED, &ASN1_ENUMERATED_free>>;
using GeneralNamePtr = std::unique_ptr<GENERAL_NAME, OpenSslDeleter<GENERAL_NAME, &GENERAL_NAME_free>>;
using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, OpenSslDeleter<GENERAL_NAMES, &GENERAL_NAMES_free>>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, OpenSslDeleter<EVP_MD_CTX, &EVP_MD_CTX_free>>;
using BioPtr = std::unique_ptr<BIO, OpenSslDeleter<BIO, &BIO_free_all>>;
using PKey = std::shared_ptr<EVP_PKEY>;
using Der = std::vector<unsigned char>;

void require(bool condition, const char* what)
{
  if (!condition)
  {
    ERR_clear_error();
    throw std::runtime_error{std::string{"test fixture construction failed: "} + what};
  }
}

/// A key the fixtures can be built on: RSA with a modulus size, ECC on a named curve, or EdDSA.
struct KeyType
{
  const char* label;
  const char* algorithm;  ///< "RSA", "EC", "ED25519" or "ED448".
  const char* curve;  ///< Only for "EC".
  int rsaBits;  ///< Only for "RSA".
};

constexpr KeyType rsa2048{"Rsa2048", "RSA", "", 2048};
constexpr KeyType p256{"NistP256", "EC", "P-256", 0};
constexpr KeyType p384{"NistP384", "EC", "P-384", 0};
constexpr KeyType p521{"NistP521", "EC", "P-521", 0};
constexpr KeyType ed25519{"Ed25519", "ED25519", "", 0};
constexpr KeyType ed448{"Ed448", "ED448", "", 0};

/// The shared test key cache's type for @p type.
test_keys::KeyType cache_type_of(const KeyType& type)
{
  static const std::map<std::string, test_keys::KeyType> types{{"Rsa1024", test_keys::KeyType::Rsa1024},
    {"Rsa2048", test_keys::KeyType::Rsa2048},
    {"Rsa3072", test_keys::KeyType::Rsa3072},
    {"Rsa4096", test_keys::KeyType::Rsa4096},
    {"NistP256", test_keys::KeyType::P256},
    {"NistP384", test_keys::KeyType::P384},
    {"NistP521", test_keys::KeyType::P521},
    {"BrainpoolP256r1", test_keys::KeyType::Bp256},
    {"BrainpoolP384r1", test_keys::KeyType::Bp384},
    {"BrainpoolP512r1", test_keys::KeyType::Bp512},
    {"Ed25519", test_keys::KeyType::Ed25519},
    {"Ed448", test_keys::KeyType::Ed448}};
  const auto found = types.find(type.label);
  if (found == types.end())
  {
    throw std::logic_error{std::string{"the test key cache has no key type for "} + type.label};
  }
  return found->second;
}

/// The key of @p type in the named @p slot, from the shared test key cache (generated once per machine, not
/// per test); null when this OpenSSL build cannot make one. Each slot name is a distinct cache slot.
PKey key_of(const KeyType& type, const std::string& slot = "default")
{
  static std::map<std::string, PKey> cache;
  static std::map<std::string, unsigned> slots;
  const std::string name = std::string{type.label} + "/" + slot;
  const auto found = cache.find(name);
  if (found != cache.end())
  {
    return found->second;
  }
  const auto cacheType = cache_type_of(type);
  const auto slotNumber = slots.emplace(slot, static_cast<unsigned>(slots.size())).first->second;
  PKey key{test_keys::new_evp_pkey(cacheType, slotNumber), EVP_PKEY_free};
  cache.emplace(name, key);
  return key;
}

PKey required_key(const KeyType& type, const std::string& slot = "default")
{
  auto key = key_of(type, slot);
  require(key != nullptr, type.label);
  return key;
}

/// One attribute of an X.501 Name. @c type is an MBSTRING_* input format or a V_ASN1_* string type to encode
/// as; @c joinPrevious puts the attribute into the previous RDN (a multi-valued RDN).
struct NameAttribute
{
  int nid;
  std::string value;
  int type;
  bool joinPrevious;
};

NameAttribute utf8(int nid, std::string value)
{
  return NameAttribute{nid, std::move(value), MBSTRING_UTF8, false};
}

using NameSpec = std::vector<NameAttribute>;

X509NamePtr make_name(const NameSpec& spec)
{
  X509NamePtr name{X509_NAME_new()};
  require(name != nullptr, "X509_NAME_new");
  for (const auto& attribute : spec)
  {
    require(X509_NAME_add_entry_by_NID(name.get(),
              attribute.nid,
              attribute.type,
              reinterpret_cast<const unsigned char*>(attribute.value.data()),
              static_cast<int>(attribute.value.size()),
              -1,
              attribute.joinPrevious ? -1 : 0) == 1,
      "X509_NAME_add_entry_by_NID");
  }
  return name;
}

struct Extension
{
  int nid;
  std::string value;
};

struct CertSpec
{
  long version = 2;  ///< Zero-indexed: 2 is X.509 v3, 0 is v1.
  NameSpec subject = {utf8(NID_commonName, "Accessor Leaf")};
  std::string serialHex = "1001";
  std::string notBefore = "250101000000Z";  ///< 13 characters: UTCTime; 15: GeneralizedTime.
  std::string notAfter = "350101000000Z";
  std::vector<Extension> extensions;  ///< Added in order, through X509V3_EXT_conf_nid.
  std::vector<Der> rawIpSans;  ///< When non-empty: a SAN of iPAddress entries carrying exactly these octets.
};

/// The issuing side. A null @c certificate means self-issued (named by its own subject); a null @c key
/// means signed with the subject key.
struct Signer
{
  X509* certificate;
  EVP_PKEY* key;
};

constexpr Signer self{nullptr, nullptr};

void add_extension(X509* certificate, X509* issuer, const Extension& extension)
{
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer != nullptr ? issuer : certificate, certificate, nullptr, nullptr, 0);
  X509ExtensionPtr built{X509V3_EXT_conf_nid(nullptr, &ctx, extension.nid, extension.value.c_str())};
  require(built != nullptr, "X509V3_EXT_conf_nid");
  require(X509_add_ext(certificate, built.get(), -1) == 1, "X509_add_ext");
}

void add_raw_ip_sans(X509* certificate, const std::vector<Der>& addresses)
{
  GeneralNamesPtr names{sk_GENERAL_NAME_new_null()};
  require(names != nullptr, "sk_GENERAL_NAME_new_null");
  for (const auto& octets : addresses)
  {
    GeneralNamePtr name{GENERAL_NAME_new()};
    Asn1OctetStringPtr address{ASN1_OCTET_STRING_new()};
    require(name != nullptr && address != nullptr, "GENERAL_NAME_new");
    require(ASN1_OCTET_STRING_set(address.get(), octets.data(), static_cast<int>(octets.size())) == 1,
      "ASN1_OCTET_STRING_set");
    GENERAL_NAME_set0_value(name.get(), GEN_IPADD, address.release());
    require(sk_GENERAL_NAME_push(names.get(), name.get()) > 0, "sk_GENERAL_NAME_push");
    static_cast<void>(name.release());
  }
  require(X509_add1_ext_i2d(certificate, NID_subject_alt_name, names.get(), 0, X509V3_ADD_DEFAULT) == 1,
    "X509_add1_ext_i2d");
}

void sign(X509* certificate, EVP_PKEY* key, const EVP_MD* digest, bool pss)
{
  if (pss)
  {
    EvpMdCtxPtr mdCtx{EVP_MD_CTX_new()};
    require(mdCtx != nullptr, "EVP_MD_CTX_new");
    EVP_PKEY_CTX* pkeyCtx = nullptr;
    require(EVP_DigestSignInit(mdCtx.get(), &pkeyCtx, digest, nullptr, key) == 1, "EVP_DigestSignInit");
    require(EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) > 0, "PSS padding");
    require(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) > 0, "PSS salt length");
    require(X509_sign_ctx(certificate, mdCtx.get()) > 0, "X509_sign_ctx");
    return;
  }
  const bool pure = EVP_PKEY_id(key) == EVP_PKEY_ED25519 || EVP_PKEY_id(key) == EVP_PKEY_ED448;
  require(X509_sign(certificate, key, pure ? nullptr : digest) > 0, "X509_sign");
}

X509Ptr build_certificate(const CertSpec& spec, EVP_PKEY* subjectKey, const Signer& signer = self,
  const EVP_MD* digest = EVP_sha256(), bool pss = false)
{
  X509Ptr certificate{X509_new()};
  require(certificate != nullptr, "X509_new");
  require(X509_set_version(certificate.get(), spec.version) == 1, "X509_set_version");

  BIGNUM* rawSerial = nullptr;
  require(BN_hex2bn(&rawSerial, spec.serialHex.c_str()) > 0, "BN_hex2bn");
  BignumPtr serialNumber{rawSerial};
  Asn1IntegerPtr serial{BN_to_ASN1_INTEGER(serialNumber.get(), nullptr)};
  require(serial != nullptr && X509_set_serialNumber(certificate.get(), serial.get()) == 1, "serial");

  const auto subject = make_name(spec.subject);
  require(X509_set_subject_name(certificate.get(), subject.get()) == 1, "subject");
  require(X509_set_issuer_name(certificate.get(),
            signer.certificate != nullptr ? X509_get_subject_name(signer.certificate) : subject.get()) == 1,
    "issuer");

  Asn1TimePtr notBefore{ASN1_TIME_new()};
  Asn1TimePtr notAfter{ASN1_TIME_new()};
  require(notBefore != nullptr && notAfter != nullptr, "ASN1_TIME_new");
  require(ASN1_TIME_set_string(notBefore.get(), spec.notBefore.c_str()) == 1, "notBefore");
  require(ASN1_TIME_set_string(notAfter.get(), spec.notAfter.c_str()) == 1, "notAfter");
  require(X509_set1_notBefore(certificate.get(), notBefore.get()) == 1, "X509_set1_notBefore");
  require(X509_set1_notAfter(certificate.get(), notAfter.get()) == 1, "X509_set1_notAfter");

  require(X509_set_pubkey(certificate.get(), subjectKey) == 1, "X509_set_pubkey");
  for (const auto& extension : spec.extensions)
  {
    add_extension(certificate.get(), signer.certificate, extension);
  }
  if (!spec.rawIpSans.empty())
  {
    add_raw_ip_sans(certificate.get(), spec.rawIpSans);
  }
  sign(certificate.get(), signer.key != nullptr ? signer.key : subjectKey, digest, pss);
  return certificate;
}

// The encoders below take `const` objects in OpenSSL 3 but not in 1.1.1, although they do not modify them;
// the const_casts let one source build against both.
Der der_of(const X509* certificate)
{
  const int length = i2d_X509(const_cast<X509*>(certificate), nullptr);
  require(length > 0, "i2d_X509 length");
  Der der(static_cast<std::size_t>(length));
  unsigned char* out = der.data();
  require(i2d_X509(const_cast<X509*>(certificate), &out) == length, "i2d_X509");
  return der;
}

Der der_of_name(const X509_NAME* name)
{
  unsigned char* out = nullptr;
  const int length = i2d_X509_NAME(const_cast<X509_NAME*>(name), &out);
  require(length > 0, "i2d_X509_NAME");
  Der der(out, out + length);
  OPENSSL_free(out);
  return der;
}

Der public_key_info_of(const EVP_PKEY* key)
{
  unsigned char* out = nullptr;
  const int length = i2d_PUBKEY(const_cast<EVP_PKEY*>(key), &out);
  require(length > 0, "i2d_PUBKEY");
  Der der(out, out + length);
  OPENSSL_free(out);
  return der;
}

Der sha1_of(const Der& bytes)
{
  Der digest(EVP_MAX_MD_SIZE);
  unsigned int length = 0;
  require(EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha1(), nullptr) == 1, "SHA-1");
  digest.resize(length);
  return digest;
}

Der hex_bytes(const std::string& hex)
{
  long length = 0;
  unsigned char* raw = OPENSSL_hexstr2buf(hex.c_str(), &length);
  require(raw != nullptr, "OPENSSL_hexstr2buf");
  Der bytes(raw, raw + length);
  OPENSSL_free(raw);
  return bytes;
}

Der pem_of(const X509* certificate)
{
  BioPtr bio{BIO_new(BIO_s_mem())};
  require(bio != nullptr && PEM_write_bio_X509(bio.get(), const_cast<X509*>(certificate)) == 1,
    "PEM_write_bio_X509");
  BUF_MEM* memory = nullptr;
  BIO_get_mem_ptr(bio.get(), &memory);
  require(memory != nullptr, "BIO_get_mem_ptr");
  return Der(memory->data, memory->data + memory->length);
}

/// A CRL issued by @p issuer: @p revoked lists {serial hex, reason code}; a reason below zero is left out.
X509CrlPtr build_crl(X509* issuer, EVP_PKEY* issuerKey,
  const std::vector<std::pair<std::string, int>>& revoked, const std::string& lastUpdate)
{
  X509CrlPtr crl{X509_CRL_new()};
  require(crl != nullptr, "X509_CRL_new");
  require(X509_CRL_set_version(crl.get(), 1) == 1, "X509_CRL_set_version");
  require(X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) == 1, "CRL issuer");
  Asn1TimePtr thisUpdate{ASN1_TIME_new()};
  Asn1TimePtr nextUpdate{ASN1_TIME_new()};
  require(thisUpdate != nullptr && nextUpdate != nullptr &&
            ASN1_TIME_set_string(thisUpdate.get(), lastUpdate.c_str()) == 1 &&
            ASN1_TIME_set_string(nextUpdate.get(), "350101000000Z") == 1 &&
            X509_CRL_set1_lastUpdate(crl.get(), thisUpdate.get()) == 1 &&
            X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get()) == 1,
    "CRL times");
  for (const auto& [serialHex, reason] : revoked)
  {
    X509_REVOKED* entry = X509_REVOKED_new();
    require(entry != nullptr, "X509_REVOKED_new");
    BIGNUM* rawSerial = nullptr;
    require(BN_hex2bn(&rawSerial, serialHex.c_str()) > 0, "revoked serial");
    BignumPtr serialNumber{rawSerial};
    Asn1IntegerPtr serial{BN_to_ASN1_INTEGER(serialNumber.get(), nullptr)};
    require(serial != nullptr && X509_REVOKED_set_serialNumber(entry, serial.get()) == 1 &&
              X509_REVOKED_set_revocationDate(entry, thisUpdate.get()) == 1,
      "revoked entry");
    if (reason >= 0)
    {
      Asn1EnumeratedPtr code{ASN1_ENUMERATED_new()};
      require(code != nullptr && ASN1_ENUMERATED_set(code.get(), reason) == 1 &&
                X509_REVOKED_add1_ext_i2d(entry, NID_crl_reason, code.get(), 0, 0) == 1,
        "reasonCode");
    }
    require(X509_CRL_add0_revoked(crl.get(), entry) == 1, "X509_CRL_add0_revoked");
  }
  require(X509_CRL_sort(crl.get()) == 1, "X509_CRL_sort");
  require(X509_CRL_sign(crl.get(), issuerKey, EVP_sha256()) > 0, "X509_CRL_sign");
  return crl;
}

Der der_of_crl(const X509_CRL* crl)
{
  const int length = i2d_X509_CRL(const_cast<X509_CRL*>(crl), nullptr);
  require(length > 0, "i2d_X509_CRL length");
  Der der(static_cast<std::size_t>(length));
  unsigned char* out = der.data();
  require(i2d_X509_CRL(const_cast<X509_CRL*>(crl), &out) == length, "i2d_X509_CRL");
  return der;
}

Der pem_of_crl(const X509_CRL* crl)
{
  BioPtr bio{BIO_new(BIO_s_mem())};
  require(bio != nullptr && PEM_write_bio_X509_CRL(bio.get(), const_cast<X509_CRL*>(crl)) == 1,
    "PEM_write_bio_X509_CRL");
  BUF_MEM* memory = nullptr;
  BIO_get_mem_ptr(bio.get(), &memory);
  require(memory != nullptr, "BIO_get_mem_ptr");
  return Der(memory->data, memory->data + memory->length);
}

// ---------------------------------------------------------------------------------------------------------
// The SDK side: bytes in, as a production caller hands them over.
// ---------------------------------------------------------------------------------------------------------

const Crypto& crypto()
{
  static const std::shared_ptr<const Crypto> instance = BackendOpenSslFiles::create_crypto();
  return *instance;
}

std::vector<ua::byte> to_ua_bytes(const Der& der)
{
  std::vector<ua::byte> bytes;
  bytes.reserve(der.size());
  for (const unsigned char c : der)
  {
    bytes.push_back(static_cast<ua::byte>(c));
  }
  return bytes;
}

std::shared_ptr<const X509Certificate> read(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return crypto().read_certificate_from_der(span<const ua::byte>{bytes});
}

std::shared_ptr<const X509Certificate> read(const X509Ptr& certificate)
{
  return read(der_of(certificate.get()));
}

Der bytes_of(const ByteString& value)
{
  return Der(value.begin(), value.end());
}

Der bytes_of(const std::string& value)
{
  return Der(value.begin(), value.end());
}

Status status_of(const std::function<void()>& call)
{
  try
  {
    call();
  }
  catch (const UaException& exception)
  {
    return exception.status();
  }
  return Status::Good;
}

auto seconds_of(const DateTime& time)
{
  return std::chrono::time_point_cast<std::chrono::seconds>(time.value());
}

template<typename Param>
std::string label_of(const ::testing::TestParamInfo<Param>& info)
{
  return std::string{info.param.label};
}

// ---------------------------------------------------------------------------------------------------------
// Names: the DER Name, and each attribute accessor.
// ---------------------------------------------------------------------------------------------------------

NameSpec full_name(const std::string& commonName)
{
  return {utf8(NID_countryName, "GB"),
    utf8(NID_stateOrProvinceName, "Antrim"),
    utf8(NID_localityName, "Belfast"),
    utf8(NID_organizationName, "reduktive"),
    utf8(NID_organizationalUnitName, "Certificates"),
    utf8(NID_domainComponent, "example"),
    utf8(NID_distinguishedName, "CN=Embedded"),
    utf8(NID_commonName, commonName)};
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, EachSubjectAttributeIsReportedByItsOwnAccessor)
{
  CertSpec spec;
  spec.subject = full_name("Accessor Subject");
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(certificate->subject_country(), "GB");
  EXPECT_EQ(certificate->subject_state(), "Antrim");
  EXPECT_EQ(certificate->subject_locality(), "Belfast");
  EXPECT_EQ(certificate->subject_organization(), "reduktive");
  EXPECT_EQ(certificate->subject_organizational_unit(), "Certificates");
  EXPECT_EQ(certificate->subject_domain_component(), "example");
  EXPECT_EQ(certificate->subject_distinguished_name(), "CN=Embedded")
    << "the distinguishedName attribute (2.5.4.49), not a rendering of the whole Name";
  EXPECT_EQ(certificate->subject_common_name(), "Accessor Subject");
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, AnAbsentSubjectAttributeIsEmpty)
{
  CertSpec spec;
  spec.subject = {utf8(NID_commonName, "Only A Common Name")};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(certificate->subject_common_name(), "Only A Common Name");
  EXPECT_EQ(certificate->subject_country(), "");
  EXPECT_EQ(certificate->subject_state(), "");
  EXPECT_EQ(certificate->subject_locality(), "");
  EXPECT_EQ(certificate->subject_organization(), "");
  EXPECT_EQ(certificate->subject_organizational_unit(), "");
  EXPECT_EQ(certificate->subject_domain_component(), "");
  EXPECT_EQ(certificate->subject_distinguished_name(), "");
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, EachIssuerAttributeIsTheIssuingCertificatesSubjectAttribute)
{
  CertSpec caSpec;
  caSpec.subject = full_name("Accessor Issuer");
  const auto caKey = required_key(p256, "issuer");
  const auto ca = build_certificate(caSpec, caKey.get());
  CertSpec leafSpec;
  leafSpec.subject = {utf8(NID_commonName, "Accessor Issued"), utf8(NID_organizationName, "Other Org")};
  const auto leaf =
    read(build_certificate(leafSpec, required_key(p256).get(), Signer{ca.get(), caKey.get()}));
  EXPECT_EQ(leaf->issuer_country(), "GB");
  EXPECT_EQ(leaf->issuer_state(), "Antrim");
  EXPECT_EQ(leaf->issuer_locality(), "Belfast");
  EXPECT_EQ(leaf->issuer_organization(), "reduktive");
  EXPECT_EQ(leaf->issuer_organizational_unit(), "Certificates");
  EXPECT_EQ(leaf->issuer_domain_component(), "example");
  EXPECT_EQ(leaf->issuer_distinguished_name(), "CN=Embedded");
  EXPECT_EQ(leaf->issuer_common_name(), "Accessor Issuer");
  EXPECT_EQ(leaf->subject_organization(), "Other Org") << "control: the subject is the leaf's own name";
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, AnAbsentIssuerAttributeIsEmpty)
{
  const auto caKey = required_key(p256, "issuer");
  CertSpec caSpec;
  caSpec.subject = {utf8(NID_commonName, "Bare Issuer")};
  const auto ca = build_certificate(caSpec, caKey.get());
  CertSpec leafSpec;
  leafSpec.subject = full_name("Full Leaf");
  const auto leaf =
    read(build_certificate(leafSpec, required_key(p256).get(), Signer{ca.get(), caKey.get()}));
  EXPECT_EQ(leaf->issuer_common_name(), "Bare Issuer");
  EXPECT_EQ(leaf->issuer_country(), "");
  EXPECT_EQ(leaf->issuer_state(), "");
  EXPECT_EQ(leaf->issuer_locality(), "");
  EXPECT_EQ(leaf->issuer_organization(), "");
  EXPECT_EQ(leaf->issuer_organizational_unit(), "");
  EXPECT_EQ(leaf->issuer_domain_component(), "");
  EXPECT_EQ(leaf->issuer_distinguished_name(), "");
}

// A BIT STRING attribute survives DER parsing but cannot be converted to UTF-8. The accessor must
// return an empty value without throwing on validation and failure paths.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-UNCONVERTIBLE-NAME-IS-EMPTY, scope=function)
TEST(X509AccessorNames, AnAttributeThatIsNotConvertibleToUtf8IsEmpty)
{
  CertSpec spec;
  spec.subject = {NameAttribute{NID_commonName, "Opaque common name", V_ASN1_BIT_STRING, false},
    NameAttribute{NID_organizationName, "Opaque organization", V_ASN1_BIT_STRING, false},
    utf8(NID_localityName, "Readable")};
  const auto built = build_certificate(spec, required_key(p256).get());
  const auto der = der_of(built.get());
  const unsigned char* cursor = der.data();
  X509Ptr decoded{d2i_X509(nullptr, &cursor, static_cast<long>(der.size()))};
  ASSERT_NE(decoded, nullptr);
  ASSERT_EQ(cursor, der.data() + der.size());
  auto* subject = X509_get_subject_name(decoded.get());
  for (const auto nid : {NID_commonName, NID_organizationName})
  {
    const auto index = X509_NAME_get_index_by_NID(subject, nid, -1);
    ASSERT_GE(index, 0);
    const auto* value = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index));
    unsigned char* converted{nullptr};
    EXPECT_LT(ASN1_STRING_to_UTF8(&converted, value), 0);
    OPENSSL_free(converted);
    ERR_clear_error();
  }
  const auto certificate = read(der);

  std::string commonName{"unset"};
  std::string organization{"unset"};
  EXPECT_NO_THROW(commonName = certificate->subject_common_name());
  EXPECT_NO_THROW(organization = certificate->subject_organization());
  EXPECT_EQ(commonName, "");
  EXPECT_EQ(organization, "");
  EXPECT_EQ(certificate->subject_locality(), "Readable");
}

// UTF8String, PrintableString and BMPString attributes are all returned as UTF-8 text.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, EveryDirectoryStringEncodingIsReturnedAsUtf8)
{
  const std::string utf8Text =
    "Pr\xC3\xBC"
    "fstelle Z\xC3\xBCrich";
  const std::string bmpOmega{
    "\x03\xA9\x00m\x00"
    "e\x00g\x00"
    "a",
    10};  // UCS-2BE of "Omega" with a capital omega
  CertSpec spec;
  spec.subject = {NameAttribute{NID_commonName, utf8Text, MBSTRING_UTF8, false},
    NameAttribute{NID_organizationName, "Plain Org", V_ASN1_PRINTABLESTRING, false},
    NameAttribute{NID_localityName, bmpOmega, V_ASN1_BMPSTRING, false}};
  const auto built = build_certificate(spec, required_key(p256).get());
  const X509_NAME* name = X509_get_subject_name(built.get());
  require(
    ASN1_STRING_type(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, 0))) == V_ASN1_UTF8STRING &&
      ASN1_STRING_type(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, 1))) == V_ASN1_PRINTABLESTRING &&
      ASN1_STRING_type(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, 2))) == V_ASN1_BMPSTRING,
    "fixture string types");
  const auto certificate = read(built);
  EXPECT_EQ(certificate->subject_common_name(), utf8Text);
  EXPECT_EQ(certificate->subject_organization(), "Plain Org");
  EXPECT_EQ(certificate->subject_locality(), "\xCE\xA9mega");
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, EachAttributeOfAMultiValuedRdnIsReported)
{
  CertSpec spec;
  spec.subject = {utf8(NID_organizationName, "reduktive"),
    utf8(NID_commonName, "Multi"),
    NameAttribute{NID_organizationalUnitName, "Unit", MBSTRING_UTF8, true}};
  const auto built = build_certificate(spec, required_key(p256).get());
  require(X509_NAME_entry_count(X509_get_subject_name(built.get())) == 3 &&
            X509_NAME_ENTRY_set(X509_NAME_get_entry(X509_get_subject_name(built.get()), 1)) ==
              X509_NAME_ENTRY_set(X509_NAME_get_entry(X509_get_subject_name(built.get()), 2)),
    "fixture: CN and OU share one RDN");
  const auto certificate = read(built);
  EXPECT_EQ(certificate->subject_common_name(), "Multi");
  EXPECT_EQ(certificate->subject_organizational_unit(), "Unit");
  EXPECT_EQ(certificate->subject_organization(), "reduktive");
}

// subject() and issuer() are the DER encodings of the whole Names; the leaf's differ (control).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-NAMES, scope=function)
TEST(X509AccessorNames, SubjectAndIssuerAreTheDerEncodedNames)
{
  const auto caKey = required_key(p256, "issuer");
  CertSpec caSpec;
  caSpec.subject = full_name("Der Issuer");
  const auto ca = build_certificate(caSpec, caKey.get());
  CertSpec leafSpec;
  leafSpec.subject = {utf8(NID_commonName, "Der Subject"), utf8(NID_organizationName, "reduktive")};
  const auto built = build_certificate(leafSpec, required_key(p256).get(), Signer{ca.get(), caKey.get()});
  const auto leaf = read(built);
  EXPECT_EQ(bytes_of(leaf->subject()), der_of_name(X509_get_subject_name(built.get())));
  EXPECT_EQ(bytes_of(leaf->issuer()), der_of_name(X509_get_subject_name(ca.get())));
  EXPECT_NE(leaf->subject(), leaf->issuer());
}

// ---------------------------------------------------------------------------------------------------------
// Serial number and version.
// ---------------------------------------------------------------------------------------------------------

struct SerialCase
{
  const char* label;
  const char* hex;
  const char* decimal;
};

class X509AccessorSerialNumber : public ::testing::TestWithParam<SerialCase>
{};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-43-SERIAL-VERSION, scope=function)
TEST_P(X509AccessorSerialNumber, TheSerialNumberIsItsBase10Text)
{
  CertSpec spec;
  spec.serialHex = GetParam().hex;
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(certificate->serial_number(), GetParam().decimal);
}

INSTANTIATE_TEST_SUITE_P(Serials, X509AccessorSerialNumber,
  ::testing::Values(SerialCase{"One", "01", "1"}, SerialCase{"TwoOctets", "0100", "256"},
    // The top bit is set, so the DER INTEGER carries a leading zero octet that is not part of the value.
    SerialCase{"LeadingZeroOctet", "80000000000000000001", "604462909807314587353089"},
    // 20 octets, the largest RFC 5280 permits.
    SerialCase{"TwentyOctets",
      "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "730750818665451459101842416358141509827966271487"}),
  label_of<SerialCase>);

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-43-SERIAL-VERSION, scope=function)
TEST(X509AccessorVersion, TheVersionIsZeroIndexedForV1AndV3)
{
  CertSpec v1;
  v1.version = 0;
  CertSpec v3;
  v3.extensions = {{NID_basic_constraints, "critical,CA:FALSE"}};
  EXPECT_EQ(read(build_certificate(v1, required_key(p256).get()))->version(), 0);
  EXPECT_EQ(read(build_certificate(v3, required_key(p256).get()))->version(), 2);
}

// ---------------------------------------------------------------------------------------------------------
// Validity.
// ---------------------------------------------------------------------------------------------------------

struct ValidityCase
{
  const char* label;
  const char* encoded;  ///< 13 characters: UTCTime; 15: GeneralizedTime.
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
};

class X509AccessorValidity : public ::testing::TestWithParam<ValidityCase>
{
protected:
  static DateTime expected()
  {
    const auto& c = GetParam();
    return DateTime{c.year, c.month, c.day, c.hour, c.minute, static_cast<double>(c.second), 0};
  }
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-44-VALIDITY, scope=function)
TEST_P(X509AccessorValidity, ValidityFromIsNotBefore)
{
  CertSpec spec;
  spec.notBefore = GetParam().encoded;
  spec.notAfter = "20991231235959Z";
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(seconds_of(certificate->validity_from()), seconds_of(expected()));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-44-VALIDITY, scope=function)
TEST_P(X509AccessorValidity, ValidityToIsNotAfter)
{
  CertSpec spec;
  spec.notBefore = "19500101000000Z";
  spec.notAfter = GetParam().encoded;
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(seconds_of(certificate->validity_to()), seconds_of(expected()));
}

INSTANTIATE_TEST_SUITE_P(Encodings, X509AccessorValidity,
  ::testing::Values(ValidityCase{"UtcTime", "250615123045Z", 2025, 6, 15, 12, 30, 45},
    ValidityCase{"GeneralizedTime", "20250615123045Z", 2025, 6, 15, 12, 30, 45},
    ValidityCase{"UtcTimeAfter2038", "390119031408Z", 2039, 1, 19, 3, 14, 8},
    ValidityCase{"GeneralizedTimeAfter2049", "20510301101010Z", 2051, 3, 1, 10, 10, 10},
    // RFC 5280 4.1.2.5.1: a two-digit year of 50 or more is 19YY.
    ValidityCase{"UtcTimeYear50Is1950", "500101000000Z", 1950, 1, 1, 0, 0, 0}),
  label_of<ValidityCase>);

// ---------------------------------------------------------------------------------------------------------
// keyUsage, extendedKeyUsage, basicConstraints.
// ---------------------------------------------------------------------------------------------------------

using BoolAccessor = bool (X509Certificate::*)() const;

struct KeyUsageBit
{
  const char* label;
  const char* name;  ///< The bit's name in the X509V3 configuration syntax.
  BoolAccessor accessor;
};

const std::vector<KeyUsageBit>& key_usage_bits()
{
  static const std::vector<KeyUsageBit> bits{
    {"DigitalSignature", "digitalSignature", &X509Certificate::key_usage_digital_signature},
    {"NonRepudiation", "nonRepudiation", &X509Certificate::key_usage_non_repudiation},
    {"KeyEncipherment", "keyEncipherment", &X509Certificate::key_usage_key_encipherment},
    {"DataEncipherment", "dataEncipherment", &X509Certificate::key_usage_data_encipherment},
    {"KeyAgreement", "keyAgreement", &X509Certificate::key_usage_key_agreement},
    {"KeyCertSign", "keyCertSign", &X509Certificate::key_usage_key_cert_sign},
    {"CrlSign", "cRLSign", &X509Certificate::key_usage_crl_sign},
    {"EncipherOnly", "encipherOnly", &X509Certificate::key_usage_encipher_only},
    {"DecipherOnly", "decipherOnly", &X509Certificate::key_usage_decipher_only}};
  return bits;
}

class X509AccessorKeyUsage : public ::testing::TestWithParam<KeyUsageBit>
{};

// A certificate carrying one bit: that bit's accessor is true and every other accessor is false.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST_P(X509AccessorKeyUsage, OnlyTheBitThatIsSetIsReported)
{
  CertSpec spec;
  spec.extensions = {{NID_key_usage, std::string{"critical,"} + GetParam().name}};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  for (const auto& bit : key_usage_bits())
  {
    EXPECT_EQ(((*certificate).*(bit.accessor))(), std::string{bit.label} == GetParam().label) << bit.label;
  }
}

INSTANTIATE_TEST_SUITE_P(
  EachBit, X509AccessorKeyUsage, ::testing::ValuesIn(key_usage_bits()), label_of<KeyUsageBit>);

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST(X509AccessorKeyUsageExtension, EveryBitSetIsReported)
{
  std::string all = "critical";
  for (const auto& bit : key_usage_bits())
  {
    all += std::string{","} + bit.name;
  }
  CertSpec spec;
  spec.extensions = {{NID_key_usage, all}};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  for (const auto& bit : key_usage_bits())
  {
    EXPECT_TRUE(((*certificate).*(bit.accessor))()) << bit.label;
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST(X509AccessorKeyUsageExtension, AnAbsentExtensionReportsNoBit)
{
  const auto certificate = read(build_certificate(CertSpec{}, required_key(p256).get()));
  for (const auto& bit : key_usage_bits())
  {
    EXPECT_FALSE(((*certificate).*(bit.accessor))()) << bit.label;
  }
}

struct ExtendedKeyUsageCase
{
  const char* label;
  const char* value;  ///< Empty: the extension is absent.
  bool serverAuth;
  bool clientAuth;
};

class X509AccessorExtendedKeyUsage : public ::testing::TestWithParam<ExtendedKeyUsageCase>
{
protected:
  static std::shared_ptr<const X509Certificate> certificate()
  {
    CertSpec spec;
    if (std::string{GetParam().value}.size() > 0)
    {
      spec.extensions = {{NID_ext_key_usage, GetParam().value}};
    }
    return read(build_certificate(spec, required_key(p256).get()));
  }
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST_P(X509AccessorExtendedKeyUsage, ServerAuthIsReportedOnlyWhenListed)
{
  EXPECT_EQ(certificate()->extended_key_usage_server_auth(), GetParam().serverAuth);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST_P(X509AccessorExtendedKeyUsage, ClientAuthIsReportedOnlyWhenListed)
{
  EXPECT_EQ(certificate()->extended_key_usage_client_auth(), GetParam().clientAuth);
}

INSTANTIATE_TEST_SUITE_P(Purposes, X509AccessorExtendedKeyUsage,
  ::testing::Values(ExtendedKeyUsageCase{"ServerAuth", "serverAuth", true, false},
    ExtendedKeyUsageCase{"ClientAuth", "clientAuth", false, true},
    ExtendedKeyUsageCase{"Both", "serverAuth,clientAuth", true, true},
    ExtendedKeyUsageCase{"OtherPurposeOnly", "codeSigning", false, false},
    ExtendedKeyUsageCase{"Absent", "", false, false}),
  label_of<ExtendedKeyUsageCase>);

struct BasicConstraintsCase
{
  const char* label;
  const char* value;  ///< Empty: the extension is absent.
  bool ca;
  uint32_t pathLength;
};

constexpr uint32_t unconstrained = std::numeric_limits<uint32_t>::max();

class X509AccessorBasicConstraints : public ::testing::TestWithParam<BasicConstraintsCase>
{
protected:
  static std::shared_ptr<const X509Certificate> certificate()
  {
    CertSpec spec;
    spec.extensions = {{NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign"}};
    if (std::string{GetParam().value}.size() > 0)
    {
      spec.extensions.push_back({NID_basic_constraints, GetParam().value});
    }
    return read(build_certificate(spec, required_key(p256).get()));
  }
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST_P(X509AccessorBasicConstraints, TheCaFlagIsTheEncodedFlag)
{
  EXPECT_EQ(certificate()->basic_constraints_ca(), GetParam().ca);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-45-USAGE-CONSTRAINTS, scope=function)
TEST_P(X509AccessorBasicConstraints, ThePathLengthIsTheEncodedConstraintOrUnconstrained)
{
  EXPECT_EQ(certificate()->basic_constraints_path_length(), GetParam().pathLength);
}

INSTANTIATE_TEST_SUITE_P(Constraints, X509AccessorBasicConstraints,
  ::testing::Values(BasicConstraintsCase{"Absent", "", false, unconstrained},
    BasicConstraintsCase{"CaFalse", "critical,CA:FALSE", false, unconstrained},
    BasicConstraintsCase{"CaTrueNoPathLength", "critical,CA:TRUE", true, unconstrained},
    BasicConstraintsCase{"CaTruePathLength0", "critical,CA:TRUE,pathlen:0", true, 0},
    BasicConstraintsCase{"CaTruePathLength3", "critical,CA:TRUE,pathlen:3", true, 3}),
  label_of<BasicConstraintsCase>);

// ---------------------------------------------------------------------------------------------------------
// subjectAltName.
// ---------------------------------------------------------------------------------------------------------

struct SanCase
{
  const char* label;
  const char* value;  ///< Empty: the extension is absent.
  std::vector<std::string> uris;
  std::vector<std::string> hostnames;
  std::vector<std::string> ipAddresses;
};

class X509AccessorSubjectAltName : public ::testing::TestWithParam<SanCase>
{
protected:
  static std::shared_ptr<const X509Certificate> certificate()
  {
    CertSpec spec;
    if (std::string{GetParam().value}.size() > 0)
    {
      spec.extensions = {{NID_subject_alt_name, GetParam().value}};
    }
    return read(build_certificate(spec, required_key(p256).get()));
  }
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-46-SUBJECT-ALT-NAME, scope=function)
TEST_P(X509AccessorSubjectAltName, SanUrisAreTheUriEntriesInOrder)
{
  EXPECT_EQ(certificate()->san_uris(), GetParam().uris);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-46-SUBJECT-ALT-NAME, scope=function)
TEST_P(X509AccessorSubjectAltName, SanHostnamesAreTheDnsEntriesInOrder)
{
  EXPECT_EQ(certificate()->san_hostnames(), GetParam().hostnames);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-46-SUBJECT-ALT-NAME, scope=function)
TEST_P(X509AccessorSubjectAltName, SanIpAddressesAreTheIpEntriesInOrder)
{
  std::vector<asio::ip::address> expected;
  for (const auto& text : GetParam().ipAddresses)
  {
    expected.push_back(asio::ip::make_address(text));
  }
  EXPECT_EQ(certificate()->san_ip_addresses(), expected);
}

INSTANTIATE_TEST_SUITE_P(Entries, X509AccessorSubjectAltName,
  ::testing::Values(SanCase{"Absent", "", {}, {}, {}},
    SanCase{"OneUri", "URI:urn:accessor:one", {"urn:accessor:one"}, {}, {}},
    SanCase{"OneHostname", "DNS:localhost", {}, {"localhost"}, {}},
    SanCase{"OneIpv4", "IP:192.168.1.20", {}, {}, {"192.168.1.20"}},
    SanCase{"OneIpv6", "IP:2001:db8::1", {}, {}, {"2001:db8::1"}},
    SanCase{"SeveralOfEach",
      "URI:urn:accessor:one,DNS:host-one,IP:10.0.0.1,URI:urn:accessor:two,DNS:host-two,IP:fe80::1",
      {"urn:accessor:one", "urn:accessor:two"},
      {"host-one", "host-two"},
      {"10.0.0.1", "fe80::1"}}),
  label_of<SanCase>);

struct MalformedIpCase
{
  const char* label;
  std::size_t length;
};

class X509AccessorMalformedIpSan : public ::testing::TestWithParam<MalformedIpCase>
{};

// An iPAddress entry that is neither 4 nor 16 octets is a certificate defect: Bad_CertificateInvalid.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-46-SUBJECT-ALT-NAME, scope=function)
TEST_P(X509AccessorMalformedIpSan, AnIpEntryOfAnotherLengthIsCertificateInvalid)
{
  CertSpec spec;
  spec.rawIpSans = {Der{127, 0, 0, 1}, Der(GetParam().length, 0x0A)};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(
    status_of([&] { static_cast<void>(certificate->san_ip_addresses()); }), Status::BadCertificateInvalid);
}

INSTANTIATE_TEST_SUITE_P(Lengths, X509AccessorMalformedIpSan,
  ::testing::Values(MalformedIpCase{"Empty", 0}, MalformedIpCase{"ThreeOctets", 3},
    MalformedIpCase{"FiveOctets", 5}, MalformedIpCase{"EightOctetsAddressAndMask", 8},
    MalformedIpCase{"SeventeenOctets", 17}, MalformedIpCase{"ThirtyTwoOctetsIpv6AndMask", 32}),
  label_of<MalformedIpCase>);

// Control: the same raw construction with a 4-octet and a 16-octet entry reads both.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-46-SUBJECT-ALT-NAME, scope=function)
TEST(X509AccessorMalformedIpSanControl, RawEntriesOfFourAndSixteenOctetsAreRead)
{
  CertSpec spec;
  Der v6(16, 0);
  v6[0] = 0x20;
  v6[1] = 0x01;
  v6[2] = 0x0D;
  v6[3] = 0xB8;
  v6[15] = 0x01;
  spec.rawIpSans = {Der{127, 0, 0, 1}, v6};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  const std::vector<asio::ip::address> expected{
    asio::ip::make_address("127.0.0.1"), asio::ip::make_address("2001:db8::1")};
  EXPECT_EQ(certificate->san_ip_addresses(), expected);
}

// ---------------------------------------------------------------------------------------------------------
// Key identifiers.
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-47-KEY-IDENTIFIERS, scope=function)
TEST(X509AccessorKeyIdentifiers, TheSubjectKeyIdentifierIsTheExtensionValue)
{
  CertSpec spec;
  spec.extensions = {{NID_subject_key_identifier, "0A:0B:0C:0D:0E:0F"}};
  const auto certificate = read(build_certificate(spec, required_key(p256).get()));
  EXPECT_EQ(bytes_of(certificate->subject_key_identifier()), hex_bytes("0A0B0C0D0E0F"));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-47-KEY-IDENTIFIERS, scope=function)
TEST(X509AccessorKeyIdentifiers, AnAbsentSubjectKeyIdentifierIsEmpty)
{
  const auto certificate = read(build_certificate(CertSpec{}, required_key(p256).get()));
  EXPECT_TRUE(certificate->subject_key_identifier().empty());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-47-KEY-IDENTIFIERS, scope=function)
TEST(X509AccessorKeyIdentifiers, TheAuthorityKeyIdentifierIsTheIssuersKeyIdentifier)
{
  const auto caKey = required_key(p256, "issuer");
  CertSpec caSpec;
  caSpec.subject = {utf8(NID_commonName, "Key Id Issuer")};
  caSpec.extensions = {{NID_subject_key_identifier, "C0:FF:EE:01"}};
  const auto ca = build_certificate(caSpec, caKey.get());
  CertSpec leafSpec;
  leafSpec.extensions = {{NID_authority_key_identifier, "keyid:always"}};
  const auto leaf =
    read(build_certificate(leafSpec, required_key(p256).get(), Signer{ca.get(), caKey.get()}));
  EXPECT_EQ(bytes_of(leaf->authority_key_identifier()), hex_bytes("C0FFEE01"));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-47-KEY-IDENTIFIERS, scope=function)
TEST(X509AccessorKeyIdentifiers, AnAbsentAuthorityKeyIdentifierIsEmpty)
{
  const auto certificate = read(build_certificate(CertSpec{}, required_key(p256).get()));
  EXPECT_TRUE(certificate->authority_key_identifier().empty());
}

// ---------------------------------------------------------------------------------------------------------
// Subject public key.
// ---------------------------------------------------------------------------------------------------------

struct KeyCase
{
  const char* label;
  KeyType type;
  CertificateKeyAlgorithm algorithm;
  std::size_t bits;  ///< RSA: modulus size; ECC: the field (curve) size; EdDSA: the profile database key
                     ///< length (Ed25519 256, Ed448 456 - owner decision C).
};

class X509AccessorPublicKey : public ::testing::TestWithParam<KeyCase>
{
protected:
  void SetUp() override
  {
    mKey = key_of(GetParam().type);
    ASSERT_TRUE(mKey) << "no " << GetParam().label << " key";
    mCertificate = read(build_certificate(CertSpec{}, mKey.get()));
  }

  PKey mKey;
  std::shared_ptr<const X509Certificate> mCertificate;
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-48-PUBLIC-KEY, scope=function)
TEST_P(X509AccessorPublicKey, TheKeyAlgorithmIsTheSubjectKeyFamilyAndCurve)
{
  EXPECT_EQ(mCertificate->key_algorithm(), GetParam().algorithm);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-48-PUBLIC-KEY, scope=function)
TEST_P(X509AccessorPublicKey, TheBitLengthIsTheModulusOrFieldSize)
{
  EXPECT_EQ(mCertificate->public_key_bit_length(), GetParam().bits);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-48-PUBLIC-KEY, scope=function)
TEST_P(X509AccessorPublicKey, ThePublicKeyIsTheDerSubjectPublicKeyInfo)
{
  EXPECT_EQ(bytes_of(mCertificate->public_key()), public_key_info_of(mKey.get()));
}

INSTANTIATE_TEST_SUITE_P(KeyTypes, X509AccessorPublicKey,
  ::testing::Values(
    KeyCase{"Rsa1024", KeyType{"Rsa1024", "RSA", "", 1024}, CertificateKeyAlgorithm::Rsa, 1024},
    KeyCase{"Rsa2048", rsa2048, CertificateKeyAlgorithm::Rsa, 2048},
    KeyCase{"Rsa3072", KeyType{"Rsa3072", "RSA", "", 3072}, CertificateKeyAlgorithm::Rsa, 3072},
    KeyCase{"Rsa4096", KeyType{"Rsa4096", "RSA", "", 4096}, CertificateKeyAlgorithm::Rsa, 4096},
    KeyCase{"NistP256", p256, CertificateKeyAlgorithm::EccNistP256, 256},
    KeyCase{"NistP384", p384, CertificateKeyAlgorithm::EccNistP384, 384},
    KeyCase{"NistP521", p521, CertificateKeyAlgorithm::EccNistP521, 521},
    KeyCase{"BrainpoolP256r1",
      KeyType{"BrainpoolP256r1", "EC", "brainpoolP256r1", 0},
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      256},
    KeyCase{"BrainpoolP384r1",
      KeyType{"BrainpoolP384r1", "EC", "brainpoolP384r1", 0},
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      384},
    KeyCase{"BrainpoolP512r1",
      KeyType{"BrainpoolP512r1", "EC", "brainpoolP512r1", 0},
      CertificateKeyAlgorithm::EccBrainpoolP512r1,
      512},
    KeyCase{"Ed25519", ed25519, CertificateKeyAlgorithm::EccCurve25519, 256},
    KeyCase{"Ed448", ed448, CertificateKeyAlgorithm::EccCurve448, 456}),
  label_of<KeyCase>);

// ---------------------------------------------------------------------------------------------------------
// Signature.
// ---------------------------------------------------------------------------------------------------------

struct SignatureCase
{
  const char* label;
  KeyType signer;
  const char* digest;  ///< OpenSSL digest name; ignored for EdDSA.
  bool pss;
  CertificateSignatureAlgorithm algorithm;
};

class X509AccessorSignature : public ::testing::TestWithParam<SignatureCase>
{
protected:
  void SetUp() override
  {
    const auto key = key_of(GetParam().signer);
    const EVP_MD* digest = EVP_get_digestbyname(GetParam().digest);
    ASSERT_TRUE(key) << "no signing key for " << GetParam().label;
    ASSERT_NE(digest, nullptr) << "no digest " << GetParam().digest << " for " << GetParam().label;
    mBuilt = build_certificate(CertSpec{}, key.get(), self, digest, GetParam().pss);
    mCertificate = read(mBuilt);
  }

  X509Ptr mBuilt;
  std::shared_ptr<const X509Certificate> mCertificate;
};

// An algorithm the CertificateSignatureAlgorithm enumeration has no value for reports Invalid, never
// another algorithm.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-49-SIGNATURE, scope=function)
TEST_P(X509AccessorSignature, TheSignatureAlgorithmIsTheIssuersAlgorithm)
{
  EXPECT_EQ(mCertificate->signature_algorithm(), GetParam().algorithm);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-49-SIGNATURE, scope=function)
TEST_P(X509AccessorSignature, TheSignatureIsTheEncodedSignatureValue)
{
  const ASN1_BIT_STRING* signature = nullptr;
  const X509_ALGOR* algorithm = nullptr;
  X509_get0_signature(&signature, &algorithm, mBuilt.get());
  require(signature != nullptr, "X509_get0_signature");
  const Der expected(signature->data, signature->data + signature->length);
  EXPECT_EQ(bytes_of(mCertificate->signature()), expected);
}

INSTANTIATE_TEST_SUITE_P(Algorithms, X509AccessorSignature,
  ::testing::Values(
    SignatureCase{"RsaPkcs15Sha1", rsa2048, "SHA1", false, CertificateSignatureAlgorithm::RsaPkcs15Sha1},
    SignatureCase{
      "RsaPkcs15Sha224", rsa2048, "SHA224", false, CertificateSignatureAlgorithm::RsaPkcs15Sha2224},
    SignatureCase{
      "RsaPkcs15Sha256", rsa2048, "SHA256", false, CertificateSignatureAlgorithm::RsaPkcs15Sha2256},
    SignatureCase{
      "RsaPkcs15Sha384", rsa2048, "SHA384", false, CertificateSignatureAlgorithm::RsaPkcs15Sha2384},
    SignatureCase{
      "RsaPkcs15Sha512", rsa2048, "SHA512", false, CertificateSignatureAlgorithm::RsaPkcs15Sha2512},
    SignatureCase{"RsaPssSha256", rsa2048, "SHA256", true, CertificateSignatureAlgorithm::RsaPssSha2256},
    SignatureCase{"EcdsaSha256", p256, "SHA256", false, CertificateSignatureAlgorithm::EcDsaSha2256},
    SignatureCase{"EcdsaSha384", p384, "SHA384", false, CertificateSignatureAlgorithm::EcDsaSha2384},
    SignatureCase{"EcdsaSha512", p521, "SHA512", false, CertificateSignatureAlgorithm::EcDsaSha2512},
    SignatureCase{"UnclassifiedEcdsaSha224", p256, "SHA224", false, CertificateSignatureAlgorithm::Invalid},
    SignatureCase{"Ed25519", ed25519, "SHA256", false, CertificateSignatureAlgorithm::PureEdDsa25519},
    SignatureCase{"Ed448", ed448, "SHA256", false, CertificateSignatureAlgorithm::PureEdDsa448}),
  label_of<SignatureCase>);

// ---------------------------------------------------------------------------------------------------------
// Issuance: self_signed, issued_by, issuer_of.
// ---------------------------------------------------------------------------------------------------------

struct IssuancePki
{
  std::shared_ptr<const X509Certificate> ca;  ///< Self-signed, SKI CA010101.
  std::shared_ptr<const X509Certificate> v1Root;  ///< Self-signed X.509 v1, no extensions.
  std::shared_ptr<const X509Certificate> impostor;  ///< The CA's name, another key, SKI BAD00001.
  std::shared_ptr<const X509Certificate> otherCa;  ///< Another name, another key.
  std::shared_ptr<const X509Certificate> leaf;  ///< Issued by the CA, AKI = the CA's SKI.
  std::shared_ptr<const X509Certificate> leafWithoutAki;  ///< Issued by the CA, no AKI.
  std::shared_ptr<const X509Certificate> selfIssuedOtherKey;  ///< Subject = issuer, signed by another key.
  std::shared_ptr<const X509Certificate> selfIssuedOtherKeyWithAki;  ///< As above, AKI = the signer's SKI.
};

const IssuancePki& issuance_pki()
{
  static const IssuancePki pki = []
  {
    IssuancePki built;
    const auto caKey = required_key(p256, "ca");
    const auto impostorKey = required_key(p256, "impostor");
    const auto otherKey = required_key(p256, "other");
    const auto leafKey = required_key(p256, "leaf");
    const NameSpec caName{utf8(NID_commonName, "Issuance CA"), utf8(NID_organizationName, "reduktive")};
    const std::vector<Extension> caExtensions{
      {NID_basic_constraints, "critical,CA:TRUE"}, {NID_key_usage, "critical,keyCertSign,cRLSign"}};

    CertSpec caSpec;
    caSpec.subject = caName;
    caSpec.extensions = caExtensions;
    caSpec.extensions.push_back({NID_subject_key_identifier, "CA:01:01:01"});
    const auto ca = build_certificate(caSpec, caKey.get());
    built.ca = read(ca);

    CertSpec v1Spec;
    v1Spec.version = 0;
    v1Spec.subject = {utf8(NID_commonName, "Issuance V1 Root")};
    built.v1Root = read(build_certificate(v1Spec, otherKey.get()));

    CertSpec impostorSpec;
    impostorSpec.subject = caName;
    impostorSpec.extensions = caExtensions;
    impostorSpec.extensions.push_back({NID_subject_key_identifier, "BA:D0:00:01"});
    built.impostor = read(build_certificate(impostorSpec, impostorKey.get()));

    CertSpec otherSpec;
    otherSpec.subject = {utf8(NID_commonName, "Issuance Other CA")};
    otherSpec.extensions = caExtensions;
    otherSpec.extensions.push_back({NID_subject_key_identifier, "0C:A0:00:01"});
    const auto other = build_certificate(otherSpec, otherKey.get());
    built.otherCa = read(other);

    CertSpec leafSpec;
    leafSpec.subject = {utf8(NID_commonName, "Issuance Leaf")};
    leafSpec.extensions = {{NID_authority_key_identifier, "keyid:always"}};
    built.leaf = read(build_certificate(leafSpec, leafKey.get(), Signer{ca.get(), caKey.get()}));

    CertSpec bareLeafSpec;
    bareLeafSpec.subject = {utf8(NID_commonName, "Issuance Leaf Without AKI")};
    built.leafWithoutAki =
      read(build_certificate(bareLeafSpec, leafKey.get(), Signer{ca.get(), caKey.get()}));

    CertSpec selfIssuedSpec;
    selfIssuedSpec.subject = {utf8(NID_commonName, "Issuance Self Issued")};
    built.selfIssuedOtherKey =
      read(build_certificate(selfIssuedSpec, leafKey.get(), Signer{nullptr, otherKey.get()}));

    // Named by its own subject, signed by the other CA's key, AKI naming that key.
    CertSpec selfIssuedAkiSpec;
    selfIssuedAkiSpec.subject = {utf8(NID_commonName, "Issuance Self Issued With AKI")};
    selfIssuedAkiSpec.extensions = {{NID_authority_key_identifier, "keyid:always"}};
    auto selfIssuedAki =
      build_certificate(selfIssuedAkiSpec, leafKey.get(), Signer{other.get(), otherKey.get()});
    const auto selfName = make_name(selfIssuedAkiSpec.subject);
    require(X509_set_issuer_name(selfIssuedAki.get(), selfName.get()) == 1, "self-issued issuer name");
    sign(selfIssuedAki.get(), otherKey.get(), EVP_sha256(), false);
    built.selfIssuedOtherKeyWithAki = read(selfIssuedAki);
    return built;
  }();
  return pki;
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, ASelfSignedRootIsSelfSigned)
{
  EXPECT_TRUE(issuance_pki().ca->self_signed());
  EXPECT_TRUE(issuance_pki().v1Root->self_signed()) << "an X.509 v1 root carries no extensions";
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, ACaIssuedCertificateIsNotSelfSigned)
{
  EXPECT_FALSE(issuance_pki().leaf->self_signed());
}

// Subject equals issuer, but another key signed it: the certificate does not sign itself.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, ASelfIssuedCertificateSignedByAnotherKeyIsNotSelfSigned)
{
  EXPECT_FALSE(issuance_pki().selfIssuedOtherKey->self_signed());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, ASelfIssuedCertificateWhoseAkiNamesAnotherKeyIsNotSelfSigned)
{
  EXPECT_FALSE(issuance_pki().selfIssuedOtherKeyWithAki->self_signed());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuedByIsTrueForTheTrueIssuer)
{
  EXPECT_TRUE(issuance_pki().leaf->issued_by(*issuance_pki().ca));
  EXPECT_TRUE(issuance_pki().leafWithoutAki->issued_by(*issuance_pki().ca));
}

// The impostor has the CA's name and another key; the leaf's AKI names the CA's key.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuedByIsFalseForTheSameNameWithAnotherKeyIdentifier)
{
  EXPECT_FALSE(issuance_pki().leaf->issued_by(*issuance_pki().impostor));
}

// No AKI to compare: only the signature tells the impostor from the CA.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuedByIsFalseForTheSameNameWithAnotherKeyAndNoAki)
{
  EXPECT_FALSE(issuance_pki().leafWithoutAki->issued_by(*issuance_pki().impostor));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuedByIsFalseForAnotherName)
{
  EXPECT_FALSE(issuance_pki().leaf->issued_by(*issuance_pki().otherCa));
  EXPECT_FALSE(issuance_pki().leafWithoutAki->issued_by(*issuance_pki().otherCa));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuerOfIsTrueOnlyForTheTrueIssuer)
{
  EXPECT_TRUE(issuance_pki().ca->issuer_of(*issuance_pki().leaf));
  EXPECT_TRUE(issuance_pki().ca->issuer_of(*issuance_pki().leafWithoutAki));
  EXPECT_FALSE(issuance_pki().impostor->issuer_of(*issuance_pki().leaf));
  EXPECT_FALSE(issuance_pki().impostor->issuer_of(*issuance_pki().leafWithoutAki));
  EXPECT_FALSE(issuance_pki().otherCa->issuer_of(*issuance_pki().leaf));
}

// issuer_of is the inverse of issued_by for every pair.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-50-ISSUANCE, scope=function)
TEST(X509AccessorIssuance, IssuerOfIsTheInverseOfIssuedBy)
{
  const auto& pki = issuance_pki();
  const std::vector<std::shared_ptr<const X509Certificate>> all{
    pki.ca, pki.v1Root, pki.impostor, pki.otherCa, pki.leaf, pki.leafWithoutAki, pki.selfIssuedOtherKey};
  for (std::size_t issued = 0; issued < all.size(); ++issued)
  {
    for (std::size_t issuer = 0; issuer < all.size(); ++issuer)
    {
      EXPECT_EQ(all[issued]->issued_by(*all[issuer]), all[issuer]->issuer_of(*all[issued]))
        << "issued " << issued << ", issuer " << issuer;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------
// Encoding and identity.
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-51-ENCODING, scope=function)
TEST(X509AccessorEncoding, TheDerEncodingRoundTripsByteForByte)
{
  const Der der = der_of(build_certificate(CertSpec{}, required_key(p256).get()).get());
  EXPECT_EQ(bytes_of(read(der)->der_encoding()), der);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-51-ENCODING, scope=function)
TEST(X509AccessorEncoding, TheThumbprintIsTheSha1OfTheDer)
{
  const Der der = der_of(build_certificate(CertSpec{}, required_key(p256).get()).get());
  EXPECT_EQ(bytes_of(read(der)->thumbprint()), sha1_of(der));
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-51-ENCODING, scope=function)
TEST(X509AccessorEncoding, EqualityFollowsTheEncoding)
{
  const Der der = der_of(build_certificate(CertSpec{}, required_key(p256).get()).get());
  CertSpec other;
  other.serialHex = "1002";
  const auto different = read(build_certificate(other, required_key(p256).get()));
  EXPECT_TRUE(*read(der) == *read(der)) << "two reads of the same bytes";
  EXPECT_FALSE(*read(der) == *different) << "control: one serial apart";
}

// ---------------------------------------------------------------------------------------------------------
// CRL handle: der_encoding, thumbprint, equality (the whole X509Crl interface).
// ---------------------------------------------------------------------------------------------------------

struct CrlPki
{
  X509Ptr ca;
  PKey key;
  Der crl;  ///< Revokes 1001 (keyCompromise) and 1002 (no reason).
  Der otherCrl;  ///< The same issuer, a later thisUpdate, revokes 1003.
};

const CrlPki& crl_pki()
{
  static const CrlPki pki = []
  {
    CrlPki built;
    built.key = required_key(p256, "crl-ca");
    CertSpec caSpec;
    caSpec.subject = {utf8(NID_commonName, "CRL Issuer")};
    caSpec.extensions = {{NID_basic_constraints, "critical,CA:TRUE"},
      {NID_key_usage, "critical,keyCertSign,cRLSign"},
      {NID_subject_key_identifier, "C1:C1:C1:01"}};
    built.ca = build_certificate(caSpec, built.key.get());
    built.crl = der_of_crl(
      build_crl(built.ca.get(), built.key.get(), {{"1001", 1}, {"1002", -1}}, "250101000000Z").get());
    built.otherCrl =
      der_of_crl(build_crl(built.ca.get(), built.key.get(), {{"1003", 4}}, "250201000000Z").get());
    return built;
  }();
  return pki;
}

std::shared_ptr<const X509Crl> read_crl(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return crypto().read_crl_from_der(span<const ua::byte>{bytes});
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-52-CRL, scope=function)
TEST(X509CrlAccessor, TheDerEncodingRoundTripsByteForByte)
{
  EXPECT_EQ(bytes_of(read_crl(crl_pki().crl)->der_encoding()), crl_pki().crl);
}

// The interface names no digest, so the obligation is identity: the same bytes give the same thumbprint and
// another CRL gives another.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-52-CRL, scope=function)
TEST(X509CrlAccessor, TheThumbprintIdentifiesTheEncoding)
{
  const auto first = read_crl(crl_pki().crl)->thumbprint();
  EXPECT_FALSE(first.empty());
  EXPECT_EQ(first, read_crl(crl_pki().crl)->thumbprint());
  EXPECT_NE(first, read_crl(crl_pki().otherCrl)->thumbprint());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-52-CRL, scope=function)
TEST(X509CrlAccessor, EqualityFollowsTheEncoding)
{
  EXPECT_TRUE(*read_crl(crl_pki().crl) == *read_crl(crl_pki().crl));
  EXPECT_FALSE(*read_crl(crl_pki().crl) == *read_crl(crl_pki().otherCrl));
}

// ---------------------------------------------------------------------------------------------------------
// Parsers.
// ---------------------------------------------------------------------------------------------------------

/// root <- intermediate <- leaf, each DER, in leaf-first order.
const std::vector<Der>& chain_of_three()
{
  static const std::vector<Der> chain = []
  {
    const auto rootKey = required_key(p256, "parser-root");
    const auto intermediateKey = required_key(p256, "parser-intermediate");
    CertSpec rootSpec;
    rootSpec.subject = {utf8(NID_commonName, "Parser Root")};
    rootSpec.extensions = {{NID_basic_constraints, "critical,CA:TRUE"}};
    const auto root = build_certificate(rootSpec, rootKey.get());
    CertSpec intermediateSpec;
    intermediateSpec.subject = {utf8(NID_commonName, "Parser Intermediate")};
    intermediateSpec.extensions = {{NID_basic_constraints, "critical,CA:TRUE"}};
    const auto intermediate =
      build_certificate(intermediateSpec, intermediateKey.get(), Signer{root.get(), rootKey.get()});
    CertSpec leafSpec;
    leafSpec.subject = {utf8(NID_commonName, "Parser Leaf")};
    const auto leaf = build_certificate(
      leafSpec, required_key(p256, "parser-leaf").get(), Signer{intermediate.get(), intermediateKey.get()});
    return std::vector<Der>{der_of(leaf.get()), der_of(intermediate.get()), der_of(root.get())};
  }();
  return chain;
}

Der concatenate(const std::vector<Der>& parts)
{
  Der all;
  for (const auto& part : parts)
  {
    all.insert(all.end(), part.begin(), part.end());
  }
  return all;
}

Der truncated(Der der)
{
  der.resize(der.size() - 7);
  return der;
}

Status status_of_read_certificate(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return status_of(
    [&] { static_cast<void>(crypto().read_certificate_from_der(span<const ua::byte>{bytes})); });
}

Status status_of_read_certificates(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return status_of(
    [&] { static_cast<void>(crypto().read_certificates_from_der(span<const ua::byte>{bytes})); });
}

Status status_of_read_crl(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return status_of([&] { static_cast<void>(crypto().read_crl_from_der(span<const ua::byte>{bytes})); });
}

Status status_of_read_crls(const Der& der)
{
  const auto bytes = to_ua_bytes(der);
  return status_of([&] { static_cast<void>(crypto().read_crls_from_der(span<const ua::byte>{bytes})); });
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificateFromDerParsesOneCertificate)
{
  const auto& leaf = chain_of_three().front();
  EXPECT_EQ(bytes_of(read(leaf)->der_encoding()), leaf);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerParsesAChainOfThreeInOrder)
{
  const auto bytes = to_ua_bytes(concatenate(chain_of_three()));
  const auto parsed = crypto().read_certificates_from_der(span<const ua::byte>{bytes});
  ASSERT_EQ(parsed.size(), 3u);
  for (std::size_t i = 0; i < parsed.size(); ++i)
  {
    EXPECT_EQ(bytes_of(parsed[i]->der_encoding()), chain_of_three()[i]) << "position " << i;
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificateFromDerRefusesTruncatedBytes)
{
  EXPECT_EQ(status_of_read_certificate(truncated(chain_of_three().front())), Status::BadCertificateInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-42-UNCONVERTIBLE-NAME-IS-EMPTY, scope=function)
TEST(CertificateParsers, ReadCertificateFromDerRefusesMalformedNameEncodings)
{
  CertSpec spec;
  spec.subject = {utf8(NID_commonName, "CN1"), utf8(NID_organizationName, "BMP")};
  const auto valid = der_of(build_certificate(spec, required_key(p256).get()).get());
  const std::vector<std::pair<Der, Der>> replacements{
    {{0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 'C', 'N', '1'},
      {0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0xff, 0xfe, 0xfd}},
    {{0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 'B', 'M', 'P'},
      {0x06, 0x03, 0x55, 0x04, 0x0a, 0x1e, 0x03, 0x00, 0x41, 0x00}}};
  for (const auto& [original, replacement] : replacements)
  {
    ASSERT_NE(read(valid), nullptr) << "control: the unaltered certificate parses";
    auto malformed = valid;
    // The self-signed issuer precedes the subject; alter the final matching Name attribute.
    const auto attribute =
      std::find_end(malformed.begin(), malformed.end(), original.begin(), original.end());
    ASSERT_NE(attribute, malformed.end());
    ASSERT_EQ(original.size(), replacement.size());
    std::copy(replacement.begin(), replacement.end(), attribute);
    try
    {
      static_cast<void>(read(malformed));
      FAIL() << "malformed subject Name must be rejected";
    }
    catch (const UaException& exception)
    {
      EXPECT_EQ(exception.status(), Status::BadCertificateInvalid);
      EXPECT_NE(exception.detail(), nullptr);
    }
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificateFromDerRefusesEmptyBytes)
{
  EXPECT_EQ(status_of_read_certificate(Der{}), Status::BadCertificateInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificateFromDerRefusesPemText)
{
  const auto& leaf = chain_of_three().front();
  const unsigned char* p = leaf.data();
  X509Ptr x509{d2i_X509(nullptr, &p, static_cast<long>(leaf.size()))};
  require(x509 != nullptr, "d2i_X509");
  EXPECT_EQ(status_of_read_certificate(pem_of(x509.get())), Status::BadCertificateInvalid);
}

// Approved item 7: bytes after the last certificate refuse the whole field.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerRefusesTrailingBytes)
{
  auto bytes = concatenate(chain_of_three());
  bytes.push_back(0x30);
  bytes.push_back(0x00);
  EXPECT_EQ(status_of_read_certificates(bytes), Status::BadCertificateInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerRefusesATruncatedLastCertificate)
{
  const auto& chain = chain_of_three();
  EXPECT_EQ(status_of_read_certificates(concatenate({chain[0], chain[1], truncated(chain[2])})),
    Status::BadCertificateInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerRefusesATruncatedFirstCertificate)
{
  EXPECT_EQ(status_of_read_certificates(truncated(chain_of_three().front())), Status::BadCertificateInvalid);
}

// A list parser over zero bytes reads a list of no certificates: no byte is left outside a complete
// certificate. Refusing an empty certificate FIELD is the field parser's rule (CertificateFieldEmpty), not
// the list parser's (oracle correction, triage round 1 O2).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerReadsNoCertificatesFromEmptyBytes)
{
  const auto bytes = to_ua_bytes(Der{});
  EXPECT_EQ(crypto().read_certificates_from_der(span<const ua::byte>{bytes}).size(), 0u);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCertificatesFromDerRefusesPemText)
{
  const auto& leaf = chain_of_three().front();
  const unsigned char* p = leaf.data();
  X509Ptr x509{d2i_X509(nullptr, &p, static_cast<long>(leaf.size()))};
  require(x509 != nullptr, "d2i_X509");
  EXPECT_EQ(status_of_read_certificates(pem_of(x509.get())), Status::BadCertificateInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlFromDerParsesOneCrl)
{
  EXPECT_EQ(bytes_of(read_crl(crl_pki().crl)->der_encoding()), crl_pki().crl);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlsFromDerParsesTwoInOrder)
{
  const auto bytes = to_ua_bytes(concatenate({crl_pki().crl, crl_pki().otherCrl}));
  const auto parsed = crypto().read_crls_from_der(span<const ua::byte>{bytes});
  ASSERT_EQ(parsed.size(), 2u);
  EXPECT_EQ(bytes_of(parsed[0]->der_encoding()), crl_pki().crl);
  EXPECT_EQ(bytes_of(parsed[1]->der_encoding()), crl_pki().otherCrl);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlFromDerRefusesTruncatedEmptyAndPem)
{
  const unsigned char* p = crl_pki().crl.data();
  X509CrlPtr crl{d2i_X509_CRL(nullptr, &p, static_cast<long>(crl_pki().crl.size()))};
  require(crl != nullptr, "d2i_X509_CRL");
  EXPECT_EQ(status_of_read_crl(truncated(crl_pki().crl)), Status::BadCertificateInvalid) << "truncated";
  EXPECT_EQ(status_of_read_crl(Der{}), Status::BadCertificateInvalid) << "empty";
  EXPECT_EQ(status_of_read_crl(pem_of_crl(crl.get())), Status::BadCertificateInvalid) << "PEM";
}

// "Throws if any CRL fails to parse": a truncated second CRL, no CRL at all, or PEM text.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlsFromDerRefusesATruncatedLastCrl)
{
  EXPECT_EQ(status_of_read_crls(concatenate({crl_pki().crl, truncated(crl_pki().otherCrl)})),
    Status::BadCertificateInvalid);
}

// A list parser over zero bytes reads a list of no CRLs (oracle correction, triage round 1 O2); the
// single-CRL parser still refuses empty input (ReadCrlFromDerRefusesTruncatedEmptyAndPem).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlsFromDerReadsNoCrlsFromEmptyBytes)
{
  const auto bytes = to_ua_bytes(Der{});
  EXPECT_EQ(crypto().read_crls_from_der(span<const ua::byte>{bytes}).size(), 0u);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-53-PARSERS, scope=function)
TEST(CertificateParsers, ReadCrlsFromDerRefusesPemText)
{
  const unsigned char* p = crl_pki().crl.data();
  X509CrlPtr crl{d2i_X509_CRL(nullptr, &p, static_cast<long>(crl_pki().crl.size()))};
  require(crl != nullptr, "d2i_X509_CRL");
  EXPECT_EQ(status_of_read_crls(pem_of_crl(crl.get())), Status::BadCertificateInvalid);
}

}  // namespace
