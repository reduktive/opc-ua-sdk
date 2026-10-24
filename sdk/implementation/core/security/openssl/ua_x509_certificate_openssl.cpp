// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "openssl/bn.h"
#include "openssl/x509v3.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000L
// 1.1.x curve identification uses the low-level EC group + object-name lookup (no OSSL_PARAM API).
#include "openssl/ec.h"
#include "openssl/objects.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include <memory>
#endif
#include "ua_x509_certificate_openssl.h"
#include "ua_crypto_openssl.h"
#include "ua_error_detail.h"
#include "ua_openssl_error_helpers.h"

namespace ua
{
namespace
{
struct GeneralNamesDeleter
{
  void operator()(GENERAL_NAMES* names) const noexcept
  {
    GENERAL_NAMES_free(names);
  }
};

using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter>;

GeneralNamesPtr subject_alternative_names(X509& certificate)
{
  return GeneralNamesPtr{
    reinterpret_cast<GENERAL_NAMES*>(X509_get_ext_d2i(&certificate, NID_subject_alt_name, NULL, NULL))};
}
}  // namespace

int X509CertificateOpenSsl::version() const
{
  return numeric_cast<int>(X509_get_version(&mCert));
}

std::string X509CertificateOpenSsl::serial_number() const
{
  const auto* asn1Integer = X509_get0_serialNumber(&mCert);
  auto* bn = ASN1_INTEGER_to_BN(asn1Integer, NULL);
  auto* dec = BN_bn2dec(bn);
  std::string result{dec};
  OPENSSL_free(dec);
  BN_free(bn);
  return result;
}

ByteString X509CertificateOpenSsl::signature() const
{
  const ASN1_BIT_STRING* sig{nullptr};
  const X509_ALGOR* alg{nullptr};

  X509_get0_signature(&sig, &alg, &mCert);

  ByteString result;
  if (sig && (sig->length > 0))
  {
    // sig->length > 0 proven by the enclosing if-condition
    const size_t lengthInBytes = static_cast<size_t>(sig->length);
    result.resize(lengthInBytes);
    std::memcpy(result.data(), sig->data, result.size());
  }

  return result;
}

std::string X509CertificateOpenSsl::issuer() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_as_string(*name);
}

std::string X509CertificateOpenSsl::issuer_country() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_countryName);
}

std::string X509CertificateOpenSsl::issuer_organization() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_organizationName);
}

std::string X509CertificateOpenSsl::issuer_organizational_unit() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_organizationalUnitName);
}

std::string X509CertificateOpenSsl::issuer_distinguished_name() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_distinguishedName);
}

std::string X509CertificateOpenSsl::issuer_state() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_stateOrProvinceName);
}

std::string X509CertificateOpenSsl::issuer_common_name() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_commonName);
}

std::string X509CertificateOpenSsl::issuer_domain_component() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_domainComponent);
}

std::string X509CertificateOpenSsl::issuer_locality() const
{
  auto* name = X509_get_issuer_name(&mCert);
  return get_name_component_by_nid(*name, NID_localityName);
}

UtcTime X509CertificateOpenSsl::validity_from() const
{
  const auto* from = X509_get0_notBefore(&mCert);
  return get_time_from_asn1(*from);
}

UtcTime X509CertificateOpenSsl::validity_to() const
{
  const auto* from = X509_get0_notAfter(&mCert);
  return get_time_from_asn1(*from);
}

std::string X509CertificateOpenSsl::subject() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_as_string(*name);
}

std::string X509CertificateOpenSsl::subject_country() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_countryName);
}

std::string X509CertificateOpenSsl::subject_organization() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_organizationName);
}

std::string X509CertificateOpenSsl::subject_organizational_unit() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_organizationalUnitName);
}

std::string X509CertificateOpenSsl::subject_distinguished_name() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_distinguishedName);
}

std::string X509CertificateOpenSsl::subject_state() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_stateOrProvinceName);
}

std::string X509CertificateOpenSsl::subject_common_name() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_commonName);
}

std::string X509CertificateOpenSsl::subject_domain_component() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_domainComponent);
}

std::string X509CertificateOpenSsl::subject_locality() const
{
  auto* name = X509_get_subject_name(&mCert);
  return get_name_component_by_nid(*name, NID_localityName);
}

ByteString X509CertificateOpenSsl::public_key() const
{
  auto* key = X509_get0_pubkey(&mCert);
  if (key == nullptr)
  {
    return {};  // SubjectPublicKeyInfo did not decode (see read_certificate_from_der)
  }
  unsigned char* pp{nullptr};
  auto len = i2d_PUBKEY(key, &pp);
  ByteString der{pp, pp + len};
  OPENSSL_free(pp);
  return der;
}

size_t X509CertificateOpenSsl::public_key_bit_length() const
{
  auto* key = X509_get0_pubkey(&mCert);
  if (key == nullptr)
  {
    return 0;
  }
  // EdDSA keys are reported by the OPC UA profile database convention (decision C): 256 bits for
  // Ed25519 and 456 for Ed448 - the encoded public key size - rather than the curve sizes EVP_PKEY_bits
  // reports (253 and 456).
  const auto keyType = EVP_PKEY_base_id(key);
  if (keyType == EVP_PKEY_ED25519)
  {
    return 256;
  }
  if (keyType == EVP_PKEY_ED448)
  {
    return 456;
  }
  // EVP_PKEY_bits is the spelling common to 1.1.x and 3.x (the get_-prefixed alias is 3.x-only).
  return numeric_cast<size_t>(EVP_PKEY_bits(key));
}

CertificateKeyAlgorithm X509CertificateOpenSsl::key_algorithm() const
{
  auto* key = X509_get0_pubkey(&mCert);
  if (key == nullptr)
  {
    // d2i_X509 decodes the SubjectPublicKeyInfo opportunistically and still succeeds when it cannot
    // (unknown algorithm or curve OID); the parser refuses such certificates, so this is the
    // backstop for an X509 obtained any other way.
    return CertificateKeyAlgorithm::Invalid;
  }
  // EVP_PKEY_base_id is the spelling common to 1.1.x and 3.x (the get_-prefixed alias is 3.x-only).
  auto keyType = EVP_PKEY_base_id(key);

  if (keyType == EVP_PKEY_RSA)
  {
    return CertificateKeyAlgorithm::Rsa;
  }
  else if (keyType == EVP_PKEY_EC)
  {
    // Distinguish curves by querying the group name from the EC key.
    std::string_view name;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char curveName[64] = {};  // only the 3.x OSSL_PARAM path writes into a caller buffer
    if (EVP_PKEY_get_utf8_string_param(key, "group", curveName, sizeof(curveName), nullptr))
    {
      name = curveName;
    }
#else
    // OpenSSL 1.1.x has no OSSL_PARAM API: derive the curve's short name from the low-level EC group.
    if (const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(key))
    {
      if (const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey))
      {
        const int curveNid = EC_GROUP_get_curve_name(ecGroup);
        if (curveNid != NID_undef)
        {
          if (const char* shortName = OBJ_nid2sn(curveNid))
          {
            name = shortName;  // OBJ_nid2sn returns a static, NUL-terminated string
          }
        }
      }
    }
#endif
    if (!name.empty())
    {
      if (name == "prime256v1" || name == "P-256")
      {
        return CertificateKeyAlgorithm::EccNistP256;
      }
      else if (name == "secp384r1" || name == "P-384")
      {
        return CertificateKeyAlgorithm::EccNistP384;
      }
      else if (name == "secp521r1" || name == "P-521")
      {
        return CertificateKeyAlgorithm::EccNistP521;
      }
      else if (name == "brainpoolP256r1")
      {
        return CertificateKeyAlgorithm::EccBrainpoolP256r1;
      }
      else if (name == "brainpoolP384r1")
      {
        return CertificateKeyAlgorithm::EccBrainpoolP384r1;
      }
      else if (name == "brainpoolP512r1")
      {
        return CertificateKeyAlgorithm::EccBrainpoolP512r1;
      }
    }
    return CertificateKeyAlgorithm::Invalid;
  }
  else if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_X25519)
  {
    return CertificateKeyAlgorithm::EccCurve25519;
  }
  else if (keyType == EVP_PKEY_ED448 || keyType == EVP_PKEY_X448)
  {
    return CertificateKeyAlgorithm::EccCurve448;
  }

  return CertificateKeyAlgorithm::Invalid;
}

ByteString X509CertificateOpenSsl::authority_key_identifier() const
{
  ByteString result;
  const auto* id = X509_get0_authority_key_id(&mCert);
  if (id)
  {
    result = octet_string_to_bytes(*id);
  }
  return result;
}

ByteString X509CertificateOpenSsl::subject_key_identifier() const
{
  ByteString result;
  const auto* id = X509_get0_subject_key_id(&mCert);
  if (id)
  {
    result = octet_string_to_bytes(*id);
  }
  return result;
}

bool X509CertificateOpenSsl::key_usage_digital_signature() const
{
  return get_key_usage(KU_DIGITAL_SIGNATURE);
}

bool X509CertificateOpenSsl::key_usage_non_repudiation() const
{
  return get_key_usage(KU_NON_REPUDIATION);
}

bool X509CertificateOpenSsl::key_usage_key_encipherment() const
{
  return get_key_usage(KU_KEY_ENCIPHERMENT);
}

bool X509CertificateOpenSsl::key_usage_data_encipherment() const
{
  return get_key_usage(KU_DATA_ENCIPHERMENT);
}

bool X509CertificateOpenSsl::key_usage_key_agreement() const
{
  return get_key_usage(KU_KEY_AGREEMENT);
}

bool X509CertificateOpenSsl::key_usage_key_cert_sign() const
{
  return get_key_usage(KU_KEY_CERT_SIGN);
}

bool X509CertificateOpenSsl::key_usage_crl_sign() const
{
  return get_key_usage(KU_CRL_SIGN);
}

bool X509CertificateOpenSsl::key_usage_encipher_only() const
{
  return get_key_usage(KU_ENCIPHER_ONLY);
}

bool X509CertificateOpenSsl::key_usage_decipher_only() const
{
  return get_key_usage(KU_DECIPHER_ONLY);
}

std::vector<asio::ip::address> X509CertificateOpenSsl::san_ip_addresses() const
{
  std::vector<asio::ip::address> result;

  auto san = subject_alternative_names(mCert);
  if (san)
  {
    auto num = sk_GENERAL_NAME_num(san.get());
    for (int i = 0; i < num; ++i)
    {
      const auto* name = sk_GENERAL_NAME_value(san.get(), i);
      if (name->type == GEN_IPADD)
      {
        const auto* ipaddr = ASN1_STRING_get0_data(name->d.iPAddress);
        const auto addressLength = ASN1_STRING_length(name->d.iPAddress);
        if (addressLength == numeric_cast<int>(asio::ip::address_v4::bytes_type{}.size()))
        {
          asio::ip::address_v4::bytes_type bytes{};
          std::copy_n(ipaddr, bytes.size(), bytes.begin());
          result.emplace_back(asio::ip::address_v4{bytes});
        }
        else if (addressLength == numeric_cast<int>(asio::ip::address_v6::bytes_type{}.size()))
        {
          asio::ip::address_v6::bytes_type bytes{};
          std::copy_n(ipaddr, bytes.size(), bytes.begin());
          result.emplace_back(asio::ip::address_v6{bytes});
        }
        else
        {
          // A malformed certificate, not an SDK fault: Bad_CertificateInvalid names the real cause, and the
          // host-name check and validation pass it through (security review B3-12(b)).
          throw UaException{Status::BadCertificateInvalid,
            ErrorDetail::build("InvalidIpAddressLength",
              "SAN IP address has unexpected length (expected IPv4 or IPv6 width)",
              "X509Certificate")
              .context(ua::ContextKeys::sizeActual, addressLength)
              .context(ua::ContextKeys::sizeExpected, "4 or 16")
              .context(ua::ContextKeys::index, i)};
        }
      }
    }
  }

  return result;
}

std::vector<std::string> X509CertificateOpenSsl::san_hostnames() const
{
  std::vector<std::string> result;

  auto san = subject_alternative_names(mCert);
  if (san)
  {
    auto num = sk_GENERAL_NAME_num(san.get());
    for (int i = 0; i < num; ++i)
    {
      const auto* name = sk_GENERAL_NAME_value(san.get(), i);
      if (name->type == GEN_DNS)
      {
        const auto* hostname = utils::unsigned_chars_to_chars(ASN1_STRING_get0_data(name->d.dNSName));
        const std::string value{hostname, numeric_cast<size_t>(ASN1_STRING_length(name->d.dNSName))};
        result.push_back(value);
      }
    }
  }

  return result;
}

std::vector<std::string> X509CertificateOpenSsl::san_uris() const
{
  std::vector<std::string> result;

  auto san = subject_alternative_names(mCert);
  if (san)
  {
    auto num = sk_GENERAL_NAME_num(san.get());
    for (int i = 0; i < num; ++i)
    {
      const auto* name = sk_GENERAL_NAME_value(san.get(), i);
      if (name->type == GEN_URI)
      {
        const auto* uri =
          utils::unsigned_chars_to_chars(ASN1_STRING_get0_data(name->d.uniformResourceIdentifier));
        const std::string value{
          uri, numeric_cast<size_t>(ASN1_STRING_length(name->d.uniformResourceIdentifier))};
        result.push_back(value);
      }
    }
  }

  return result;
}

bool X509CertificateOpenSsl::basic_constraints_ca() const
{
  return X509_get_extension_flags(&mCert) & EXFLAG_CA;
}

uint32_t X509CertificateOpenSsl::basic_constraints_path_length() const
{
  // X509_get_pathlen() returns a non-negative pathLenConstraint, or -1 when the
  // constraint is absent (or unparsable). The absent sentinel intentionally maps to
  // UINT32_MAX, matching the documented "unconstrained" semantics of this accessor.
  return static_cast<uint32_t>(X509_get_pathlen(&mCert));
}

bool X509CertificateOpenSsl::extended_key_usage_client_auth() const
{
  return get_ext_key_usage(XKU_SSL_CLIENT);
}

bool X509CertificateOpenSsl::extended_key_usage_server_auth() const
{
  return get_ext_key_usage(XKU_SSL_SERVER);
}

ByteString X509CertificateOpenSsl::thumbprint() const
{
  auto crypto = CryptoOpenSsl::create();
  auto der = der_encoding();
  auto result = crypto->calculate_digest_sync(HashAlgorithm::Sha1, der);
  return result;
}

ByteString X509CertificateOpenSsl::der_encoding() const
{
  auto length = i2d_X509(&mCert, NULL);
  if (length < 0)
  {
    throw UaException{Status::BadInternalError,
      detail::make_openssl_error_detail("DerEncodingFailed",
        "Failed to compute DER encoding length for X509 certificate",
        "X509Certificate")};
  }

  ByteString result;
  // length >= 0 proven by the `length < 0` guard above; i2d_X509(cert, NULL) returns a
  // negative value on error and the non-negative encoding length otherwise.
  result.resize(static_cast<size_t>(length));
  auto* dest = result.data();
  length = i2d_X509(&mCert, &dest);
  if (length < 0)
  {
    throw UaException{Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DerEncodingFailed", "Failed to DER-encode X509 certificate", "X509Certificate")};
  }

  return result;
}

bool X509CertificateOpenSsl::verifies_with_key_of(const X509Certificate& signer) const
{
  // The signer's key, without a copy when the signer is an OpenSSL certificate; otherwise decoded from
  // its SubjectPublicKeyInfo. Cost: one signature verification per call.
  EVP_PKEY* key = nullptr;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> decoded{nullptr, &EVP_PKEY_free};
  if (const auto* concrete = dynamic_cast<const X509CertificateOpenSsl*>(&signer))
  {
    key = X509_get0_pubkey(&concrete->mCert);
  }
  else
  {
    const auto spki = signer.public_key();
    const unsigned char* cursor = spki.data();
    decoded.reset(d2i_PUBKEY(nullptr, &cursor, numeric_cast<long>(spki.size())));
    key = decoded.get();
  }
  if (key == nullptr)
  {
    ERR_clear_error();
    return false;
  }
  const bool verified = X509_verify(&mCert, key) == 1;
  // A failed verification leaves its reason on the thread's error queue; this is a yes/no question,
  // so the queue is left as it was found.
  ERR_clear_error();
  return verified;
}

bool X509CertificateOpenSsl::issued_by(const X509Certificate& issuer) const
{
  // The names must chain, the key identifiers must agree when both are present, and the issuer's key
  // must verify this certificate's signature (decision B). issuer_of is defined through this function,
  // so a.issued_by(b) == b.issuer_of(a) always.
  if (this->issuer() != issuer.subject())
  {
    return false;
  }
  const auto authorityKeyId = authority_key_identifier();
  const auto issuerSubjectKeyId = issuer.subject_key_identifier();
  if (!authorityKeyId.empty() && !issuerSubjectKeyId.empty() && authorityKeyId != issuerSubjectKeyId)
  {
    return false;
  }
  return verifies_with_key_of(issuer);
}

bool X509CertificateOpenSsl::issuer_of(const X509Certificate& issued) const
{
  return issued.issued_by(*this);
}

bool X509CertificateOpenSsl::self_signed() const
{
  // Subject equals issuer (with agreeing key identifiers, which EXFLAG_SS records) and the certificate's
  // own key verifies its signature (decision B).
  auto flags = X509_get_extension_flags(&mCert);
  return (flags & EXFLAG_SS) != 0 && verifies_with_key_of(*this);
}

CertificateSignatureAlgorithm X509CertificateOpenSsl::signature_algorithm() const
{
  auto result = CertificateSignatureAlgorithm::Invalid;
  auto nid = X509_get_signature_nid(&mCert);
  switch (nid)
  {
  case NID_sha1WithRSAEncryption:
    result = CertificateSignatureAlgorithm::RsaPkcs15Sha1;
    break;

  case NID_sha256WithRSAEncryption:
    result = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    break;

  case NID_sha224WithRSAEncryption:
    result = CertificateSignatureAlgorithm::RsaPkcs15Sha2224;
    break;

  case NID_sha384WithRSAEncryption:
    result = CertificateSignatureAlgorithm::RsaPkcs15Sha2384;
    break;

  case NID_sha512WithRSAEncryption:
    result = CertificateSignatureAlgorithm::RsaPkcs15Sha2512;
    break;

  case NID_rsassaPss:
  {
    // RSASSA-PSS names its hash in the algorithm parameters, not in the OID; X509_get_signature_info
    // decodes them. A PSS signature with any other hash is Invalid.
    int digestNid = NID_undef;
    if (X509_get_signature_info(&mCert, &digestNid, nullptr, nullptr, nullptr) == 1)
    {
      if (digestNid == NID_sha256)
      {
        result = CertificateSignatureAlgorithm::RsaPssSha2256;
      }
      else if (digestNid == NID_sha384)
      {
        result = CertificateSignatureAlgorithm::RsaPssSha2384;
      }
      else if (digestNid == NID_sha512)
      {
        result = CertificateSignatureAlgorithm::RsaPssSha2512;
      }
    }
    ERR_clear_error();
    break;
  }

  case NID_ecdsa_with_SHA256:
    result = CertificateSignatureAlgorithm::EcDsaSha2256;
    break;

  case NID_ecdsa_with_SHA384:
    result = CertificateSignatureAlgorithm::EcDsaSha2384;
    break;

  case NID_ecdsa_with_SHA512:
    result = CertificateSignatureAlgorithm::EcDsaSha2512;
    break;

  case NID_ED25519:
    result = CertificateSignatureAlgorithm::PureEdDsa25519;
    break;

  case NID_ED448:
    result = CertificateSignatureAlgorithm::PureEdDsa448;
    break;

  default:
    break;
  }
  return result;
}

X509CertificateOpenSsl::X509CertificateOpenSsl(X509& cert) : mCert(cert)
{}

X509CertificateOpenSsl::~X509CertificateOpenSsl()
{
  X509_free(&mCert);
}

std::string X509CertificateOpenSsl::get_name_component_by_nid(const X509_NAME& name, int nid) const
{
  std::string result;
  // 1.1.x takes a non-const X509_NAME* here; 3.x made it const. const_cast bridges both.
  auto index = X509_NAME_get_index_by_NID(const_cast<X509_NAME*>(&name), nid, -1);
  if (index != -1)
  {
    auto* entry = X509_NAME_get_entry(&name, index);
    auto* data = X509_NAME_ENTRY_get_data(entry);
    unsigned char* out{nullptr};
    auto len = ASN1_STRING_to_UTF8(&out, data);
    // A value OpenSSL cannot convert, such as a BIT STRING attribute accepted by d2i_X509, is reported
    // as no value. Names are read on validation and error paths that must not throw.
    if (len < 0)
    {
      ERR_clear_error();
      return result;
    }
    result = std::string{utils::unsigned_chars_to_chars(out), numeric_cast<size_t>(len)};
    OPENSSL_free(out);
  }
  return result;
}

std::string X509CertificateOpenSsl::get_name_as_string(const X509_NAME& name) const
{
  unsigned char* pp{nullptr};
  // 1.1.x takes a non-const X509_NAME* here; 3.x made it const. const_cast bridges both.
  auto len = i2d_X509_NAME(const_cast<X509_NAME*>(&name), &pp);
  if (len < 0)
  {
    ERR_clear_error();
    return {};
  }
  std::string nameString{utils::unsigned_chars_to_chars(pp), numeric_cast<size_t>(len)};
  OPENSSL_free(pp);
  return nameString;
}

UtcTime X509CertificateOpenSsl::get_time_from_asn1(const ASN1_TIME& time) const
{
  UtcTime result;
  std::tm tm{};
  if (ASN1_TIME_to_tm(&time, &tm))
  {
    int offset{0};
#ifdef __linux__
    const int secsPerMin{60};
    offset = numeric_cast<int>(tm.tm_gmtoff / secsPerMin);
#endif  //__linux__

    result = UtcTime{tm.tm_year + 1900,
      tm.tm_mon + 1,
      tm.tm_mday,
      tm.tm_hour,
      tm.tm_min,
      numeric_cast<double>(tm.tm_sec),
      offset};
  }
  return result;
}

bool X509CertificateOpenSsl::get_key_usage(int usage) const
{
  auto flags = X509_get_extension_flags(&mCert);
  if (flags & EXFLAG_KUSAGE)
  {
    // usage is a positive KU_* bitmask constant; the & is against a uint32 flag word.
    return X509_get_key_usage(&mCert) & static_cast<uint32_t>(usage);
  }
  return false;
}

bool X509CertificateOpenSsl::get_ext_key_usage(int usage) const
{
  auto flags = X509_get_extension_flags(&mCert);
  if (flags & EXFLAG_XKUSAGE)
  {
    // usage is a positive XKU_* bitmask constant; the & is against a uint32 flag word.
    return X509_get_extended_key_usage(&mCert) & static_cast<uint32_t>(usage);
  }
  return false;
}

ByteString X509CertificateOpenSsl::octet_string_to_bytes(const ASN1_OCTET_STRING& octetString)
{
  ByteString result;
  if (octetString.length > 0)
  {
    // octetString.length > 0 proven by the enclosing if-condition
    result.resize(static_cast<size_t>(octetString.length));
    std::copy_n(octetString.data, result.size(), result.data());
  }
  return result;
}

bool X509CertificateOpenSsl::operator==(const X509Certificate& obj) const
{
  return (obj.thumbprint() == thumbprint());
}

const X509& X509CertificateOpenSsl::cert() const
{
  return mCert;
}

}  // namespace ua
