// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#define OPENSSL_API_COMPAT 10100

#include <cctype>
#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "ua_crypto_openssl.h"
#include "ua_secure_memory.h"
#include "ua_certificate_store.h"
#include "ua_certificate_validation_paths.h"
#include "ua_certificate_hostname.h"
#include "ua_security_policy.h"
#include "ua_x509_certificate_openssl.h"
#include "ua_x509_crl_openssl.h"
#include "ua_string.h"
#include "ua_byte_string.h"
#include "ua_status_code.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_openssl_error_helpers.h"
#include "ua_to_result.h"
#include "ua_callback_safety.h"
#include "ua_url_parser.h"

#include "fmt/format.h"

#include <boost/asio/ip/host_name.hpp>

namespace
{

using namespace ua;

bool is_openssl_result_good(int result)
{
  return (1 == result);
}

// The OpenSSL cipher for an AEAD SymmetricEncryptionAlgorithm. Every one has a 96-bit IV and a 128-bit tag.
const EVP_CIPHER* aead_cipher(SymmetricEncryptionAlgorithm algorithm, const char* operation)
{
  switch (algorithm)
  {
  case SymmetricEncryptionAlgorithm::ChaCha20Poly1305:
    return EVP_chacha20_poly1305();
  case SymmetricEncryptionAlgorithm::Aes128Gcm:
    return EVP_aes_128_gcm();
  case SymmetricEncryptionAlgorithm::Aes256Gcm:
    return EVP_aes_256_gcm();
  case SymmetricEncryptionAlgorithm::Invalid:
  case SymmetricEncryptionAlgorithm::Aes128Cbc:
  case SymmetricEncryptionAlgorithm::Aes256Cbc:
    break;
  }
  throw UaException(Status::BadInvalidArgument,
    ErrorDetail::build(
      "InvalidAlgorithm", std::string("algorithm is invalid in ") + operation, "OpenSslCrypto")
      .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
}

bool is_certificate_time_error(int error) noexcept
{
  switch (error)
  {
  case X509_V_ERR_CERT_HAS_EXPIRED:
  case X509_V_ERR_CERT_NOT_YET_VALID:
    return true;
  default:
    return false;
  }
}

bool is_revocation_status_unknown_error(int error) noexcept
{
  switch (error)
  {
  case X509_V_ERR_UNABLE_TO_GET_CRL:
  case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
  case X509_V_ERR_CRL_SIGNATURE_FAILURE:
  case X509_V_ERR_CRL_NOT_YET_VALID:
  case X509_V_ERR_CRL_HAS_EXPIRED:
  case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
  case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
#ifdef X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
  case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
#endif
  // A CRL that cannot be used - its signer may not sign CRLs, it carries an unhandled critical extension,
  // its scope or path does not match - establishes no revocation status either (Table 106 Find Revocation
  // List). These also follow from an incomplete chain, where the CRL is matched against the wrong issuer;
  // classified here they rank at their own step instead of masking the chain fault as unclassified.
  case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
  case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
  case X509_V_ERR_DIFFERENT_CRL_SCOPE:
  case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
    return true;
  default:
    return false;
  }
}

/// One error OpenSSL's path validation reported, as the verification callback saw it.
struct RecordedVerifyError
{
  int error = X509_V_OK;  ///< The X509_V_ERR_* code.
  int depth = 0;  ///< The chain position: 0 is the certificate under validation.
  bool selfSigned = false;  ///< The certificate at that position signed itself.
  std::string issuer;  ///< That certificate's issuer Name, OpenSSL's one-line rendering.
};

/// Every error of one `X509_verify_cert` call. Borrowed through `X509_STORE_CTX` app-data only for the
/// synchronous verification call.
struct VerifyErrorRecorder
{
  std::vector<RecordedVerifyError> errors;
  bool recordingFailed = false;  ///< An error could not be recorded; verification was stopped.
};

struct OpenSslTextDeleter
{
  void operator()(char* text) const noexcept
  {
    OPENSSL_free(text);
  }
};

std::string x509_name_text(const X509_NAME* name)
{
  const std::unique_ptr<char, OpenSslTextDeleter> text{name ? X509_NAME_oneline(name, nullptr, 0) : nullptr};
  return text ? std::string{text.get()} : std::string{};
}

/// OpenSSL's verification callback: records every error it is shown and lets verification continue.
///
/// Part 4 section 6.1.3 orders the validation steps and halts at the first error that is not suppressed,
/// and OpenSSL reports errors in its own order, not Table 106's. Every error is therefore recorded and
/// verification runs to the end; validate_certificate_impl then maps each error to its Table 106 step,
/// sets the suppressed ones aside and reports the earliest of the rest. Returning 1 here never makes a
/// verification succeed: the verdict is decided from the record, not from `X509_verify_cert`'s result.
/// Cost: one small record per error, and none for a certificate that verifies.
int record_certificate_error_and_continue(int preverificationSucceeded, X509_STORE_CTX* context) noexcept
{
  if (preverificationSucceeded == 1)
  {
    return 1;
  }
  if (!context)
  {
    return 0;
  }
  auto* recorder = static_cast<VerifyErrorRecorder*>(X509_STORE_CTX_get_app_data(context));
  if (!recorder)
  {
    return 0;
  }
  try
  {
    RecordedVerifyError record;
    record.error = X509_STORE_CTX_get_error(context);
    record.depth = X509_STORE_CTX_get_error_depth(context);
    X509* current = X509_STORE_CTX_get_current_cert(context);
    if (current)
    {
      record.selfSigned = (X509_get_extension_flags(current) & EXFLAG_SS) != 0;
      record.issuer = x509_name_text(X509_get_issuer_name(current));
    }
    recorder->errors.push_back(std::move(record));
    return 1;
  }
  catch (...)
  {
    // Stop the verification: an error that cannot be recorded cannot be judged, so the call fails closed.
    recorder->recordingFailed = true;
    return 0;
  }
}

/// The rows of OPC 10000-4 Table 106, in the order the validation steps run.
namespace table_106
{
constexpr int structure = 1;
constexpr int buildChain = 2;
constexpr int signature = 3;
constexpr int securityPolicy = 4;
constexpr int trustList = 5;
constexpr int validity = 6;
constexpr int hostName = 7;
constexpr int uri = 8;
constexpr int usage = 9;
constexpr int findRevocationList = 10;
constexpr int revocationCheck = 11;
}  // namespace table_106

/// What Table 106 says about one OpenSSL verification error at one chain depth.
struct VerifyErrorRule
{
  int step = table_106::structure;
  Status status = Status::BadSecurityChecksFailed;
  std::optional<TrustListValidationOptions::Bit>
    suppressedBy;  ///< The Part 12 Table 31 bit, if suppressible.
  const char* code = "CertificateChainValidationFailed";
  const char* summary = "Certificate chain validation failed";
};

/// Maps an OpenSSL verification error to its Table 106 step and code: the certificate's own code at depth 0,
/// the issuer variant above it. Returns nothing for an error that is not a fault in OPC UA terms: OpenSSL
/// reports a chain ending at a self-signed certificate it was not given as an anchor, but every self-signed
/// certificate of the lists is an anchor here, and whether the chain is TRUSTED is the Trust List Check,
/// which validate_certificate_impl makes itself.
std::optional<VerifyErrorRule> verify_error_rule(int error, int depth) noexcept
{
  using Bit = TrustListValidationOptions::Bit;
  const bool leaf = depth == 0;
  if (is_certificate_time_error(error))
  {
    return VerifyErrorRule{table_106::validity,
      leaf ? Status::BadCertificateTimeInvalid : Status::BadCertificateIssuerTimeInvalid,
      leaf ? Bit::SuppressCertificateExpired : Bit::SuppressIssuerCertificateExpired,
      "CertificateTimeInvalid",
      "Certificate chain validation failed: time invalid"};
  }
  if (is_revocation_status_unknown_error(error))
  {
    return VerifyErrorRule{table_106::findRevocationList,
      leaf ? Status::BadCertificateRevocationUnknown : Status::BadCertificateIssuerRevocationUnknown,
      leaf ? Bit::SuppressRevocationStatusUnknown : Bit::SuppressIssuerRevocationStatusUnknown,
      "CertificateRevocationUnknown",
      "Certificate revocation status unknown"};
  }
  switch (error)
  {
  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    return std::nullopt;
  // Certificate Structure: a field that cannot be read as RFC 5280 defines it. A malformed validity time
  // is a structural fault, not an expiry, so no expiry suppression bit applies to it. No issuer variant.
  case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
  case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
  case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
#ifdef X509_V_ERR_ISSUER_NAME_EMPTY
  case X509_V_ERR_ISSUER_NAME_EMPTY:
#endif
#ifdef X509_V_ERR_SUBJECT_NAME_EMPTY
  case X509_V_ERR_SUBJECT_NAME_EMPTY:
#endif
#ifdef X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH
  case X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH:
#endif
#ifdef X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY
  case X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY:
#endif
#ifdef X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3
  case X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3:
#endif
    return VerifyErrorRule{table_106::structure,
      Status::BadCertificateInvalid,
      std::nullopt,
      "CertificateStructureInvalid",
      "Certificate structure invalid"};
  // Build Certificate Chain: an issuer that is in neither list leaves the chain incomplete, which is a
  // different fault from a complete chain that ends at an untrusted root.
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
  case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    return VerifyErrorRule{table_106::buildChain, Status::BadCertificateChainIncomplete, std::nullopt};
  // Signature: the certificate's signature does not verify with its issuer's key. No issuer variant.
  case X509_V_ERR_CERT_SIGNATURE_FAILURE:
  case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
  case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    return VerifyErrorRule{table_106::signature, Status::BadCertificateInvalid, std::nullopt};
  case X509_V_ERR_CERT_UNTRUSTED:
  case X509_V_ERR_CERT_REJECTED:
    return VerifyErrorRule{table_106::trustList, Status::BadCertificateUntrusted, std::nullopt};
  // Certificate Usage: the CA constraints of the chain. On an issuer these are the issuer variant (owner
  // decision 22.3: pathLen exceeded and an intermediate without cA TRUE are IssuerUseNotAllowed).
  case X509_V_ERR_INVALID_CA:
  case X509_V_ERR_PATH_LENGTH_EXCEEDED:
  case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
  case X509_V_ERR_INVALID_NON_CA:
  case X509_V_ERR_INVALID_PURPOSE:
  case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
#ifdef X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA
  case X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA:
#endif
#ifdef X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA
  case X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA:
#endif
#ifdef X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN
  case X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN:
#endif
    return VerifyErrorRule{table_106::usage,
      leaf ? Status::BadCertificateUseNotAllowed : Status::BadCertificateIssuerUseNotAllowed,
      std::nullopt};
  case X509_V_ERR_CERT_REVOKED:
    return VerifyErrorRule{table_106::revocationCheck,
      leaf ? Status::BadCertificateRevoked : Status::BadCertificateIssuerRevoked,
      std::nullopt};
  default:
    // An error this mapping does not classify (for example a structural defect the strict mode finds)
    // refuses the certificate as before, ahead of every other step.
    return VerifyErrorRule{};
  }
}

/// The Certificate Structure rules (Table 106 step 1) that OpenSSL's path validation does not report
/// itself: why @p certificate is not a structurally valid OPC UA certificate, or null when it is. OpenSSL
/// marks a certificate whose extensions it could not read (malformed or repeated) invalid and then only
/// declines to use it as an issuer; Part 6 Table 43 requires version 3; RFC 5280 section 4.1.2.2 bounds
/// the serialNumber to 20 octets (a negative one is to be handled gracefully, so it is accepted). RFC 5280
/// section 4.1.2.6 requires a CA's subject to be non-empty; OpenSSL 3 reports that itself
/// (X509_V_ERR_SUBJECT_NAME_EMPTY), OpenSSL 1.1.1 does not, so it is checked here on 1.1.1 only. Cost:
/// three field reads per chain certificate per validation, two more on OpenSSL 1.1.1.
const char* certificate_structure_defect(const X509& certificate) noexcept
{
  auto* x509 = const_cast<X509*>(&certificate);
  if ((X509_get_extension_flags(x509) & EXFLAG_INVALID) != 0)
  {
    return "an extension is malformed or occurs more than once";
  }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (X509_check_ca(x509) != 0 && X509_NAME_entry_count(X509_get_subject_name(x509)) == 0)
  {
    return "a CA certificate has an empty subject";
  }
#endif
  // X509_get_version is zero-based: 2 is version 3 (X509_VERSION_3, which OpenSSL 1.1.1 does not define).
  if (X509_get_version(x509) != 2)
  {
    return "the certificate is not version 3";
  }
  const ASN1_INTEGER* serial = X509_get0_serialNumber(x509);
  if (serial == nullptr || ASN1_STRING_length(serial) > 20)
  {
    return "the serialNumber is longer than 20 octets";
  }
  return nullptr;
}

/// One Table 106 fault found while validating a certificate.
struct CertificateValidationFault
{
  int step = table_106::structure;  ///< The Table 106 row.
  int depth = 0;  ///< The chain position: 0 is the certificate under validation.
  UaException error;  ///< The refusal, with its ErrorDetail.
};

/// The name of a chain position, for an ErrorDetail.
const char* chain_position_name(int depth)
{
  return depth == 0 ? "EndEntity" : (depth == 1 ? "IssuingCa" : "HigherCa");
}

bool is_ecdsa_algorithm(AsymmetricSignatureAlgorithm algorithm)
{
  return algorithm == AsymmetricSignatureAlgorithm::EcDsaSha2256 ||
         algorithm == AsymmetricSignatureAlgorithm::EcDsaSha2384 ||
         algorithm == AsymmetricSignatureAlgorithm::EcDsaSha2512;
}

struct EcdsaSigDeleterLocal
{
  void operator()(ECDSA_SIG* p) const
  {
    ECDSA_SIG_free(p);
  }
};

using LocalEcdsaSigPtr = unique_ptr<ECDSA_SIG, EcdsaSigDeleterLocal>;

// Convert ECDSA DER-encoded signature to IEEE P1363 fixed-size format (r || s).
ByteString ecdsa_der_to_p1363(span<const byte> derSignature, size_t componentSize)
{
  const auto* derData = reinterpret_cast<const unsigned char*>(derSignature.data());
  const LocalEcdsaSigPtr ecdsaSig{d2i_ECDSA_SIG(nullptr, &derData, numeric_cast<long>(derSignature.size()))};
  if (!ecdsaSig)
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("SignatureConversionFailed", "d2i_ECDSA_SIG() failed", "OpenSslCrypto"));
  }

  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(ecdsaSig.get(), &r, &s);

  ByteString p1363;
  p1363.resize(componentSize * 2);
  // Every OpenSSL return is checked (CRY-11): a component wider than the curve's size fails to pad.
  if (r == nullptr || s == nullptr ||
      BN_bn2binpad(r, reinterpret_cast<unsigned char*>(p1363.data()), numeric_cast<int>(componentSize)) < 0 ||
      BN_bn2binpad(s,
        reinterpret_cast<unsigned char*>(p1363.data()) + componentSize,
        numeric_cast<int>(componentSize)) < 0)
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("SignatureConversionFailed", "BN_bn2binpad() failed", "OpenSslCrypto"));
  }

  return p1363;
}

// Convert IEEE P1363 fixed-size ECDSA signature (r || s) to DER format.
ByteString ecdsa_p1363_to_der(span<const byte> p1363Signature, size_t componentSize)
{
  if (p1363Signature.size() != componentSize * 2)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "SignatureConversionFailed", "P1363 signature size does not match expected size", "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(p1363Signature.size()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(componentSize * 2)));
  }

  BIGNUM* r = BN_bin2bn(
    reinterpret_cast<const unsigned char*>(p1363Signature.data()), numeric_cast<int>(componentSize), nullptr);
  BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(p1363Signature.data()) + componentSize,
    numeric_cast<int>(componentSize),
    nullptr);

  // Every OpenSSL return is checked (CRY-11); the BIGNUMs are owned here until set0 has taken them.
  const LocalEcdsaSigPtr ecdsaSig{ECDSA_SIG_new()};
  if (r == nullptr || s == nullptr || !ecdsaSig || ECDSA_SIG_set0(ecdsaSig.get(), r, s) != 1)
  {
    BN_free(r);
    BN_free(s);
    throw UaException(Status::BadInternalError,
      make_error_detail("SignatureConversionFailed", "ECDSA_SIG construction failed", "OpenSslCrypto"));
  }

  const int derLen = i2d_ECDSA_SIG(ecdsaSig.get(), nullptr);
  if (derLen <= 0)
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("SignatureConversionFailed", "i2d_ECDSA_SIG() sizing failed", "OpenSslCrypto"));
  }
  ByteString der;
  der.resize(numeric_cast<size_t>(derLen));
  auto* derOut = reinterpret_cast<unsigned char*>(der.data());
  if (i2d_ECDSA_SIG(ecdsaSig.get(), &derOut) != derLen)
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("SignatureConversionFailed", "i2d_ECDSA_SIG() failed", "OpenSslCrypto"));
  }

  return der;
}

void populate_name_field(string_view value, int nid, X509_NAME& name)
{
  if (!value.empty() && X509_NAME_add_entry_by_NID(&name,
                          nid,
                          MBSTRING_UTF8,
                          utils::chars_to_unsigned_chars(value.data()),
                          numeric_cast<int>(value.size()),
                          -1,
                          0) != 1)
  {
    // OpenSSL refuses a value outside the attribute's RFC 5280 bounds (for example a commonName longer
    // than 64 characters). Refused here rather than issuing a certificate without that attribute, which
    // would leave the subject empty.
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateNameFieldInvalid", "A certificate name attribute is outside its bounds", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::fieldName, std::string{OBJ_nid2sn(nid)})
        .context(ua::ContextKeys::actual, value.size()));
  }
}

void populate_name(const CryptoOpenSsl::Name& parameters, X509_NAME& name)
{
  populate_name_field(parameters.commonName, NID_commonName, name);
  populate_name_field(parameters.organization, NID_organizationName, name);
  populate_name_field(parameters.organizationUnit, NID_organizationalUnitName, name);
  populate_name_field(parameters.distinguishedName, NID_distinguishedName, name);
  populate_name_field(parameters.locality, NID_localityName, name);
  populate_name_field(parameters.state, NID_stateOrProvinceName, name);
  populate_name_field(parameters.country, NID_countryName, name);
}

struct Certs
{
  X509& subject;
  X509& issuer;

  Certs(X509& subjectCert, X509& issuerCert) : subject(subjectCert), issuer(issuerCert)
  {}
};

void add_extension(Certs certs, int nid, std::string value)
{
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);

  X509V3_set_ctx(&ctx, &certs.issuer, &certs.subject, NULL, NULL, 0);

  X509_EXTENSION* ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value.c_str());
  if (!ex)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "CertificateError", "Could not create X509 extension for certificate", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
  }

  const int result = X509_add_ext(&certs.subject, ex, -1);
  X509_EXTENSION_free(ex);

  if (result != 1)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("CertificateError", "Could not add X509 extension to certificate", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
  }
}

/// Collects the extensions destined for one CSR so they are attached in a SINGLE
/// `X509_REQ_add_extensions` call.
///
/// That function does not append to an extension list: it adds the whole list as the CSR's `extReq`
/// ATTRIBUTE. Calling it once per extension therefore asks the request to carry several extReq
/// attributes, and OpenSSL 3 rejects the second with
/// `error:0580008C:x509 certificate routines::duplicate attribute` - so a CSR needing more than one
/// extension could not be produced at all. Every SDK CSR needs at least two (keyUsage and
/// subjectAltName), which is why CreateSigningRequest failed outright.
///
/// The stack is owned here, so the throwing paths no longer leak it either - the previous code
/// allocated the stack before the extension it might throw on.
class CsrExtensions
{
public:
  explicit CsrExtensions(X509_REQ& csr) : mCsr(&csr), mStack(sk_X509_EXTENSION_new_null())
  {
    if (!mStack)
    {
      throw UaException(Status::BadOutOfMemory,
        make_error_detail("CertificateError", "Could not allocate the CSR extension list", "OpenSslCrypto"));
    }
  }

  ~CsrExtensions()
  {
    if (mStack)
      sk_X509_EXTENSION_pop_free(mStack, X509_EXTENSION_free);
  }

  CsrExtensions(const CsrExtensions&) = delete;
  CsrExtensions& operator=(const CsrExtensions&) = delete;
  CsrExtensions(CsrExtensions&&) = delete;
  CsrExtensions& operator=(CsrExtensions&&) = delete;

  void push(int nid, const std::string& value)
  {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, mCsr, NULL, 0);

    X509_EXTENSION* extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value.c_str());
    if (!extension)
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("CertificateError", "Could not create X509 extension for CSR", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
    }
    if (sk_X509_EXTENSION_push(mStack, extension) == 0)
    {
      X509_EXTENSION_free(extension);
      throw UaException(Status::BadOutOfMemory,
        ErrorDetail::build("CertificateError", "Could not collect the CSR extension", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
    }
  }

  /// Attaches everything collected so far. A CSR with no extensions is left alone: an empty extReq
  /// attribute is not the same as its absence.
  void attach()
  {
    if (sk_X509_EXTENSION_num(mStack) == 0)
      return;
    if (!is_openssl_result_good(X509_REQ_add_extensions(mCsr, mStack)))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("CertificateError", "Could not add extensions to CSR", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors()));
    }
  }

private:
  X509_REQ* mCsr;
  STACK_OF(X509_EXTENSION) * mStack;
};

/// Routes an extension destined for a CSR into the accumulator rather than attaching it immediately.
void add_extension(CsrExtensions& extensions, int nid, std::string value)
{
  extensions.push(nid, value);
}

void add_extension(X509_CRL& crl, X509& issuer, int nid, std::string value)
{
  X509V3_CTX context;
  X509V3_set_ctx_nodb(&context);
  X509V3_set_ctx(&context, &issuer, nullptr, nullptr, &crl, 0);

  X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value.c_str());
  if (extension == nullptr)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("CrlExtensionCreationFailed",
        "Could not create X509 extension for certificate revocation list",
        "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
  }

  const int result = X509_CRL_add_ext(&crl, extension, -1);
  X509_EXTENSION_free(extension);
  if (result != 1)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("CrlExtensionAddFailed",
        "Could not add X509 extension to certificate revocation list",
        "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoNid, std::to_string(nid)));
  }
}

int signature_algorithm_priority(const X509& certificate) noexcept
{
  const int signatureNid = X509_get_signature_nid(&certificate);
  int digestNid = NID_undef;
  int publicKeyNid = NID_undef;
  if (OBJ_find_sigid_algs(signatureNid, &digestNid, &publicKeyNid) == 1)
  {
    switch (digestNid)
    {
    case NID_sha1:
      return 1;
    case NID_sha224:
      return 2;
    case NID_sha256:
      return 3;
    case NID_sha384:
      return 4;
    case NID_sha512:
      return 5;
    default:
      break;
    }
  }

  switch (signatureNid)
  {
  case NID_ED25519:
    return 3;
  case NID_ED448:
    return 5;
  default:
    return 0;
  }
}

void validate_chain_monotonicity(X509_STORE_CTX& storeContext)
{
  const STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(&storeContext);
  const int chainSize = chain == nullptr ? 0 : sk_X509_num(chain);
  for (int issuedIndex = 0; issuedIndex + 1 < chainSize; ++issuedIndex)
  {
    const X509* issued = sk_X509_value(chain, issuedIndex);
    const X509* issuer = sk_X509_value(chain, issuedIndex + 1);
    if (issued == nullptr || issuer == nullptr)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build("CertificateChainEntryMissing",
          "OpenSSL returned an incomplete verified certificate chain",
          "CertificateValidation")
          .context(ua::ContextKeys::chainDepth, std::to_string(issuedIndex))};
    }

    // Key lengths by the profile-database convention (X509Certificate::public_key_bit_length: Ed25519 256,
    // Ed448 456), the same measure the Security Policy Check uses, not OpenSSL's EVP_PKEY_bits.
    const auto keyBits = [](const X509* certificate) -> int
    {
      if (X509_get0_pubkey(certificate) == nullptr)
      {
        return 0;
      }
      // The wrapper owns one reference (its destructor frees it); take one for it.
      auto* owned = const_cast<X509*>(certificate);
      if (X509_up_ref(owned) != 1)
      {
        return 0;
      }
      const X509CertificateOpenSsl wrapper{*owned};
      return static_cast<int>(wrapper.public_key_bit_length());
    };
    const int issuedKeyBits = keyBits(issued);
    const int issuerKeyBits = keyBits(issuer);
    if (issuedKeyBits <= 0 || issuerKeyBits <= 0)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build("CertificateChainKeyLengthUnavailable",
          "A verified certificate chain entry has no measurable public key",
          "CertificateValidation")
          .context(ua::ContextKeys::chainDepth, std::to_string(issuedIndex))
          .context(ua::ContextKeys::actual, std::to_string(issuedKeyBits))
          .context(ua::ContextKeys::expected, std::to_string(issuerKeyBits))};
    }
    if (issuedKeyBits > issuerKeyBits)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build("CertificateChainKeyLengthIncreases",
          "An issued certificate has a longer key than its issuer",
          "CertificateValidation")
          .context(ua::ContextKeys::chainDepth, std::to_string(issuedIndex))
          .context(ua::ContextKeys::actual, std::to_string(issuedKeyBits))
          .context(ua::ContextKeys::expected, std::to_string(issuerKeyBits))};
    }

    const int issuedPriority = signature_algorithm_priority(*issued);
    const int issuerPriority = signature_algorithm_priority(*issuer);
    if (issuedPriority > 0 && issuerPriority > 0 && issuedPriority > issuerPriority)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build("CertificateChainSignatureStrengthIncreases",
          "A certificate uses a higher-priority signature algorithm than its issuer",
          "CertificateValidation")
          .context(ua::ContextKeys::chainDepth, std::to_string(issuedIndex))
          .context(ua::ContextKeys::actual, std::to_string(X509_get_signature_nid(issued)))
          .context(ua::ContextKeys::expected, std::to_string(X509_get_signature_nid(issuer)))};
    }
  }
}

void add_key_usage_extension(auto& target, const CryptoOpenSsl::KeyUsage& keyUsage)
{
  if (keyUsage.digitalSignature || keyUsage.nonRepudiation || keyUsage.keyEncipherment ||
      keyUsage.dataEncipherment || keyUsage.keyAgreement || keyUsage.keyCertSign || keyUsage.crlSign ||
      keyUsage.encipherOnly || keyUsage.decipherOnly)
  {
    std::string value = "";

    if (keyUsage.digitalSignature)
    {
      value += "digitalSignature";
    }
    if (keyUsage.nonRepudiation)
    {
      if (!value.empty())
        value += ", ";
      value += "nonRepudiation";
    }
    if (keyUsage.keyEncipherment)
    {
      if (!value.empty())
        value += ", ";
      value += "keyEncipherment";
    }
    if (keyUsage.dataEncipherment)
    {
      if (!value.empty())
        value += ", ";
      value += "dataEncipherment";
    }
    if (keyUsage.keyAgreement)
    {
      if (!value.empty())
        value += ", ";
      value += "keyAgreement";
    }
    if (keyUsage.keyCertSign)
    {
      if (!value.empty())
        value += ", ";
      value += "keyCertSign";
    }
    if (keyUsage.crlSign)
    {
      if (!value.empty())
        value += ", ";
      value += "cRLSign";
    }
    if (keyUsage.encipherOnly)
    {
      if (!value.empty())
        value += ", ";
      value += "encipherOnly";
    }
    if (keyUsage.decipherOnly)
    {
      if (!value.empty())
        value += ", ";
      value += "decipherOnly";
    }

    add_extension(target, NID_key_usage, "critical, " + value);
  }

  if (keyUsage.clientAuth || keyUsage.serverAuth)
  {
    std::string value = "";

    if (keyUsage.clientAuth)
    {
      value += "clientAuth";
    }
    if (keyUsage.serverAuth)
    {
      if (!value.empty())
        value += ", ";
      value += "serverAuth";
    }

    add_extension(target, NID_ext_key_usage, "critical, " + value);
  }
}

void add_basic_constraints(auto& target, CryptoOpenSsl::BasicConstraints basicConstraints)
{
  if (basicConstraints.cA.has_value())
  {
    std::string value = "";

    if (basicConstraints.cA.value())
    {
      value += "CA:TRUE";
    }
    else
    {
      value += "CA:FALSE";
    }
    if (basicConstraints.pathLength.has_value())
    {
      value += fmt::format(", pathlen:{}", basicConstraints.pathLength.value());
    }

    add_extension(target, NID_basic_constraints, "critical, " + value);
  }
}

void add_subject_alternate_name(auto& target, CryptoOpenSsl::SubjectAlternateName subjectAlternateName)
{
  std::string value;

  for (auto& uri : subjectAlternateName.uris)
  {
    value += fmt::format("URI:{}, ", uri);
  }

  for (auto& hostname : subjectAlternateName.hostnames)
  {
    value += fmt::format("DNS:{}, ", hostname);
  }

  for (auto& ip : subjectAlternateName.ipAddresses)
  {
    value += fmt::format("IP:{}, ", ip.to_string());
  }

  if (!value.empty())
  {
    value.pop_back();
    value.pop_back();

    add_extension(target, NID_subject_alt_name, value);
  }
}

struct MdCtxDeleter
{
  void operator()(EVP_MD_CTX* p) const
  {
    EVP_MD_CTX_free(p);
  }
};

using UniquePtrToMdCtx = unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

struct EvpCipherCtxDeleter
{
  void operator()(EVP_CIPHER_CTX* p) const
  {
    EVP_CIPHER_CTX_free(p);
  }
};

using UniquePtrToEvpCipherCtx = unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
struct EcKeyDeleter
{
  void operator()(EC_KEY* p) const
  {
    EC_KEY_free(p);
  }
};

using UniquePtrToEcKey = unique_ptr<EC_KEY, EcKeyDeleter>;

#endif

struct EvpKeyDeleter
{
  void operator()(EVP_PKEY* p) const
  {
    EVP_PKEY_free(p);
  }
};

using UniquePtrToEvpKey = unique_ptr<EVP_PKEY, EvpKeyDeleter>;

struct EvpKeyCtxDeleter
{
  void operator()(EVP_PKEY_CTX* p) const
  {
    EVP_PKEY_CTX_free(p);
  }
};

using UniquePtrToEvpKeyCtx = unique_ptr<EVP_PKEY_CTX, EvpKeyCtxDeleter>;

struct EvpMdCtxDeleter
{
  void operator()(EVP_MD_CTX* p) const
  {
    EVP_MD_CTX_free(p);
  }
};

using UniquePtrToEvpMdCtx = unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

struct BioDeleter
{
  void operator()(BIO* p) const
  {
    BIO_free(p);
  }
};

using UniquePtrToBio = unique_ptr<BIO, BioDeleter>;

struct CertDeleter
{
  void operator()(X509* p) const
  {
    X509_free(p);
  }
};

using UniquePtrToCert = unique_ptr<X509, CertDeleter>;

struct CsrDeleter
{
  void operator()(X509_REQ* p) const
  {
    X509_REQ_free(p);
  }
};

using UniquePtrToCsr = unique_ptr<X509_REQ, CsrDeleter>;

struct BigNumDeleter
{
  void operator()(BIGNUM* p) const
  {
    BN_free(p);
  }
};

using UniquePtrToBigNum = unique_ptr<BIGNUM, BigNumDeleter>;

struct X509StoreDeleter
{
  void operator()(X509_STORE* p) const
  {
    X509_STORE_free(p);
  }
};

using UniquePtrToX509Store = unique_ptr<X509_STORE, X509StoreDeleter>;

struct X509StoreCtxDeleter
{
  void operator()(X509_STORE_CTX* p) const
  {
    X509_STORE_CTX_free(p);
  }
};

using UniquePtrToX509StoreCtx = unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

struct StackOfX509Deleter
{
  void operator()(STACK_OF(X509) * p) const
  {
    sk_X509_free(p);
  }
};

using UniquePtrToStackOfX509 = unique_ptr<STACK_OF(X509), StackOfX509Deleter>;

struct Asn1TimeDeleter
{
  void operator()(ASN1_TIME* p) const
  {
    ASN1_TIME_free(p);
  }
};

using UniquePtrToAsn1Time = unique_ptr<ASN1_TIME, Asn1TimeDeleter>;

struct Asn1IntegerDeleter
{
  void operator()(ASN1_INTEGER* p) const
  {
    ASN1_INTEGER_free(p);
  }
};

using UniquePtrToAsn1Integer = unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter>;

struct X509CrlDeleter
{
  void operator()(X509_CRL* p) const
  {
    X509_CRL_free(p);
  }
};

using UniquePtrToX509Crl = unique_ptr<X509_CRL, X509CrlDeleter>;

struct OpenSslFreeDeleter
{
  void operator()(void* p) const
  {
    OPENSSL_free(p);
  }
};

using UniquePtrToOpenSslBuf = unique_ptr<unsigned char, OpenSslFreeDeleter>;
using UniquePtrToOpenSslCharBuf = unique_ptr<char, OpenSslFreeDeleter>;

class BnContextOwner
{
private:
  BN_CTX& mCtx;
  bool mStarted;

public:
  explicit BnContextOwner(BN_CTX& ctx, bool start = false) : mCtx(ctx), mStarted(start)
  {
    if (mStarted)
    {
      BN_CTX_start(&mCtx);
    }
  }

  ~BnContextOwner()
  {
    if (mStarted)
    {
      BN_CTX_end(&mCtx);
    }
    BN_CTX_free(&mCtx);
  }

  // Owns mCtx (freed in the destructor) via a reference; a synthesized copy/move would
  // double-free / double-end it. This is an in-place stack guard, never copied or moved.
  BnContextOwner(const BnContextOwner&) = delete;
  BnContextOwner& operator=(const BnContextOwner&) = delete;
  BnContextOwner(BnContextOwner&&) = delete;
  BnContextOwner& operator=(BnContextOwner&&) = delete;
};

class AsymmetricKeyPairOpenSsl : public AsymmetricKeyPair
{
public:
  AsymmetricKeyPairOpenSsl(CertificateKeyAlgorithm algorithm,
    CryptoOpenSsl::PrivateKeyCredentialCallback privateKeyCredentialCallback, const EVP_PKEY& evpKey);

  AsymmetricKeyPairOpenSsl(CertificateKeyAlgorithm algorithm,
    CryptoOpenSsl::PrivateKeyCredentialCallback privateKeyCredentialCallback, span<const byte> privateKeyPem);

  /// Public-key-only constructor. The private key will be empty; calling private_key_pem()
  /// returns an empty ByteString and private_key_evp() will return an empty unique_ptr.
  AsymmetricKeyPairOpenSsl(CertificateKeyAlgorithm algorithm, span<const byte> publicKeyDer);

  CertificateKeyAlgorithm algorithm() const override;

  ByteString public_key_der() const override;

  ByteString private_key_pem() const override;

  UniquePtrToEvpKey public_key_evp() const;

  UniquePtrToEvpKey private_key_evp() const;

private:
  const CertificateKeyAlgorithm mAlgorithm;
  const CryptoOpenSsl::PrivateKeyCredentialCallback mPrivateKeyCredentialCallback;
  ByteString mPublicKeyDer;
  ByteString mPrivateKeyPem;

  void public_key_from_evp_key(const EVP_PKEY& evpKey);
  void private_key_from_evp_key(const EVP_PKEY& evpKey);
};

CertificateKeyAlgorithm AsymmetricKeyPairOpenSsl::algorithm() const
{
  return mAlgorithm;
}

ByteString AsymmetricKeyPairOpenSsl::public_key_der() const
{
  return mPublicKeyDer;
}

ByteString AsymmetricKeyPairOpenSsl::private_key_pem() const
{
  return mPrivateKeyPem;
}

UniquePtrToEvpKey AsymmetricKeyPairOpenSsl::public_key_evp() const
{
  UniquePtrToEvpKey evpKey;

  if (!mPublicKeyDer.empty())
  {
    const auto* in = mPublicKeyDer.data();
    auto* key = d2i_PUBKEY(NULL, &in, numeric_cast<int>(mPublicKeyDer.size()));
    if (key)
    {
      evpKey.reset(key);
    }
    else
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build(
          "OpenSslError", "d2i_PUBKEY() failed: could not decode DER public key", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::sizeActual, std::to_string(mPublicKeyDer.size())));
    }
  }

  return evpKey;
}

UniquePtrToEvpKey AsymmetricKeyPairOpenSsl::private_key_evp() const
{
  UniquePtrToEvpKey evpKey;

  if (!mPrivateKeyPem.empty())
  {
    const UniquePtrToBio bio{BIO_new(BIO_s_mem())};
    BIO_write(bio.get(), mPrivateKeyPem.data(), numeric_cast<int>(mPrivateKeyPem.size()));

    if (!mPrivateKeyCredentialCallback)
    {
      throw UaException(Status::BadInternalError,
        make_error_detail("OpenSslError",
          "Private key credential callback is not set; cannot decrypt PEM private key",
          "OpenSslCrypto"));
    }

    // API-D7.2: the passphrase goes to OpenSSL straight from the SecureString, which wipes it on scope exit.
    const SecureString credential = mPrivateKeyCredentialCallback();
    if (credential.empty())
    {
      throw UaException(Status::BadInternalError,
        make_error_detail("OpenSslError",
          "Private key credential is empty; cannot decrypt PEM private key",
          "OpenSslCrypto"));
    }

    auto* key = PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, const_cast<char*>(credential.c_str()));
    if (key)
    {
      evpKey.reset(key);
    }
    else
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build(
          "OpenSslError", "PEM_read_bio_PrivateKey() failed: could not read PEM private key", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::sizeActual, std::to_string(mPrivateKeyPem.size())));
    }
  }

  return evpKey;
}

void AsymmetricKeyPairOpenSsl::public_key_from_evp_key(const EVP_PKEY& evpKey)
{
  ByteString publicKey;

  // OpenSSL 1.1.x takes a non-const EVP_PKEY* here; 3.x made it const. const_cast bridges both.
  int length = i2d_PUBKEY(const_cast<EVP_PKEY*>(&evpKey), 0);
  if (length > 0)
  {
    // length > 0 proven by the enclosing if-branch guard above.
    publicKey.resize(static_cast<size_t>(length));

    uint8_t* pp = publicKey.data();
    length = i2d_PUBKEY(const_cast<EVP_PKEY*>(&evpKey), &pp);
    if (length != numeric_cast<int>(publicKey.size()))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build(
          "OpenSslError", "i2d_PUBKEY() failed: second call returned unexpected byte count", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeExpected, std::to_string(numeric_cast<int>(publicKey.size()))));
    }

    mPublicKeyDer = std::move(publicKey);
  }
}

void AsymmetricKeyPairOpenSsl::private_key_from_evp_key(const EVP_PKEY& evpKey)
{
  if (!mPrivateKeyCredentialCallback)
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("OpenSslError",
        "Private key credential callback is not set; cannot encrypt PEM private key",
        "OpenSslCrypto"));
  }

  // API-D7.2: the passphrase goes to OpenSSL straight from the SecureString, which wipes it on scope exit.
  const SecureString credential = mPrivateKeyCredentialCallback();
  if (credential.empty())
  {
    throw UaException(Status::BadInternalError,
      make_error_detail(
        "OpenSslError", "Private key credential is empty; cannot encrypt PEM private key", "OpenSslCrypto"));
  }

  const UniquePtrToBio bio{BIO_new(BIO_s_mem())};

  if (is_openssl_result_good(PEM_write_bio_PrivateKey(bio.get(),
        const_cast<EVP_PKEY*>(&evpKey),
        EVP_aes_256_cbc(),
        NULL,
        0,
        NULL,
        const_cast<char*>(credential.c_str()))))
  {
    unsigned char* pp{nullptr};
    // BIO_get_mem_data() returns the (non-negative) number of bytes buffered in the
    // memory BIO; range-check the long->size_t narrowing defensively.
    const size_t length = numeric_cast<size_t>(BIO_get_mem_data(bio.get(), &pp));

    ByteString result;
    result.resize(length);
    auto lengthRead = BIO_read(bio.get(), result.data(), numeric_cast<int>(result.size()));
    if (lengthRead != numeric_cast<int>(length))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build(
          "OpenSslError", "BIO_read() failed: read fewer bytes than expected", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::sizeActual, std::to_string(lengthRead))
          .context(ua::ContextKeys::sizeExpected, std::to_string(length)));
    }
    mPrivateKeyPem = std::move(result);
  }
}

AsymmetricKeyPairOpenSsl::AsymmetricKeyPairOpenSsl(CertificateKeyAlgorithm algorithm,
  CryptoOpenSsl::PrivateKeyCredentialCallback privateKeyCredentialCallback, const EVP_PKEY& evpKey)
  : mAlgorithm(algorithm), mPrivateKeyCredentialCallback(std::move(privateKeyCredentialCallback))
{
  public_key_from_evp_key(evpKey);
  private_key_from_evp_key(evpKey);
}

AsymmetricKeyPairOpenSsl::AsymmetricKeyPairOpenSsl(CertificateKeyAlgorithm algorithm,
  CryptoOpenSsl::PrivateKeyCredentialCallback privateKeyCredentialCallback, span<const byte> privateKeyPem)
  : mAlgorithm(algorithm), mPrivateKeyCredentialCallback(std::move(privateKeyCredentialCallback))
{
  mPrivateKeyPem = ByteString{privateKeyPem};
}

AsymmetricKeyPairOpenSsl::AsymmetricKeyPairOpenSsl(
  CertificateKeyAlgorithm algorithm, span<const byte> publicKeyDer)
  : mAlgorithm(algorithm)
{
  mPublicKeyDer = ByteString{publicKeyDer};
  // Validate that the DER is parseable
  const auto* in = mPublicKeyDer.data();
  const UniquePtrToEvpKey key{d2i_PUBKEY(NULL, &in, numeric_cast<int>(mPublicKeyDer.size()))};
  if (!key)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "OpenSslError", "d2i_PUBKEY() failed: could not decode DER public key", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(mPublicKeyDer.size())));
  }
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int ec_key_size_bytes_from_group_name(string_view groupName)
{
  // groupName is typically a short name like "prime256v1" or "brainpoolP256r1".
  int nid = OBJ_txt2nid(std::string(groupName).c_str());
  if (nid == NID_undef)
  {
    nid = OBJ_sn2nid(std::string(groupName).c_str());
  }
  if (nid == NID_undef)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError", "Could not convert EC group name to NID", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }

  EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
  if (!group)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError", "EC_GROUP_new_by_curve_name() failed for group", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }

  const int degree = EC_GROUP_get_degree(group);
  EC_GROUP_free(group);
  if (degree <= 0)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "OpenSslError", "EC_GROUP_get_degree() returned non-positive degree", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName))
        .context(ua::ContextKeys::cryptoCurveDegree, std::to_string(degree)));
  }
  return (degree + 7) / 8;
}

std::string ec_group_name_from_key(const EVP_PKEY& key)
{
  size_t len = 0;
  if (EVP_PKEY_get_utf8_string_param(&key, OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &len) != 1 || len == 0)
  {
    // Some provider configurations may not expose the group name via params.
    return {};
  }

  // OpenSSL reports length including terminating NUL.
  std::string groupName;
  groupName.resize(len);
  if (EVP_PKEY_get_utf8_string_param(
        &key, OSSL_PKEY_PARAM_GROUP_NAME, groupName.data(), groupName.size(), &len) != 1)
  {
    return {};
  }

  if (!groupName.empty() && groupName.back() == '\0')
  {
    groupName.pop_back();
  }
  return groupName;
}

std::string ec_group_name_from_curve_nid(int curveNid)
{
  const char* sn = OBJ_nid2sn(curveNid);
  if (!sn)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError", "OBJ_nid2sn() failed for curve NID", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoNid, std::to_string(curveNid)));
  }
  return std::string{sn};
}

std::vector<unsigned char> ec_public_key_uncompressed(const EVP_PKEY& key)
{
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len) != 1 || len == 0)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("OpenSslError",
        "EVP_PKEY_get_octet_string_param() failed: could not query EC public key length",
        "OpenSslCrypto"));
  }

  std::vector<unsigned char> pub;
  pub.resize(len);
  if (EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size(), &len) != 1)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError",
        "EVP_PKEY_get_octet_string_param() failed: could not read EC public key",
        "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(len)));
  }
  pub.resize(len);
  return pub;
}

UniquePtrToEvpKey ec_peer_public_key_from_xy(string_view groupName, span<const std::byte> xAndY)
{
  if (groupName.empty())
  {
    throw UaException(Status::BadInternalError,
      make_error_detail("OpenSslError",
        "EC group name is empty; cannot reconstruct peer public key from X/Y coordinates",
        "OpenSslCrypto"));
  }
  const int keySize = ec_key_size_bytes_from_group_name(groupName);
  if (xAndY.size_bytes() != numeric_cast<size_t>(2 * keySize))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidKeySize", "Remote EC public key size is unexpected", "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(xAndY.size_bytes()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(2 * keySize))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(keySize))
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }

  std::vector<unsigned char> pub;
  pub.resize(numeric_cast<size_t>(1 + 2 * keySize));
  pub[0] = 0x04;  // uncompressed
  memcpy(pub.data() + 1, utils::bytes_to_unsigned_chars(xAndY.data()), xAndY.size_bytes());

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError", "EVP_PKEY_CTX_new_from_name failed for EC key", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }
  const UniquePtrToEvpKeyCtx ctxOwner(ctx);

  if (EVP_PKEY_fromdata_init(ctx) != 1)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("OpenSslError", "EVP_PKEY_fromdata_init() failed for EC key", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }

  // OSSL_PARAM_construct_utf8_string requires a mutable char*.
  std::string groupNameMutable{groupName};
  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(
                           OSSL_PKEY_PARAM_GROUP_NAME, groupNameMutable.data(), groupNameMutable.size()),
    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()),
    OSSL_PARAM_construct_end()};

  EVP_PKEY* peer = nullptr;
  if (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params) != 1 || !peer)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "OpenSslError", "EVP_PKEY_fromdata() failed: could not construct EC peer public key", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoCurve, std::string(groupName)));
  }
  return UniquePtrToEvpKey{peer};
}
#endif

}  // namespace

namespace ua
{

CryptoOpenSsl::CryptoOpenSsl() : CryptoOpenSsl([] { return SecureString{""}; })
{}

CryptoOpenSsl::CryptoOpenSsl(const PrivateKeyCredentialCallback privateKeyCredentialCallback)
  : mPrivateKeyCredentialCallback(privateKeyCredentialCallback)
{
  const int result = RAND_status();
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("OpenSslError", "OpenSSL PRNG is not properly seeded", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoRandStatus, std::to_string(result)));
  }
}

ByteString CryptoOpenSsl::calculate_hmac(
  HashAlgorithm algorithm, span<const byte> key, span<const byte> data) const
{
  if (key.empty() || data.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "HMAC input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoDataSize, std::to_string(data.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  switch (algorithm)
  {
  case HashAlgorithm::Sha1:
    digest = EVP_sha1();
    break;

  case HashAlgorithm::Sha2256:
    digest = EVP_sha256();
    break;

  case HashAlgorithm::Sha2384:
    digest = EVP_sha384();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "Unsupported hash algorithm for HMAC", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  ByteString hash;
  // EVP_MD_size() returns the positive digest size for a valid EVP_MD selected above.
  hash.resize(numeric_cast<size_t>(EVP_MD_size(digest)));

  unsigned int hashLength = 0;
  const unsigned char* result = HMAC(digest,
    key.data(),
    numeric_cast<int>(key.size_bytes()),
    utils::bytes_to_unsigned_chars(data.data()),
    data.size_bytes(),
    hash.data(),
    &hashLength);

  if (!result || (hashLength != hash.size()))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("HashFailed", "HMAC() produced unexpected output length", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeExpected, std::to_string(hash.size()))
        .context(ua::ContextKeys::sizeActual, std::to_string(hashLength)));
  }
  return hash;
}

ByteString CryptoOpenSsl::calculate_psha(
  HashAlgorithm algorithm, span<const byte> secret, span<const byte> seed, size_t noOfBytes) const
{
  if (secret.empty() || seed.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "P-SHA input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoSecretSize, std::to_string(secret.size_bytes()))
        .context(ua::ContextKeys::cryptoSeedSize, std::to_string(seed.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  switch (algorithm)
  {
  case HashAlgorithm::Sha1:
    digest = EVP_sha1();
    break;

  case HashAlgorithm::Sha2256:
    digest = EVP_sha256();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "Unsupported hash algorithm for P-SHA", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  // A(0) = seed
  // A(n) = HMAC_SHAx(secret, A(n-1))
  const size_t hashSize = numeric_cast<size_t>(EVP_MD_size(digest));
  size_t iterations = (noOfBytes / hashSize);
  if (noOfBytes % hashSize)
  {
    iterations++;
  }

  std::vector<std::byte> seedBuffer;
  seedBuffer.resize(hashSize + seed.size_bytes());

  std::vector<std::byte> a;
  a.resize(hashSize);

  // Calculate A(1)
  const unsigned char* result = HMAC(digest,
    secret.data(),
    numeric_cast<int>(secret.size_bytes()),
    utils::bytes_to_unsigned_chars(seed.data()),
    seed.size_bytes(),
    utils::bytes_to_unsigned_chars(a.data()),
    0);

  if (!result)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "DeriveKeyFailed", "HMAC() failed computing A(1) in P-SHA derivation", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeBlock, std::to_string(hashSize))
        .context(ua::ContextKeys::length, std::to_string(noOfBytes)));
  }

  std::copy(a.begin(), a.end(), seedBuffer.begin());
  std::copy(seed.begin(), seed.end(), &seedBuffer[hashSize]);

  std::vector<std::byte> hashBuffer;
  hashBuffer.resize(iterations * hashSize);

  for (size_t i = 0; i < iterations; i++)
  {
    // Calculate P_SHAx(n) = HMAC_SHAx(secret, A(n-1) + seed)
    result = HMAC(digest,
      secret.data(),
      numeric_cast<int>(secret.size_bytes()),
      utils::bytes_to_unsigned_chars(seedBuffer.data()),
      hashSize + seed.size_bytes(),
      utils::bytes_to_unsigned_chars(&hashBuffer[i * hashSize]),
      0);

    if (!result)
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("DeriveKeyFailed", "HMAC() failed computing a P-SHA iteration", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::index, std::to_string(i + 1))
          .context(ua::ContextKeys::sizeMax, std::to_string(iterations))
          .context(ua::ContextKeys::sizeBlock, std::to_string(hashSize))
          .context(ua::ContextKeys::length, std::to_string(noOfBytes)));
    }

    // Calculate A(n) = HMAC_SHAx(secret, A(n-1))
    result = HMAC(digest,
      secret.data(),
      numeric_cast<int>(secret.size_bytes()),
      utils::bytes_to_unsigned_chars(seedBuffer.data()),
      hashSize,
      utils::bytes_to_unsigned_chars(seedBuffer.data()),
      0);

    if (!result)
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build(
          "DeriveKeyFailed", "HMAC() failed computing A(n) in P-SHA derivation", "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::index, std::to_string(i + 1))
          .context(ua::ContextKeys::sizeMax, std::to_string(iterations))
          .context(ua::ContextKeys::sizeBlock, std::to_string(hashSize))
          .context(ua::ContextKeys::length, std::to_string(noOfBytes)));
    }
  }

  ByteString psha;
  psha.resize(noOfBytes);
  std::copy(utils::bytes_to_unsigned_chars(hashBuffer.data()),
    utils::bytes_to_unsigned_chars(hashBuffer.data()) + noOfBytes,
    psha.data());
  return psha;
}

ByteString CryptoOpenSsl::calculate_hkdf(HashAlgorithm algorithm, span<const byte> secret,
  span<const byte> salt, span<const byte> info, size_t noOfBytes) const
{
  if (secret.empty() || salt.empty() || info.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "HKDF input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoSecretSize, std::to_string(secret.size_bytes()))
        .context(ua::ContextKeys::cryptoSaltSize, std::to_string(salt.size_bytes()))
        .context(ua::ContextKeys::cryptoInfoSize, std::to_string(info.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  switch (algorithm)
  {
  case HashAlgorithm::Sha1:
    digest = EVP_sha1();
    break;

  case HashAlgorithm::Sha2256:
    digest = EVP_sha256();
    break;

  case HashAlgorithm::Sha2384:
    digest = EVP_sha384();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "Unsupported hash algorithm for HKDF", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF) failed", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx ctxOwner(ctx);

  int result = EVP_PKEY_derive_init(ctx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_derive_init() failed for HKDF context", "OpenSslCrypto"));
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  result = EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
#else
  // OpenSSL 1.1.x spells this macro without the "set_" prefix (same EVP_PKEY_CTRL_HKDF_MODE ctrl).
  result = EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
#endif
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_CTX_hkdf_mode(EXTRACT_AND_EXPAND) failed", "OpenSslCrypto"));
  }

  result = EVP_PKEY_CTX_set_hkdf_md(ctx, digest);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("DeriveKeyFailed", "EVP_PKEY_CTX_set_hkdf_md() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  result = EVP_PKEY_CTX_set1_hkdf_salt(
    ctx, utils::bytes_to_unsigned_chars(salt.data()), numeric_cast<int>(salt.size_bytes()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("DeriveKeyFailed", "EVP_PKEY_CTX_set1_hkdf_salt() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoSaltSize, std::to_string(salt.size_bytes())));
  }

  result = EVP_PKEY_CTX_set1_hkdf_key(
    ctx, utils::bytes_to_unsigned_chars(secret.data()), numeric_cast<int>(secret.size_bytes()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("DeriveKeyFailed", "EVP_PKEY_CTX_set1_hkdf_key() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoSecretSize, std::to_string(secret.size_bytes())));
  }

  result = EVP_PKEY_CTX_add1_hkdf_info(
    ctx, utils::bytes_to_unsigned_chars(info.data()), numeric_cast<int>(info.size_bytes()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("DeriveKeyFailed", "EVP_PKEY_CTX_add1_hkdf_info() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoInfoSize, std::to_string(info.size_bytes())));
  }

  ByteString hkdf;
  hkdf.resize(noOfBytes);
  size_t outputLength = noOfBytes;
  result = EVP_PKEY_derive(ctx, hkdf.data(), &outputLength);
  if (!is_openssl_result_good(result) || (noOfBytes != outputLength))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "DeriveKeyFailed", "EVP_PKEY_derive() failed for HKDF: output length mismatch", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeExpected, std::to_string(noOfBytes))
        .context(ua::ContextKeys::sizeActual, std::to_string(outputLength)));
  }
  return hkdf;
}

ByteString CryptoOpenSsl::get_entropy_sync(size_t numberOfBytes) const
{
  ByteString entropy;

  if (numberOfBytes == 0)
  {
    return entropy;
  }

  entropy.resize(numberOfBytes);

  const int result = RAND_priv_bytes(entropy.data(), numeric_cast<int>(entropy.size()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "NonceGenerationFailed", "RAND_priv_bytes() failed: could not generate entropy", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(numberOfBytes)));
  }
  return entropy;
}

void CryptoOpenSsl::get_entropy_async(
  size_t numberOfBytes, GetEntropyCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return get_entropy_sync(numberOfBytes); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::calculate_digest_sync(HashAlgorithm algorithm, span<const byte> input) const
{
  if (input.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidInputSize", "Digest input buffer is empty", "OpenSslCrypto"));
  }

  const EVP_MD* digest = nullptr;
  switch (algorithm)
  {
  case HashAlgorithm::Sha1:
    digest = EVP_sha1();
    break;

  case HashAlgorithm::Sha2256:
    digest = EVP_sha256();
    break;

  case HashAlgorithm::Sha2384:
    digest = EVP_sha384();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("UnsupportedAlgorithm", "Unsupported hash algorithm for digest", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  ByteString hash;
  // EVP_MD_size() returns the positive digest size for a valid EVP_MD selected above.
  hash.resize(numeric_cast<size_t>(EVP_MD_size(digest)));

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "HashFailed", "EVP_MD_CTX_new() failed for digest computation", "OpenSslCrypto"));
  }
  const UniquePtrToEvpMdCtx ctxOwner(ctx);

  int result = EVP_DigestInit(ctx, digest);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("HashFailed", "EVP_DigestInit() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  result = EVP_DigestUpdate(ctx, input.data(), input.size());
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("HashFailed", "EVP_DigestUpdate() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(input.size())));
  }

  unsigned int hashLength = 0;
  result = EVP_DigestFinal(ctx, hash.data(), &hashLength);
  if (!is_openssl_result_good(result) || (hashLength != hash.size()))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("HashFailed", "EVP_DigestFinal() produced unexpected output length", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeExpected, std::to_string(hash.size()))
        .context(ua::ContextKeys::sizeActual, std::to_string(hashLength)));
  }
  return hash;
}

void CryptoOpenSsl::calculate_digest_async(HashAlgorithm algorithm, ByteString inputBuffer,
  span<const byte> input, CalculateDigestCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result(
      [&]() -> CalculateDigestOutput
      {
        auto digest = calculate_digest_sync(algorithm, input);
        return CalculateDigestOutput{std::move(inputBuffer), std::move(digest)};
      }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm,
  size_t numberOfBytes, span<const byte> secret, span<const byte> seed) const
{
  if (secret.empty() || seed.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidInputSize", "Symmetric key derivation input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoSecretSize, std::to_string(secret.size_bytes()))
        .context(ua::ContextKeys::cryptoSeedSize, std::to_string(seed.size_bytes())));
  }

  HashAlgorithm hashAlgorithm = HashAlgorithm::Invalid;
  switch (algorithm)
  {
  case SymmetricKeyDerivationAlgorithm::PSha1:
    hashAlgorithm = HashAlgorithm::Sha1;
    break;

  case SymmetricKeyDerivationAlgorithm::PSha2256:
    hashAlgorithm = HashAlgorithm::Sha2256;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "UnsupportedAlgorithm", "Unsupported symmetric key derivation algorithm", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  return calculate_psha(hashAlgorithm, secret, seed, numberOfBytes);
}

void CryptoOpenSsl::derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm,
  size_t numberOfBytes, ByteString secret, ByteString seed,
  DeriveSymmetricKeysCompleteCallback callback) const noexcept
{
  const security::ScrubOnExit scrubSecret{secret};  // the caller's copy of a key-derivation secret
  try
  {
    callback(
      detail::to_result([&] { return derive_symmetric_keys_sync(algorithm, numberOfBytes, secret, seed); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm,
  size_t numberOfBytes, span<const byte> secret, span<const byte> salt, span<const byte> info) const
{
  if (secret.empty() || salt.empty() || info.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidInputSize", "HKDF symmetric key derivation input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoSecretSize, std::to_string(secret.size_bytes()))
        .context(ua::ContextKeys::cryptoSaltSize, std::to_string(salt.size_bytes()))
        .context(ua::ContextKeys::cryptoInfoSize, std::to_string(info.size_bytes())));
  }

  HashAlgorithm hashAlgorithm = HashAlgorithm::Invalid;
  switch (algorithm)
  {
  case SymmetricKeyDerivationAlgorithm::HkdfSha2256:
    hashAlgorithm = HashAlgorithm::Sha2256;
    break;

  case SymmetricKeyDerivationAlgorithm::HkdfSha2384:
    hashAlgorithm = HashAlgorithm::Sha2384;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "UnsupportedAlgorithm", "Unsupported HKDF symmetric key derivation algorithm", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  return calculate_hkdf(hashAlgorithm, secret, salt, info, numberOfBytes);
}

void CryptoOpenSsl::derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm,
  size_t numberOfBytes, ByteString secret, ByteString salt, ByteString info,
  DeriveSymmetricKeysCompleteCallback callback) const noexcept
{
  const security::ScrubOnExit scrubSecret{secret};  // the caller's copy of the input keying material
  try
  {
    callback(detail::to_result(
      [&] { return derive_symmetric_keys_sync(algorithm, numberOfBytes, secret, salt, info); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::symmetric_encrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
  span<const byte> key, span<const byte> plainText, span<byte> cipherText) const
{
  if (iv.empty() || key.empty() || plainText.empty() || cipherText.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "Symmetric encrypt input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes())));
  }

  const EVP_CIPHER* cipher = nullptr;
  switch (algorithm)
  {
  case SymmetricEncryptionAlgorithm::Aes128Cbc:
    cipher = EVP_aes_128_cbc();
    break;

  case SymmetricEncryptionAlgorithm::Aes256Cbc:
    cipher = EVP_aes_256_cbc();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("EncryptionFailed", "Unsupported symmetric encryption algorithm", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  if ((numeric_cast<int>(iv.size_bytes()) != EVP_CIPHER_iv_length(cipher)) ||
      (numeric_cast<int>(key.size_bytes()) != EVP_CIPHER_key_length(cipher)))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidKeySize", "IV or key length is invalid for symmetric encryption", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoIvExpected, std::to_string(EVP_CIPHER_iv_length(cipher)))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySizeExpected, std::to_string(EVP_CIPHER_key_length(cipher))));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_CIPHER_CTX_new() failed for symmetric encryption", "OpenSslCrypto"));
  }
  const UniquePtrToEvpCipherCtx ctxOwner(ctx);

  int result = EVP_EncryptInit(
    ctx, cipher, utils::bytes_to_unsigned_chars(key.data()), utils::bytes_to_unsigned_chars(iv.data()));

  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("EncryptionFailed", "EVP_EncryptInit() failed", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes())));
  }

  EVP_CIPHER_CTX_set_padding(ctx, 0);
  if ((0 != (plainText.size_bytes() % numeric_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx)))) ||
      (plainText.size_bytes() != cipherText.size_bytes()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "plainText or cipherText length is invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::sizeBlock, std::to_string(EVP_CIPHER_CTX_block_size(ctx))));
  }

  int outputLength = 0;
  result = EVP_EncryptUpdate(ctx,
    utils::bytes_to_unsigned_chars(cipherText.data()),
    &outputLength,
    utils::bytes_to_unsigned_chars(plainText.data()),
    numeric_cast<int>(plainText.size_bytes()));

  if (!is_openssl_result_good(result) || (outputLength != numeric_cast<int>(plainText.size_bytes())))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "EncryptionFailed", "EVP_EncryptUpdate() produced unexpected output length", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(outputLength))
        .context(ua::ContextKeys::sizeExpected, std::to_string(plainText.size_bytes())));
  }

  result = EVP_EncryptFinal(ctx, 0, &outputLength);
  if (!is_openssl_result_good(result) || (outputLength != 0))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("EncryptionFailed", "EVP_EncryptFinal() produced unexpected output", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(outputLength)));
  }
}

void CryptoOpenSsl::symmetric_encrypt_async(shared_ptr<const void> resource,
  SymmetricEncryptionAlgorithm algorithm, span<const byte> iv, span<const byte> key,
  span<const byte> plainText, span<byte> cipherText, SymmetricEncryptCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(detail::to_result([&] { symmetric_encrypt_sync(algorithm, iv, key, plainText, cipherText); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::symmetric_decrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
  span<const byte> key, span<const byte> cipherText, span<byte> plainText) const
{
  if (iv.empty() || key.empty() || cipherText.empty() || plainText.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInputSize", "Symmetric decrypt input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes())));
  }

  const EVP_CIPHER* cipher = nullptr;
  switch (algorithm)
  {
  case SymmetricEncryptionAlgorithm::Aes128Cbc:
    cipher = EVP_aes_128_cbc();
    break;

  case SymmetricEncryptionAlgorithm::Aes256Cbc:
    cipher = EVP_aes_256_cbc();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("DecryptionFailed", "Unsupported symmetric decryption algorithm", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  if ((numeric_cast<int>(iv.size_bytes()) != EVP_CIPHER_iv_length(cipher)) ||
      (numeric_cast<int>(key.size_bytes()) != EVP_CIPHER_key_length(cipher)) ||
      (plainText.size_bytes() < cipherText.size_bytes()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidKeySize", "Symmetric decrypt buffer length is invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoIvExpected, std::to_string(EVP_CIPHER_iv_length(cipher)))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySizeExpected, std::to_string(EVP_CIPHER_key_length(cipher)))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes())));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DecryptionFailed", "EVP_CIPHER_CTX_new() failed for symmetric decryption", "OpenSslCrypto"));
  }
  const UniquePtrToEvpCipherCtx ctxOwner(ctx);

  int result = EVP_DecryptInit(
    ctx, cipher, utils::bytes_to_unsigned_chars(key.data()), utils::bytes_to_unsigned_chars(iv.data()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DecryptionFailed",
        fmt::format(
          "EVP_DecryptInit() failed (key={} bytes, iv={} bytes)", key.size_bytes(), iv.size_bytes()),
        "OpenSslCrypto"));
  }

  EVP_CIPHER_CTX_set_padding(ctx, 0);
  if (0 != (cipherText.size_bytes() % numeric_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx))))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidInputSize", "cipherText length is not a multiple of block size", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::sizeBlock, std::to_string(EVP_CIPHER_CTX_block_size(ctx))));
  }

  int outputLength = 0;
  result = EVP_DecryptUpdate(ctx,
    utils::bytes_to_unsigned_chars(plainText.data()),
    &outputLength,
    utils::bytes_to_unsigned_chars(cipherText.data()),
    numeric_cast<int>(cipherText.size_bytes()));
  if (!is_openssl_result_good(result) || (numeric_cast<int>(cipherText.size_bytes()) != outputLength))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "DecryptionFailed", "EVP_DecryptUpdate() produced unexpected output length", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(outputLength))
        .context(ua::ContextKeys::sizeExpected, std::to_string(cipherText.size_bytes())));
  }

  result = EVP_DecryptFinal(ctx, 0, &outputLength);
  if (!is_openssl_result_good(result) || (0 != outputLength))
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build("DecryptionFailed", "EVP_DecryptFinal() produced unexpected output", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(outputLength)));
  }
}

void CryptoOpenSsl::symmetric_decrypt_async(shared_ptr<const void> resource,
  SymmetricEncryptionAlgorithm algorithm, span<const byte> iv, span<const byte> key,
  span<const byte> cipherText, span<byte> plainText, SymmetricDecryptCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  check(callback);
  try
  {
    callback(detail::to_result([&] { symmetric_decrypt_sync(algorithm, iv, key, cipherText, plainText); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::symmetric_encrypt_and_sign_sync(SymmetricEncryptionAlgorithm algorithm,
  span<const byte> iv, span<const byte> key, span<const byte> plainText, span<const byte> additionalData,
  span<byte> cipherText) const
{
  // An empty plaintext is valid: AEAD Sign mode authenticates the whole chunk as additional data and
  // encrypts nothing (Part 6 6.7.2.1 Figure 12).
  if (iv.empty() || key.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric AEAD encrypt input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes())));
  }

  const EVP_CIPHER* cipher = aead_cipher(algorithm, "symmetric_encrypt_and_sign_sync");

  if ((numeric_cast<int>(iv.size_bytes()) != EVP_CIPHER_iv_length(cipher)) ||
      (numeric_cast<int>(key.size_bytes()) != EVP_CIPHER_key_length(cipher)) ||
      (cipherText.size_bytes() < plainText.size_bytes()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric AEAD encrypt buffer size invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoIvExpected, std::to_string(EVP_CIPHER_iv_length(cipher)))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySizeExpected, std::to_string(EVP_CIPHER_key_length(cipher)))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes())));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("EncryptionFailed",
        "EVP_CIPHER_CTX_new() failed in symmetric_encrypt_and_sign_sync",
        "OpenSslCrypto"));
  }
  const UniquePtrToEvpCipherCtx ctxOwner(ctx);

  int result = EVP_EncryptInit(ctx, cipher, NULL, NULL);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_EncryptInit() failed in symmetric_encrypt_and_sign_sync", "OpenSslCrypto"));
  }

  result = EVP_EncryptInit(
    ctx, NULL, utils::bytes_to_unsigned_chars(key.data()), utils::bytes_to_unsigned_chars(iv.data()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_EncryptInit() failed in symmetric_encrypt_and_sign_sync", "OpenSslCrypto"));
  }

  int outputLength = 0;
  if (!additionalData.empty())
  {
    result = EVP_EncryptUpdate(ctx,
      NULL,
      &outputLength,
      utils::bytes_to_unsigned_chars(additionalData.data()),
      numeric_cast<int>(additionalData.size_bytes()));
    if (!is_openssl_result_good(result) || (outputLength != numeric_cast<int>(additionalData.size_bytes())))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EncryptionFailed",
          "EVP_EncryptUpdate() AAD failed in symmetric_encrypt_and_sign_sync",
          "OpenSslCrypto"));
    }
  }

  int written = 0;
  if (!plainText.empty())
  {
    result = EVP_EncryptUpdate(ctx,
      utils::bytes_to_unsigned_chars(cipherText.data()),
      &written,
      utils::bytes_to_unsigned_chars(plainText.data()),
      numeric_cast<int>(plainText.size_bytes()));
    if (!is_openssl_result_good(result) || (written != numeric_cast<int>(plainText.size_bytes())))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EncryptionFailed",
          "EVP_EncryptUpdate() failed in symmetric_encrypt_and_sign_sync",
          "OpenSslCrypto"));
    }
  }

  // An AEAD cipher writes nothing at Final; the offset is still the end of what Update wrote.
  outputLength = 0;
  result =
    EVP_EncryptFinal_ex(ctx, utils::bytes_to_unsigned_chars(cipherText.data()) + written, &outputLength);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("EncryptionFailed",
        "EVP_EncryptFinal_ex() failed in symmetric_encrypt_and_sign_sync",
        "OpenSslCrypto"));
  }

  constexpr int tagLength = 16;
  ByteString signature;
  signature.resize(tagLength);

  result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLength, signature.data());
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("EncryptionFailed",
        "EVP_CIPHER_CTX_ctrl() failed in symmetric_encrypt_and_sign_sync",
        "OpenSslCrypto"));
  }
  return signature;
}

void CryptoOpenSsl::symmetric_encrypt_and_sign_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv,
  ByteString key, ByteString plainTextBuffer, span<const byte> plainText, span<const byte> additionalData,
  optional<ByteString> cipherTextBuffer, span<byte> cipherText,
  SymmetricEncryptAndSignCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result(
      [&]() -> SymmetricEncryptAndSignOutput
      {
        auto signature =
          symmetric_encrypt_and_sign_sync(algorithm, iv, key, plainText, additionalData, cipherText);
        return SymmetricEncryptAndSignOutput{
          std::move(plainTextBuffer), std::move(cipherTextBuffer), std::move(signature)};
      }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::symmetric_verify_and_decrypt_sync(SymmetricEncryptionAlgorithm algorithm,
  span<const byte> iv, span<const byte> key, span<const byte> cipherText, span<const byte> additionalData,
  span<const byte> signature, span<byte> plainText) const
{
  // An empty ciphertext is valid: in AEAD Sign mode the tag authenticates additional data only.
  if (iv.empty() || key.empty() || signature.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric AEAD decrypt input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::cryptoSignatureSize, std::to_string(signature.size_bytes())));
  }

  // Poly1305 and GCM tags are 16 bytes; OpenSSL accepts a shorter tag and compares only that many
  // bytes, so the length is pinned here rather than taken from the input (CRY-8). Checked before any
  // byte is decrypted.
  constexpr size_t aeadTagLength = 16;
  if (signature.size_bytes() != aeadTagLength)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      ErrorDetail::build("VerificationFailed",
        "AEAD authentication tag length is not the algorithm's tag length",
        "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(signature.size_bytes()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(aeadTagLength)));
  }

  const EVP_CIPHER* cipher = aead_cipher(algorithm, "symmetric_verify_and_decrypt_sync");

  if ((numeric_cast<int>(iv.size_bytes()) != EVP_CIPHER_iv_length(cipher)) ||
      (numeric_cast<int>(key.size_bytes()) != EVP_CIPHER_key_length(cipher)) ||
      (plainText.size_bytes() < cipherText.size_bytes()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric AEAD decrypt buffer size invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoIvSize, std::to_string(iv.size_bytes()))
        .context(ua::ContextKeys::cryptoIvExpected, std::to_string(EVP_CIPHER_iv_length(cipher)))
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoKeySizeExpected, std::to_string(EVP_CIPHER_key_length(cipher)))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes())));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DecryptionFailed",
        "EVP_CIPHER_CTX_new() failed in symmetric_verify_and_decrypt_sync",
        "OpenSslCrypto"));
  }
  const UniquePtrToEvpCipherCtx ctxOwner(ctx);

  int result = EVP_DecryptInit(ctx, cipher, NULL, NULL);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DecryptionFailed",
        "EVP_DecryptInit() failed in symmetric_verify_and_decrypt_sync",
        "OpenSslCrypto"));
  }

  result = EVP_DecryptInit(
    ctx, NULL, utils::bytes_to_unsigned_chars(key.data()), utils::bytes_to_unsigned_chars(iv.data()));
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DecryptionFailed",
        "EVP_DecryptInit() failed in symmetric_verify_and_decrypt_sync",
        "OpenSslCrypto"));
  }

  int outputLength = 0;
  if (!additionalData.empty())
  {
    result = EVP_DecryptUpdate(ctx,
      NULL,
      &outputLength,
      utils::bytes_to_unsigned_chars(additionalData.data()),
      numeric_cast<int>(additionalData.size_bytes()));
    if (!is_openssl_result_good(result) || (outputLength != numeric_cast<int>(additionalData.size_bytes())))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("DecryptionFailed",
          "EVP_DecryptUpdate() AAD failed in symmetric_verify_and_decrypt_sync",
          "OpenSslCrypto"));
    }
  }

  if (!cipherText.empty())
  {
    outputLength = 0;
    result = EVP_DecryptUpdate(ctx,
      utils::bytes_to_unsigned_chars(plainText.data()),
      &outputLength,
      utils::bytes_to_unsigned_chars(cipherText.data()),
      numeric_cast<int>(cipherText.size_bytes()));
    if (!is_openssl_result_good(result) || (outputLength != numeric_cast<int>(cipherText.size_bytes())))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("DecryptionFailed",
          "EVP_DecryptUpdate() failed in symmetric_verify_and_decrypt_sync",
          "OpenSslCrypto"));
    }
  }

  std::vector<unsigned char> sigRw;
  sigRw.resize(signature.size_bytes());

  memcpy(sigRw.data(), signature.data(), signature.size_bytes());

  result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, numeric_cast<int>(sigRw.size()), sigRw.data());
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DecryptionFailed",
        "EVP_CIPHER_CTX_ctrl() failed in symmetric_verify_and_decrypt_sync",
        "OpenSslCrypto"));
  }

  result = EVP_DecryptFinal(ctx, 0, &outputLength);
  if (!is_openssl_result_good(result) || (outputLength != 0))
  {
    // Update has already written the decrypted bytes; none of them may reach the caller unverified.
    if (!plainText.empty())
    {
      OPENSSL_cleanse(plainText.data(), plainText.size_bytes());
    }
    throw UaException(Status::BadSecurityChecksFailed,
      detail::make_openssl_error_detail("VerificationFailed",
        "AEAD tag verification failed in symmetric_verify_and_decrypt_sync",
        "OpenSslCrypto"));
  }
}

void CryptoOpenSsl::symmetric_verify_and_decrypt_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv,
  ByteString key, ByteString cipherTextBuffer, span<const byte> cipherText, span<const byte> additionalData,
  span<const byte> signature, optional<ByteString> plainTextBuffer, span<byte> plainText,
  SymmetricVerifyAndDecryptCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result(
      [&]() -> SymmetricVerifyAndDecryptOutput
      {
        symmetric_verify_and_decrypt_sync(
          algorithm, iv, key, cipherText, additionalData, signature, plainText);
        return SymmetricVerifyAndDecryptOutput{std::move(cipherTextBuffer), std::move(plainTextBuffer)};
      }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::symmetric_sign_sync(
  SymmetricSignatureAlgorithm algorithm, span<const byte> key, span<const byte> data) const
{
  if (key.empty() || data.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric sign input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoDataSize, std::to_string(data.size_bytes())));
  }

  HashAlgorithm hashAlgorithm = HashAlgorithm::Invalid;
  switch (algorithm)
  {
  case SymmetricSignatureAlgorithm::HmacSha1:
    hashAlgorithm = HashAlgorithm::Sha1;
    break;

  case SymmetricSignatureAlgorithm::HmacSha2256:
    hashAlgorithm = HashAlgorithm::Sha2256;
    break;

  case SymmetricSignatureAlgorithm::HmacSha2384:
    hashAlgorithm = HashAlgorithm::Sha2384;
    break;

  default:
    // An AEAD tag (ChaCha20-Poly1305, AES-GCM) is produced by symmetric_encrypt_and_sign_async with
    // the encrypting key; it is never a standalone keyed MAC over a raw key. Any algorithm that is not
    // an HMAC is rejected here.
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidAlgorithm", "algorithm is invalid in symmetric_sign_sync", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  return calculate_hmac(hashAlgorithm, key, data);
}

void CryptoOpenSsl::symmetric_sign_async(shared_ptr<const void> resource,
  SymmetricSignatureAlgorithm algorithm, span<const byte> key, span<const byte> input,
  SymmetricSignCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(detail::to_result([&] { return symmetric_sign_sync(algorithm, key, input); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::symmetric_verify_sync(SymmetricSignatureAlgorithm algorithm, span<const byte> key,
  span<const byte> data, span<const byte> signature) const
{
  if (key.empty() || data.empty() || signature.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Symmetric verify input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoKeySize, std::to_string(key.size_bytes()))
        .context(ua::ContextKeys::cryptoDataSize, std::to_string(data.size_bytes()))
        .context(ua::ContextKeys::cryptoSignatureSize, std::to_string(signature.size_bytes())));
  }

  HashAlgorithm hashAlgorithm = HashAlgorithm::Invalid;
  switch (algorithm)
  {
  case SymmetricSignatureAlgorithm::HmacSha1:
    hashAlgorithm = HashAlgorithm::Sha1;
    break;

  case SymmetricSignatureAlgorithm::HmacSha2256:
    hashAlgorithm = HashAlgorithm::Sha2256;
    break;

  case SymmetricSignatureAlgorithm::HmacSha2384:
    hashAlgorithm = HashAlgorithm::Sha2384;
    break;

  default:
    // An AEAD tag (ChaCha20-Poly1305, AES-GCM) is checked by symmetric_verify_and_decrypt_async with
    // the encrypting key; it is never a standalone keyed MAC over a raw key. Any algorithm that is not
    // an HMAC is rejected here.
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidAlgorithm", "algorithm is invalid in symmetric_verify_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  ByteString calculatedSignature = calculate_hmac(hashAlgorithm, key, data);

  // The MAC length is the algorithm's, never the input's: a shorter signature would compare a
  // truncated prefix and a longer one would read past the calculated MAC (CRY-8).
  if (signature.size_bytes() != calculatedSignature.size())
  {
    throw UaException(Status::BadSecurityChecksFailed,
      ErrorDetail::build("VerificationFailed",
        "Symmetric signature length does not match the algorithm's MAC length",
        "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(signature.size_bytes()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(calculatedSignature.size())));
  }

  if (CRYPTO_memcmp(calculatedSignature.data(), signature.data(), signature.size_bytes()) != 0)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      detail::make_openssl_error_detail("VerificationFailed",
        "Symmetric signature verification failed in symmetric_verify_sync",
        "OpenSslCrypto"));
  }
}

void CryptoOpenSsl::symmetric_verify_async(shared_ptr<const void> resource,
  SymmetricSignatureAlgorithm algorithm, span<const byte> key, span<const byte> input,
  span<const byte> signature, SymmetricVerifyCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  check(callback);
  try
  {
    callback(detail::to_result([&] { symmetric_verify_sync(algorithm, key, input, signature); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::asymmetric_encrypt_sync(AsymmetricEncryptionAlgorithm algorithm,
  span<const byte> publicKey, span<const byte> plainText, span<byte> cipherText) const
{
  if (publicKey.empty() || plainText.empty() || cipherText.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Asymmetric encrypt input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPublickeySize, std::to_string(publicKey.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  int padding = 0;
  switch (algorithm)
  {
  case AsymmetricEncryptionAlgorithm::RsaPkcs15:
    padding = RSA_PKCS1_PADDING;
    // digest = EVP_sha1();
    break;

  case AsymmetricEncryptionAlgorithm::RsaOaepSha1:
    padding = RSA_PKCS1_OAEP_PADDING;
    digest = EVP_sha1();
    break;

  case AsymmetricEncryptionAlgorithm::RsaOaepSha2256:
    padding = RSA_PKCS1_OAEP_PADDING;
    digest = EVP_sha256();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAlgorithm", "algorithm is invalid in asymmetric_encrypt_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  const unsigned char* pp = utils::bytes_to_unsigned_chars(publicKey.data());
  EVP_PKEY* evpKey = nullptr;
  evpKey = d2i_PUBKEY(&evpKey, &pp, numeric_cast<long>(publicKey.size_bytes()));
  if (!evpKey)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "d2i_PUBKEY() failed in asymmetric_encrypt_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKey evpKeyOwner(evpKey);

  if (numeric_cast<int>(plainText.size_bytes()) > EVP_PKEY_size(evpKey))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidInputSize", "plainText length is too long in asymmetric_encrypt_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(plainText.size_bytes()))
        .context(ua::ContextKeys::sizeMax, std::to_string(EVP_PKEY_size(evpKey))));
  }

  EVP_PKEY_CTX* evpKeyCtx = EVP_PKEY_CTX_new(evpKey, NULL);
  if (!evpKeyCtx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_PKEY_CTX_new() failed in asymmetric_encrypt_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx evpKeyCtxOwner(evpKeyCtx);

  int result = EVP_PKEY_encrypt_init(evpKeyCtx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_PKEY_encrypt_init() failed in asymmetric_encrypt_sync", "OpenSslCrypto"));
  }

  result = EVP_PKEY_CTX_set_rsa_padding(evpKeyCtx, padding);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("EncryptionFailed",
        "EVP_PKEY_CTX_set_rsa_padding() failed in asymmetric_encrypt_sync",
        "OpenSslCrypto"));
  }

  if (RSA_PKCS1_OAEP_PADDING == padding)
  {
    result = EVP_PKEY_CTX_set_rsa_oaep_md(evpKeyCtx, digest);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EncryptionFailed",
          "EVP_PKEY_CTX_set_rsa_oaep_md() failed in asymmetric_encrypt_sync",
          "OpenSslCrypto"));
    }
  }

  size_t outputLength = cipherText.size_bytes();
  result = EVP_PKEY_encrypt(evpKeyCtx,
    utils::bytes_to_unsigned_chars(cipherText.data()),
    &outputLength,
    utils::bytes_to_unsigned_chars(plainText.data()),
    plainText.size_bytes());

  if (!is_openssl_result_good(result) || (outputLength != cipherText.size_bytes()))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "EncryptionFailed", "EVP_PKEY_encrypt() failed in asymmetric_encrypt_sync", "OpenSslCrypto"));
  }
}

void CryptoOpenSsl::asymmetric_encrypt_async(shared_ptr<const void> resource,
  AsymmetricEncryptionAlgorithm algorithm, span<const byte> publicKey, span<const byte> plainText,
  span<byte> cipherText, AsymmetricEncryptCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(
      detail::to_result([&] { asymmetric_encrypt_sync(algorithm, publicKey, plainText, cipherText); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

span<const byte> CryptoOpenSsl::asymmetric_decrypt_sync(AsymmetricEncryptionAlgorithm algorithm,
  shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> cipherText, span<byte> plainText) const
{
  if (!privateKey || cipherText.empty() || plainText.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Asymmetric decrypt input is invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPrivatekeyPresent, (privateKey ? "true" : "false"))
        .context(ua::ContextKeys::cryptoCiphertextSize, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::cryptoPlaintextSize, std::to_string(plainText.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  int padding = 0;
  switch (algorithm)
  {
  case AsymmetricEncryptionAlgorithm::RsaPkcs15:
    padding = RSA_PKCS1_PADDING;
    // digest = EVP_sha1();
    break;

  case AsymmetricEncryptionAlgorithm::RsaOaepSha1:
    padding = RSA_PKCS1_OAEP_PADDING;
    digest = EVP_sha1();
    break;

  case AsymmetricEncryptionAlgorithm::RsaOaepSha2256:
    padding = RSA_PKCS1_OAEP_PADDING;
    digest = EVP_sha256();
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAlgorithm", "algorithm is invalid in asymmetric_decrypt_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  const auto* key = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(privateKey.get());
  if (!key)
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail(
        "InvalidKeySize", "Private key is invalid in asymmetric_decrypt_sync", "OpenSslCrypto"));
  }
  auto evpKey = key->private_key_evp();

  if (numeric_cast<int>(cipherText.size_bytes()) > EVP_PKEY_size(evpKey.get()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidInputSize", "cipherText length is too large in asymmetric_decrypt_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::sizeActual, std::to_string(cipherText.size_bytes()))
        .context(ua::ContextKeys::sizeMax, std::to_string(EVP_PKEY_size(evpKey.get()))));
  }

  EVP_PKEY_CTX* evpKeyCtx = EVP_PKEY_CTX_new(evpKey.get(), NULL);
  if (!evpKeyCtx)
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail(
        "DecryptionFailed", "EVP_PKEY_CTX_new() failed in asymmetric_decrypt_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx evpKeyCtxOwner(evpKeyCtx);

  int result = EVP_PKEY_decrypt_init(evpKeyCtx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail(
        "DecryptionFailed", "EVP_PKEY_decrypt_init() failed in asymmetric_decrypt_sync", "OpenSslCrypto"));
  }

  result = EVP_PKEY_CTX_set_rsa_padding(evpKeyCtx, padding);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail("DecryptionFailed",
        "EVP_PKEY_CTX_set_rsa_padding() failed in asymmetric_decrypt_sync",
        "OpenSslCrypto"));
  }

  if (RSA_PKCS1_OAEP_PADDING == padding)
  {
    result = EVP_PKEY_CTX_set_rsa_oaep_md(evpKeyCtx, digest);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInvalidArgument,
        detail::make_openssl_error_detail("DecryptionFailed",
          "EVP_PKEY_CTX_set_rsa_oaep_md() failed in asymmetric_decrypt_sync",
          "OpenSslCrypto"));
    }
  }

  size_t outputLength = plainText.size_bytes();
  result = EVP_PKEY_decrypt(evpKeyCtx,
    utils::bytes_to_unsigned_chars(plainText.data()),
    &outputLength,
    utils::bytes_to_unsigned_chars(cipherText.data()),
    cipherText.size_bytes());
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail(
        "DecryptionFailed", "EVP_PKEY_decrypt() failed in asymmetric_decrypt_sync", "OpenSslCrypto"));
  }

  return span{plainText.data(), outputLength};
}

void CryptoOpenSsl::asymmetric_decrypt_async(shared_ptr<const void> resource,
  AsymmetricEncryptionAlgorithm algorithm, shared_ptr<const AsymmetricKeyPair> privateKey,
  span<const byte> cipherText, span<byte> plainText,
  AsymmetricDecryptCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(detail::to_result(
      [&] { return asymmetric_decrypt_sync(algorithm, privateKey, cipherText, plainText); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::asymmetric_sign_sync(AsymmetricSignatureAlgorithm algorithm,
  shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> input) const
{
  if (!privateKey || input.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Asymmetric sign input is invalid", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPrivatekeyPresent, (privateKey ? "true" : "false"))
        .context(ua::ContextKeys::sizeActual, std::to_string(input.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  int padding = 0;
  int keyType = 0;
  switch (algorithm)
  {
  case AsymmetricSignatureAlgorithm::RsaPkcs15Sha1:
    digest = EVP_sha1();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::RsaPssSha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PSS_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2384:
    digest = EVP_sha384();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2512:
    digest = EVP_sha512();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::PureEdDsa25519:
    keyType = EVP_PKEY_ED25519;
    break;

  case AsymmetricSignatureAlgorithm::PureEdDsa448:
    keyType = EVP_PKEY_ED448;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidAlgorithm", "Algorithm is invalid in asymmetric_sign_sync", "OpenSslCrypto")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  const auto* key = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(privateKey.get());
  if (!key)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidKeySize", "Private key is invalid in asymmetric_sign_sync", "OpenSslCrypto"));
  }
  auto evpKey = key->private_key_evp();
  EVP_MD_CTX* evpMdCtx = EVP_MD_CTX_new();
  if (!evpMdCtx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "SigningFailed", "EVP_MD_CTX_new() failed in asymmetric_sign_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpMdCtx evpMdCtxOwner(evpMdCtx);

  EVP_PKEY_CTX* evpKeyCtx = nullptr;
  int result = 0;
  if ((keyType == EVP_PKEY_ED25519) || (keyType == EVP_PKEY_ED448))
  {
    result = EVP_DigestSignInit(evpMdCtx, &evpKeyCtx, NULL, 0, evpKey.get());
  }
  else
  {
    result = EVP_DigestSignInit(evpMdCtx, &evpKeyCtx, digest, 0, evpKey.get());
  }
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "SigningFailed", "EVP_DigestSignInit() failed in asymmetric_sign_sync", "OpenSslCrypto"));
  }

  if (keyType == EVP_PKEY_RSA)
  {
    result = EVP_PKEY_CTX_set_rsa_padding(evpKeyCtx, padding);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "SigningFailed", "EVP_PKEY_CTX_set_rsa_padding() failed in asymmetric_sign_sync", "OpenSslCrypto"));
    }
  }

  if (keyType == EVP_PKEY_RSA)
  {
    result = EVP_PKEY_CTX_set_signature_md(evpKeyCtx, digest);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("SigningFailed",
          "EVP_PKEY_CTX_set_signature_md() failed in asymmetric_sign_sync",
          "OpenSslCrypto"));
    }
  }

  if ((keyType == EVP_PKEY_RSA) && (RSA_PKCS1_PSS_PADDING == padding))
  {
    result = EVP_PKEY_CTX_set_rsa_pss_saltlen(evpKeyCtx, -1);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("SigningFailed",
          "EVP_PKEY_CTX_set_rsa_pss_saltlen() failed in asymmetric_sign_sync",
          "OpenSslCrypto"));
    }
  }

  size_t outputLength{0};
  result = EVP_DigestSign(
    evpMdCtx, NULL, &outputLength, utils::bytes_to_unsigned_chars(input.data()), input.size_bytes());
  if (!is_openssl_result_good(result) || (outputLength == 0))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "SigningFailed", "EVP_DigestSign() failed in asymmetric_sign_sync", "OpenSslCrypto"));
  }

  // outputLength > 0 is guaranteed by the (outputLength == 0) check above.
  ByteString signature;
  signature.resize(outputLength);

  result = EVP_DigestSign(evpMdCtx,
    signature.data(),
    &outputLength,
    utils::bytes_to_unsigned_chars(input.data()),
    input.size_bytes());
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "SigningFailed", "EVP_DigestSign() failed in asymmetric_sign_sync", "OpenSslCrypto"));
  }

  signature.resize(outputLength);

  // ECDSA: convert DER-encoded signature to fixed-size IEEE P1363 format (r || s)
  if (is_ecdsa_algorithm(algorithm))
  {
    const auto keyBits = numeric_cast<size_t>(EVP_PKEY_bits(evpKey.get()));
    const auto compSize = (keyBits + 7) / 8;
    signature = ecdsa_der_to_p1363(signature, compSize);
  }

  return signature;
}

void CryptoOpenSsl::asymmetric_sign_async(shared_ptr<const void> resource,
  AsymmetricSignatureAlgorithm algorithm, shared_ptr<const AsymmetricKeyPair> privateKey,
  span<const byte> input, AsymmetricSignCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(detail::to_result([&] { return asymmetric_sign_sync(algorithm, privateKey, input); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void CryptoOpenSsl::asymmetric_verify_sync(AsymmetricSignatureAlgorithm algorithm, span<const byte> publicKey,
  span<const byte> data, span<const byte> signature) const
{
  if (publicKey.empty() || data.empty() || signature.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Asymmetric verify input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPublickeySize, std::to_string(publicKey.size_bytes()))
        .context(ua::ContextKeys::cryptoDataSize, std::to_string(data.size_bytes()))
        .context(ua::ContextKeys::cryptoSignatureSize, std::to_string(signature.size_bytes())));
  }

  const EVP_MD* digest = nullptr;
  int padding = RSA_PKCS1_PADDING;
  int keyType = 0;
  switch (algorithm)
  {
  case AsymmetricSignatureAlgorithm::RsaPkcs15Sha1:
    digest = EVP_sha1();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::RsaPssSha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_RSA;
    padding = RSA_PKCS1_PSS_PADDING;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2256:
    digest = EVP_sha256();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2384:
    digest = EVP_sha384();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::EcDsaSha2512:
    digest = EVP_sha512();
    keyType = EVP_PKEY_EC;
    padding = 0;
    break;

  case AsymmetricSignatureAlgorithm::PureEdDsa25519:
    keyType = EVP_PKEY_ED25519;
    break;

  case AsymmetricSignatureAlgorithm::PureEdDsa448:
    keyType = EVP_PKEY_ED448;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAlgorithm", "algorithm is invalid in asymmetric_verify_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  const unsigned char* pp = utils::bytes_to_unsigned_chars(publicKey.data());
  EVP_PKEY* evpKey = nullptr;
  evpKey = d2i_PUBKEY(&evpKey, &pp, numeric_cast<int>(publicKey.size_bytes()));
  if (!evpKey)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "VerificationFailed", "d2i_PUBKEY() failed in asymmetric_verify_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKey evpKeyOwner(evpKey);  // owned before any check can throw

  if (EVP_PKEY_base_id(evpKey) != keyType)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      ErrorDetail::build(
        "VerificationFailed", "Public key type mismatch in asymmetric_verify_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeExpected, std::to_string(keyType))
        .context(ua::ContextKeys::typeActual, std::to_string(EVP_PKEY_base_id(evpKey))));
  }

  EVP_MD_CTX* evpMdCtx = EVP_MD_CTX_new();
  if (!evpMdCtx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "VerificationFailed", "EVP_MD_CTX_new() failed in asymmetric_verify_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpMdCtx evpMdCtxOwner(evpMdCtx);

  EVP_PKEY_CTX* evpKeyCtx = nullptr;
  int result = 0;
  if ((keyType == EVP_PKEY_ED25519) || (keyType == EVP_PKEY_ED448))
  {
    result = EVP_DigestVerifyInit(evpMdCtx, &evpKeyCtx, NULL, 0, evpKey);
  }
  else
  {
    result = EVP_DigestVerifyInit(evpMdCtx, &evpKeyCtx, digest, 0, evpKey);
  }
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "VerificationFailed", "EVP_DigestVerifyInit() failed in asymmetric_verify_sync", "OpenSslCrypto"));
  }

  if (keyType == EVP_PKEY_RSA)
  {
    result = EVP_PKEY_CTX_set_rsa_padding(evpKeyCtx, padding);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("VerificationFailed",
          "EVP_PKEY_CTX_set_rsa_padding() failed in asymmetric_verify_sync",
          "OpenSslCrypto"));
    }
  }

  if (keyType == EVP_PKEY_RSA)
  {
    result = EVP_PKEY_CTX_set_signature_md(evpKeyCtx, digest);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("VerificationFailed",
          "EVP_PKEY_CTX_set_signature_md() failed in asymmetric_verify_sync",
          "OpenSslCrypto"));
    }
  }

  if ((keyType == EVP_PKEY_RSA) && (RSA_PKCS1_PSS_PADDING == padding))
  {
    result = EVP_PKEY_CTX_set_rsa_pss_saltlen(evpKeyCtx, -1);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("VerificationFailed",
          "EVP_PKEY_CTX_set_rsa_pss_saltlen() failed in asymmetric_verify_sync",
          "OpenSslCrypto"));
    }
  }

  // ECDSA: convert IEEE P1363 fixed-size signature to DER for OpenSSL verification
  ByteString derSignature;
  const unsigned char* sigData = utils::bytes_to_unsigned_chars(signature.data());
  auto sigSize = signature.size_bytes();
  if (is_ecdsa_algorithm(algorithm))
  {
    const auto keyBits = numeric_cast<size_t>(EVP_PKEY_bits(evpKey));
    const auto compSize = (keyBits + 7) / 8;
    derSignature = ecdsa_p1363_to_der(signature, compSize);
    sigData = derSignature.data();
    sigSize = derSignature.size();
  }

  result = EVP_DigestVerify(
    evpMdCtx, sigData, sigSize, utils::bytes_to_unsigned_chars(data.data()), data.size_bytes());
  if (result == 0)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      detail::make_openssl_error_detail("VerificationFailed",
        "Asymmetric signature verification failed in asymmetric_verify_sync",
        "OpenSslCrypto"));
  }
  if (result < 0)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "VerificationFailed", "EVP_DigestVerify() failed in asymmetric_verify_sync", "OpenSslCrypto"));
  }
}

void CryptoOpenSsl::asymmetric_verify_async(shared_ptr<const void> resource,
  AsymmetricSignatureAlgorithm algorithm, span<const byte> publicKey, span<const byte> input,
  span<const byte> signature, AsymmetricVerifyCompleteCallback callback) const noexcept
{
  UA_UNUSED(resource);
  try
  {
    callback(detail::to_result([&] { asymmetric_verify_sync(algorithm, publicKey, input, signature); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

shared_ptr<const AsymmetricKeyPair> CryptoOpenSsl::create_asymmetric_key_pair_sync(
  CertificateKeyAlgorithm algorithm, optional<size_t> keyLengthInBits) const
{
  int keyType = 0;
  int ecCurveId = 0;
  // Validated RSA key length (bits); engaged only on the RSA branch and used when keyType == EVP_PKEY_RSA.
  size_t rsaKeyLengthInBits = 0;
  switch (algorithm)
  {
  case CertificateKeyAlgorithm::Rsa:
  {
    if (!keyLengthInBits.has_value() || keyLengthInBits.value() <= 0)
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("KeyGenerationFailed",
          "keyLengthInBits is invalid in create_asymmetric_key_pair_sync",
          "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoKeySize,
            keyLengthInBits.has_value() ? std::to_string(keyLengthInBits.value()) : "none"));
    }
    rsaKeyLengthInBits = keyLengthInBits.value();
    keyType = EVP_PKEY_RSA;
  }
  break;

  case CertificateKeyAlgorithm::EccNistP256:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_X9_62_prime256v1;
    break;

  case CertificateKeyAlgorithm::EccNistP384:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_secp384r1;
    break;

  case CertificateKeyAlgorithm::EccNistP521:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_secp521r1;
    break;

  case CertificateKeyAlgorithm::EccBrainpoolP256r1:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_brainpoolP256r1;
    break;

  case CertificateKeyAlgorithm::EccBrainpoolP384r1:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_brainpoolP384r1;
    break;

  case CertificateKeyAlgorithm::EccBrainpoolP512r1:
    keyType = EVP_PKEY_EC;
    ecCurveId = NID_brainpoolP512r1;
    break;

  case CertificateKeyAlgorithm::EccCurve25519:
    keyType = EVP_PKEY_ED25519;
    break;

  case CertificateKeyAlgorithm::EccCurve448:
    keyType = EVP_PKEY_ED448;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "KeyGenerationFailed", "algorithm is invalid in create_asymmetric_key_pair_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(keyType, NULL);
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyGenerationFailed",
        "EVP_PKEY_CTX_new_id() failed in create_asymmetric_key_pair_sync",
        "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx ctxOwner(ctx);

  int result = EVP_PKEY_keygen_init(ctx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyGenerationFailed",
        "EVP_PKEY_keygen_init() failed in create_asymmetric_key_pair_sync",
        "OpenSslCrypto"));
  }

  if (keyType == EVP_PKEY_RSA)
  {
    result = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, numeric_cast<int>(rsaKeyLengthInBits));
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("KeyGenerationFailed",
          "EVP_PKEY_CTX_set_rsa_keygen_bits() failed in create_asymmetric_key_pair_sync",
          "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoKeySize, std::to_string(numeric_cast<int>(rsaKeyLengthInBits))));
    }
  }
  else if (ecCurveId)
  {
    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ecCurveId);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("KeyGenerationFailed",
          "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed in create_asymmetric_key_pair_sync",
          "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoNid, std::to_string(ecCurveId)));
    }
  }

  EVP_PKEY* evpKeyRaw = nullptr;
  result = EVP_PKEY_keygen(ctx, &evpKeyRaw);
  if (!is_openssl_result_good(result) || !evpKeyRaw)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyGenerationFailed",
        "EVP_PKEY_keygen() failed in create_asymmetric_key_pair_sync",
        "OpenSslCrypto"));
  }
  UniquePtrToEvpKey evpKey(evpKeyRaw);
  return make_shared<AsymmetricKeyPairOpenSsl>(algorithm, mPrivateKeyCredentialCallback, *evpKey);
}

void CryptoOpenSsl::create_asymmetric_key_pair_async(CertificateKeyAlgorithm algorithm,
  optional<size_t> keyLengthInBytes, CreateAsymmetricKeyPairCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return create_asymmetric_key_pair_sync(algorithm, keyLengthInBytes); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

namespace
{

// RSA-DH key agreement in the RFC 7919 ffdhe3072 group (Part 6 6.9 and Table 72): a 275-bit private
// exponent, and public values and shared secrets encoded as 384-byte zero-padded big-endian integers. The
// arithmetic uses BIGNUM directly, which is the same on OpenSSL 1.1.1 and 3.
constexpr size_t ffdhe3072Bytes = 384;
constexpr int ffdhe3072PrivateBits = 275;
constexpr size_t ffdhe3072PrivateBytes = (ffdhe3072PrivateBits + 7) / 8;

// RFC 7919 Appendix A.2.
constexpr const char* ffdhe3072PrimeHex =
  "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
  "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
  "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
  "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
  "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
  "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
  "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
  "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";

UniquePtrToBigNum bignum_or_throw(BIGNUM* value, const char* what)
{
  if (!value)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyAgreementFailed", what, "OpenSslCrypto"));
  }
  return UniquePtrToBigNum(value);
}

// A secret BIGNUM is cleared before it is freed.
struct ClearingBigNumDeleter
{
  void operator()(BIGNUM* p) const
  {
    BN_clear_free(p);
  }
};

using UniquePtrToSecretBigNum = unique_ptr<BIGNUM, ClearingBigNumDeleter>;

UniquePtrToBigNum ffdhe3072_prime()
{
  BIGNUM* prime = nullptr;
  if (BN_hex2bn(&prime, ffdhe3072PrimeHex) == 0)
  {
    BN_free(prime);
    prime = nullptr;
  }
  return bignum_or_throw(prime, "BN_hex2bn() failed for the ffdhe3072 prime");
}

ByteString bignum_to_padded(const BIGNUM& value, size_t length)
{
  ByteString out;
  out.resize(length);
  if (BN_bn2binpad(&value, reinterpret_cast<unsigned char*>(out.data()), numeric_cast<int>(length)) !=
      numeric_cast<int>(length))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "BN_bn2binpad() failed for an ffdhe3072 value", "OpenSslCrypto"));
  }
  return out;
}

// base^exponent mod ffdhe3072 prime, with the exponent treated as secret.
UniquePtrToSecretBigNum ffdhe3072_power(const BIGNUM& base, BIGNUM& exponent, const BIGNUM& prime)
{
  BN_CTX* bnCtx = BN_CTX_new();
  if (!bnCtx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "BN_CTX_new() failed for ffdhe3072", "OpenSslCrypto"));
  }
  const BnContextOwner bnCtxOwner(*bnCtx);
  UniquePtrToSecretBigNum result(BN_new());
  BN_set_flags(&exponent, BN_FLG_CONSTTIME);
  if (!result || !is_openssl_result_good(
                   BN_mod_exp_mont_consttime(result.get(), &base, &exponent, &prime, bnCtx, nullptr)))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "BN_mod_exp_mont_consttime() failed for ffdhe3072", "OpenSslCrypto"));
  }
  return result;
}

Crypto::EphemeralKeyPair create_ffdhe3072_keys()
{
  const auto prime = ffdhe3072_prime();
  UniquePtrToSecretBigNum privateExponent(BN_new());
  // BN_RAND_TOP_ONE sets the top bit, so the exponent has exactly 275 bits as Table 72 requires.
  if (!privateExponent ||
      !is_openssl_result_good(
        BN_priv_rand(privateExponent.get(), ffdhe3072PrivateBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyGenerationFailed", "BN_priv_rand() failed for an ffdhe3072 private key", "OpenSslCrypto"));
  }
  const auto generator = bignum_or_throw(BN_new(), "BN_new() failed for the ffdhe3072 generator");
  if (!is_openssl_result_good(BN_set_word(generator.get(), 2)))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyGenerationFailed", "BN_set_word() failed for the ffdhe3072 generator", "OpenSslCrypto"));
  }
  const auto publicValue = ffdhe3072_power(*generator, *privateExponent, *prime);

  Crypto::EphemeralKeyPair keyPair;
  keyPair.publicKey = bignum_to_padded(*publicValue, ffdhe3072Bytes);
  keyPair.privateKey = bignum_to_padded(*privateExponent, ffdhe3072PrivateBytes);
  return keyPair;
}

ByteString calculate_ffdhe3072_shared_secret(
  span<const byte> localPrivateKey, span<const byte> remotePublicKey)
{
  if (remotePublicKey.size_bytes() != ffdhe3072Bytes)
  {
    throw UaException(Status::BadNonceInvalid,
      ErrorDetail::build("InvalidPublicKey", "An ffdhe3072 public value is not 384 bytes", "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(remotePublicKey.size_bytes()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(ffdhe3072Bytes)));
  }
  if (localPrivateKey.size_bytes() != ffdhe3072PrivateBytes)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidPrivateKey", "An ffdhe3072 private key is not 35 bytes", "OpenSslCrypto")
        .context(ua::ContextKeys::sizeActual, std::to_string(localPrivateKey.size_bytes()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(ffdhe3072PrivateBytes)));
  }

  const auto prime = ffdhe3072_prime();
  const auto peerValue = bignum_or_throw(BN_bin2bn(utils::bytes_to_unsigned_chars(remotePublicKey.data()),
                                           numeric_cast<int>(remotePublicKey.size_bytes()),
                                           nullptr),
    "BN_bin2bn() failed for an ffdhe3072 public value");

  // RFC 7919 5.1: a peer value outside 2 <= y <= p - 2 is refused. 0, 1 and p - 1 would fix the shared
  // secret to a value an attacker knows; p and above are not group elements.
  const auto upperBound = bignum_or_throw(BN_dup(prime.get()), "BN_dup() failed for the ffdhe3072 prime");
  if (!is_openssl_result_good(BN_sub_word(upperBound.get(), 2)))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "BN_sub_word() failed for ffdhe3072", "OpenSslCrypto"));
  }
  if (BN_cmp(peerValue.get(), BN_value_one()) <= 0 || BN_cmp(peerValue.get(), upperBound.get()) > 0)
  {
    throw UaException(Status::BadNonceInvalid,
      ErrorDetail::build(
        "InvalidPublicKey", "An ffdhe3072 public value is outside 2 to p - 2", "OpenSslCrypto"));
  }

  UniquePtrToSecretBigNum privateExponent(BN_bin2bn(utils::bytes_to_unsigned_chars(localPrivateKey.data()),
    numeric_cast<int>(localPrivateKey.size_bytes()),
    nullptr));
  if (!privateExponent)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "BN_bin2bn() failed for an ffdhe3072 private key", "OpenSslCrypto"));
  }
  const auto secret = ffdhe3072_power(*peerValue, *privateExponent, *prime);
  return bignum_to_padded(*secret, ffdhe3072Bytes);
}

}  // namespace

Crypto::EphemeralKeyPair CryptoOpenSsl::create_ephemeral_keys_sync(EphemeralKeyAlgorithm algorithm) const
{
  if (algorithm == EphemeralKeyAlgorithm::RsaDhFfdhe3072)
  {
    return create_ffdhe3072_keys();
  }

  int keyType = 0;
  int curveId = 0;
  switch (algorithm)
  {
  case EphemeralKeyAlgorithm::EccNistP256:
    keyType = EVP_PKEY_EC;
    curveId = NID_X9_62_prime256v1;
    break;

  case EphemeralKeyAlgorithm::EccNistP384:
    keyType = EVP_PKEY_EC;
    curveId = NID_secp384r1;
    break;

  case EphemeralKeyAlgorithm::EccBrainpoolP256r1:
    keyType = EVP_PKEY_EC;
    curveId = NID_brainpoolP256r1;
    break;

  case EphemeralKeyAlgorithm::EccBrainpoolP384r1:
    keyType = EVP_PKEY_EC;
    curveId = NID_brainpoolP384r1;
    break;

  case EphemeralKeyAlgorithm::EccCurve25519:
    keyType = EVP_PKEY_X25519;
    break;

  case EphemeralKeyAlgorithm::EccCurve448:
    keyType = EVP_PKEY_X448;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAlgorithm", "algorithm is invalid in create_ephemeral_keys_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(keyType, NULL);
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyGenerationFailed",
        "EVP_PKEY_CTX_new_id() failed in create_ephemeral_keys_sync",
        "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx ctxOwner(ctx);

  int result = EVP_PKEY_keygen_init(ctx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("KeyGenerationFailed",
        "EVP_PKEY_keygen_init() failed in create_ephemeral_keys_sync",
        "OpenSslCrypto"));
  }

  if (curveId)
  {
    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveId);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("EccOperationFailed",
          "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::cryptoNid, std::to_string(curveId)));
    }
  }

  EVP_PKEY* evpKey = nullptr;
  result = EVP_PKEY_keygen(ctx, &evpKey);
  if (!is_openssl_result_good(result) || !evpKey)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyGenerationFailed", "EVP_PKEY_keygen() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKey keyOwner(evpKey);

  EphemeralKeyPair keyPair;

  if (curveId)
  {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    std::string groupName = ec_group_name_from_key(*evpKey);
    if (groupName.empty())
    {
      groupName = ec_group_name_from_curve_nid(curveId);
    }
    const int keySize = ec_key_size_bytes_from_group_name(groupName);

    auto pub = ec_public_key_uncompressed(*evpKey);
    if (pub.size() != numeric_cast<size_t>(1 + 2 * keySize) || pub[0] != 0x04)
    {
      throw UaException(Status::BadInternalError,
        ErrorDetail::build("KeyGenerationFailed",
          "Unexpected EC public key encoding in create_ephemeral_keys_sync",
          "OpenSslCrypto")
          .detail(detail::drain_openssl_errors())
          .context(ua::ContextKeys::sizeActual, std::to_string(pub.size()))
          .context(ua::ContextKeys::sizeExpected, std::to_string(1 + 2 * keySize)));
    }

    // Part 6 1.05.07 section 6.8.1: the wire nonce contains padded X || Y, without SEC1's prefix.
    keyPair.publicKey.assign(pub.data() + 1, pub.data() + pub.size());

    int privateLength = i2d_PrivateKey(evpKey, 0);
    if (privateLength <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "i2d_PrivateKey() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }
    keyPair.privateKey.resize(numeric_cast<size_t>(privateLength));
    auto* destination = keyPair.privateKey.data();
    privateLength = i2d_PrivateKey(evpKey, &destination);
    if (privateLength != numeric_cast<int>(keyPair.privateKey.size()))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "i2d_PrivateKey() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }
#else
    const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(evpKey);
    if (!ecKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EVP_PKEY_get0_EC_KEY() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }

    int keySize = EC_GROUP_get_degree(EC_KEY_get0_group(ecKey));
    if (keySize <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_GROUP_get_degree() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }

    keySize = (keySize + 7) / 8;
    // Part 6 1.05.07 section 6.8.1: the wire nonce contains padded X || Y, without SEC1's prefix.
    keyPair.publicKey.resize(numeric_cast<size_t>(keySize) * 2);

    BN_CTX* bnCtx = BN_CTX_new();
    if (!bnCtx)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "BN_CTX_new() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }
    BnContextOwner bnCtxOwner(*bnCtx, true);

    BIGNUM* x = BN_CTX_get(bnCtx);
    if (!x)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "BN_CTX_get() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }

    BIGNUM* y = BN_CTX_get(bnCtx);
    if (!y)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "BN_CTX_get() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }

    const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
    if (!point)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_KEY_get0_public_key() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }

    uint8_t* destination = keyPair.publicKey.data();

    result = EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ecKey), point, x, y, bnCtx);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_POINT_get_affine_coordinates() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }

    result = BN_bn2binpad(x, destination, keySize);
    if (result <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "BN_bn2binpad() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }

    result = BN_bn2binpad(y, destination + keySize, keySize);
    if (result <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "BN_bn2binpad() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }

    int privateLength = i2d_PrivateKey(evpKey, 0);
    if (privateLength <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "i2d_PrivateKey() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }
    keyPair.privateKey.resize(numeric_cast<size_t>(privateLength));
    destination = keyPair.privateKey.data();

    privateLength = i2d_PrivateKey(evpKey, &destination);
    if (privateLength != numeric_cast<int>(keyPair.privateKey.size()))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyGenerationFailed", "i2d_PrivateKey() failed in create_ephemeral_keys_sync", "OpenSslCrypto"));
    }
#endif
  }
  else
  {
    size_t outputLength = 0;
    result = EVP_PKEY_get_raw_public_key(evpKey, 0, &outputLength);
    if (!is_openssl_result_good(result) || (outputLength == 0))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyGenerationFailed",
          "EVP_PKEY_get_raw_public_key() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }
    keyPair.publicKey.resize(outputLength);
    uint8_t* destination = keyPair.publicKey.data();

    result = EVP_PKEY_get_raw_public_key(evpKey, destination, &outputLength);
    if (!is_openssl_result_good(result) || (outputLength != keyPair.publicKey.size()))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyGenerationFailed",
          "EVP_PKEY_get_raw_public_key() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }

    outputLength = 0;
    result = EVP_PKEY_get_raw_private_key(evpKey, 0, &outputLength);
    if (!is_openssl_result_good(result) || (outputLength == 0))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyGenerationFailed",
          "EVP_PKEY_get_raw_private_key() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }
    keyPair.privateKey.resize(outputLength);
    destination = keyPair.privateKey.data();

    result = EVP_PKEY_get_raw_private_key(evpKey, destination, &outputLength);
    if (!is_openssl_result_good(result) || (outputLength != keyPair.privateKey.size()))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyGenerationFailed",
          "EVP_PKEY_get_raw_private_key() failed in create_ephemeral_keys_sync",
          "OpenSslCrypto"));
    }
  }
  return keyPair;
}

void CryptoOpenSsl::create_ephemeral_keys_async(
  EphemeralKeyAlgorithm algorithm, CreateEphemeralKeysCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return create_ephemeral_keys_sync(algorithm); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

ByteString CryptoOpenSsl::calculate_shared_secret_sync(
  EphemeralKeyAlgorithm algorithm, span<const byte> localPrivateKey, span<const byte> remotePublicKey) const
{
  // ffdhe3072 checks its own lengths, so an empty peer value is a wrong-length nonce like any other.
  if (algorithm == EphemeralKeyAlgorithm::RsaDhFfdhe3072)
  {
    return calculate_ffdhe3072_shared_secret(localPrivateKey, remotePublicKey);
  }

  if (localPrivateKey.empty() || remotePublicKey.empty())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidInput", "Shared secret input buffer is empty", "OpenSslCrypto")
        .context(ua::ContextKeys::cryptoPrivatekeySize, std::to_string(localPrivateKey.size_bytes()))
        .context(ua::ContextKeys::cryptoPublickeySize, std::to_string(remotePublicKey.size_bytes())));
  }

  ByteString sharedSecret;
  int keyType = 0;
  int curveId = 0;
  switch (algorithm)
  {
  case EphemeralKeyAlgorithm::EccNistP256:
    keyType = EVP_PKEY_EC;
    curveId = NID_X9_62_prime256v1;
    break;

  case EphemeralKeyAlgorithm::EccNistP384:
    keyType = EVP_PKEY_EC;
    curveId = NID_secp384r1;
    break;

  case EphemeralKeyAlgorithm::EccBrainpoolP256r1:
    keyType = EVP_PKEY_EC;
    curveId = NID_brainpoolP256r1;
    break;

  case EphemeralKeyAlgorithm::EccBrainpoolP384r1:
    keyType = EVP_PKEY_EC;
    curveId = NID_brainpoolP384r1;
    break;

  case EphemeralKeyAlgorithm::EccCurve25519:
    keyType = EVP_PKEY_X25519;
    break;

  case EphemeralKeyAlgorithm::EccCurve448:
    keyType = EVP_PKEY_X448;
    break;

  default:
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAlgorithm", "algorithm is invalid in calculate_shared_secret_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(algorithm))));
  }

  EVP_PKEY* remoteKey = 0;
  UniquePtrToEvpKey remoteKeyOwner;
  EVP_PKEY* localKey = 0;
  UniquePtrToEvpKey localKeyOwner;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  UniquePtrToEcKey ecKeyOwner;
#endif

  if (curveId)
  {
    // Part 6 1.05.07 section 6.8.1: every byte belongs to raw X || Y, including a leading 0x04.
    const auto remotePubXY = remotePublicKey;

    const unsigned char* pp = utils::bytes_to_unsigned_chars(localPrivateKey.data());
    localKey = d2i_PrivateKey(keyType, 0, &pp, numeric_cast<int>(localPrivateKey.size_bytes()));
    if (!localKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "d2i_PrivateKey() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    localKeyOwner.reset(localKey);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    std::string groupName = ec_group_name_from_key(*localKey);
    if (groupName.empty())
    {
      groupName = ec_group_name_from_curve_nid(curveId);
    }
    remoteKeyOwner = ec_peer_public_key_from_xy(groupName, remotePubXY);
    remoteKey = remoteKeyOwner.get();
#else
    int keySize = 0;
    const EC_KEY* localEcKey = EVP_PKEY_get0_EC_KEY(localKey);
    if (!localEcKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EVP_PKEY_get0_EC_KEY() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }

    keySize = EC_GROUP_get_degree(EC_KEY_get0_group(localEcKey));
    if (keySize <= 0)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_GROUP_get_degree() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }

    keySize = (keySize + 7) / 8;
    // As the 3.x import (ec_peer_public_key_from_xy): exactly X || Y, so a SEC1-prefixed or padded
    // value is refused rather than read from its first 2 * keySize bytes.
    if (remotePubXY.size_bytes() != numeric_cast<size_t>(2 * keySize))
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("InvalidKeySize", "Remote EC public key size is unexpected", "OpenSslCrypto")
          .context(ua::ContextKeys::sizeActual, std::to_string(remotePubXY.size_bytes()))
          .context(ua::ContextKeys::sizeExpected, std::to_string(2 * keySize))
          .context(ua::ContextKeys::cryptoKeySize, std::to_string(keySize)));
    }

    BN_CTX* bnCtx = BN_CTX_new();
    if (!bnCtx)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "BN_CTX_new() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    BnContextOwner bnCtxOwner(*bnCtx, true);

    BIGNUM* x = BN_CTX_get(bnCtx);
    if (!x)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "BN_CTX_get() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    BIGNUM* y = BN_CTX_get(bnCtx);
    if (!y)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "BN_CTX_get() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }

    x = BN_bin2bn(utils::bytes_to_unsigned_chars(remotePubXY.data()), keySize, x);
    if (!x)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "BN_bin2bn() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    y = BN_bin2bn(utils::bytes_to_unsigned_chars(remotePubXY.data()) + keySize, keySize, y);
    if (!y)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "BN_bin2bn() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }

    EC_KEY* remoteEcKey = EC_KEY_new();
    if (!remoteEcKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "EccOperationFailed", "EC_KEY_new() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    ecKeyOwner.reset(remoteEcKey);

    int result = EC_KEY_set_group(remoteEcKey, EC_KEY_get0_group(localEcKey));
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_KEY_set_group() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }

    result = EC_KEY_set_public_key_affine_coordinates(remoteEcKey, x, y);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EC_KEY_set_public_key_affine_coordinates() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }

    remoteKey = EVP_PKEY_new();
    if (!remoteKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail(
          "KeyAgreementFailed", "EVP_PKEY_new() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
    }
    remoteKeyOwner.reset(remoteKey);

    result = EVP_PKEY_set1_EC_KEY(remoteKey, remoteEcKey);
    if (!is_openssl_result_good(result))
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("EccOperationFailed",
          "EVP_PKEY_set1_EC_KEY() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }
#endif
  }
  else
  {
    localKey = EVP_PKEY_new_raw_private_key(
      keyType, 0, utils::bytes_to_unsigned_chars(localPrivateKey.data()), localPrivateKey.size_bytes());
    if (!localKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyAgreementFailed",
          "EVP_PKEY_new_raw_private_key() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }
    localKeyOwner.reset(localKey);

    remoteKey = EVP_PKEY_new_raw_public_key(
      keyType, 0, utils::bytes_to_unsigned_chars(remotePublicKey.data()), remotePublicKey.size_bytes());
    if (!remoteKey)
    {
      throw UaException(Status::BadInternalError,
        detail::make_openssl_error_detail("KeyAgreementFailed",
          "EVP_PKEY_new_raw_public_key() failed in calculate_shared_secret_sync",
          "OpenSslCrypto"));
    }
    remoteKeyOwner.reset(remoteKey);
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(localKey, NULL);
  if (!ctx)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "KeyAgreementFailed", "EVP_PKEY_CTX_new() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
  }
  const UniquePtrToEvpKeyCtx evpKeyContextOwner(ctx);

  int result = EVP_PKEY_derive_init(ctx);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_derive_init() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
  }

  result = EVP_PKEY_derive_set_peer(ctx, remoteKey);
  if (!is_openssl_result_good(result))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail("DeriveKeyFailed",
        "EVP_PKEY_derive_set_peer() failed in calculate_shared_secret_sync",
        "OpenSslCrypto"));
  }

  size_t outputLength = 0;
  result = EVP_PKEY_derive(ctx, 0, &outputLength);
  if (!is_openssl_result_good(result) || (outputLength == 0))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_derive() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
  }
  sharedSecret.resize(outputLength);
  uint8_t* destination = sharedSecret.data();

  outputLength = sharedSecret.size();
  result = EVP_PKEY_derive(ctx, destination, &outputLength);
  if (!is_openssl_result_good(result) || (outputLength != sharedSecret.size()))
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DeriveKeyFailed", "EVP_PKEY_derive() failed in calculate_shared_secret_sync", "OpenSslCrypto"));
  }

  return sharedSecret;
}

void CryptoOpenSsl::calculate_shared_secret_async(EphemeralKeyAlgorithm algorithm, ByteString localPrivateKey,
  ByteString remotePublicKey, CalculateSharedSecretCompleteCallback callback) const noexcept
{
  const security::ScrubOnExit scrubPrivateKey{localPrivateKey};  // the caller's copy of the private key
  try
  {
    callback(detail::to_result(
      [&] { return calculate_shared_secret_sync(algorithm, localPrivateKey, remotePublicKey); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

namespace
{

/// d2i_X509 decodes the SubjectPublicKeyInfo opportunistically: a certificate whose key algorithm or
/// curve it cannot decode still parses, with a null public key behind it. Every consumer of a
/// certificate assumes a key, so such a certificate is refused here, at the one place DER enters.
void reject_certificate_without_decodable_key(X509* cert, std::string_view where)
{
  if (X509_get0_pubkey(cert) != nullptr)
  {
    return;
  }
  X509_free(cert);
  throw UaException(Status::BadCertificateInvalid,
    detail::make_openssl_error_detail("CertificateError",
      fmt::format("Certificate public key cannot be decoded in {}", where),
      "OpenSslCrypto"));
}

}  // namespace

namespace
{
/// The refusal of DER input that holds bytes after the last complete structure (decision D, item 7): a
/// certificate field is the structure and nothing else, and a partial result is never returned.
[[noreturn]] void throw_trailing_bytes(std::string_view operation, size_t trailing)
{
  // A failed decode leaves its reason on the thread's error queue; the refusal names it itself.
  ERR_clear_error();
  throw UaException(Status::BadCertificateInvalid,
    ErrorDetail::build("CertificateTrailingBytes",
      "the DER input holds bytes after the last complete structure",
      "OpenSslCrypto")
      .detail(fmt::format("{}: {} byte(s) not part of a complete structure", operation, trailing)));
}

/// Refuses a certificate whose outer SEQUENCE header at @p p is not DER (OpenSSL's decoder accepts BER): an
/// indefinite length, or a long-form length with more octets than its value needs (X.690 10.1; OPC 10000-6
/// 6.2.6 makes certificate fields DER). Cost: at most six byte reads per certificate.
void require_der_header(const unsigned char* p, const unsigned char* end, std::string_view operation)
{
  const auto refuse = [operation](const char* why)
  {
    throw UaException(Status::BadCertificateInvalid,
      ErrorDetail::build("CertificateNotDer", "the certificate is not DER encoded", "OpenSslCrypto")
        .detail(fmt::format("{}: {}", operation, why)));
  };
  if (end - p < 2)
  {
    return;  // Too short for any certificate: the decoder refuses it.
  }
  const unsigned char first = p[1];
  if (first == 0x80)
  {
    refuse("indefinite length");
  }
  if (first > 0x80)
  {
    const int octets = first & 0x7F;
    if (octets > 4 || end - p < 2 + octets)
    {
      return;  // Longer than any field: the decoder refuses it.
    }
    if (p[2] == 0x00 || (octets == 1 && p[2] < 0x80))
    {
      refuse("non-minimal long-form length");
    }
  }
}
}  // namespace

shared_ptr<const X509Certificate> CryptoOpenSsl::read_certificate_from_der(span<const byte> der) const
{
  const unsigned char* start = utils::bytes_to_unsigned_chars(der.data());
  const unsigned char* p = start;
  require_der_header(p, start + der.size(), "read_certificate_from_der");
  auto* cert = d2i_X509(NULL, &p, numeric_cast<long>(der.size()));
  if (cert == nullptr)
  {
    throw UaException(Status::BadCertificateInvalid,
      detail::make_openssl_error_detail(
        "CertificateError", "Could not parse certificate in read_certificate_from_der", "OpenSslCrypto"));
  }
  if (const auto consumed = static_cast<size_t>(p - start); consumed != der.size())
  {
    X509_free(cert);
    throw_trailing_bytes("read_certificate_from_der", der.size() - consumed);
  }
  reject_certificate_without_decodable_key(cert, "read_certificate_from_der");

  return make_shared<X509CertificateOpenSsl>(*cert);
}

std::vector<shared_ptr<const X509Certificate>> CryptoOpenSsl::read_certificates_from_der(
  span<const byte> der) const
{
  const unsigned char* start = utils::bytes_to_unsigned_chars(der.data());
  const unsigned char* end = start + der.size();
  const unsigned char* next = start;

  // Every byte must belong to a complete certificate; on any failure the certificates parsed so far
  // are released with `result` and nothing is returned.
  std::vector<shared_ptr<const X509Certificate>> result;
  while (next < end)
  {
    require_der_header(next, end, "read_certificates_from_der");
    auto* cert = d2i_X509(NULL, &next, numeric_cast<long>(end - next));
    if (cert == nullptr)
    {
      throw_trailing_bytes("read_certificates_from_der", static_cast<size_t>(end - next));
    }
    reject_certificate_without_decodable_key(cert, "read_certificates_from_der");
    result.push_back(make_shared<X509CertificateOpenSsl>(*cert));
  }

  return result;
}

shared_ptr<const X509Crl> CryptoOpenSsl::read_crl_from_der(span<const byte> der) const
{
  const unsigned char* start = utils::bytes_to_unsigned_chars(der.data());
  const unsigned char* p = start;
  auto* crl = d2i_X509_CRL(NULL, &p, numeric_cast<long>(der.size()));
  if (crl == nullptr)
  {
    throw UaException(Status::BadCertificateInvalid,
      detail::make_openssl_error_detail(
        "CertificateError", "Could not parse CRL in read_crl_from_der", "OpenSslCrypto"));
  }
  if (const auto consumed = static_cast<size_t>(p - start); consumed != der.size())
  {
    X509_CRL_free(crl);
    throw_trailing_bytes("read_crl_from_der", der.size() - consumed);
  }

  return make_shared<X509CrlOpenSsl>(*crl);
}

std::vector<shared_ptr<const X509Crl>> CryptoOpenSsl::read_crls_from_der(span<const byte> der) const
{
  const unsigned char* start = utils::bytes_to_unsigned_chars(der.data());
  const unsigned char* end = start + der.size();
  const unsigned char* next = start;

  std::vector<shared_ptr<const X509Crl>> result;
  while (next < end)
  {
    auto* crl = d2i_X509_CRL(NULL, &next, numeric_cast<long>(end - next));
    if (crl == nullptr)
    {
      throw_trailing_bytes("read_crls_from_der", static_cast<size_t>(end - next));
    }
    result.push_back(make_shared<X509CrlOpenSsl>(*crl));
  }

  return result;
}

void CryptoOpenSsl::create_certificate_async(
  const CreateCertificateConfig& parameters, CreateCertificateCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return create_certificate_sync(parameters); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

shared_ptr<const X509Certificate> CryptoOpenSsl::create_certificate_sync(
  const CreateCertificateConfig& parameters) const
{
  if (parameters.basicConstraint.pathLength &&
      (!parameters.basicConstraint.cA.value_or(false) || !parameters.keyUsage.keyCertSign))
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail("CertificateError",
        "pathLength requires CA=true and keyCertSign in create_certificate_sync",
        "OpenSslCrypto"));
  }
  if (!parameters.basicConstraint.cA.has_value() && parameters.keyUsage.keyCertSign)
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail("CertificateError",
        "keyCertSign requires explicit basic constraints in create_certificate_sync",
        "OpenSslCrypto"));
  }

  UniquePtrToCert x509Cert{X509_new()};
  auto* cert = x509Cert.get();

  X509_set_version(cert, 2);

  BIGNUM* bn{nullptr};
  auto noOfChars = BN_dec2bn(&bn, parameters.serialNumber.c_str());
  if ((noOfChars == 0) || !bn)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateError", "Serial number string invalid in create_certificate_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::certificateSerialNumber, parameters.serialNumber));
  }
  const UniquePtrToBigNum bigNum{bn};
  auto* ai = BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
  if (!ai)
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateError", "Serial number string invalid in create_certificate_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::certificateSerialNumber, parameters.serialNumber));
  }

  // Set notBefore/notAfter via ASN.1 strings rather than time_t. On 32-bit platforms time_t is
  // signed 32-bit and silently overflows for dates >= 2038-01-19; a 2050 expiry would land in 1901
  // and the certificate would appear expired immediately. ASN1_TIME_set_string_X509 takes a
  // YYYYMMDDHHMMSSZ string and selects UTCTime or GeneralizedTime per RFC 5280.
  auto formatAsn1Time = [](const UtcTime& time) -> std::string
  {
    auto sysTime = time.value();
    auto dp = std::chrono::floor<std::chrono::days>(sysTime);
    const std::chrono::year_month_day ymd{dp};
    auto totalSeconds = std::chrono::duration_cast<std::chrono::seconds>(sysTime - dp);
    const std::chrono::hh_mm_ss hms{totalSeconds};
    return fmt::format("{:04d}{:02d}{:02d}{:02d}{:02d}{:02d}Z",
      static_cast<int>(ymd.year()),
      static_cast<unsigned>(ymd.month()),
      static_cast<unsigned>(ymd.day()),
      hms.hours().count(),
      hms.minutes().count(),
      hms.seconds().count());
  };

  auto fromStr = formatAsn1Time(parameters.from);
  if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), fromStr.c_str()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateError", "Invalid notBefore time in create_certificate_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::certificateNotBefore, fromStr));
  }

  auto toStr = formatAsn1Time(parameters.to);
  if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), toStr.c_str()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "CertificateError", "Invalid notAfter time in create_certificate_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::certificateNotAfter, toStr));
  }

  X509_NAME* subjectName = X509_get_subject_name(cert);
  populate_name(parameters.subject, *subjectName);

  X509_NAME* issuerName = X509_get_issuer_name(cert);
  if (!parameters.issuer)
  {
    // Self-signed certificate
    populate_name(parameters.subject, *issuerName);
  }
  else
  {
    // Issued certificate
    const auto& issuer = *parameters.issuer;

    populate_name_field(issuer.subject_common_name(), NID_commonName, *issuerName);
    populate_name_field(issuer.subject_organization(), NID_organizationName, *issuerName);
    populate_name_field(issuer.subject_organizational_unit(), NID_organizationalUnitName, *issuerName);
    populate_name_field(issuer.subject_distinguished_name(), NID_distinguishedName, *issuerName);
    populate_name_field(issuer.subject_locality(), NID_localityName, *issuerName);
    populate_name_field(issuer.subject_state(), NID_stateOrProvinceName, *issuerName);
    populate_name_field(issuer.subject_country(), NID_countryName, *issuerName);
  }

  X509* issuer = nullptr;
  UniquePtrToCert issuerCert;
  if (parameters.issuer)
  {
    auto der = parameters.issuer->der_encoding();
    const unsigned char* p = der.data();
    issuer = d2i_X509(NULL, &p, numeric_cast<long>(der.size()));
    if (issuer == nullptr)
    {
      throw UaException(Status::BadCertificateInvalid,
        detail::make_openssl_error_detail("CertificateError",
          "Could not parse issuer certificate in create_certificate_sync",
          "OpenSslCrypto"));
    }
    issuerCert.reset(issuer);
  }
  else
  {
    issuer = cert;
  }
  auto certs{Certs{*cert, *issuer}};
  add_key_usage_extension(certs, parameters.keyUsage);
  add_subject_alternate_name(certs, parameters.subjectAlternateName);
  add_basic_constraints(certs, parameters.basicConstraint);

  const auto* subjectKeys = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(parameters.subjectKeys.get());
  if (!subjectKeys)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidKeySize",
        "AsymmetricKeyPair of invalid concrete type in create_certificate_sync",
        "OpenSslCrypto"));
  }

  X509_set_pubkey(cert, subjectKeys->public_key_evp().get());
  add_extension(certs, NID_subject_key_identifier, "hash");
  add_extension(certs, NID_authority_key_identifier, "keyid:always");

  const auto* issuerKeys = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(parameters.issuerKeys.get());
  if (!issuerKeys)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidKeySize",
        "AsymmetricKeyPair of invalid concrete type in create_certificate_sync",
        "OpenSslCrypto"));
  }

  const EVP_MD* md = nullptr;
  switch (parameters.certificateSignatureAlgorithm)
  {
  case CertificateSignatureAlgorithm::RsaPkcs15Sha1:
    md = EVP_sha1();
    break;

  case CertificateSignatureAlgorithm::RsaPkcs15Sha2256:
  case CertificateSignatureAlgorithm::EcDsaSha2256:
    md = EVP_sha256();
    break;

  case CertificateSignatureAlgorithm::RsaPkcs15Sha2224:
    md = EVP_sha224();
    break;

  case CertificateSignatureAlgorithm::RsaPkcs15Sha2384:
    md = EVP_sha384();
    break;

  case CertificateSignatureAlgorithm::RsaPkcs15Sha2512:
    md = EVP_sha512();
    break;

  case CertificateSignatureAlgorithm::RsaPssSha2256:
  case CertificateSignatureAlgorithm::RsaPssSha2384:
  case CertificateSignatureAlgorithm::RsaPssSha2512:
    // Creating RSASSA-PSS signatures is not supported; refused rather than signed with another padding.
    throw UaException(Status::BadNotSupported,
      ErrorDetail::build("CertificateSignatureAlgorithmNotSupported",
        "Creating an RSASSA-PSS certificate signature is not supported",
        "OpenSslCrypto"));

  case CertificateSignatureAlgorithm::EcDsaSha2384:
    md = EVP_sha384();
    break;

  case CertificateSignatureAlgorithm::EcDsaSha2512:
    md = EVP_sha512();
    break;

  case CertificateSignatureAlgorithm::PureEdDsa25519:
  case CertificateSignatureAlgorithm::PureEdDsa448:
  default:
    break;
  }

  if (X509_sign(cert, issuerKeys->private_key_evp().get(), md) == 0)
  {
    throw UaException(Status::BadInternalError,
      ErrorDetail::build(
        "SigningFailed", "Certificate signing failed in create_certificate_sync", "OpenSslCrypto")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::certificateSubject, parameters.subject.commonName));
  }

  // Part 6 section 6.2.2 requires keyCertSign on self-signed application certificates with cA FALSE.
  // Permit that combination only for an actual self-signature; it does not grant issuer authority.
  if (!parameters.basicConstraint.cA.value_or(false) && parameters.keyUsage.keyCertSign &&
      (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) != 0 ||
        X509_verify(cert, subjectKeys->public_key_evp().get()) != 1))
  {
    throw UaException{Status::BadInvalidArgument,
      detail::make_openssl_error_detail("CertificateError",
        "Non-CA certificate signing usage requires a self-signed certificate",
        "OpenSslCrypto")};
  }

  shared_ptr<const X509Certificate> result = make_unique<X509CertificateOpenSsl>(*cert);
  // X509CertificateOpenSsl adopted *cert and frees it in its dtor; detach our handle so the X509 is not
  // double-freed. Released after a successful make_unique, so a make_unique failure still frees via x509Cert.
  [[maybe_unused]] const X509* const released = x509Cert.release();
  return result;
}

void CryptoOpenSsl::create_certificate_signing_request_async(
  const CreateCsrConfig& parameters, CreateCertificateSigningRequestCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result(
      [&]() -> ByteString
      {
        if (parameters.basicConstraint.pathLength &&
            (!parameters.basicConstraint.cA.value_or(false) || !parameters.keyUsage.keyCertSign))
        {
          throw UaException(Status::BadInvalidArgument,
            detail::make_openssl_error_detail("CertificateError",
              "pathLength requires CA=true and keyCertSign in create_certificate_signing_request_async",
              "OpenSslCrypto"));
        }
        if (!parameters.basicConstraint.cA.value_or(false) && parameters.keyUsage.keyCertSign)
        {
          throw UaException(Status::BadInvalidArgument,
            detail::make_openssl_error_detail("CertificateError",
              "keyCertSign requires CA=true in create_certificate_signing_request_async",
              "OpenSslCrypto"));
        }

        const UniquePtrToCsr x509Csr{X509_REQ_new()};
        auto* csr = x509Csr.get();

        X509_NAME* subjectName = X509_REQ_get_subject_name(csr);
        populate_name(parameters.subject, *subjectName);

        // Collected, then attached once: see CsrExtensions. Attaching each in turn made the second one
        // a duplicate extReq attribute, which OpenSSL 3 refuses.
        CsrExtensions extensions{*csr};
        add_key_usage_extension(extensions, parameters.keyUsage);
        add_subject_alternate_name(extensions, parameters.subjectAlternateName);
        add_basic_constraints(extensions, parameters.basicConstraint);
        extensions.attach();

        const auto* subjectKeys = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(parameters.subjectKeys.get());
        if (!subjectKeys)
        {
          throw UaException(Status::BadInvalidArgument,
            make_error_detail("InvalidKeySize",
              "AsymmetricKeyPair of invalid concrete type in create_certificate_signing_request_async",
              "OpenSslCrypto"));
        }

        X509_REQ_set_pubkey(csr, subjectKeys->public_key_evp().get());

        // In a CSR, extensions like SKI and AKID that require an issuer or subject certificate
        // to be fully formed cannot be added using the simple "hash" or "keyid" string configuration
        // if the context is not fully available. For now, we omit them from the CSR as they are
        // typically added by the CA during signing.

        const EVP_MD* md = nullptr;
        switch (parameters.certificateSignatureAlgorithm)
        {
        case CertificateSignatureAlgorithm::RsaPkcs15Sha1:
          md = EVP_sha1();
          break;

        case CertificateSignatureAlgorithm::RsaPkcs15Sha2256:
        case CertificateSignatureAlgorithm::EcDsaSha2256:
          md = EVP_sha256();
          break;

        case CertificateSignatureAlgorithm::RsaPkcs15Sha2224:
          md = EVP_sha224();
          break;

        case CertificateSignatureAlgorithm::RsaPkcs15Sha2384:
          md = EVP_sha384();
          break;

        case CertificateSignatureAlgorithm::RsaPkcs15Sha2512:
          md = EVP_sha512();
          break;

        case CertificateSignatureAlgorithm::RsaPssSha2256:
        case CertificateSignatureAlgorithm::RsaPssSha2384:
        case CertificateSignatureAlgorithm::RsaPssSha2512:
          // Creating RSASSA-PSS signatures is not supported; refused rather than signed with another padding.
          throw UaException(Status::BadNotSupported,
            ErrorDetail::build("CertificateSignatureAlgorithmNotSupported",
              "Creating an RSASSA-PSS certificate signature is not supported",
              "OpenSslCrypto"));

        case CertificateSignatureAlgorithm::EcDsaSha2384:
          md = EVP_sha384();
          break;

        case CertificateSignatureAlgorithm::EcDsaSha2512:
          md = EVP_sha512();
          break;

        case CertificateSignatureAlgorithm::PureEdDsa25519:
        case CertificateSignatureAlgorithm::PureEdDsa448:
        default:
          break;
        }

        if (X509_REQ_sign(csr, subjectKeys->private_key_evp().get(), md) == 0)
        {
          throw UaException(Status::BadInternalError,
            ErrorDetail::build("SigningFailed",
              "Certificate request signing failed in create_certificate_signing_request_async",
              "OpenSslCrypto")
              .detail(detail::drain_openssl_errors())
              .context(ua::ContextKeys::certificateSubject, parameters.subject.commonName));
        }

        auto length = i2d_X509_REQ(csr, NULL);
        if (length < 0)
        {
          throw UaException(Status::BadInternalError,
            detail::make_openssl_error_detail("CertificateError",
              "i2d_X509_REQ() failed to compute DER length in create_certificate_signing_request_async",
              "OpenSslCrypto"));
        }

        ByteString result;
        // i2d_X509_REQ() returns the positive DER length on success and a negative value on
        // error; the `length < 0` guard above proves length is non-negative here.
        result.resize(static_cast<size_t>(length));
        auto* dest = result.data();
        length = i2d_X509_REQ(csr, &dest);
        if (length < 0)
        {
          throw UaException(Status::BadInternalError,
            detail::make_openssl_error_detail("CertificateError",
              "i2d_X509_REQ() failed to encode DER in create_certificate_signing_request_async",
              "OpenSslCrypto"));
        }

        return result;
      }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

shared_ptr<const AsymmetricKeyPair> CryptoOpenSsl::get_public_key_from_der(
  CertificateKeyAlgorithm keyAlgorithm, span<const byte> der) const
{
  return make_shared<AsymmetricKeyPairOpenSsl>(keyAlgorithm, der);
}

void CryptoOpenSsl::sign_certificate_request_async(
  const SignCsrConfig& parameters, SignCsrCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return sign_certificate_request_sync(parameters); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

shared_ptr<const X509Certificate> CryptoOpenSsl::sign_certificate_request_sync(
  const SignCsrConfig& parameters) const
{
  // 1. Parse the CSR DER
  const unsigned char* csrIn = parameters.csrDer.data();
  const UniquePtrToCsr csr{d2i_X509_REQ(NULL, &csrIn, numeric_cast<long>(parameters.csrDer.size()))};
  if (!csr)
  {
    throw UaException(Status::BadDecodingError,
      detail::make_openssl_error_detail(
        "CsrParseFailed", "d2i_X509_REQ() failed: could not parse CSR DER", "OpenSslCrypto"));
  }

  // 2. Verify the CSR self-signature
  const UniquePtrToEvpKey csrPubKey{X509_REQ_get_pubkey(csr.get())};
  if (!csrPubKey)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      detail::make_openssl_error_detail("CsrPubKeyFailed", "X509_REQ_get_pubkey() failed", "OpenSslCrypto"));
  }

  if (X509_REQ_verify(csr.get(), csrPubKey.get()) != 1)
  {
    throw UaException(Status::BadSecurityChecksFailed,
      detail::make_openssl_error_detail("CsrVerifyFailed",
        "X509_REQ_verify() failed: CSR self-signature verification failed",
        "OpenSslCrypto"));
  }

  // 3. Extract the public key DER
  const int pubKeyLen = i2d_PUBKEY(csrPubKey.get(), nullptr);
  if (pubKeyLen <= 0)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "PubKeyEncodeFailed", "i2d_PUBKEY() failed to compute DER length", "OpenSslCrypto"));
  }
  ByteString pubKeyDer;
  // pubKeyLen > 0 proven by the (pubKeyLen <= 0) throw guard above.
  pubKeyDer.resize(static_cast<size_t>(pubKeyLen));
  auto* pubKeyDest = pubKeyDer.data();
  i2d_PUBKEY(csrPubKey.get(), &pubKeyDest);

  // 4. Determine the key algorithm from the CSR public key
  CertificateKeyAlgorithm keyAlgorithm = CertificateKeyAlgorithm::Rsa;
  const int keyType = EVP_PKEY_base_id(csrPubKey.get());
  if (keyType == EVP_PKEY_EC)
  {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    auto groupName = ec_group_name_from_key(*csrPubKey);
    // P-256 (prime256v1) is the default for EC keys, including unrecognised curves.
    keyAlgorithm = CertificateKeyAlgorithm::EccNistP256;
    if (groupName == "secp384r1" || groupName == "P-384")
      keyAlgorithm = CertificateKeyAlgorithm::EccNistP384;
    else if (groupName == "brainpoolP256r1")
      keyAlgorithm = CertificateKeyAlgorithm::EccBrainpoolP256r1;
    else if (groupName == "brainpoolP384r1")
      keyAlgorithm = CertificateKeyAlgorithm::EccBrainpoolP384r1;
#else
    keyAlgorithm = CertificateKeyAlgorithm::EccNistP256;
#endif
  }
  else if (keyType == EVP_PKEY_ED25519)
  {
    keyAlgorithm = CertificateKeyAlgorithm::EccCurve25519;
  }
  else if (keyType == EVP_PKEY_ED448)
  {
    keyAlgorithm = CertificateKeyAlgorithm::EccCurve448;
  }

  // 5. Create a public-key-only AsymmetricKeyPair
  auto subjectKeys = get_public_key_from_der(keyAlgorithm, pubKeyDer);

  // 6. Extract the subject name from the CSR
  X509_NAME* csrSubject = X509_REQ_get_subject_name(csr.get());
  Crypto::Name subject;
  if (csrSubject)
  {
    auto extractField = [&](int nid) -> std::string
    {
      const int idx = X509_NAME_get_index_by_NID(csrSubject, nid, -1);
      if (idx < 0)
        return {};
      X509_NAME_ENTRY* entry = X509_NAME_get_entry(csrSubject, idx);
      if (!entry)
        return {};
      ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
      if (!data)
        return {};
      UniquePtrToOpenSslBuf utf8{nullptr};
      unsigned char* utf8Raw = nullptr;
      const int len = ASN1_STRING_to_UTF8(&utf8Raw, data);
      utf8.reset(utf8Raw);
      if (len < 0 || !utf8)
        return {};
      return std::string(reinterpret_cast<char*>(utf8.get()), numeric_cast<size_t>(len));
    };

    subject.commonName = extractField(NID_commonName);
    subject.organization = extractField(NID_organizationName);
    subject.organizationUnit = extractField(NID_organizationalUnitName);
    subject.distinguishedName = extractField(NID_distinguishedName);
    subject.locality = extractField(NID_localityName);
    subject.state = extractField(NID_stateOrProvinceName);
    subject.country = extractField(NID_countryName);

    if (subject.commonName.empty() && subject.organization.empty() && subject.organizationUnit.empty() &&
        subject.distinguishedName.empty() && subject.locality.empty() && subject.state.empty() &&
        subject.country.empty())
    {
      const UniquePtrToOpenSslCharBuf oneline{X509_NAME_oneline(csrSubject, nullptr, 0)};
      if (oneline && oneline.get()[0] != '\0')
      {
        subject.commonName = oneline.get();
      }
    }
  }

  // 7. Build CreateCertificateConfig and delegate to create_certificate_sync
  CreateCertificateConfig certParams;
  certParams.serialNumber = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
  certParams.subject = std::move(subject);
  certParams.issuer = parameters.issuer;
  certParams.issuerKeys = parameters.issuerKeys;
  certParams.subjectKeys = std::move(subjectKeys);
  certParams.certificateSignatureAlgorithm = parameters.signatureAlgorithm;
  certParams.from = parameters.from;
  certParams.to = parameters.to;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.nonRepudiation = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.keyUsage.dataEncipherment = true;
  certParams.keyUsage.serverAuth = true;
  certParams.keyUsage.clientAuth = true;
  certParams.subjectAlternateName = parameters.subjectAlternateName;

  return create_certificate_sync(certParams);
}

shared_ptr<const ErrorDetail> CryptoOpenSsl::validate_certificate_impl(
  const CertificateValidationRequest& request, const CertificateValidationMaterial& material) const
{
  // What is validated comes from the request; what it is validated against from the material. The
  // request's own options and connection trust were resolved into the material by the caller.
  const TrustListValidationOptions& validationOptions = material.options;
  const shared_ptr<const X509Certificate>& certificate = request.certificate;
  const std::vector<shared_ptr<const X509Certificate>>& trustedCertificates = material.trusted;
  const std::vector<shared_ptr<const X509Crl>>& trustedCrls = material.trustedCrls;
  const std::vector<shared_ptr<const X509Certificate>>& issuerCertificates = material.issuers;
  const std::vector<shared_ptr<const X509Crl>>& issuerCrls = material.issuerCrls;
  const optional<std::string>& applicationUri = request.applicationUri;
  const optional<std::string>& endpointUrl = request.endpointUrl;
  const CertificateUse use = request.use.value_or(CertificateUse::ApplicationInstance);

  const bool checkRevocationOffline =
    validationOptions.test(TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  const bool checkRevocationOnline =
    validationOptions.test(TrustListValidationOptions::Bit::CheckRevocationStatusOnline);

  // Online revocation checks (AIA/OCSP/CRLDP fetching) are intentionally not implemented.
  if (checkRevocationOnline && !checkRevocationOffline)
  {
    throw UaException{Status::BadNotSupported,
      make_error_detail("OnlineRevocationNotSupported",
        "Online-only certificate revocation checking is not supported; "
        "enable CheckRevocationStatusOffline or disable CheckRevocationStatusOnline",
        "CertificateValidation")};
  }

  const auto* concreteCertificate = dynamic_cast<const X509CertificateOpenSsl*>(certificate.get());
  if (!concreteCertificate)
  {
    throw UaException{Status::BadCertificateInvalid,
      make_error_detail("CertificateNotReadable",
        "the certificate is null or not an OpenSSL certificate",
        "CertificateValidation")};
  }

  // Part 4 section 6.1.3, Build Certificate Chain: the chain is built from the trusted list, the issuer
  // list and the certificates the peer presented (request.presentedIssuers), and must reach
  // a self-signed root wherever that root is. So every SELF-SIGNED certificate of either list is a
  // path-building anchor in the X509_STORE, and every other certificate is untrusted chain material.
  // Being an anchor confers no trust here: the Trust List Check below decides trust from the built chain,
  // so a trusted intermediate or leaf is found as chain material and still counts, and OpenSSL never stops
  // its search at a trusted certificate that is not a root. Partial-chain mode is never used (owner
  // decision 22.5): a certificate accepted for one session is an additional trusted certificate and its
  // chain must still be complete. Cost: one extension-flag read per list certificate per validation.
  // Every list certificate, for the retries below and the Certificate Structure check of a refused
  // candidate issuer.
  const auto forEachListedCertificate = [&](const auto& visit)
  {
    for (const auto* certificates : {&trustedCertificates, &issuerCertificates, &request.presentedIssuers})
    {
      for (const auto& cert : *certificates)
      {
        if (const auto* ct = dynamic_cast<const X509CertificateOpenSsl*>(cert.get()))
        {
          visit(ct->cert());
        }
      }
    }
  };

  // OpenSSL picks one issuer by name and key identifier and does not try another when that issuer's key
  // does not verify the signature. Two list certificates can carry the same name, and only one of them may
  // be the real issuer, so a signature failure on an issuer that has a same-name alternative repeats the
  // path building without it. Each repeat excludes one more list certificate, so there are at most as many
  // repeats as list certificates, and there are none when the first chain has no such signature failure.
  std::vector<const X509*> excludedIssuers;
  UniquePtrToX509Store store;
  UniquePtrToStackOfX509 chainMaterial;
  UniquePtrToX509StoreCtx storeCtx;
  VerifyErrorRecorder recorder;
  int verifyResult = 0;
  for (;;)
  {
    storeCtx.reset();
    store.reset(X509_STORE_new());
    chainMaterial.reset(sk_X509_new_null());
    if (!store || !chainMaterial)
    {
      throw UaException{Status::BadOutOfMemory,
        ErrorDetail::build("CertificateValidationSetupFailed",
          "Could not allocate the certificate store for validation",
          "CertificateValidation")
          .detail(detail::drain_openssl_errors())};
    }
    const auto addAnchorOrChainMaterial =
      [&store, &chainMaterial, &excludedIssuers](
        const std::vector<shared_ptr<const X509Certificate>>& certificates)
    {
      for (const auto& cert : certificates)
      {
        const auto* ct = dynamic_cast<const X509CertificateOpenSsl*>(cert.get());
        if (!ct || std::ranges::find(excludedIssuers, &ct->cert()) != excludedIssuers.end())
        {
          continue;
        }
        auto* x509 = const_cast<X509*>(&ct->cert());
        if ((X509_get_extension_flags(x509) & EXFLAG_SS) != 0)
        {
          X509_STORE_add_cert(store.get(), x509);
        }
        else
        {
          sk_X509_push(chainMaterial.get(), x509);
        }
      }
    };
    addAnchorOrChainMaterial(trustedCertificates);
    addAnchorOrChainMaterial(issuerCertificates);
    // The presented issuers are chain material only: they never confer trust (the Trust List Check reads
    // the material's trusted list alone).
    addAnchorOrChainMaterial(request.presentedIssuers);

    for (const auto* crls : {&trustedCrls, &issuerCrls})
    {
      for (const auto& crl : *crls)
      {
        const auto* concreteCrl = dynamic_cast<const X509CrlOpenSsl*>(crl.get());
        if (concreteCrl)
        {
          X509_STORE_add_crl(store.get(), const_cast<X509_CRL*>(&concreteCrl->crl()));
        }
      }
    }

    storeCtx.reset(X509_STORE_CTX_new());
    if (!storeCtx || X509_STORE_CTX_init(storeCtx.get(),
                       store.get(),
                       const_cast<X509*>(&concreteCertificate->cert()),
                       chainMaterial.get()) != 1)
    {
      throw UaException{Status::BadOutOfMemory,
        ErrorDetail::build("CertificateValidationSetupFailed",
          "Could not initialise the certificate verification context",
          "CertificateValidation")
          .detail(detail::drain_openssl_errors())};
    }

    // Strict flags for OPC UA compliance. CHECK_SS_SIGNATURE: a self-signed certificate's own signature is
    // verified too (Table 106 Signature), which OpenSSL otherwise skips for the root.
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(storeCtx.get());
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (checkRevocationOffline)
    {
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK_ALL);
    }

    recorder = VerifyErrorRecorder{};
    X509_STORE_CTX_set_app_data(storeCtx.get(), &recorder);
    X509_STORE_CTX_set_verify_cb(storeCtx.get(), record_certificate_error_and_continue);

    verifyResult = X509_verify_cert(storeCtx.get());

    // The issuer to build without, if a signature failed and a same-name alternative is still untried.
    const X509* refusedIssuer = nullptr;
    if (!recorder.recordingFailed)
    {
      const STACK_OF(X509)* builtChain = X509_STORE_CTX_get0_chain(storeCtx.get());
      const int builtSize = builtChain == nullptr ? 0 : sk_X509_num(builtChain);
      for (const auto& record : recorder.errors)
      {
        if ((record.error != X509_V_ERR_CERT_SIGNATURE_FAILURE &&
              record.error != X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE) ||
            record.depth + 1 >= builtSize)
        {
          continue;
        }
        X509* subject = sk_X509_value(builtChain, record.depth);
        const X509* issuer = sk_X509_value(builtChain, record.depth + 1);
        bool alternativeExists = false;
        forEachListedCertificate(
          [&](const X509& candidate)
          {
            alternativeExists =
              alternativeExists ||
              (&candidate != issuer &&
                std::ranges::find(excludedIssuers, &candidate) == excludedIssuers.end() &&
                X509_NAME_cmp(X509_get_subject_name(&candidate), X509_get_issuer_name(subject)) == 0);
          });
        if (alternativeExists)
        {
          refusedIssuer = issuer;
          break;
        }
      }
    }
    if (refusedIssuer == nullptr)
    {
      break;
    }
    excludedIssuers.push_back(refusedIssuer);
    detail::drain_openssl_errors();
  }
  const std::string openSslErrors = detail::drain_openssl_errors();
  if (recorder.recordingFailed || (verifyResult < 0 && recorder.errors.empty()))
  {
    throw UaException{Status::BadSecurityChecksFailed,
      ErrorDetail::build("CertificateChainValidationFailed",
        "Certificate chain validation could not run to completion",
        "CertificateValidation")
        .detail(openSslErrors)
        .context(ua::ContextKeys::certificateSubject, certificate->subject_common_name())};
  }

  const auto certSubject = certificate->subject_common_name();

  // The chain OpenSSL built, from the certificate under validation towards its root, each entry also as an
  // X509Certificate (one reference count and one small allocation per chain certificate per validation) so
  // the Security Policy Check and the fault reports can name and examine every certificate of it.
  const STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(storeCtx.get());
  const int chainSize = chain == nullptr ? 0 : sk_X509_num(chain);
  X509* chainEnd = chainSize > 0 ? sk_X509_value(chain, chainSize - 1) : nullptr;
  const bool chainReachesSelfSignedRoot =
    chainEnd != nullptr && (X509_get_extension_flags(chainEnd) & EXFLAG_SS) != 0;
  std::vector<shared_ptr<const X509Certificate>> chainCertificates;
  chainCertificates.reserve(static_cast<std::size_t>(chainSize));
  for (int index = 0; index < chainSize; ++index)
  {
    X509* entry = sk_X509_value(chain, index);
    if (entry == nullptr || X509_up_ref(entry) != 1)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build("CertificateChainEntryMissing",
          "OpenSSL returned an incomplete verified certificate chain",
          "CertificateValidation")
          .context(ua::ContextKeys::chainDepth, std::to_string(index))};
    }
    chainCertificates.push_back(std::make_shared<X509CertificateOpenSsl>(*entry));
  }
  // The subject of the certificate at @p depth of the chain; the certificate under validation's otherwise.
  const auto subjectAt = [&chainCertificates, &certSubject](int depth)
  {
    return depth > 0 && static_cast<std::size_t>(depth) < chainCertificates.size()
             ? chainCertificates[static_cast<std::size_t>(depth)]->subject_common_name()
             : certSubject;
  };

  // Part 4 section 6.1.3: the steps run in Table 106 order and the first error that is not suppressed
  // decides. Every fault is collected with its step; a suppressed one is set aside (it is still reported
  // through auditing, which is why it is kept), and the earliest remaining step is the verdict.
  std::vector<CertificateValidationFault> faults;
  std::vector<CertificateValidationFault> suppressedFaults;
  const auto addFault =
    [&faults, &suppressedFaults, &validationOptions](
      int step, int depth, std::optional<TrustListValidationOptions::Bit> suppressedBy, UaException error)
  {
    auto& target = (suppressedBy && validationOptions.test(*suppressedBy)) ? suppressedFaults : faults;
    target.push_back(CertificateValidationFault{step, depth, std::move(error)});
  };

  bool chainIncompleteRecorded = false;
  for (const auto& record : recorder.errors)
  {
    // A directly trusted self-signed certificate has no issuing CA and therefore no issuer CRL.
    if (record.selfSigned && is_revocation_status_unknown_error(record.error))
    {
      continue;
    }
    int classifiedError = record.error;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    // OpenSSL 1.1.1's strict mode reports a pathLenConstraint on a certificate that is not a CA as
    // X509_V_ERR_INVALID_EXTENSION, a code it also uses for CRL and RFC 3779 faults; OpenSSL 3 reports it
    // as X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA. It is classified as the same Certificate Usage fault, by
    // the condition 1.1.1 tests (x509_vfy.c check_chain_extensions).
    if (record.error == X509_V_ERR_INVALID_EXTENSION && record.depth >= 0 && record.depth < chainSize)
    {
      X509* reported = sk_X509_value(chain, record.depth);
      if ((X509_get_extension_flags(reported) & EXFLAG_CA) == 0 && X509_get_pathlen(reported) != -1)
      {
        classifiedError = X509_V_ERR_INVALID_NON_CA;
      }
    }
#endif
    const auto rule = verify_error_rule(classifiedError, record.depth);
    if (!rule)
    {
      continue;
    }
    auto builder = ErrorDetail::build(rule->code, rule->summary, "CertificateValidation");
    builder.detail(openSslErrors)
      .context(ua::ContextKeys::certificateSubject, subjectAt(record.depth))
      .context(ua::ContextKeys::chainDepth, std::to_string(record.depth))
      .context(ua::ContextKeys::cryptoError, std::string(X509_verify_cert_error_string(record.error)));
    if (rule->step == table_106::buildChain)
    {
      // Part 4 section 6.1.3 (owner decision 22.5): the missing issuer is named.
      chainIncompleteRecorded = true;
      builder.context(ua::ContextKeys::certificateIssuer, record.issuer);
    }
    addFault(rule->step, record.depth, rule->suppressedBy, UaException{rule->status, std::move(builder)});
  }

  // Certificate Structure (Table 106 step 1) for the rules OpenSSL does not report: every certificate of
  // the built chain, and, when the chain stops short of a root, every list certificate that carries the
  // missing issuer's name - OpenSSL declines to use a structurally invalid certificate as an issuer, which
  // would otherwise be reported as an incomplete chain rather than as the invalid certificate it is.
  const auto addStructureFault = [&addFault, &openSslErrors](
                                   const X509& defective, int depth, const char* why)
  {
    auto* x509 = const_cast<X509*>(&defective);
    addFault(table_106::structure,
      depth,
      std::nullopt,
      UaException{Status::BadCertificateInvalid,
        ErrorDetail::build("CertificateStructureInvalid",
          std::string{"Certificate structure invalid: "} + why,
          "CertificateValidation")
          .detail(openSslErrors)
          .context(ua::ContextKeys::certificateSubject, x509_name_text(X509_get_subject_name(x509)))
          .context(ua::ContextKeys::chainDepth, std::to_string(depth))});
  };
  if (chainSize == 0)
  {
    if (const char* why = certificate_structure_defect(concreteCertificate->cert()))
    {
      addStructureFault(concreteCertificate->cert(), 0, why);
    }
  }
  for (int index = 0; index < chainSize; ++index)
  {
    if (const char* why = certificate_structure_defect(*sk_X509_value(chain, index)))
    {
      addStructureFault(*sk_X509_value(chain, index), index, why);
    }
  }
  if (!chainReachesSelfSignedRoot)
  {
    X509* lastBuilt = chainEnd != nullptr ? chainEnd : const_cast<X509*>(&concreteCertificate->cert());
    forEachListedCertificate(
      [&](const X509& candidate)
      {
        if (X509_NAME_cmp(X509_get_subject_name(&candidate), X509_get_issuer_name(lastBuilt)) != 0)
        {
          return;
        }
        if (const char* why = certificate_structure_defect(candidate))
        {
          addStructureFault(candidate, chainSize, why);
        }
      });
  }

  // Build Certificate Chain, made explicit: a chain that does not end at a self-signed certificate is
  // incomplete even if OpenSSL reported it in a way the mapping above does not classify.
  if (!chainReachesSelfSignedRoot && !chainIncompleteRecorded)
  {
    auto builder = ErrorDetail::build(
      "CertificateChainValidationFailed", "Certificate chain validation failed", "CertificateValidation");
    builder.detail(openSslErrors)
      .context(ua::ContextKeys::certificateSubject, certSubject)
      .context(ua::ContextKeys::chainDepth, std::to_string(chainSize > 0 ? chainSize - 1 : 0));
    if (chainEnd != nullptr)
    {
      builder.context(ua::ContextKeys::certificateIssuer, x509_name_text(X509_get_issuer_name(chainEnd)));
    }
    addFault(table_106::buildChain,
      chainSize > 0 ? chainSize - 1 : 0,
      std::nullopt,
      UaException{Status::BadCertificateChainIncomplete, std::move(builder)});
  }

  // Security Policy Check (Table 106 step 4), after the chain and its signatures and before trust; never
  // suppressed (owner decision 22.3). Part 6 section 6.1 adds two edge-wise invariants beyond RFC 5280
  // path validation: an issued certificate cannot have a longer key or a higher-priority signature
  // algorithm than its issuer. With a policy named they are its Bad_CertificatePolicyCheckFailed; without
  // one they keep their own refusal.
  shared_ptr<const SecurityPolicy> policy;
  if (request.policyId.has_value())
  {
    const auto supportedPolicies = SecurityPolicy::supported_policy_ids();
    if (std::find(supportedPolicies.begin(), supportedPolicies.end(), *request.policyId) !=
        supportedPolicies.end())
    {
      policy = SecurityPolicy::create(*request.policyId);
    }
    else
    {
      auto builder = ErrorDetail::build("UnknownSecurityPolicy",
        "The request names a SecurityPolicyId that has no policy",
        "CertificateValidation");
      builder.context(
        ua::ContextKeys::securityPolicy, std::to_string(utils::to_underlying(*request.policyId)));
      addFault(table_106::securityPolicy,
        0,
        std::nullopt,
        UaException{Status::BadCertificatePolicyCheckFailed, std::move(builder)});
    }
  }
  if (chainSize > 1)
  {
    try
    {
      validate_chain_monotonicity(*storeCtx);
    }
    catch (const UaException& e)
    {
      addFault(table_106::securityPolicy,
        0,
        std::nullopt,
        policy ? UaException{Status::BadCertificatePolicyCheckFailed, e.status_code().shared_detail()} : e);
    }
  }
  // The policy's own rules, for EVERY certificate of the chain (Part 6 section 6.1: "including Issuers in
  // the chain"): the leaf as EndEntity, its issuer as IssuingCa, every CA above as HigherCa; each judged
  // with the key that signed it, the self-signed root with its own. A chain that does not reach a root
  // has no signer for its last certificate, and has already failed Build Certificate Chain.
  if (policy)
  {
    for (int index = 0; index < chainSize; ++index)
    {
      const bool last = index + 1 == chainSize;
      if (last && !chainReachesSelfSignedRoot)
      {
        break;
      }
      const auto& subject = *chainCertificates[static_cast<std::size_t>(index)];
      const auto& signer = last ? subject : *chainCertificates[static_cast<std::size_t>(index + 1)];
      const auto position = index == 0   ? CertificateChainPosition::EndEntity
                            : index == 1 ? CertificateChainPosition::IssuingCa
                                         : CertificateChainPosition::HigherCa;
      const auto verdict = policy->check_certificate_compliance(subject, signer, position);
      if (verdict.is_bad())
      {
        addFault(table_106::securityPolicy, index, std::nullopt, UaException{verdict.status_code()});
      }
    }
  }

  // Trust List Check: a complete chain is trusted when the certificate or at least one certificate of its
  // chain is in the trusted list, matched by thumbprint and DER encoding (X509_cmp compares the SHA-1
  // digest, then the encoding). Only meaningful for a complete chain: an incomplete one already failed the
  // earlier step. Cost: one comparison per chain certificate per trusted certificate.
  if (chainReachesSelfSignedRoot)
  {
    bool trusted = false;
    for (int index = 0; index < chainSize && !trusted; ++index)
    {
      const X509* chainCertificate = sk_X509_value(chain, index);
      for (const auto& trustedCertificate : trustedCertificates)
      {
        const auto* ct = dynamic_cast<const X509CertificateOpenSsl*>(trustedCertificate.get());
        if (ct && chainCertificate && X509_cmp(chainCertificate, &ct->cert()) == 0)
        {
          trusted = true;
          break;
        }
      }
    }
    if (!trusted)
    {
      addFault(table_106::trustList,
        0,
        std::nullopt,
        UaException{Status::BadCertificateUntrusted,
          ErrorDetail::build("CertificateChainValidationFailed",
            "Certificate chain validation failed",
            "CertificateValidation")
            .detail("neither the certificate nor any certificate of its chain is in the trusted list")
            .context(ua::ContextKeys::certificateSubject, certSubject)
            .context(ua::ContextKeys::chainDepth, std::to_string(chainSize - 1))});
    }
  }

  // The host name and the URI do not apply to a certificate requested as a CA.
  if (use != CertificateUse::CertificateAuthority)
  {
    // Host Name: against the EndpointUrl, when there is one.
    if (endpointUrl)
    {
      // Extract hostname from endpointUrl (e.g. opc.tcp://localhost:4840). An IPv6 literal is
      // bracketed (opc.tcp://[::1]:4840, RFC 3986): the host is what the brackets enclose, since a
      // cut at the first ':' would leave "[" and fail every IPv6 endpoint closed (review B3-12). A
      // value the parser refuses is compared whole, as a bare host name: a malformed URL then matches
      // no SAN and the check fails closed.
      auto parsedEndpoint = ua::transport::parse_opc_tcp_url(*endpointUrl, "CertificateValidation");
      std::string targetHost =
        parsedEndpoint.is_good() ? std::move(parsedEndpoint).value().hostname : std::string{*endpointUrl};

      // The one host-name rule (ua::detail::certificate_matches_hostname), shared with the client's
      // CreateSession check and the server's endpoint check.
      const bool found = ua::detail::certificate_matches_hostname(targetHost, *certificate);

      if (!found)
      {
        addFault(table_106::hostName,
          0,
          TrustListValidationOptions::Bit::SuppressHostNameInvalid,
          UaException{Status::BadCertificateHostNameInvalid,
            ErrorDetail::build("CertificateHostNameMismatch",
              "Certificate SAN does not contain the hostname from the EndpointUrl",
              "CertificateValidation")
              .context(ua::ContextKeys::certificateSubject, certSubject)
              .context(ua::ContextKeys::endpointAddress, targetHost)
              .context(ua::ContextKeys::endpointUrl, *endpointUrl)});
      }
    }

    // URI: against the ApplicationUri, when there is one. Never suppressed (Part 4; owner decision 22.3).
    if (applicationUri)
    {
      const auto uris = certificate->san_uris();
      if (std::find(uris.begin(), uris.end(), *applicationUri) == uris.end())
      {
        addFault(table_106::uri,
          0,
          std::nullopt,
          UaException{Status::BadCertificateUriInvalid,
            ErrorDetail::build("CertificateUriMismatch",
              "Certificate SAN URIs do not contain the expected ApplicationUri",
              "CertificateValidation")
              .context(ua::ContextKeys::certificateSubject, certSubject)
              .context(ua::ContextKeys::applicationUri, *applicationUri)});
      }
    }
  }

  // Certificate Usage, by the use requested (Part 4 Table 106 "shall match use requested for the
  // Certificate"): OPC 10000-6 Table 43 for an ApplicationInstance Certificate, Table 44 for a User
  // Certificate, Table 45 for a CA. Never suppressed (owner decision 22.3). The rules live in one place,
  // ua::detail::check_certificate_usage, which the client's check of its own certificate also applies.
  // Faults on an issuer are found by OpenSSL's path validation above and reported as
  // Bad_CertificateIssuerUseNotAllowed.
  if (auto usage = ua::detail::check_certificate_usage(*certificate, use); !usage.is_good())
  {
    addFault(table_106::usage,
      0,
      std::nullopt,
      UaException{Status::BadCertificateUseNotAllowed, usage.shared_detail()});
  }

  if (faults.empty())
  {
    // Part 4 section 6.1.3: a suppressed error is "always reported via auditing". The Good result lists
    // each suppressed fault (owner decision 22.6), in Table 106 order: one ErrorDetail per fault, its code
    // as the inner status and the faulty certificate's subject and chain position as context, linked
    // through mCause. Nothing suppressed -> no detail. Cost: one ErrorDetail per suppressed fault.
    std::stable_sort(suppressedFaults.begin(),
      suppressedFaults.end(),
      [](const CertificateValidationFault& a, const CertificateValidationFault& b)
      { return a.step != b.step ? a.step < b.step : a.depth < b.depth; });
    shared_ptr<const ErrorDetail> listing;
    for (auto fault = suppressedFaults.rbegin(); fault != suppressedFaults.rend(); ++fault)
    {
      std::unique_ptr<ErrorDetail> entry =
        ErrorDetail::build("CertificateValidationErrorSuppressed",
          "A certificate validation error was suppressed by the validation options",
          "CertificateValidation")
          .context(ua::ContextKeys::certificateSubject, subjectAt(fault->depth))
          .context(ua::ContextKeys::chainDepth, std::to_string(fault->depth))
          .context(ua::ContextKeys::certificateChainPosition, std::string{chain_position_name(fault->depth)});
      entry->innerStatus = StatusCode{fault->error.status()}.value();
      entry->cause = std::move(listing);
      listing = std::move(entry);
    }
    return listing;
  }
  // The earliest step decides; on one step the certificate under validation comes before its issuers
  // (the specification does not order faults on different certificates, and the oracle accepts either).
  const auto earliest = std::min_element(faults.begin(),
    faults.end(),
    [](const CertificateValidationFault& a, const CertificateValidationFault& b)
    { return a.step != b.step ? a.step < b.step : a.depth < b.depth; });
  throw earliest->error;
}

void CryptoOpenSsl::validate_certificate_async(const CertificateValidationRequest& request,
  CertificateValidationMaterial material, CertificateValidationCompleteCallback callback) const noexcept
{
  Result<void> result;
  try
  {
    // A Good verdict that suppressed anything carries the suppressed faults (owner decision 22.6).
    if (auto suppressed = validate_certificate_impl(request, material))
    {
      result = Result<void>::good_with_detail(std::move(suppressed));
    }
  }
  catch (...)
  {
    result = ua::exception_to_status_code(std::current_exception());
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void CryptoOpenSsl::validate_crl_impl(const TrustListValidationOptions& validationOptions,
  const shared_ptr<const X509Crl>& crl,
  const std::vector<shared_ptr<const X509Certificate>>& issuerCandidates) const
{
  const auto* concreteCrl = dynamic_cast<const X509CrlOpenSsl*>(crl.get());
  if (!concreteCrl)
  {
    throw UaException{Status::BadCertificateInvalid,
      make_error_detail("CrlNotReadable", "the CRL is null or not an OpenSSL CRL", "CertificateValidation")};
  }
  auto* x509Crl = const_cast<X509_CRL*>(&concreteCrl->crl());
  const X509_NAME* crlIssuer = X509_CRL_get_issuer(x509Crl);
  const UniquePtrToOpenSslCharBuf issuerText{crlIssuer ? X509_NAME_oneline(crlIssuer, nullptr, 0) : nullptr};
  const std::string issuerName = issuerText ? std::string{issuerText.get()} : std::string{};

  // Signed by its issuer: a candidate whose subject is the CRL's issuer name and whose public key
  // verifies the CRL's signature. Cost: one name comparison per candidate and one signature
  // verification per candidate with that name (an administrative operation, never per request).
  bool issuerFound = false;
  bool signatureVerified = false;
  // A failed attempt's OpenSSL errors are taken off the thread's queue at once (drained, which clears
  // it), so a later candidate's success leaves no stale errors behind; the last ones are kept for the
  // refusal's detail.
  std::string verifyErrors;
  for (const auto& candidate : issuerCandidates)
  {
    const auto* concreteCandidate = dynamic_cast<const X509CertificateOpenSsl*>(candidate.get());
    if (!concreteCandidate || !crlIssuer ||
        X509_NAME_cmp(X509_get_subject_name(&concreteCandidate->cert()), crlIssuer) != 0)
      continue;
    issuerFound = true;
    EVP_PKEY* issuerKey = X509_get0_pubkey(&concreteCandidate->cert());
    if (issuerKey && X509_CRL_verify(x509Crl, issuerKey) == 1)
    {
      signatureVerified = true;
      break;
    }
    verifyErrors = detail::drain_openssl_errors();
  }
  if (!issuerFound)
  {
    throw UaException{Status::BadCertificateChainIncomplete,
      ErrorDetail::build("CrlIssuerNotFound",
        "the certificate that issued the CRL is in neither the trusted nor the issuer certificates",
        "CertificateValidation")
        .detail(detail::drain_openssl_errors())
        .context(ua::ContextKeys::crlIssuer, issuerName)};
  }
  if (!signatureVerified)
  {
    throw UaException{Status::BadSecurityChecksFailed,
      ErrorDetail::build("CrlSignatureInvalid",
        "the CRL's signature does not verify with the public key of its issuer's certificate",
        "CertificateValidation")
        .detail(std::move(verifyErrors))
        .context(ua::ContextKeys::crlIssuer, issuerName)};
  }

  // A CRL outside its thisUpdate/nextUpdate window cannot establish revocation status: the same fault
  // OpenSSL reports as revocation status unknown, and suppressed by the same options. It matters only
  // when revocation is checked: with checking off no CRL is consulted, so none is required to be
  // current (Part 4 6.1.3 makes revocation checking a configured step).
  const bool revocationChecked =
    validationOptions.test(TrustListValidationOptions::Bit::CheckRevocationStatusOffline) ||
    validationOptions.test(TrustListValidationOptions::Bit::CheckRevocationStatusOnline);
  if (!revocationChecked ||
      validationOptions.test(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown) ||
      validationOptions.test(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown))
  {
    return;
  }
  const ASN1_TIME* thisUpdate = X509_CRL_get0_lastUpdate(x509Crl);
  const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(x509Crl);
  const bool notYetValid = !thisUpdate || X509_cmp_current_time(thisUpdate) >= 0;
  const bool expired = nextUpdate && X509_cmp_current_time(nextUpdate) <= 0;
  if (notYetValid || expired)
  {
    throw UaException{Status::BadCertificateRevocationUnknown,
      ErrorDetail::build("CrlTimeInvalid",
        "the current time is outside the CRL's thisUpdate/nextUpdate validity window",
        "CertificateValidation")
        .context(ua::ContextKeys::crlIssuer, issuerName)};
  }
}

void CryptoOpenSsl::validate_crl_async(TrustListValidationOptions validationOptions,
  shared_ptr<const X509Crl> crl, std::vector<shared_ptr<const X509Certificate>> issuerCandidates,
  CrlValidationCompleteCallback callback) const noexcept
{
  Result<void> result;
  try
  {
    validate_crl_impl(validationOptions, crl, issuerCandidates);
  }
  catch (...)
  {
    result = ua::exception_to_status_code(std::current_exception());
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

void CryptoOpenSsl::create_crl_async(shared_ptr<const X509Certificate> issuer,
  shared_ptr<const AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers,
  CreateCrlCompleteCallback callback) const noexcept
{
  try
  {
    callback(detail::to_result([&] { return create_crl_sync(issuer, issuerKeys, revokedSerialNumbers); }));
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

shared_ptr<const X509Crl> CryptoOpenSsl::create_crl_sync(shared_ptr<const X509Certificate> issuer,
  shared_ptr<const AsymmetricKeyPair> issuerKeys, const std::vector<std::string>& revokedSerialNumbers) const
{
  UniquePtrToCert issuerX509;
  {
    auto der = issuer->der_encoding();
    const unsigned char* p = der.data();
    issuerX509.reset(d2i_X509(NULL, &p, numeric_cast<long>(der.size())));
  }

  const auto* keys = dynamic_cast<const AsymmetricKeyPairOpenSsl*>(issuerKeys.get());
  if (!keys)
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail("CertificateError",
        "AsymmetricKeyPair of invalid concrete type in create_crl_sync",
        "OpenSslCrypto"));
  }

  UniquePtrToX509Crl crl(X509_CRL_new());
  if (!crl)
  {
    throw UaException(Status::BadOutOfMemory,
      detail::make_openssl_error_detail(
        "CertificateError", "X509_CRL_new() allocation failed in create_crl_sync", "OpenSslCrypto"));
  }

  X509_CRL_set_version(crl.get(), 1);  // Version 2 (value 1)
  X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuerX509.get()));
  // Part 6 section 6.2.5 and Table 46 require every CRL to identify the issuer key. The issuer
  // certificate supplies the SubjectKeyIdentifier from which OpenSSL derives this value.
  add_extension(*crl, *issuerX509, NID_authority_key_identifier, "keyid:always");

  {
    const UniquePtrToAsn1Time lastUpdate(ASN1_TIME_new());
    const UniquePtrToAsn1Time nextUpdate(ASN1_TIME_new());
    X509_gmtime_adj(lastUpdate.get(), 0);
    X509_gmtime_adj(nextUpdate.get(), static_cast<long>(24) * 60 * 60 * 30);  // 30 days
    X509_CRL_set1_lastUpdate(crl.get(), lastUpdate.get());
    X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get());
  }

  for (const auto& sn : revokedSerialNumbers)
  {
    X509_REVOKED* revoked = X509_REVOKED_new();
    UniquePtrToBigNum bn;
    {
      BIGNUM* bnRaw = nullptr;
      BN_dec2bn(&bnRaw, sn.c_str());
      bn.reset(bnRaw);
    }
    const UniquePtrToAsn1Integer serial(BN_to_ASN1_INTEGER(bn.get(), NULL));
    X509_REVOKED_set_serialNumber(revoked, serial.get());

    {
      const UniquePtrToAsn1Time revDate(ASN1_TIME_new());
      X509_gmtime_adj(revDate.get(), 0);
      X509_REVOKED_set_revocationDate(revoked, revDate.get());
    }

    // add0 transfers ownership of revoked to the CRL.
    X509_CRL_add0_revoked(crl.get(), revoked);
  }

  X509_CRL_sort(crl.get());

  // An EdDSA key signs the message itself (RFC 8032), so OpenSSL takes no separate digest for it; every
  // other issuer key signs a SHA-256 digest.
  const auto issuerKey = keys->private_key_evp();
  const bool edDsa =
    EVP_PKEY_id(issuerKey.get()) == EVP_PKEY_ED25519 || EVP_PKEY_id(issuerKey.get()) == EVP_PKEY_ED448;
  const EVP_MD* md = edDsa ? nullptr : EVP_sha256();
  if (X509_CRL_sign(crl.get(), issuerKey.get(), md) == 0)
  {
    throw UaException(Status::BadInternalError,
      detail::make_openssl_error_detail(
        "CertificateError", "X509_CRL_sign() failed in create_crl_sync", "OpenSslCrypto"));
  }

  // X509CrlOpenSsl takes ownership via its destructor.
  return make_shared<X509CrlOpenSsl>(*crl.release());
}

shared_ptr<const AsymmetricKeyPair> CryptoOpenSsl::get_private_key_from_pem(
  CertificateKeyAlgorithm keyAlgorithm, span<byte> pem) const
{
  // First load from PEM to parse and validate the key
  auto tempKeyPair = make_shared<AsymmetricKeyPairOpenSsl>(keyAlgorithm, mPrivateKeyCredentialCallback, pem);
  UniquePtrToEvpKey evpKey;
  try
  {
    evpKey = tempKeyPair->private_key_evp();
  }
  catch (...)
  {
    throw UaException(Status::BadInvalidArgument,
      detail::make_openssl_error_detail("CertificateKeyExtractionFailed",
        "Private key PEM is invalid in get_private_key_from_pem",
        "OpenSslCrypto"));
  }

  if (!evpKey)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("CertificateKeyExtractionFailed",
        "Private key PEM produced null EVP_PKEY in get_private_key_from_pem",
        "OpenSslCrypto"));
  }

  // Reconstruct using the EVP_PKEY constructor which populates both public and private key
  return make_shared<AsymmetricKeyPairOpenSsl>(keyAlgorithm, mPrivateKeyCredentialCallback, *evpKey);
}

namespace
{

class Wrapper : public CryptoOpenSsl
{
public:
  Wrapper() : CryptoOpenSsl()
  {}

  explicit Wrapper(PrivateKeyCredentialCallback privateKeyCredentialCallback)
    : CryptoOpenSsl(std::move(privateKeyCredentialCallback))
  {}
};

}  // namespace

shared_ptr<const CryptoOpenSsl> CryptoOpenSsl::create()
{
  return make_shared<Wrapper>();
}

shared_ptr<const CryptoOpenSsl> CryptoOpenSsl::create(
  const PrivateKeyCredentialCallback privateKeyCredentialCallback)
{
  return make_shared<Wrapper>(privateKeyCredentialCallback);
}

}  // namespace ua
