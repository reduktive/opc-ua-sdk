// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_validation_paths.h"

#include <cstdint>
#include <exception>
#include <string_view>

#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_security_policy.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_x509_certificate.h"

namespace ua::detail
{

std::vector<StatusCode> suppressed_certificate_errors(const VoidResult& result)
{
  std::vector<StatusCode> suppressed;
  if (!result.is_good())
    return suppressed;
  for (const ErrorDetail* entry = result.shared_detail().get(); entry != nullptr; entry = entry->cause.get())
  {
    if (entry->code == "CertificateValidationErrorSuppressed")
      suppressed.emplace_back(entry->innerStatus);
  }
  return suppressed;
}

namespace
{

/// The refusal of one Certificate Usage rule: Bad_CertificateUseNotAllowed, coded for the rule, the rule's
/// text as the error message and, for a keyUsage bit, the bit and what the key type requires.
VoidResult refuse_use(const X509Certificate& certificate, const char* code, const char* rule,
  std::string_view bitName = {}, std::string_view expected = {})
{
  auto detail = ErrorDetail::build(code, "Certificate use is not allowed", "CertificateValidation");
  detail.context(ContextKeys::certificateSubject, certificate.subject_common_name())
    .context(ContextKeys::errorMessage, std::string{rule});
  if (!bitName.empty())
  {
    detail.context(ContextKeys::bitName, std::string{bitName});
  }
  if (!expected.empty())
  {
    detail.context(ContextKeys::expected, std::string{expected});
  }
  return VoidResult{StatusCode{Status::BadCertificateUseNotAllowed, std::move(detail)}};
}

}  // namespace

VoidResult check_certificate_usage(const X509Certificate& certificate, CertificateUse use)
{
  if (use == CertificateUse::CertificateAuthority)
  {
    // Part 6 Table 45: a CA certificate must say it is one, basicConstraints cA TRUE. The certificate
    // under validation gets the certificate's own code; the issuer variant is for its issuers (owner
    // decision 22.4, Table 182). Nothing else of Table 45 is enforced here (pathLength and keyCertSign are
    // not required).
    if (!certificate.basic_constraints_ca())
    {
      return VoidResult{StatusCode{Status::BadCertificateUseNotAllowed,
        ErrorDetail::build("CertificateIsNotACa",
          "A certificate requested as a CA certificate does not have basicConstraints cA=TRUE; "
          "Part 6 Table 45 requires TRUE",
          "CertificateValidation")
          .context(ContextKeys::certificateSubject, certificate.subject_common_name())}};
    }
    return VoidResult{};
  }

  const bool isCa = certificate.basic_constraints_ca();
  // basic_constraints_path_length() reports an absent pathLength as UINT32_MAX.
  const bool hasPathLength = certificate.basic_constraints_path_length() != UINT32_MAX;

  if (use == CertificateUse::User)
  {
    // Table 44: "The cA flag shall be FALSE for User Certificates. The pathLength shall not be present."
    // Table 43's keyUsage and extendedKeyUsage rows do not apply.
    if (isCa)
    {
      return refuse_use(certificate,
        "CertificateIsMarkedAsCa",
        "a User Certificate has cA TRUE; OPC 10000-6 Table 44 requires FALSE");
    }
    if (hasPathLength)
    {
      return refuse_use(certificate,
        "CertificatePathLengthPresent",
        "a User Certificate carries a pathLength; OPC 10000-6 Table 44 says it shall not be present");
    }
    if (!certificate.key_usage_digital_signature())
    {
      return refuse_use(
        certificate, "CertificateKeyUsageInvalid", "keyUsage omits digitalSignature", "digitalSignature");
    }
    return VoidResult{};
  }

  // Table 43 basicConstraints: "The cA flag shall be FALSE for ApplicationInstance Certificates issued by a
  // CA" - the case with teeth: a CA-issued leaf that is a CA could issue certificates chaining to an
  // already-trusted root. A self-signed certificate "should" be FALSE but "TRUE shall be accepted"; where it
  // is TRUE, "the pathLength shall be 0" (an ABSENT pathLength is accepted, owner decision 25) and it "shall
  // also include keyCertSign" (applied where cA is TRUE only: RFC 5280 4.2.1.9 forbids keyCertSign without
  // cA). Self-signed means the certificate's own key verifies its signature (decision B), not merely that
  // its issuer and subject Names are equal.
  if (isCa)
  {
    if (!certificate.self_signed())
    {
      return refuse_use(certificate,
        "CertificateIsMarkedAsCa",
        "a CA-issued ApplicationInstance Certificate has cA TRUE; OPC 10000-6 Table 43 requires FALSE");
    }
    if (hasPathLength && certificate.basic_constraints_path_length() >= 1)
    {
      return refuse_use(certificate,
        "CertificatePathLengthInvalid",
        "a self-signed ApplicationInstance Certificate with cA TRUE has a pathLength above 0; OPC 10000-6 "
        "Table 43 requires 0");
    }
    if (!certificate.key_usage_key_cert_sign())
    {
      return refuse_use(certificate,
        "CertificateKeyUsageInvalid",
        "a self-signed ApplicationInstance Certificate with cA TRUE omits keyCertSign, which OPC 10000-6 "
        "Table 43 requires",
        "keyCertSign");
    }
  }

  // keyUsage and extendedKeyUsage: Table 43 states them separately for RSA and ECC keys. "For RSA keys, the
  // keyUsage shall include digitalSignature, nonRepudiation, keyEncipherment and dataEncipherment"; "the
  // extendedKeyUsage shall specify serverAuth and/or clientAuth". An ECC key cannot do RSA-style key or data
  // transport, so of these only digitalSignature applies to it. The first missing bit is named.
  const bool rsa = certificate.key_algorithm() == CertificateKeyAlgorithm::Rsa;
  constexpr std::string_view rsaBits =
    "digitalSignature, keyEncipherment and dataEncipherment are all required for an RSA key";
  if (!certificate.key_usage_digital_signature())
  {
    return refuse_use(certificate,
      "CertificateKeyUsageInvalid",
      "keyUsage omits digitalSignature, which OPC 10000-6 Table 43 requires of every ApplicationInstance "
      "Certificate",
      "digitalSignature",
      rsa ? rsaBits : std::string_view{"digitalSignature is required for an ECC key"});
  }
  if (!rsa)
  {
    return VoidResult{};
  }
  if (!certificate.key_usage_key_encipherment())
  {
    return refuse_use(certificate,
      "CertificateKeyUsageInvalid",
      "keyUsage omits keyEncipherment, which OPC 10000-6 Table 43 requires for RSA keys",
      "keyEncipherment",
      rsaBits);
  }
  if (!certificate.key_usage_data_encipherment())
  {
    return refuse_use(certificate,
      "CertificateKeyUsageInvalid",
      "keyUsage omits dataEncipherment, which OPC 10000-6 Table 43 requires for RSA keys",
      "dataEncipherment",
      rsaBits);
  }
  if (!certificate.key_usage_non_repudiation())
  {
    return refuse_use(certificate,
      "CertificateKeyUsageInvalid",
      "keyUsage omits nonRepudiation, which OPC 10000-6 Table 43 requires for RSA keys",
      "nonRepudiation",
      "nonRepudiation is required for an RSA key (OPC 10000-6 Table 43)");
  }
  // Part 6 section 6.2.2 Table 50 requires the EKU of the RSA application's role.
  // Generic administrative validation accepts either role; ECC EKUs remain optional above.
  const bool serverAuth = certificate.extended_key_usage_server_auth();
  const bool clientAuth = certificate.extended_key_usage_client_auth();
  if ((use == CertificateUse::ServerApplicationInstance && !serverAuth) ||
      (use == CertificateUse::ClientApplicationInstance && !clientAuth) || (!serverAuth && !clientAuth))
  {
    return refuse_use(certificate,
      "CertificateExtendedKeyUsageInvalid",
      "extendedKeyUsage omits the required RSA application purpose; OPC 10000-6 section 6.2.2 Table 50 "
      "requires serverAuth for a Server and clientAuth for a Client",
      {},
      use == CertificateUse::ServerApplicationInstance   ? "serverAuth"
      : use == CertificateUse::ClientApplicationInstance ? "clientAuth"
                                                         : "serverAuth or clientAuth");
  }
  return VoidResult{};
}

Result<std::vector<std::shared_ptr<const X509Certificate>>> parse_certificate_field(
  const Crypto& crypto, span<const byte> certificateField) noexcept
{
  try
  {
    auto certificates = crypto.read_certificates_from_der(certificateField);
    if (certificates.empty() || !certificates.front())
    {
      return StatusCode{Status::BadCertificateInvalid,
        make_error_detail("CertificateFieldEmpty",
          "The certificate field holds no certificate",
          "CertificateValidationPaths")};
    }
    return certificates;
  }
  catch (...)
  {
    // The parser refuses a malformed field as Bad_CertificateInvalid; keep its detail as the cause.
    return StatusCode{Status::BadCertificateInvalid,
      make_error_detail("CertificateFieldInvalid",
        "The certificate field is not a sequence of complete DER certificates",
        "CertificateValidationPaths",
        exception_to_status_code(std::current_exception()))};
  }
}

Result<CertificateValidationRequest> make_validation_request(
  const Crypto& crypto, span<const byte> certificateField, CertificateValidationRequest request) noexcept
{
  auto parsed = parse_certificate_field(crypto, certificateField);
  if (!parsed.is_good())
  {
    return parsed.status_code();
  }
  auto certificates = std::move(parsed).value();
  request.certificate = std::move(certificates.front());
  request.presentedIssuers.assign(
    std::make_move_iterator(certificates.begin() + 1), std::make_move_iterator(certificates.end()));
  return request;
}

ByteString encode_certificate_field(const std::shared_ptr<const X509Certificate>& certificate,
  const std::vector<std::shared_ptr<const X509Certificate>>& issuers)
{
  if (!certificate)
  {
    return ByteString{};
  }
  std::vector<uint8_t> bytes;
  const auto append = [&bytes](const X509Certificate& next)
  {
    const auto der = next.der_encoding();
    bytes.insert(bytes.end(), der.begin(), der.end());
  };
  append(*certificate);
  for (const auto& issuer : issuers)
  {
    if (issuer)
    {
      append(*issuer);
    }
  }
  return ByteString{std::move(bytes)};
}

}  // namespace ua::detail
