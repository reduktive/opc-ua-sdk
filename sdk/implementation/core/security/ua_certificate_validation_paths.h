// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_VALIDATION_PATHS_H
#define UA_CERTIFICATE_VALIDATION_PATHS_H

/// @file
/// @brief The internal pieces every certificate-validation path shares: the one request builder (which
///        holds the one chain parser for OPC UA certificate fields) and the own-certificate check against
///        the SecurityPolicies a server serves.
/// @ingroup core

#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ua_byte_string.h"
#include "ua_certificate_store.h"
#include "ua_logger.h"
#include "ua_result.h"

namespace ua
{
class Crypto;
class SecurityPolicy;
class X509Certificate;
}  // namespace ua

namespace ua::detail
{

/// Parses an OPC UA certificate field (OPC 10000-6 section 6.2.6: one or more DER certificates back to back,
/// the leaf first) into a leaf and the presented issuers, in field order.
///
/// @param crypto           Parses the DER (Crypto::read_certificates_from_der: no trailing bytes, no partial
///                         result).
/// @param certificateField The field bytes as they arrived.
/// @return The parsed certificates (at least one); Bad_CertificateInvalid when the field is empty, is not a
///         sequence of complete DER certificates, or holds bytes after the last one.
[[nodiscard]] Result<std::vector<std::shared_ptr<const X509Certificate>>> parse_certificate_field(
  const Crypto& crypto, span<const byte> certificateField) noexcept;

/// The one builder of a CertificateValidationRequest from a certificate field. Every path (OPN sender
/// certificate, CreateSession client/server certificate, X509 user token, GetEndpoints, LDS registration,
/// UpdateCertificate) sets its own fields on @p request (use, policy, ApplicationUri, endpoint URL,
/// connection trust) and calls this; the builder sets mCertificate to the field's first certificate and
/// presentedIssuers to the rest, and hands every other field through unchanged.
///
/// @param crypto           Parses the field (@ref parse_certificate_field).
/// @param certificateField The certificate field bytes.
/// @param request          The caller's fields; mCertificate and presentedIssuers are overwritten.
/// @return The request; the parser's Bad_CertificateInvalid when the field does not parse.
[[nodiscard]] Result<CertificateValidationRequest> make_validation_request(
  const Crypto& crypto, span<const byte> certificateField, CertificateValidationRequest request) noexcept;

/// Encodes an own certificate field: the leaf then each issuer in order (OPC 10000-6 section 6.2.6;
/// decision 24, ApplicationCertificate::issuerCertificates / X509Identity::issuerCertificates).
///
/// @param certificate The leaf; null yields an empty field.
/// @param issuers     The leaf's issuer chain, nearest issuer first.
/// @return The concatenated DER.
[[nodiscard]] ByteString encode_certificate_field(const std::shared_ptr<const X509Certificate>& certificate,
  const std::vector<std::shared_ptr<const X509Certificate>>& issuers);

/// The errors a Good validation result suppressed (owner decision 22.6): one status per ErrorDetail entry
/// coded CertificateValidationErrorSuppressed in the result's detail chain, its innerStatus, in chain
/// order. Cost: one walk of the detail chain; nothing allocated when nothing was suppressed.
///
/// @param result A certificate validation verdict.
/// @return The suppressed statuses; empty for a Bad result or a Good one that suppressed nothing.
[[nodiscard]] std::vector<StatusCode> suppressed_certificate_errors(const VoidResult& result);

/// The Certificate Usage rules for the certificate under validation (OPC 10000-4 section 6.1.3 Table 106:
/// the uses "shall match use requested for the Certificate"), by the use requested: OPC 10000-6 Table 43
/// for an ApplicationInstance Certificate, Table 44 for a User Certificate, Table 45 for a CA. The one
/// implementation of these rules: the validator's Usage step and the client's create-time check of its
/// own certificate both call it. Key length and algorithms are not usage rules; the SecurityPolicy checks
/// them (SecurityPolicy::check_certificate_compliance).
///
/// A certificate is self-signed when its own key verifies its signature (X509Certificate::self_signed,
/// decision B). That costs one signature verification, spent only on an ApplicationInstance Certificate
/// with cA TRUE, the only case whose rules depend on it.
///
/// @param certificate The certificate under validation (the leaf; issuers are checked by path validation).
/// @param use         The use requested.
/// @return Good when the certificate's uses match @p use; otherwise Bad_CertificateUseNotAllowed for the
///         first rule it breaks, with an ErrorDetail coded for the rule (CertificateIsNotACa,
///         CertificateIsMarkedAsCa, CertificatePathLengthPresent, CertificatePathLengthInvalid,
///         CertificateKeyUsageInvalid naming the keyUsage bit, CertificateExtendedKeyUsageInvalid).
/// @throws What the certificate accessors throw.
[[nodiscard]] VoidResult check_certificate_usage(const X509Certificate& certificate, CertificateUse use);

}  // namespace ua::detail

#endif  // UA_CERTIFICATE_VALIDATION_PATHS_H
