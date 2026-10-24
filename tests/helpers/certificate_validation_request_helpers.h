// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
//
// Builders for the single certificate-validation request (certificate-validation API proposal,
// "Owner review 2026-10-02", items 3, 5 and 6). Tests that predate the request form keep their
// argument lists and wrap them here, so the assertion each test makes is unchanged by the port.
// Members are assigned by name, so the builders do not depend on the declaration order of the
// request or the material.

#ifndef UA_TESTS_HELPERS_CERTIFICATE_VALIDATION_REQUEST_HELPERS_H
#define UA_TESTS_HELPERS_CERTIFICATE_VALIDATION_REQUEST_HELPERS_H

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_security_policy.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

namespace ua::test
{

using RequestCertificates = std::vector<std::shared_ptr<const X509Certificate>>;
using RequestCrls = std::vector<std::shared_ptr<const X509Crl>>;

/// A request for @p certificate with @p presentedIssuers as the chain the peer sent; every other member is
/// left open, so the store fills it (its options, its CertificateUse).
inline CertificateValidationRequest make_validation_request(
  std::shared_ptr<const X509Certificate> certificate, RequestCertificates presentedIssuers = {},
  std::optional<TrustListValidationOptions> options = std::nullopt,
  std::optional<std::string> applicationUri = std::nullopt,
  std::optional<std::string> endpointUrl = std::nullopt)
{
  CertificateValidationRequest request;
  request.certificate = std::move(certificate);
  request.presentedIssuers = std::move(presentedIssuers);
  if (options.has_value())
  {
    request.options = *options;
  }
  if (applicationUri.has_value())
  {
    request.applicationUri = std::move(*applicationUri);
  }
  if (endpointUrl.has_value())
  {
    request.endpointUrl = std::move(*endpointUrl);
  }
  return request;
}

/// As @ref make_validation_request, with @p trustedForThisConnection accepted by the application for this
/// connection only (CL-SECADMIN-003 AcceptForThisSession) - the replacement of the removed
/// validate_certificate_with_additional_trust_async argument list.
inline CertificateValidationRequest make_validation_request_with_connection_trust(
  std::shared_ptr<const X509Certificate> certificate, RequestCertificates trustedForThisConnection,
  RequestCertificates presentedIssuers, std::optional<TrustListValidationOptions> options,
  std::optional<std::string> applicationUri, std::optional<std::string> endpointUrl)
{
  auto request = make_validation_request(std::move(certificate),
    std::move(presentedIssuers),
    options,
    std::move(applicationUri),
    std::move(endpointUrl));
  request.trustedForThisConnection = std::move(trustedForThisConnection);
  return request;
}

/// A request that names the use and the security policy explicitly.
inline CertificateValidationRequest make_validation_request_for(
  std::shared_ptr<const X509Certificate> certificate, RequestCertificates presentedIssuers,
  CertificateUse use, std::optional<SecurityPolicyId> policyId,
  std::optional<TrustListValidationOptions> options = std::nullopt,
  std::optional<std::string> applicationUri = std::nullopt,
  std::optional<std::string> endpointUrl = std::nullopt)
{
  auto request = make_validation_request(std::move(certificate),
    std::move(presentedIssuers),
    options,
    std::move(applicationUri),
    std::move(endpointUrl));
  request.use = use;
  request.policyId = policyId;
  return request;
}

/// The request half of the removed ten-argument Crypto::validate_certificate_async.
inline CertificateValidationRequest make_crypto_request(std::shared_ptr<const X509Certificate> certificate,
  std::optional<std::string> applicationUri, std::optional<std::string> endpointUrl, CertificateUse use)
{
  auto request = make_validation_request(
    std::move(certificate), {}, std::nullopt, std::move(applicationUri), std::move(endpointUrl));
  request.use = use;
  return request;
}

/// The material half of the removed ten-argument Crypto::validate_certificate_async: the trust list, the
/// issuer list, their CRLs and the resolved options.
inline CertificateValidationMaterial make_validation_material(TrustListValidationOptions options,
  RequestCertificates trusted, RequestCrls trustedCrls, RequestCertificates issuers, RequestCrls issuerCrls)
{
  CertificateValidationMaterial material;
  material.trusted = std::move(trusted);
  material.trustedCrls = std::move(trustedCrls);
  material.issuers = std::move(issuers);
  material.issuerCrls = std::move(issuerCrls);
  material.options = options;
  return material;
}

}  // namespace ua::test

#endif  // UA_TESTS_HELPERS_CERTIFICATE_VALIDATION_REQUEST_HELPERS_H
