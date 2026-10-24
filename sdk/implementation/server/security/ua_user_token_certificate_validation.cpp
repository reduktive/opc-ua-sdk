// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_user_token_certificate_validation.h"

#include <exception>
#include <utility>

#include "ua_certificate_store.h"
#include "ua_certificate_validation_paths.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_security_policy.h"
#include "ua_server_observer.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

namespace ua::server::detail
{

VoidResult check_own_certificate_against_endpoints(const X509Certificate& certificate,
  const X509Certificate& issuer,
  const std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>& endpoints) noexcept
{
  for (const auto& [endpoint, policy] : endpoints)
  {
    if (!policy)
    {
      continue;
    }
    VoidResult compliance{};
    try
    {
      compliance =
        policy->check_certificate_compliance(certificate, issuer, CertificateChainPosition::EndEntity);
    }
    catch (const UaException& e)
    {
      compliance = VoidResult{e.status_code()};
    }
    catch (const std::exception&)
    {
      compliance = VoidResult{StatusCode{Status::BadCertificatePolicyCheckFailed}};
    }
    if (!compliance.is_good())
    {
      const auto cause = compliance.status_code();
      return VoidResult{StatusCode{Status::BadConfigurationError,
        make_error_detail("OwnCertificateViolatesEndpointPolicy",
          "The own application certificate does not comply with the SecurityPolicy " +
            std::string(policy->uri()) + " of endpoint " + endpoint,
          "CertificateValidationPaths",
          cause)}};
    }
  }
  return VoidResult{};
}

void report_suppressed_certificate_errors(const std::shared_ptr<ServerObserver>& observer,
  const std::string& remoteAddress, const std::shared_ptr<const X509Certificate>& certificate,
  const std::vector<StatusCode>& suppressed)
{
  if (!observer)
    return;
  for (const auto& status : suppressed)
  {
    CertificateEventInfo info;
    info.remoteAddress = remoteAddress;
    info.certificate = certificate;
    info.status = status;
    observer->on_certificate_error_suppressed(info);
  }
}

void validate_user_token_certificate_async(std::shared_ptr<CertificateStore> store,
  std::shared_ptr<const Crypto> crypto, const ByteString& certificateData,
  std::shared_ptr<const SecurityPolicy> policy, std::function<void(VoidResult)> callback) noexcept
{
  static const std::string source{"Session"};
  if (!crypto)
  {
    callback(VoidResult{StatusCode{Status::BadInternalError},
      make_error_detail("CryptoUnavailable", "No Crypto to parse the X509 user token certificate", source)});
    return;
  }
  CertificateValidationRequest fields;
  fields.use = CertificateUse::User;
  if (policy)
  {
    fields.policyId = policy->id();
  }
  auto request = ua::detail::make_validation_request(*crypto, certificateData, std::move(fields));
  if (!request.is_good())
  {
    callback(VoidResult{StatusCode{Status::BadIdentityTokenInvalid},
      ErrorDetail::build(
        "UserTokenCertificateInvalid", "The X509 user token certificate field is malformed", source)
        .cause(request.status_code())});
    return;
  }
  if (!store)
  {
    callback(VoidResult{StatusCode{Status::BadIdentityTokenRejected},
      make_error_detail("NoUserCertificateStore",
        "No user-token certificate store is configured, so no user certificate can be trusted",
        source)});
    return;
  }
  auto certificate = request.value().certificate;
  store->validate_certificate_async(std::move(request).value(),
    [certificate = std::move(certificate), callback = std::move(callback)](
      VoidResult validationResult) mutable
    {
      if (validationResult.is_good())
      {
        // Good, possibly carrying suppressed faults in its ErrorDetail (22.6): passed through unchanged.
        callback(std::move(validationResult));
        return;
      }
      // A user identity token whose certificate fails validation is Bad_IdentityTokenRejected (OPC 10000-4
      // ActivateSession: the token is well-formed but rejected); the raw Table 106 code describes an
      // application-instance certificate failure, so it is kept as the cause.
      callback(VoidResult{StatusCode{Status::BadIdentityTokenRejected},
        ErrorDetail::build(
          "CertificateValidationFailed", "The X509 user token certificate failed validation", source)
          .context(ua::ContextKeys::certificateSubject, certificate->subject_common_name())
          .context(ua::ContextKeys::certificateThumbprint,
            utils::bytes_to_hex_string(ua::span<const ua::byte>{certificate->thumbprint()}))
          .cause(validationResult.status_code())});
    });
}

}  // namespace ua::server::detail
