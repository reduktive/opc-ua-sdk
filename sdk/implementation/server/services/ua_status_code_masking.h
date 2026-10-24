// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATUS_CODE_MASKING_H
#define UA_STATUS_CODE_MASKING_H

#include "ua_status_code.h"

namespace ua::server::detail
{

/// Maps detailed security-related StatusCodes to generic codes appropriate for
/// pre-authentication responses.
///
/// A certificate check is masked to BadSecurityChecksFailed exactly where OPC 10000-4 Table 106 says the
/// Server reports that code back: Certificate Structure, Build Certificate Chain, Signature, Security
/// Policy Check, Trust List Check and Revocation Check ("shall"), and Find Revocation List ("should").
/// The Validity Period, Host Name, URI and Certificate Usage rows say no such thing, and Table 12 lists
/// their codes among the OpenSecureChannel results, so those pass through.
///
/// Internal logging/observer always sees the real (unmasked) codes.
inline StatusCode mask_pre_auth_status(StatusCode sc)
{
  switch (sc.as_status())
  {
  // Certificate-related errors -> BadSecurityChecksFailed
  case Status::BadCertificateInvalid:
  case Status::BadCertificateUntrusted:
  case Status::BadCertificateRevoked:
  case Status::BadCertificateIssuerRevoked:
  case Status::BadCertificateRevocationUnknown:
  case Status::BadCertificateIssuerRevocationUnknown:
  case Status::BadCertificateChainIncomplete:
  case Status::BadCertificatePolicyCheckFailed:
    return StatusCode{Status::BadSecurityChecksFailed};

  // Identity token errors -> BadIdentityTokenRejected
  case Status::BadIdentityTokenInvalid:
    return StatusCode{Status::BadIdentityTokenRejected};

  // Nonce/signature errors -> BadSecurityChecksFailed
  case Status::BadNonceInvalid:
  case Status::BadApplicationSignatureInvalid:
  case Status::BadUserSignatureInvalid:
    return StatusCode{Status::BadSecurityChecksFailed};

  // Authorization-related codes used pre-auth (e.g. when no authenticator is
  // configured) -> generic identity-token rejection. Revealing "no authenticator
  // is configured" tells an attacker the server is misconfigured; mask it.
  case Status::BadUserAccessDenied:
    return StatusCode{Status::BadIdentityTokenRejected};

  default:
    return sc.without_detail();  // not a security-related code, pass through (strip detail)
  }
}

}  // namespace ua::server::detail

#endif  // !UA_STATUS_CODE_MASKING_H
