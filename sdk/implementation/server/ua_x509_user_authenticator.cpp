// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_built_in_authenticators.h"
#include "ua_certificate_store.h"
#include "ua_claim_keys.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include <string>

namespace ua::server
{

void X509UserAuthenticator::authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept
{
  static const std::string source{"X509UserAuthenticator"};

  if (req.identity.kind != UserTokenKind::X509)
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadUserAccessDenied},
      ua::ErrorDetail::build(
        "X509TokenExpected", "X509UserAuthenticator: only X.509 certificate tokens are accepted", source)
        .context(ua::ContextKeys::tokenKind, ua::server::to_string(req.identity.kind))});
    return;
  }

  if (!req.identity.x509Certificate || !*req.identity.x509Certificate)
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadIdentityTokenInvalid},
      ua::make_error_detail(
        "MissingCertificate", "X509UserAuthenticator: X.509 token is missing the certificate", source)});
    return;
  }

  // The certificate was validated by the session before this call (owner review 2026-10-02, item 8):
  // chain-parsed, Table 44 use, the user-token policy's Security Policy Check, the user-token store. A
  // refusal never reaches an authenticator, so this maps identity to user only.
  const auto& certificate = *req.identity.x509Certificate;
  auto commonName = certificate->subject_common_name();
  auto thumbprint = certificate->thumbprint();
  auto thumbprintHex = utils::bytes_to_hex_string(ua::span<const ua::byte>{thumbprint});

  auto userId = commonName.empty() ? thumbprintHex : commonName;

  completion(
    AuthnResult{AuthnSuccess{.user = UserIdentity{.userId = std::move(userId),
                               .displayName = commonName.empty() ? thumbprintHex : std::move(commonName),
                               .kind = UserTokenKind::X509,
                               .claims = {{ClaimKeys::thumbprint, std::move(thumbprintHex)}}},
      .audit = {}}});
}

}  // namespace ua::server
