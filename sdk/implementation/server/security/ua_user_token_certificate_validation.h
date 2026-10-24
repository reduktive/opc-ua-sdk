// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_USER_TOKEN_CERTIFICATE_VALIDATION_H
#define UA_USER_TOKEN_CERTIFICATE_VALIDATION_H

/// @file
/// @brief The session's validation of an X509 user identity token certificate (owner review 2026-10-02,
///        item 8), run before the application authenticator and again on re-evaluation after a user-token
///        trust-list change.
/// @ingroup server

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ua_byte_string.h"
#include "ua_result.h"
#include "ua_status_code.h"

namespace ua
{
class CertificateStore;
class Crypto;
class SecurityPolicy;
class X509Certificate;
}  // namespace ua

namespace ua::server
{
class ServerObserver;
}  // namespace ua::server

namespace ua::server::detail
{

/// Reports each suppressed certificate validation error through
/// ServerObserver::on_certificate_error_suppressed (OPC 10000-4 section 6.1.3, owner review item 9;
/// decision 27: one CertificateEventInfo carrying the presented certificate). Every server validation path
/// (OPN, CreateSession, X509 user token, user-identity re-evaluation) calls it with
/// @ref ua::detail::suppressed_certificate_errors of its Good verdict.
///
/// @param observer      The server observer; null reports nothing.
/// @param remoteAddress The peer's transport address.
/// @param certificate   The presented certificate that was accepted.
/// @param suppressed    The suppressed statuses, one hook call each; empty calls nothing.
/// @throws Whatever the observer throws (callers contain it, as for every observer hook).
void report_suppressed_certificate_errors(const std::shared_ptr<ServerObserver>& observer,
  const std::string& remoteAddress, const std::shared_ptr<const X509Certificate>& certificate,
  const std::vector<StatusCode>& suppressed);

/// Checks an own application certificate against the SecurityPolicy of every endpoint the server serves
/// (OPC 10000-7 profile database via SecurityPolicy::check_certificate_compliance, end-entity position). The
/// startup refusal (a server whose own certificate violates a served policy does not start) and
/// UpdateCertificate's refusal share it.
///
/// @param certificate The own certificate.
/// @param issuer      The certificate that signed it (itself when self-signed).
/// @param endpoints   One entry per served endpoint: a name for the message, and its SecurityPolicy (null
///                    entries are skipped).
/// @return Good when every policy accepts the certificate; otherwise Bad_ConfigurationError whose summary
///         names the first violated endpoint and whose cause is the policy's refusal (the rule).
[[nodiscard]] VoidResult check_own_certificate_against_endpoints(const X509Certificate& certificate,
  const X509Certificate& issuer,
  const std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>& endpoints) noexcept;

/// Validates an X509IdentityToken certificateData field through the single certificate-validation pipeline.
///
/// The field is parsed by the one chain parser into the leaf and the presented issuers; the request carries
/// mUse = CertificateUse::User (OPC 10000-4 Table 44) and @p policy (the user-token policy's SecurityPolicy,
/// Table 106 step 4; null = no Security Policy Check) and is validated by @p store (the user-token store).
///
/// @param store           The user-token certificate store; null rejects every token.
/// @param crypto          Parses the field.
/// @param certificateData The token's certificateData (leaf then issuers, OPC 10000-6 section 6.2.6).
/// @param policy          The user-token policy's SecurityPolicy, or null.
/// @param callback        Receives Good, or Bad_IdentityTokenRejected whose ErrorDetail cause is the Table
///                        106 fault (a malformed field is Bad_IdentityTokenInvalid). Called exactly once.
void validate_user_token_certificate_async(std::shared_ptr<CertificateStore> store,
  std::shared_ptr<const Crypto> crypto, const ByteString& certificateData,
  std::shared_ptr<const SecurityPolicy> policy, std::function<void(VoidResult)> callback) noexcept;

}  // namespace ua::server::detail

#endif  // UA_USER_TOKEN_CERTIFICATE_VALIDATION_H
