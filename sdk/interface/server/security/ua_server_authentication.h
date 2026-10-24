// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_AUTHENTICATION_H
#define UA_SERVER_AUTHENTICATION_H

/// @file
/// @brief Server-side user authentication extension point and its identity types.
/// @ingroup security

#include "ua_access_identity_facts.h"
#include "ua_attribute_id.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_secure_string.h"
#include "ua_status_code.h"
#include "ua_byte_string.h"
#include "ua_x509_certificate.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string>

namespace ua
{
class CertificateStore;
}

namespace ua::server
{

// Authentication remains a server surface, while the immutable facts it produces are core values
// shared unchanged with the lower address-space authorization layer.
using ::ua::EndpointSecurityContext;
using ::ua::to_string;
using ::ua::UserIdentity;
using ::ua::UserTokenKind;

/// Normalized, pre-validated view of the identity token a client presented.
///
/// Before handing this to the application, the stack has decrypted any password
/// and enforced the endpoint and user-token policy rules; the authenticator
/// sees only sanitized, ready-to-evaluate fields. The optional fields are
/// populated according to @ref kind.
/// @ingroup security
struct PresentedIdentity
{
  UserTokenKind kind{UserTokenKind::Unsupported};  ///< Which token family the remaining fields describe.

  optional<std::string> userName;  ///< Username, when @ref kind is UserName.
  optional<ua::SecureString> password;  ///< Password, already decrypted, when @ref kind is UserName.

  /// User certificate, when @ref kind is X509.
  ///
  /// `ua::X509Certificate` is an abstract interface; the shared_ptr owns an
  /// SDK-provided concrete implementation. The pointee is non-null when present.
  optional<std::shared_ptr<const ua::X509Certificate>> x509Certificate;

  /// Opaque issued-token bytes, when @ref kind is IssuedToken; validation is application-defined.
  optional<ua::ByteString> issuedToken;
};

/// One authentication request handed to a @ref UserAuthenticator.
///
/// Aggregates the negotiated security context, the presented identity, and
/// non-secret correlation data for a single activation attempt. Owned by the
/// stack and passed by value into @ref UserAuthenticator::authenticate_async.
/// @ingroup security
struct AuthnRequest
{
  /// Security context of the negotiated endpoint; the pointee is non-null and outlives the call.
  std::shared_ptr<const EndpointSecurityContext> security;
  PresentedIdentity identity;  ///< The normalized identity token to evaluate.

  ua::NodeId sessionId;  ///< Session being activated, for correlation and audit (non-secret).
  uint32_t requestHandle{};  ///< Service request handle, for correlation and audit (non-secret).

  optional<std::string> remotePeer;  ///< Remote peer address, when known (non-secret).
  /// Deadline by which the authenticator should complete, on the steady clock; absent if unbounded.
  optional<std::chrono::steady_clock::time_point> deadline;

  /// The server's user-token certificate store, or null when the deployment configured none.
  ///
  /// Delivered per request rather than to the authenticator's constructor because an authenticator
  /// is built before the Server it is installed on, so it cannot be handed a server-owned store up
  /// front. An authenticator that validates certificates should use this store unless it was given
  /// one of its own.
  std::shared_ptr<ua::CertificateStore> userTokenCertificateStore;
};

/// Payload returned on successful authentication.
/// @ingroup security
struct AuthnSuccess
{
  UserIdentity user;  ///< The authenticated identity to bind to the session.
  std::string audit;  ///< Human-readable audit string describing the successful outcome.
};

/// Outcome of an authentication attempt.
///
/// A good Result carries an `AuthnSuccess`; a bad Result carries the
/// @ref ua::StatusCode together with the optional @ref ua::ErrorDetail cause
/// chain describing why authentication failed.
using AuthnResult = ua::Result<AuthnSuccess>;

/// Completion callback for @ref UserAuthenticator::authenticate_async, receiving the @ref AuthnResult.
using AuthnComplete = std::function<void(AuthnResult)>;

/// Constructs a failed `AuthnResult` carrying a status and audit reason.
///
/// The @p audit string is recorded under `ua::ContextKeys::errorMessage` so
/// it survives as the human-readable failure reason through logs, service
/// faults, and diagnostics, while the summary stays a fixed literal.
///
/// @param status Status code describing the failure.
/// @param audit  Human-readable failure reason; recorded under error.message.
/// @param source Component name attributed as the error source.
/// @return A bad `AuthnResult` with the assembled @ref ua::ErrorDetail.
/// @see make_authn_success
inline AuthnResult make_authn_failure(
  ua::StatusCode status, std::string audit, std::string source = "Session")
{
  const auto statusValue = status.value();
  std::unique_ptr<ua::ErrorDetail> detail =
    ua::ErrorDetail::build("Authentication", "Authentication failed", std::move(source))
      .context(ua::ContextKeys::errorMessage, std::move(audit))
      .cause(std::move(status));
  return AuthnResult{ua::StatusCode{statusValue, std::move(detail)}};
}

/// Constructs a successful `AuthnResult` from a user identity and optional audit string.
///
/// @param user  Authenticated identity to bind to the session.
/// @param audit Optional human-readable audit string for the success.
/// @return A good `AuthnResult` wrapping an `AuthnSuccess`.
/// @see make_authn_failure
inline AuthnResult make_authn_success(UserIdentity user, std::string audit = {})
{
  return AuthnResult{AuthnSuccess{.user = std::move(user), .audit = std::move(audit)}};
}

/// Server-side extension point that decides whether a presented identity may activate a session.
///
/// Implement this interface to plug application authentication policy (username
/// lookup, certificate trust, issued-token validation) into the server. The
/// stack invokes the authenticator once per activation attempt, after it has
/// decrypted secrets and enforced endpoint and user-token policy.
/// @ingroup security
class UserAuthenticator
{
public:
  virtual ~UserAuthenticator() = default;

  UserAuthenticator(const UserAuthenticator&) = delete;
  UserAuthenticator& operator=(const UserAuthenticator&) = delete;
  UserAuthenticator(UserAuthenticator&&) = delete;
  UserAuthenticator& operator=(UserAuthenticator&&) = delete;

  /// Authenticates a presented identity asynchronously.
  ///
  /// Must return promptly without blocking the calling thread; perform any slow
  /// work off-thread and signal the outcome through @p completion. The callback
  /// must be invoked exactly once, on success or failure. This method is
  /// `noexcept` and reports all errors through the @ref AuthnResult rather than
  /// by throwing.
  ///
  /// @param req        The request to evaluate; consumed by value.
  /// @param completion Receives the outcome exactly once: a good @ref AuthnResult
  ///                   carrying an @ref AuthnSuccess on success, or a bad result
  ///                   carrying a @ref ua::StatusCode and @ref ua::ErrorDetail on
  ///                   failure. Build the result with @ref make_authn_success or
  ///                   @ref make_authn_failure. A Good subcode is a success. An
  ///                   Uncertain result, whether or not it holds an @ref AuthnSuccess,
  ///                   is a failed attempt: the Session is not activated, and the
  ///                   failure is `Bad_InternalError` whose ErrorDetail (code
  ///                   `AnswerUncertain`) has the Uncertain code as its cause.
  virtual void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept = 0;

protected:
  /// Default-constructs the base; only subclasses construct a `UserAuthenticator`.
  UserAuthenticator() = default;
};

}  // namespace ua::server

#endif  // !UA_SERVER_AUTHENTICATION_H
