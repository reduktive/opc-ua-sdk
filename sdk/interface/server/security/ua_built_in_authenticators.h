// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Built-in @ref ua::server::UserAuthenticator implementations (anonymous, username/password,
///        X.509, and a token-kind-dispatching composite).
/// @ingroup security

#ifndef UA_BUILT_IN_AUTHENTICATORS_H
#define UA_BUILT_IN_AUTHENTICATORS_H

#include "ua_server_authentication.h"

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace ua
{
class CertificateStore;
}

namespace ua::server
{

/// Built-in authenticator that approves anonymous tokens and rejects all others.
///
/// Install this as the server's @ref UserAuthenticator to permit only anonymous
/// access: an @ref AuthnRequest whose presented identity is
/// @ref UserTokenKind::Anonymous succeeds with an anonymous @ref UserIdentity;
/// every other token kind fails. The authenticator is stateless and immutable,
/// so a single instance may be shared across all sessions and called
/// concurrently from any thread.
/// @ingroup security
/// @see UserAuthenticator
class AnonymousAuthenticator : public UserAuthenticator
{
public:
  /// Approves anonymous identities and rejects every other token kind.
  ///
  /// Completes synchronously on the calling thread. On an anonymous identity the
  /// completion receives a successful @ref AuthnResult carrying an anonymous
  /// @ref UserIdentity; otherwise it receives a failed @ref AuthnResult whose
  /// @ref ErrorDetail records why the token was rejected. The completion is
  /// always invoked exactly once.
  ///
  /// @param req        Authentication request; only its presented identity kind
  ///                   is inspected.
  /// @param completion Receives the outcome as an @ref AuthnResult. Invoked
  ///                   exactly once. This override never throws.
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override;
};

/// Built-in @ref UserAuthenticator for username/password identity tokens.
///
/// Holds no credential store and never persists plaintext passwords. Credential
/// verification is delegated to a user-supplied @ref ValidateFn callback, which may use
/// bcrypt, an LDAP lookup, or any other mechanism. The authenticator only handles
/// username/password tokens; other token kinds are rejected.
///
/// @ingroup security
/// @see UserAuthenticator
class SimpleUserPasswordAuthenticator : public UserAuthenticator
{
public:
  /// Predicate that decides whether a username/password pair is valid.
  ///
  /// Returns `true` to accept the credentials and `false` to reject them. The callback is
  /// invoked synchronously from within @ref authenticate_async, so it must return promptly
  /// and must not block the calling thread on long-running I/O. An exception thrown from the
  /// callback is caught and surfaced as a `BadInternalError` authentication failure rather than
  /// propagated, so prefer returning `false` to signal rejection.
  ///
  /// @param username Presented username; valid only for the duration of the call.
  /// @param password Presented password in decrypted form; cleared by @ref ua::SecureString
  ///                 on destruction and valid only for the duration of the call.
  using ValidateFn = std::function<bool(std::string_view username, const ua::SecureString& password)>;

  /// Constructs an authenticator that defers credential checks to @p validate.
  ///
  /// @param validate Validation callback invoked for each username/password token. Stored and
  ///                 owned by the authenticator; must be non-empty and outlives every
  ///                 @ref authenticate_async call for the authenticator's lifetime.
  explicit SimpleUserPasswordAuthenticator(ValidateFn validate);

  /// Authenticates a presented identity token via the validation callback.
  ///
  /// Invokes the stored @ref ValidateFn synchronously and reports the outcome through
  /// @p completion, which is called exactly once and never throws. On success the
  /// @ref AuthnResult carries an @ref AuthnSuccess; on failure (rejected credentials or an
  /// unsupported token kind) it carries a status code and an @ref ErrorDetail describing the
  /// reason. Returns promptly without blocking.
  ///
  /// @param req        Authentication request: the presented identity and the non-secret
  ///                   endpoint security context.
  /// @param completion Receives the @ref AuthnResult. Invoked exactly once.
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override;

private:
  ValidateFn mValidate;
};

/// Built-in authenticator that validates X.509 user identity tokens against a CertificateStore.
///
/// On success, the resulting `ua::server::UserIdentity` uses the certificate's subject common
/// name as both the user ID and display name, falling back to the hex-encoded thumbprint when the
/// certificate has no common name; the thumbprint is always stored under @ref ClaimKeys::thumbprint.
/// Every non-X.509 token kind is rejected. The authenticator does not validate the certificate: the
/// session validates every X.509 user token certificate before any authenticator runs (chain, Table 44
/// use, the user-token policy's Security Policy Check, the server's user-token store, @ref
/// AuthnRequest::userTokenCertificateStore), and a refused token never reaches the authenticator. This
/// class maps the validated certificate to a user only.
///
/// @see ua::server::UserAuthenticator
/// @ingroup security
class X509UserAuthenticator : public UserAuthenticator
{
public:
  /// Constructs the authenticator. It takes no store: the session validates against the server's
  /// user-token store, which comes from `ServerComponents::userTokenCertificateStore` or, failing that,
  /// from `FileTrustListConfig::defaultUserTokenGroupTrustListPath`; if the deployment configures
  /// neither, the session rejects every token with `BadIdentityTokenRejected`.
  X509UserAuthenticator() = default;

  /// Maps the request's already-validated X.509 user identity token to a user.
  ///
  /// Invokes @p completion exactly once, inline. On success the @ref AuthnResult holds an @ref
  /// AuthnSuccess whose `ua::server::UserIdentity` is derived from the certificate as described in
  /// the class brief; on failure it carries a Bad status code and an @ref ua::ErrorDetail describing
  /// the reason (non-X.509 token kind: Bad_UserAccessDenied; missing certificate:
  /// Bad_IdentityTokenInvalid). This override is `noexcept` and never throws.
  ///
  /// @param req        Authentication request; only X.509 presented identities are accepted.
  /// @param completion Receives the @ref AuthnResult outcome. Invoked exactly once; do not block it.
  /// @see ua::server::UserAuthenticator::authenticate_async
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override;
};

/// A @ref UserAuthenticator that dispatches each request to a delegate chosen by token kind.
///
/// Holds an ordered list of registered delegates. On each request the first delegate registered
/// for the presented @ref UserTokenKind handles it; later delegates for the same kind are not
/// consulted. When no delegate matches the kind, the request is rejected with
/// `BadIdentityTokenRejected`.
///
/// Delegates are shared-owned for the lifetime of this authenticator. Registration via add() is
/// not synchronized against concurrent authenticate_async() calls and is expected to complete
/// during setup, before the authenticator is published to the request path.
///
/// @ingroup security
/// @see UserAuthenticator
class CompositeAuthenticator : public UserAuthenticator
{
public:
  /// Registers a delegate to handle requests of a given token kind.
  ///
  /// Appends to the delegate chain. If a delegate is already registered for @p kind, this one is
  /// added after it and therefore never selected; the first registration for a kind wins.
  ///
  /// @param kind          Token kind this delegate handles.
  /// @param authenticator Delegate to dispatch matching requests to; shared-owned for the lifetime
  ///                      of this authenticator. Must not be null.
  void add(UserTokenKind kind, std::shared_ptr<UserAuthenticator> authenticator);

  /// Dispatches the request to the first delegate registered for its token kind.
  ///
  /// Selects the delegate by `req.mIdentity.kind` and forwards the call unchanged; the chosen
  /// delegate invokes @p completion. When no delegate matches the kind, invokes @p completion
  /// directly with a failure carrying `BadIdentityTokenRejected`. Returns promptly without
  /// blocking and invokes @p completion exactly once. Does not throw.
  ///
  /// @param req        Authentication request; the token kind selects the delegate.
  /// @param completion Receives the outcome as an @ref AuthnResult - on success it holds an
  ///                   @ref AuthnSuccess; on failure it carries the status code and an
  ///                   @ref ErrorDetail cause chain. Invoked exactly once.
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override;

private:
  struct Entry
  {
    UserTokenKind kind;
    std::shared_ptr<UserAuthenticator> authenticator;
  };

  std::vector<Entry> mDelegates;
};

}  // namespace ua::server

#endif  // UA_BUILT_IN_AUTHENTICATORS_H
