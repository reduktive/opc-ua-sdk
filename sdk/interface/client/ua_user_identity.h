// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief User identity credentials supplied when activating a client session.
/// @ingroup client

#ifndef UA_USER_IDENTITY_H
#define UA_USER_IDENTITY_H

#include "ua_byte_string.h"
#include "ua_crypto.h"
#include "ua_x509_certificate.h"

#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace ua::client
{

/// Anonymous user identity, requiring no credentials.
///
/// Selects the server's anonymous user-token policy. The session is activated
/// without authenticating a user; the server applies whatever permissions it
/// grants to anonymous access.
/// @ingroup client
struct AnonymousIdentity
{};

/// Username and password credentials for a session.
///
/// Selects the server's UserName user-token policy. The SDK encrypts the
/// password as required by the negotiated security policy before it is sent.
/// @ingroup client
struct UsernamePasswordIdentity
{
  std::string username;  ///< Account name presented to the server.
  std::string password;  ///< Secret for @ref username; encrypted on the wire by the SDK.

  /// Hard opt-in for the unencrypted-password configuration (CL-IDENT-009, Part 4 section 7.41.4 / Table
  /// 193). When the resolved UserTokenPolicy SecurityPolicyUri is `None`, the password travels as plaintext
  /// UTF-8 inside the token. The spec warns this "should not be used unless the network traffic is encrypted
  /// in some other manner"  -  a serious security fault otherwise. The SDK therefore refuses to emit a
  /// plaintext password unless the application explicitly opts in here. Even with the opt-in, a password that
  /// would be fully in the clear (a None channel as well) is still refused.
  bool allowUnencryptedPassword = false;
};

/// X.509 certificate credentials with the matching signing key pair.
///
/// Selects the server's Certificate user-token policy. The SDK signs the
/// activation challenge with @ref keyPair to prove possession of the private
/// key bound to @ref certificate.
/// @ingroup client
struct X509Identity
{
  /// User certificate presented to the server. Shared, immutable; must outlive
  /// any session activated with this identity. Must not be null.
  std::shared_ptr<const ua::X509Certificate> certificate;

  /// Key pair whose private key matches @ref certificate, used to sign the
  /// activation proof. Shared, immutable; must not be null.
  std::shared_ptr<const ua::AsymmetricKeyPair> keyPair;

  /// Issuer chain of @ref certificate, leaf excluded, in order (the certificate that signed the leaf
  /// first). Sent after the leaf in the X509IdentityToken's certificateData (OPC 10000-6 section 6.2.6),
  /// so a server that lacks the intermediates can still build the chain. Empty for a self-signed user
  /// certificate or when the server already holds the issuers.
  std::vector<std::shared_ptr<const ua::X509Certificate>> issuerCertificates;
};

/// Issued-token credentials carrying an opaque, application-managed security token.
///
/// Selects the server's IssuedToken user-token policy. The token bytes are
/// treated as opaque and encrypted on the wire under the same rules as a
/// UserName token.
/// @ingroup client
struct IssuedTokenIdentity
{
  ua::ByteString tokenData;  ///< Opaque issued-token bytes; encrypted on the wire by the SDK.
};

/// User identity supplied to a client session, as one of the supported kinds.
///
/// A tagged union over the concrete identity kinds. The SDK derives the
/// matching OPC UA user-token policy from the active alternative and handles
/// token construction, encryption, and signing on activation.
///
/// @see AnonymousIdentity, UsernamePasswordIdentity, X509Identity, IssuedTokenIdentity
using UserIdentity =
  std::variant<AnonymousIdentity, UsernamePasswordIdentity, X509Identity, IssuedTokenIdentity>;

}  // namespace ua::client

#endif  // !UA_USER_IDENTITY_H
