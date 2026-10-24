// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_USER_TOKEN_ENCRYPTION_H
#define UA_USER_TOKEN_ENCRYPTION_H

#include "ua_byte_string.h"
#include "ua_logger.h"
#include "ua_result.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <functional>

namespace ua
{

class AsymmetricKeyPair;
class Crypto;
class SecurityPolicy;
class X509Certificate;
class UserNameIdentityToken;
class IssuedIdentityToken;

/// Encrypt a UserNameIdentityToken password for the active security policy.
/// Handles RSA (asymmetric encrypt), ECC CBC (EccEncryptedSecret), and ECC AEAD.
/// Mutates the token in place: sets the password to the encrypted value and
/// sets encryption_algorithm to the RSA algorithm URI or ECC policy URI.
/// RSA passwords of at most 64 bytes use the legacy form; longer passwords use RsaEncryptedSecret.
///
/// All non-pointer parameters are owning types so the heap-allocated per-flow struct can survive every
/// callback boundary in the chain.
///
/// @param policy               Security policy for the channel.
/// @param crypto               Crypto provider.
/// @param strand               Optional strand on which to marshal each continuation.
/// @param token                Token to encrypt (password is replaced in place).
/// @param serverNonce          Server nonce from CreateSession/ActivateSession response.
/// @param serverCertificate    Server's certificate (RSA: public key for encryption).
/// @param serverEphemeralPublicKey  Server's ephemeral public key (ECC: for ECDH).
/// @param clientCertificate    Client's certificate (ECC: included in blob).
/// @param clientKeyPair        Client's key pair (ECC: signs the blob).
/// @param logger               Logger used to report exceptions escaping strand-marshalled continuations.
/// @param callback             Success or error status.
void encrypt_user_token_async(shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
  boost::asio::strand<boost::asio::any_io_executor> strand, shared_ptr<UserNameIdentityToken> token,
  ByteString serverNonce, shared_ptr<const X509Certificate> serverCertificate,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ua::Logger logger,
  std::function<void(VoidResult)> callback);

/// Encrypt an IssuedIdentityToken tokenData using the Part 4 7.41.6 EncryptedSecret wire shape.
/// Unlike UserNameIdentityToken, every RSA policy (including deprecated policies) uses
/// RsaEncryptedSecret and the outer encryption_algorithm remains empty. ECC policies use
/// EccEncryptedSecret with the same empty outer field.
void encrypt_issued_token_async(shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
  boost::asio::strand<boost::asio::any_io_executor> strand, shared_ptr<IssuedIdentityToken> token,
  ByteString serverNonce, shared_ptr<const X509Certificate> serverCertificate,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ua::Logger logger,
  std::function<void(VoidResult)> callback);

/// Decrypt the Legacy UserIdentityToken encrypted secret @p cipherText (Part 4 7.40.2.2) with the server's
/// @p keys: one asymmetric decryption per CipherTextBlockSize block (OPC 10000-6 6.7.2), the recovered
/// blocks written in order into @p plainText. A 64-byte password with a 128-byte serverNonce spans two
/// blocks of a 2048-bit RSA-OAEP-SHA256 key.
///
/// @param policy               Security policy of the token (its asymmetric encryption algorithm).
/// @param crypto               Crypto provider.
/// @param strand               The strand the operation runs on.
/// @param keys                 The server key pair whose certificate encrypted the secret.
/// @param plainTextBlockSize   The policy's PlainTextBlockSize for that certificate. A @p cipherText of more
///                             blocks than the longest legacy plaintext (Length, a 64-byte password and a
///                             128-byte nonce) needs is refused before any decryption, with
///                             Bad_DecodingError.
/// @param cipherTextBlockSize  The policy's CipherTextBlockSize for that certificate. A @p cipherText that is
///                             empty or not a whole number of blocks is refused with Bad_DecodingError.
/// @param cipherText           The secret; alive until the callback.
/// @param plainText            At least as long as @p cipherText; alive until the callback.
/// @param logger               Logger used to report an exception escaping the operation.
/// @param callback             The span of @p plainText holding the recovered bytes, or the failure; on a
///                             failure the bytes already recovered are zeroed.
void decrypt_legacy_token_secret_async(shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const AsymmetricKeyPair> keys, size_t plainTextBlockSize, size_t cipherTextBlockSize,
  span<const byte> cipherText, span<byte> plainText, ua::Logger logger,
  std::function<void(Result<span<const byte>>)> callback);

/// Build the plaintext for a Legacy UserIdentityToken encrypted secret before asymmetric
/// encryption (Part 4 7.41.2.2, Table 186):
///   `Length(4 bytes, little-endian) || tokenData || serverNonce`
/// where Length counts the token data plus the server nonce (every byte after the length field).
ByteString build_legacy_encrypted_token_plaintext(span<const byte> tokenData, span<const byte> serverNonce);

/// Recover the token data (password) from the decrypted plaintext of a Legacy UserIdentityToken
/// encrypted secret. Accepts the spec format produced by build_legacy_encrypted_token_plaintext
/// (`Length || tokenData || serverNonce`, with optional trailing zero padding) and falls back to
/// the historical prefix-less `tokenData || serverNonce` form for interop. Validates that the
/// trailing bytes equal the expected server nonce and - for the spec format - that any padding
/// after the declared length is zero (Part 4 7.41.2.2). Returns Bad_IdentityTokenInvalid for a
/// truncated payload or nonce mismatch, Bad_IdentityTokenRejected for non-zero padding.
ByteStringResult parse_legacy_encrypted_token_secret(
  span<const byte> decrypted, span<const byte> serverNonce);

}  // namespace ua

#endif  // UA_USER_TOKEN_ENCRYPTION_H
