// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RSA_ENCRYPTED_SECRET_DECODER_H
#define UA_RSA_ENCRYPTED_SECRET_DECODER_H

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_defines.h"
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_string.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <functional>
#include <optional>

namespace ua
{

class AsymmetricKeyPair;
class Crypto;
class SecurityPolicy;
class X509Certificate;

/// Parsed and decrypted fields recovered from an RsaEncryptedSecret blob (Part 4, 7.41.2.3/7.41.2.4).
///
/// This is the exact inverse of the layout produced by @ref encrypt_rsa_encrypted_secret_async: the
/// KeyData is RSA-decrypted to recover the symmetric key material, the trailing HMAC is verified over the
/// signed region *before* the payload is trusted, and only then is the payload AES-CBC-decrypted to yield
/// the Nonce and Secret.
struct RsaEncryptedSecretFields
{
  String securityPolicyUri;  ///< SecurityPolicyUri from the CommonHeader.
  ByteString certificateThumbprint;  ///< Certificate field: the server-certificate SHA1 thumbprint.
  DateTime signingTime;  ///< SigningTime from the CommonHeader.
  ByteString nonce;  ///< Nonce recovered from the decrypted payload.
  ByteString secret;  ///< Secret recovered from the decrypted payload (padding stripped).
};

using RsaEncryptedSecretFieldsResult = Result<RsaEncryptedSecretFields>;
using RsaPayloadPrefixSizeResult = Result<size_t>;

/// Validates the trailing padding of a decrypted RSA secret payload and returns the unpadded prefix size.
/// This internal helper is shared by the decoder and its focused unit tests.
RsaPayloadPrefixSizeResult validate_rsa_secret_payload_padding(
  span<const byte> decrypted, bool acceptInvalidPadding);

/// Parse, verify, and decrypt an RsaEncryptedSecret blob (Part 4, 7.41.2.3/7.41.2.4).
///
/// The blob is an ExtensionObject serialized as:
///   TypeId(NodeId=RsaEncryptedSecret) | EncodingMask(Byte=0x01) | Length(Int32) |
///   CommonHeader:     SecurityPolicyUri(String) | Certificate(ByteString=server thumbprint) |
///                     SigningTime(DateTime)
///   KeyData:          KeyDataLength(UInt16) | <RSA-OAEP-encrypted SigningKey|EncryptingKey|IV>
///   EncryptedPayload: <AES-CBC-encrypted Nonce|Secret|PayloadPadding|PayloadPaddingSize>
///   Signature:        HMAC-SHA256 over CommonHeader..EncryptedPayload keyed by SigningKey (no length
///                     prefix)
///
/// Verify-then-use: the KeyData is RSA-decrypted with @p receiverKeyPair to recover the SigningKey, the
/// trailing HMAC is verified over the signed region (CommonHeader..EncryptedPayload) with that SigningKey,
/// and only if the MAC is valid is the payload AES-CBC-decrypted. The MAC check runs *before* the payload
/// is decrypted or trusted; a MAC mismatch fails with @ref Status::BadIdentityTokenInvalid and the payload
/// is never used.
///
/// Once the secret is verified and decrypted, its CommonHeader is checked against what decrypted it
/// (security review SESS-7(e)): the SecurityPolicyUri must be @p policy's URI
/// (`EncryptedSecretPolicyMismatch`) and the Certificate must be the thumbprint of
/// @p receiverCertificate (`EncryptedSecretCertificateMismatch`); either mismatch fails with
/// @ref Status::BadIdentityTokenInvalid.
///
/// All non-pointer parameters are owning types so the heap-allocated per-flow struct can survive every
/// callback boundary in the chain.
///
/// @param data             The full RsaEncryptedSecret ExtensionObject blob (token bytes).
/// @param policy           The RSA security policy (Basic256Sha256, ...) supplying algorithms and sizes.
/// @param crypto           Crypto provider.
/// @param strand           Optional strand on which to marshal each continuation.
/// @param receiverKeyPair  Server (receiver) key pair whose private key RSA-decrypts the KeyData.
/// @param receiverCertificate The certificate of @p receiverKeyPair; the CommonHeader Certificate must be
///                         its thumbprint. Null refuses every secret.
/// @param acceptInvalidPadding Whether non-zero payload-padding bytes are accepted for interoperability.
/// @param logger           Logger used to report exceptions escaping strand-marshalled continuations.
/// @param callback         Receives the parsed and decrypted fields, or an error status.
void decrypt_rsa_encrypted_secret_async(ByteString data, shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const AsymmetricKeyPair> receiverKeyPair, shared_ptr<const X509Certificate> receiverCertificate,
  bool acceptInvalidPadding, ua::Logger logger, std::function<void(RsaEncryptedSecretFieldsResult)> callback);

/// Non-throwing peek: does @p blob begin with the RsaEncryptedSecret ExtensionObject TypeId
/// (`NodeId{RsaEncryptedSecret}`)? Used to distinguish a modern RsaEncryptedSecret user-token secret
/// (whose TypeId|EncodingMask|Length|CommonHeader prefix is cleartext) from the legacy section 7.41.2.2 form
/// (an opaque RSA ciphertext, whose leading bytes are effectively random). Returns false on any decode
/// failure or TypeId mismatch  -  it never throws.
bool is_rsa_encrypted_secret(span<const byte> blob);

}  // namespace ua

#endif  // UA_RSA_ENCRYPTED_SECRET_DECODER_H
