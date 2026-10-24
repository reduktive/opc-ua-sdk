// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ECC_ENCRYPTED_SECRET_DECODER_H
#define UA_ECC_ENCRYPTED_SECRET_DECODER_H

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_logger.h"
#include "ua_result.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_string.h"

#include <functional>

namespace ua
{

class Crypto;
class SecPolEphemeralKey;
class X509Certificate;

/// Parsed and decrypted fields from an EccEncryptedSecret blob (Part 4, 7.41.2.5).
struct EccEncryptedSecretFields
{
  String securityPolicyUri;
  ByteString certificate;  // signing cert DER (may be empty)
  DateTime signingTime;
  ByteString senderPublicKey;
  ByteString receiverPublicKey;
  ByteString signature;
  // After decryption:
  ByteString nonce;
  ByteString secret;
};

using EccEncryptedSecretFieldsResult = Result<EccEncryptedSecretFields>;

/// Parse and decrypt an EccEncryptedSecret blob from UserNameIdentityToken::password().
///
/// The blob format (Part 4, 7.41.2.5):
///   CommonHeader:  SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime)
///   KeyData:       KeyDataLength(UInt16) | SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
///   EncryptedPayload: [Nonce | Secret | PayloadPadding | PayloadPaddingSize] (encrypted) | AEAD tag
///   Signature:     last N bytes (asymmetric, no length prefix)
///
/// The signature covers every byte before it. Only the payload is encrypted; KeyData is cleartext, and every
/// byte from TypeId through KeyData is the AEAD associated data (Part 6 6.8.3, OPC UA 1.05.07).
///
/// Once the secret is verified and decrypted, its CommonHeader SecurityPolicyUri must be @p eccPolicy's
/// URI (security review SESS-7(e)); a mismatch fails with @ref Status::BadIdentityTokenInvalid and
/// ErrorDetail code `EncryptedSecretPolicyMismatch`.
///
/// All non-pointer parameters are owning types so the heap-allocated per-flow struct can survive every
/// callback boundary in the chain.
///
/// @param data                    Raw bytes from UserNameIdentityToken::password().
/// @param eccPolicy               The ECC security policy for algorithm constants.
/// @param crypto                  Crypto provider.
/// @param strand                  Optional strand on which to marshal each continuation.
/// @param localEphemeralPrivateKey Server's ephemeral private key (consumed for ECDH).
/// @param localEphemeralPublicKey  Server's ephemeral public key (for receiver key verification).
/// @param remoteCertificate        Client's certificate (for signature verification; may be null).
/// @param logger                   Logger used to report exceptions escaping strand-marshalled continuations.
/// @param callback                 Receives the parsed and decrypted fields, or an error status.
void decrypt_ecc_encrypted_secret_async(ByteString data, shared_ptr<const SecPolEphemeralKey> eccPolicy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ByteString localEphemeralPrivateKey, ByteString localEphemeralPublicKey,
  shared_ptr<const X509Certificate> remoteCertificate, ua::Logger logger,
  std::function<void(EccEncryptedSecretFieldsResult)> callback);

}  // namespace ua

#endif  // UA_ECC_ENCRYPTED_SECRET_DECODER_H
