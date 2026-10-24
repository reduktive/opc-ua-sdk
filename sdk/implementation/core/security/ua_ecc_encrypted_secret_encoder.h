// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ECC_ENCRYPTED_SECRET_ENCODER_H
#define UA_ECC_ENCRYPTED_SECRET_ENCODER_H

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
class SecPolEphemeralKey;
class X509Certificate;

/// Build an EccEncryptedSecret blob for UserIdentityToken encryption (Part 4, 7.41.2.5).
///
/// The blob format:
///   Prefix:           TypeId(NodeId) | EncodingMask(Byte=1) | Length(Int32)
///   CommonHeader:     SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime)
///   KeyData:          KeyDataLength(UInt16) | SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
///   EncryptedPayload: [Nonce | Secret | PayloadPadding | PayloadPaddingSize] (encrypted) | AEAD tag
///   Signature:        last N bytes (asymmetric signature over every byte before it, no length prefix)
///
/// The payload is padded to a multiple of 16 bytes by the Part 6 6.8.3 formula, and every byte from TypeId
/// through KeyData, with the final Length, is the AEAD associated data (OPC UA 1.05.07).
///
/// All non-pointer parameters are owning types so the heap-allocated per-flow struct can survive every
/// callback boundary in the chain.
///
/// @param eccPolicy                The ECC security policy for algorithm constants.
/// @param crypto                   Crypto provider.
/// @param strand                   Optional strand on which to marshal each continuation.
/// @param serverEphemeralPublicKey Server's ephemeral public key (from CreateSession/ActivateSession).
/// @param clientCertificate        Client's certificate (DER included in CommonHeader).
/// @param clientKeyPair            Client's key pair (used to sign the blob; null skips signing).
/// @param serverNonce              Server nonce (included as Nonce in encrypted payload).
/// @param secret                   The secret to encrypt (e.g. password bytes).
/// @param logger                   Logger used to report exceptions escaping strand-marshalled continuations.
/// @param callback                 Receives the complete EccEncryptedSecret blob, or an error status.
void encrypt_ecc_encrypted_secret_async(shared_ptr<const SecPolEphemeralKey> eccPolicy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ByteString serverNonce, ByteString secret,
  ua::Logger logger, std::function<void(ByteStringResult)> callback);

}  // namespace ua

#endif  // UA_ECC_ENCRYPTED_SECRET_ENCODER_H
