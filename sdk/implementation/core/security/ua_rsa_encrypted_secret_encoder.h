// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RSA_ENCRYPTED_SECRET_ENCODER_H
#define UA_RSA_ENCRYPTED_SECRET_ENCODER_H

#include "ua_byte_string.h"
#include "ua_logger.h"
#include "ua_result.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <functional>
#include <optional>

namespace ua
{

class Crypto;
class SecurityPolicy;
class X509Certificate;

/// Build an RsaEncryptedSecret blob for UserIdentityToken secret encryption (Part 4, 7.41.2.3/7.41.2.4).
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
/// Encrypt-then-MAC: the KeyData is encrypted to the server public key, the payload is encrypted under the
/// freshly generated EncryptingKey/IV, and the whole preceding region is then MAC'd with SigningKey. For
/// the RSA variant the Signature is a *symmetric* MAC (not an asymmetric signature  -  that is the ECC
/// variant).
///
/// All owning parameters are copied into a heap-allocated per-flow struct so they survive every callback
/// boundary in the async chain.
///
/// @param policy            An RSA security policy (Basic256Sha256, ...) supplying the algorithm and key
///                          sizes.
/// @param crypto            Crypto provider.
/// @param strand            Optional strand on which to marshal each continuation.
/// @param serverCertificate Server (encrypting) certificate: its public key encrypts the KeyData and its
///                          SHA1 thumbprint is written into the CommonHeader Certificate field.
/// @param serverNonce       Server nonce, written as the Nonce in the encrypted payload.
/// @param secret            The secret to encrypt (e.g. UTF-8 password bytes).
/// @param logger            Logger used to report exceptions escaping strand-marshalled continuations.
/// @param callback          Receives the complete RsaEncryptedSecret blob, or an error status.
void encrypt_rsa_encrypted_secret_async(shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const X509Certificate> serverCertificate, ByteString serverNonce, ByteString secret,
  ua::Logger logger, std::function<void(ByteStringResult)> callback);

}  // namespace ua

#endif  // UA_RSA_ENCRYPTED_SECRET_ENCODER_H
