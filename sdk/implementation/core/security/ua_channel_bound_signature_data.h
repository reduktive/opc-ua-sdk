// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CHANNEL_BOUND_SIGNATURE_DATA_H
#define UA_CHANNEL_BOUND_SIGNATURE_DATA_H

#include "ua_byte_string.h"
#include "ua_crypto_types.h"
#include "ua_logger.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <functional>

namespace ua
{

class Crypto;

/// The session signatures whose data to sign OPC 10000-4 section 6.1.8 Table 101 defines.
enum class ChannelBoundSignature
{
  Server,  ///< The CreateSession ServerSignature.
  Client,  ///< The ActivateSession ClientSignature.
  UserToken,  ///< An X509 UserTokenSignature over a SecureChannel whose SecurityMode is not None.
  UserTokenOverNone,  ///< An X509 UserTokenSignature over a SecureChannel whose SecurityMode is None.
};

/// The values Table 101 appends. Every certificate is the DER of the leaf alone (the channel bound method
/// "always uses the leaf Certificate"); an empty one contributes an empty hash.
struct ChannelBoundSignatureInputs
{
  ByteString channelThumbprint;  ///< The SecureChannel's ChannelThumbprint (OPC 10000-6 section 6.7.5).
  ByteString clientNonce;  ///< The ClientNonce of the CreateSession request.
  ByteString serverNonce;  ///< The ServerNonce of the CreateSession or latest ActivateSession response.
  ByteString serverCertificate;  ///< The ServerCertificate of the CreateSession response.
  ByteString serverChannelCertificate;  ///< The server's certificate on the SecureChannel.
  ByteString clientCertificate;  ///< The ClientCertificate of the CreateSession request.
  ByteString clientChannelCertificate;  ///< The client's certificate on the SecureChannel.
};

/// Builds the data to sign for @p signature (OPC 10000-4 section 6.1.8 Table 101). Both roles call it, the
/// signer to sign and the receiver to verify, so the two cannot disagree on the layout.
///
/// HASH is @p hash, the CertificateThumbprintAlgorithm of the SecurityPolicy that decides the signature: the
/// SecureChannel's for the Server and Client signatures, the UserTokenPolicy's for a UserTokenSignature. The
/// certificates are hashed through @p crypto, one digest each; the fields are appended in Table 101 order.
///
/// @param signature The signature the data is for.
/// @param hash      The CertificateThumbprintAlgorithm of the deciding SecurityPolicy.
/// @param crypto    Crypto provider for the digests.
/// @param strand    The strand every continuation runs on.
/// @param logger    Logger for exceptions escaping a continuation.
/// @param inputs    The values Table 101 appends.
/// @param callback  Receives the data to sign, or the status of the digest that failed. Answered once.
void build_channel_bound_signature_data_async(ChannelBoundSignature signature, HashAlgorithm hash,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ua::Logger logger, ChannelBoundSignatureInputs inputs, std::function<void(ByteStringResult)> callback);

}  // namespace ua

#endif  // UA_CHANNEL_BOUND_SIGNATURE_DATA_H
