// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SESSION_SECURITY_INFO_H
#define UA_CLIENT_SESSION_SECURITY_INFO_H

#include "ua_byte_string.h"
#include "ua_message_security_mode.h"
#include "ua_security_policy.h"
#include "ua_x509_certificate.h"

#include <memory>
#include <vector>

namespace ua
{
class AsymmetricKeyPair;
}

namespace ua::client
{

/// Security parameters passed from the secure channel to the session. Separate from SessionImpl so the
/// channel, which only forward-declares the session, can hand them over on a re-activation as well as at
/// creation.
struct SessionSecurityInfo
{
  std::shared_ptr<const ua::X509Certificate> clientCertificate;
  std::shared_ptr<const ua::AsymmetricKeyPair> clientKeyPair;
  std::shared_ptr<ua::SecurityPolicy> securityPolicy;
  ua::MessageSecurityMode messageSecurityMode{ua::MessageSecurityMode::None};
  /// The server (GetEndpoints/OPN-time) certificate the secure channel was opened against. Used to
  /// enforce CreateSession server-certificate continuity (CL-SC-012 / OPC 10000-4 P4-0004). Null under
  /// SecurityPolicy None (no server certificate participates), which disables the continuity check.
  std::shared_ptr<const ua::X509Certificate> serverCertificate;
  /// The client certificate's issuer chain (decision 24), sent after the leaf in CreateSession
  /// clientCertificate (OPC 10000-6 section 6.2.6).
  std::vector<std::shared_ptr<const ua::X509Certificate>> clientIssuerCertificates;
  /// The channel's ChannelThumbprint (OPC 10000-6 section 6.7.5), which the channel-bound session
  /// signatures cover (OPC 10000-4 section 6.1.8). Empty under a policy without SecureChannelEnhancements.
  ua::ByteString channelThumbprint;
};

}  // namespace ua::client

#endif  // UA_CLIENT_SESSION_SECURITY_INFO_H
