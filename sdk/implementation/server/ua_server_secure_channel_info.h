// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Immutable snapshot of a server-side secure channel's negotiated security context.
/// @ingroup server

#ifndef UA_SERVER_SECURE_CHANNEL_INFO_H
#define UA_SERVER_SECURE_CHANNEL_INFO_H

#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_security_policy.h"
#include "ua_user_token_policy.h"
#include "ua_x509_certificate.h"

namespace ua::server
{

class SecureChannel;

/// Immutable snapshot of the security context of one server-side secure channel.
///
/// Captures the negotiated security parameters and connection metadata of the channel a
/// session is bound to, taken at the moment the session is created or re-activated. It is
/// handed to authentication and authorization hooks so they can make access decisions from
/// the channel's actual security properties (policy, message mode, client certificate,
/// transport endpoint) rather than re-deriving them.
///
/// This is a copyable value type and holds no ownership of the live channel: the channel is
/// referenced via a `weak_ptr` (see @ref secure_channel), while all other fields are owned
/// copies that remain valid for the lifetime of the snapshot regardless of the channel's
/// state. Accessors are plain reads with no thread or strand affinity and may be called from
/// any thread.
///
/// @ingroup server
class SecureChannelInfo
{
public:
  /// Constructs a snapshot from a channel's negotiated security parameters.
  ///
  /// @param secureChannel       Weak reference to the live channel; may be expired or empty.
  /// @param securityPolicy      Negotiated security policy. Must not be null.
  /// @param messageSecurityMode Negotiated message security mode (None / Sign / SignAndEncrypt).
  /// @param endpointPolicyId    Endpoint user-token policy identifier. Must not be empty.
  /// @param userIdentityTokens  User token policies advertised by the accepting endpoint.
  /// @param clientCertificate   Client's certificate, or null when none was supplied (e.g. a
  ///                            `MessageSecurityMode::None` channel).
  /// @param channelId           Secure channel identifier, or `0` when unknown.
  /// @param remoteAddress       Peer network address, or empty when unknown.
  /// @param endpointUrl         Server-side endpoint URL the channel terminates at; see
  ///                            @ref endpoint_url.
  /// @param transportProfileUri Transport profile URI; see @ref transport_profile_uri.
  /// @param clientIssuerCertificates The issuer certificates the client presented with
  ///                            @p clientCertificate; see @ref client_issuer_certificates.
  /// @param channelThumbprint   The ChannelThumbprint; see @ref channel_thumbprint.
  /// @param serverCertificate   The server's own certificate on the channel; see @ref server_certificate.
  /// @throws UaException with @ref Status::BadConfigurationError if @p endpointPolicyId is empty.
  /// @pre @p securityPolicy is non-null and @p endpointPolicyId is non-empty.
  SecureChannelInfo(weak_ptr<SecureChannel> secureChannel, shared_ptr<const SecurityPolicy> securityPolicy,
    MessageSecurityMode messageSecurityMode, std::string endpointPolicyId,
    std::vector<UserTokenPolicy> userIdentityTokens = {},
    shared_ptr<const X509Certificate> clientCertificate = nullptr, uint32_t channelId = 0,
    std::string remoteAddress = {}, std::string endpointUrl = {}, std::string transportProfileUri = {},
    std::vector<shared_ptr<const X509Certificate>> clientIssuerCertificates = {},
    ByteString channelThumbprint = {}, shared_ptr<const X509Certificate> serverCertificate = nullptr);

  /// Returns a weak reference to the live secure channel this snapshot describes.
  ///
  /// The snapshot never extends the channel's lifetime; lock the result before use and treat
  /// an expired or empty pointer as a closed channel.
  ///
  /// @return Weak pointer to the channel; may be expired or empty.
  weak_ptr<SecureChannel> secure_channel() const;

  /// Returns the negotiated security policy of the channel.
  ///
  /// @return Non-null shared pointer to the security policy.
  shared_ptr<const SecurityPolicy> security_policy() const;

  /// Returns the negotiated message security mode (None, Sign, or SignAndEncrypt).
  ///
  /// @return The negotiated message security mode.
  MessageSecurityMode message_security_mode() const;

  /// Returns the endpoint user-token policy identifier the channel was accepted under.
  ///
  /// @return Reference to the policy identifier; guaranteed non-empty.
  const std::string& endpoint_policy_id() const;

  /// Returns the client's X.509 certificate, if one was presented.
  ///
  /// @return Shared pointer to the client certificate, or null when none was supplied (e.g.
  ///         a `MessageSecurityMode::None` channel).
  shared_ptr<const X509Certificate> client_certificate() const;

  /// Returns the issuer certificates the client presented with its certificate (OPC 10000-6 section
  /// 6.2.6: the certificate field carries the leaf followed by its issuers), in the order received.
  ///
  /// They complete the chain of @ref client_certificate when it is validated again (OPC 10000-12
  /// section 7.8.2.3: the Server re-evaluates the Certificate of each open Session when its TrustList
  /// changes); they never confer trust.
  ///
  /// @return Reference to the presented issuers; empty when none were presented or no client
  ///         certificate was supplied.
  const std::vector<shared_ptr<const X509Certificate>>& client_issuer_certificates() const;

  /// Returns the secure channel identifier.
  ///
  /// @return The channel id, or `0` when unknown.
  uint32_t channel_id() const;

  /// Returns the peer network address of the channel.
  ///
  /// @return Reference to the remote address; empty when unknown.
  const std::string& remote_address() const;

  /// Returns the user token policies advertised by the endpoint that accepted the channel.
  ///
  /// @return Reference to the advertised user token policies.
  const std::vector<UserTokenPolicy>& user_identity_tokens() const;

  /// Returns the server-side stable endpoint URL the channel terminates at.
  ///
  /// This is the first advertised URL of the listener that accepted the connection.
  ///
  /// @return Reference to the endpoint URL; empty when the listener advertises no URLs.
  const std::string& endpoint_url() const;

  /// Returns the transport profile URI of the negotiated channel.
  ///
  /// For example, `http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary`.
  ///
  /// @return Reference to the transport profile URI.
  const std::string& transport_profile_uri() const;

  /// Returns the ChannelThumbprint (OPC 10000-6 section 6.7.5), the Signature on the channel's first
  /// OpenSecureChannel response. The channel-bound session signatures cover it (OPC 10000-4 section 6.1.8).
  ///
  /// @return Reference to the thumbprint; empty under a policy without SecureChannelEnhancements.
  const ByteString& channel_thumbprint() const;

  /// Returns the certificate the server presented on the channel, the ServerChannelCertificate of the
  /// channel-bound signatures (OPC 10000-4 section 6.1.8).
  ///
  /// @return Shared pointer to the server certificate, or null on a `SecurityPolicy` None channel.
  shared_ptr<const X509Certificate> server_certificate() const;

private:
  weak_ptr<SecureChannel> mSecureChannel;
  shared_ptr<const SecurityPolicy> mSecurityPolicy;
  MessageSecurityMode mMessageSecurityMode{MessageSecurityMode::Invalid};
  std::string mEndpointPolicyId;
  std::vector<UserTokenPolicy> mUserIdentityTokens;
  shared_ptr<const X509Certificate> mClientCertificate;
  uint32_t mChannelId{};
  std::string mRemoteAddress;
  std::string mEndpointUrl;
  std::string mTransportProfileUri;
  std::vector<shared_ptr<const X509Certificate>> mClientIssuerCertificates;
  ByteString mChannelThumbprint;
  shared_ptr<const X509Certificate> mServerCertificate;
};

inline weak_ptr<SecureChannel> SecureChannelInfo::secure_channel() const
{
  return mSecureChannel;
}

inline shared_ptr<const SecurityPolicy> SecureChannelInfo::security_policy() const
{
  return mSecurityPolicy;
}

inline MessageSecurityMode SecureChannelInfo::message_security_mode() const
{
  return mMessageSecurityMode;
}

inline const std::string& SecureChannelInfo::endpoint_policy_id() const
{
  return mEndpointPolicyId;
}

inline shared_ptr<const X509Certificate> SecureChannelInfo::client_certificate() const
{
  return mClientCertificate;
}

inline const std::vector<shared_ptr<const X509Certificate>>&
  SecureChannelInfo::client_issuer_certificates() const
{
  return mClientIssuerCertificates;
}

inline uint32_t SecureChannelInfo::channel_id() const
{
  return mChannelId;
}

inline const std::string& SecureChannelInfo::remote_address() const
{
  return mRemoteAddress;
}

inline const std::vector<UserTokenPolicy>& SecureChannelInfo::user_identity_tokens() const
{
  return mUserIdentityTokens;
}

inline const std::string& SecureChannelInfo::endpoint_url() const
{
  return mEndpointUrl;
}

inline const std::string& SecureChannelInfo::transport_profile_uri() const
{
  return mTransportProfileUri;
}

inline const ByteString& SecureChannelInfo::channel_thumbprint() const
{
  return mChannelThumbprint;
}

inline shared_ptr<const X509Certificate> SecureChannelInfo::server_certificate() const
{
  return mServerCertificate;
}

inline SecureChannelInfo::SecureChannelInfo(weak_ptr<SecureChannel> secureChannel,
  shared_ptr<const SecurityPolicy> securityPolicy, MessageSecurityMode messageSecurityMode,
  std::string endpointPolicyId, std::vector<UserTokenPolicy> userIdentityTokens,
  shared_ptr<const X509Certificate> clientCertificate, uint32_t channelId, std::string remoteAddress,
  std::string endpointUrl, std::string transportProfileUri,
  std::vector<shared_ptr<const X509Certificate>> clientIssuerCertificates, ByteString channelThumbprint,
  shared_ptr<const X509Certificate> serverCertificate)
  : mSecureChannel(secureChannel), mSecurityPolicy(securityPolicy), mMessageSecurityMode(messageSecurityMode),
    mEndpointPolicyId(std::move(endpointPolicyId)), mUserIdentityTokens(std::move(userIdentityTokens)),
    mClientCertificate(std::move(clientCertificate)), mChannelId(channelId),
    mRemoteAddress(std::move(remoteAddress)), mEndpointUrl(std::move(endpointUrl)),
    mTransportProfileUri(std::move(transportProfileUri)),
    mClientIssuerCertificates(std::move(clientIssuerCertificates)),
    mChannelThumbprint(std::move(channelThumbprint)), mServerCertificate(std::move(serverCertificate))
{
  check(mSecurityPolicy);
  if (mEndpointPolicyId.empty())
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "EmptyEndpointPolicyId", "SecureChannelInfo endpointPolicyId must not be empty", "SecureChannelInfo")
        .context(ua::ContextKeys::channelId, std::to_string(channelId))
        .context(ua::ContextKeys::remoteAddress, mRemoteAddress)};
  }
}

}  // namespace ua::server

#endif  // !UA_SERVER_SECURE_CHANNEL_INFO_H
