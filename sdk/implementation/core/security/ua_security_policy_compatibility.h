// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SECURITY_POLICY_COMPATIBILITY_H
#define UA_SECURITY_POLICY_COMPATIBILITY_H

#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_result.h"
#include "ua_structure.h"
#include "ua_user_token_policy.h"

#include <vector>
#include <string_view>

namespace ua
{

/// URI identifying the RSA asymmetric encryption algorithm, or empty for an invalid algorithm.
std::string_view asymmetric_encryption_algorithm_uri(AsymmetricEncryptionAlgorithm algorithm);

/// Validates that a user token policy is safe to use with the given channel settings.
/// Returns a bad result with ErrorDetail if the combination is invalid:
/// - UserName/IssuedToken with effective None policy on a channel that doesn't encrypt.
/// - X509 with effective None policy (requires authenticated policy for UserTokenSignature).
/// - UserName/IssuedToken naming an ECC or RSA_DH policy over a None channel, or on an endpoint whose own
///   policy does not use ephemeral key agreement (Bad_SecurityPolicyRejected, OPC 10000-4 7.41).
/// - X509 naming a policy with SecureChannelEnhancements on a secured channel without them
///   (Bad_SecurityPolicyRejected).
/// Anonymous tokens are always accepted. Runs when an endpoint is added and at every ActivateSession; it
/// creates no SecurityPolicy.
VoidResult validate_user_token_policy(
  const UserTokenPolicy& tokenPolicy, SecurityPolicyId channelPolicy, MessageSecurityMode channelMode);

/// Validates that a PRESENTED user identity token honours the encryption its matched policy requires.
///
/// `validate_user_token_policy` above checks the *configuration* -- a policy that would allow a
/// cleartext secret on a channel that does not encrypt. It cannot catch a client that simply omits
/// the encryption: it never sees the token. Part 4 section 7.41.4 Table 193 requires the secret of a
/// UserName or IssuedToken to be encrypted under the effective SecurityPolicy of the matched
/// UserTokenPolicy, and a Server that keys its handling off the token's own `encryptionAlgorithm`
/// field lets an attacker-controllable value decide whether protection applies at all.
///
/// The effective policy is the token policy's own SecurityPolicy where it names one, and the
/// channel's otherwise. Where that policy is None the secret travels in clear by design and
/// `validate_user_token_policy` has already required the channel to encrypt, so nothing is checked
/// here. Where it names a real policy, the token must carry an `encryptionAlgorithm`.
///
/// @param tokenPolicy    The advertised UserTokenPolicy the presented token's policyId matched.
/// @param channelPolicy  The SecureChannel's SecurityPolicy, used where the token policy names none.
/// @param channelMode    The SecureChannel's MessageSecurityMode.
/// @param presentedToken The token as it arrived; only its type and encryptionAlgorithm are read.
/// @return Good, or Bad_IdentityTokenInvalid naming the missing encryption.
VoidResult validate_presented_user_token(const UserTokenPolicy& tokenPolicy, SecurityPolicyId channelPolicy,
  MessageSecurityMode channelMode, const Structure& presentedToken);

/// Validates that all authenticated user token policies on an endpoint use certificate types
/// from the same compatibility family (RSA, NIST ECC, Brainpool ECC, Ed25519, Ed448).
/// Cross-family mixing is rejected with BadConfigurationError.
/// For authenticated channels, additionally validates that the user token cert family
/// matches the channel policy's family.
VoidResult validate_user_token_policy_certificate_consistency(
  SecurityPolicyId channelPolicyId, const std::vector<UserTokenPolicy>& userTokenPolicies);

}  // namespace ua

#endif  // UA_SECURITY_POLICY_COMPATIBILITY_H
