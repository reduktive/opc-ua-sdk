// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Enumerations identifying the cryptographic algorithms and security policies used by the
///        UA secure channel.
/// @ingroup security

#ifndef UA_CRYPTO_TYPES_H
#define UA_CRYPTO_TYPES_H

#include "ua_includes.h"
#include "ua_message_security_mode.h"

#include <cstdint>

namespace ua
{
/// Symmetric (bulk) encryption algorithm used to encrypt secure-channel message bodies.
///
/// Selected indirectly by the negotiated @ref SecurityPolicyId; identifies the cipher applied with
/// the session's symmetric keys after the channel is established.
/// @ingroup security
enum class SymmetricEncryptionAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  Aes128Cbc = 1,  ///< AES-128 in CBC mode.
  Aes256Cbc = 2,  ///< AES-256 in CBC mode.
  ChaCha20Poly1305 = 3,  ///< ChaCha20-Poly1305 authenticated encryption (AEAD).
  Aes128Gcm = 4,  ///< AES-128 in GCM mode (AEAD).
  Aes256Gcm = 5  ///< AES-256 in GCM mode (AEAD).
};

/// Symmetric signature (message authentication) algorithm protecting secure-channel message
/// integrity.
enum class SymmetricSignatureAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  HmacSha1 = 1,  ///< HMAC-SHA-1.
  HmacSha2256 = 2,  ///< HMAC-SHA-256.
  HmacSha2384 = 3,  ///< HMAC-SHA-384.
  // The AEAD tags below are produced by the AEAD encryption with the encrypting key, never by a
  // standalone MAC.
  ChaCha20Poly1305 = 4,  ///< The ChaCha20-Poly1305 AEAD tag.
  Aes128Gcm = 5,  ///< The AES-128-GCM AEAD tag.
  Aes256Gcm = 6  ///< The AES-256-GCM AEAD tag.
};

/// Key-derivation function used to expand the shared secret into the symmetric session keys.
enum class SymmetricKeyDerivationAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  PSha1 = 1,  ///< TLS 1.0-style P_SHA-1 PRF.
  PSha2256 = 2,  ///< TLS-style P_SHA-256 PRF.
  HkdfSha2256 = 3,  ///< HKDF with SHA-256.
  HkdfSha2384 = 4  ///< HKDF with SHA-384.
};

/// @ingroup security
/// Asymmetric encryption algorithm used to protect the secrets exchanged during channel
/// establishment (the OpenSecureChannel handshake).
enum class AsymmetricEncryptionAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  RsaPkcs15 = 1,  ///< RSA with PKCS#1 v1.5 padding.
  RsaOaepSha1 = 2,  ///< RSA-OAEP with SHA-1.
  RsaOaepSha2256 = 3  ///< RSA-OAEP with SHA-256.
};

/// @ingroup security
/// Asymmetric signature algorithm used to sign the handshake messages with the application's
/// private key.
enum class AsymmetricSignatureAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  RsaPkcs15Sha1 = 1,  ///< RSASSA-PKCS1-v1_5 with SHA-1.
  RsaPkcs15Sha2256 = 2,  ///< RSASSA-PKCS1-v1_5 with SHA-256.
  RsaPssSha2256 = 3,  ///< RSASSA-PSS with SHA-256.
  EcDsaSha2256 = 4,  ///< ECDSA with SHA-256.
  EcDsaSha2384 = 5,  ///< ECDSA with SHA-384.
  EcDsaSha2512 = 6,  ///< ECDSA with SHA-512.
  PureEdDsa25519 = 7,  ///< Pure EdDSA over Curve25519 (Ed25519).
  PureEdDsa448 = 8  ///< Pure EdDSA over Curve448 (Ed448).
};

/// @ingroup security
/// Signature algorithm with which an X.509 certificate was signed by its issuer.
enum class CertificateSignatureAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  RsaPkcs15Sha1 = 1,  ///< RSASSA-PKCS1-v1_5 with SHA-1.
  RsaPkcs15Sha2256 = 2,  ///< RSASSA-PKCS1-v1_5 with SHA-256.
  EcDsaSha2256 = 3,  ///< ECDSA with SHA-256.
  EcDsaSha2384 = 4,  ///< ECDSA with SHA-384.
  EcDsaSha2512 = 5,  ///< ECDSA with SHA-512.
  PureEdDsa25519 = 6,  ///< Pure EdDSA over Curve25519 (Ed25519).
  PureEdDsa448 = 7,  ///< Pure EdDSA over Curve448 (Ed448).
  RsaPkcs15Sha2224 = 8,  ///< RSASSA-PKCS1-v1_5 with SHA-224.
  RsaPkcs15Sha2384 = 9,  ///< RSASSA-PKCS1-v1_5 with SHA-384.
  RsaPkcs15Sha2512 = 10,  ///< RSASSA-PKCS1-v1_5 with SHA-512.
  RsaPssSha2256 = 11,  ///< RSASSA-PSS with SHA-256 (hash named in the PSS parameters).
  RsaPssSha2384 = 12,  ///< RSASSA-PSS with SHA-384.
  RsaPssSha2512 = 13  ///< RSASSA-PSS with SHA-512.
};

/// @ingroup security
/// Public-key algorithm and curve/parameters of the key carried by an X.509 certificate.
enum class CertificateKeyAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  Rsa = 1,  ///< RSA key.
  EccNistP256 = 2,  ///< ECC key on the NIST P-256 curve.
  EccNistP384 = 3,  ///< ECC key on the NIST P-384 curve.
  EccNistP521 = 4,  ///< ECC key on the NIST P-521 curve.
  EccBrainpoolP256r1 = 5,  ///< ECC key on the Brainpool P-256r1 curve.
  EccBrainpoolP384r1 = 6,  ///< ECC key on the Brainpool P-384r1 curve.
  EccBrainpoolP512r1 = 7,  ///< ECC key on the Brainpool P-512r1 curve.
  EccCurve25519 = 8,  ///< ECC key on Curve25519.
  EccCurve448 = 9  ///< ECC key on Curve448.
};

/// @ingroup security
/// Algorithm and group of the ephemeral key pair generated per key agreement (ECC or RSA-DH).
enum class EphemeralKeyAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  EccNistP256 = 1,  ///< Ephemeral ECDH key on the NIST P-256 curve.
  EccNistP384 = 2,  ///< Ephemeral ECDH key on the NIST P-384 curve.
  EccBrainpoolP256r1 = 3,  ///< Ephemeral ECDH key on the Brainpool P-256r1 curve.
  EccBrainpoolP384r1 = 4,  ///< Ephemeral ECDH key on the Brainpool P-384r1 curve.
  EccCurve25519 = 5,  ///< Ephemeral X25519 key.
  EccCurve448 = 6,  ///< Ephemeral X448 key.
  RsaDhFfdhe3072 = 7  ///< Ephemeral finite-field Diffie-Hellman key in the RFC 7919 ffdhe3072 group.
};

/// @ingroup security
/// Cryptographic hash function.
enum class HashAlgorithm
{
  Invalid = 0,  ///< No algorithm / unset.
  Sha1 = 1,  ///< SHA-1.
  Sha2256 = 2,  ///< SHA-256.
  Sha2384 = 3  ///< SHA-384.
};

/// @ingroup security
/// Identifier of an OPC UA security policy, bundling the algorithm suite negotiated for a secure
/// channel.
///
/// Each policy fixes the encryption, signature, key-derivation and hash algorithms used together;
/// the enumerator maps to a security-policy URI on the wire.
enum class SecurityPolicyId
{
  Invalid = 0,  ///< No policy / unset.
  None = 1,  ///< No security (messages neither signed nor encrypted).
  Basic128Rsa15 = 2,  ///< Deprecated Basic128Rsa15 policy.
  Basic256 = 3,  ///< Deprecated Basic256 policy.
  Basic256Sha256 = 4,  ///< Basic256Sha256 policy.
  Aes128Sha256RsaOaep = 5,  ///< Aes128_Sha256_RsaOaep policy.
  Aes256Sha256RsaPss = 6,  ///< Aes256_Sha256_RsaPss policy.
  PubSubAes128Ctr = 7,  ///< PubSub-Aes128-CTR policy (PubSub message security).
  PubSubAes256Ctr = 8,  ///< PubSub-Aes256-CTR policy (PubSub message security).
  EccNistP256AesGcm = 9,  ///< ECC_nistP256_AesGcm policy.
  EccNistP256ChaChaPoly = 10,  ///< ECC_nistP256_ChaChaPoly policy.
  EccNistP384AesGcm = 11,  ///< ECC_nistP384_AesGcm policy.
  EccNistP384ChaChaPoly = 12,  ///< ECC_nistP384_ChaChaPoly policy.
  EccBrainpoolP256r1AesGcm = 13,  ///< ECC_brainpoolP256r1_AesGcm policy.
  EccBrainpoolP256r1ChaChaPoly = 14,  ///< ECC_brainpoolP256r1_ChaChaPoly policy.
  EccBrainpoolP384r1AesGcm = 15,  ///< ECC_brainpoolP384r1_AesGcm policy.
  EccBrainpoolP384r1ChaChaPoly = 16,  ///< ECC_brainpoolP384r1_ChaChaPoly policy.
  EccCurve25519AesGcm = 17,  ///< ECC_curve25519_AesGcm policy.
  EccCurve25519ChaChaPoly = 18,  ///< ECC_curve25519_ChaChaPoly policy.
  EccCurve448AesGcm = 19,  ///< ECC_curve448_AesGcm policy.
  EccCurve448ChaChaPoly = 20,  ///< ECC_curve448_ChaChaPoly policy.
  RsaDhAesGcm = 21,  ///< RSA_DH_AesGcm policy (RSA certificates, ffdhe3072 key agreement).
  RsaDhChaChaPoly = 22  ///< RSA_DH_ChaChaPoly policy (RSA certificates, ffdhe3072 key agreement).
};

/// @ingroup security
/// Purpose-based classification of an application instance certificate.
///
/// Identifies which key/algorithm family a certificate belongs to, allowing an endpoint to select
/// the certificate matching the negotiated `SecurityPolicyId`.
enum class CertificateType
{
  Invalid,  ///< No type / unset.
  Application,  ///< Generic application instance certificate.
  Https,  ///< Certificate used for HTTPS transport.
  RsaMinApplication,  ///< Application certificate with a minimum-strength RSA key.
  RsaSha256Application,  ///< Application certificate with an RSA key signed using SHA-256.
  EccApplication,  ///< Generic ECC application certificate.
  EccNistP256Application,  ///< ECC application certificate on the NIST P-256 curve.
  EccNistP384Application,  ///< ECC application certificate on the NIST P-384 curve.
  EccBrainpoolP256r1Application,  ///< ECC application certificate on the Brainpool P-256r1 curve.
  EccBrainpoolP384r1Application,  ///< ECC application certificate on the Brainpool P-384r1 curve.
  EccCurve25519Application,  ///< ECC application certificate on Curve25519.
  EccCurve448Application  ///< ECC application certificate on Curve448.
};

/// @ingroup security
/// The use a certificate is validated for.
///
/// OPC 10000-4 section 6.1.3 Table 106, Certificate Usage: the certificate's uses "shall match use
/// requested for the Certificate (i.e. Application, Software or CA)". The requested use is the
/// caller's knowledge, so the caller states it; `Crypto::validate_certificate_async` applies the same
/// chain, signature, validity and revocation checks for every use and then the rules of the use.
enum class CertificateUse
{
  /// An ApplicationInstance Certificate without a specified application role, for administrative
  /// validation. RSA certificates require serverAuth or clientAuth. Use the role-specific values
  /// when validating a peer or the application's own certificate. ApplicationUri and hostname checks
  /// apply when requested.
  ApplicationInstance,

  /// A CA certificate (OPC 10000-6 Table 45), such as an entry of an issuer list: basicConstraints cA
  /// must be TRUE, otherwise the certificate is refused with Bad_CertificateIssuerUseNotAllowed. The
  /// end-entity rules do not apply.
  CertificateAuthority,

  /// A User Certificate presented in an X509IdentityToken (OPC 10000-6 section 6.2.3 Table 44): the
  /// end-entity rules that hold for every certificate apply (basicConstraints), the Table 43 keyUsage
  /// and extendedKeyUsage requirements do not. A server's DefaultUserTokenGroup store is constructed
  /// with this use.
  User,

  /// An ApplicationInstance Certificate used by a Server. RSA certificates require serverAuth;
  /// the role is independent of hostname-validation suppression. ECC EKUs remain optional.
  ServerApplicationInstance,

  /// An ApplicationInstance Certificate used by a Client. RSA certificates require clientAuth;
  /// ECC EKUs remain optional.
  ClientApplicationInstance,
};

/// Computes the relative security level for an endpoint description.
///
/// OPC UA Part 4 7.10 defines `securityLevel` as a Byte (0-255) indicating how secure an
/// EndpointDescription is relative to other endpoints on the same server. Higher values are
/// more secure; 0 means the endpoint is not recommended and exists only for backward
/// compatibility. The score is **relative, not absolute**, and may change as new security
/// policies are added to the SDK, so callers must use it only to rank endpoints against one
/// another - never as a measure of absolute strength.
///
/// **Ranking rationale.** The policy's tier in the SDK's one security ordering decides; the client's default
/// endpoint ranking reads the same tier.
///
/// - A policy with SecureChannelEnhancements ranks above every policy without them: ephemeral keys (so
///   forward secrecy), AEAD and channel bound session signatures.
/// - Within each group policies rank by effective symmetric strength.
/// - At equal strength, NIST curves (P-256, P-384) rank one tier below Brainpool and RSA_DH. Their
///   curve seed parameters have unverifiable provenance (cf. the Dual_EC_DRBG incident); no practical
///   attack has been demonstrated, so they remain usable, but the trust deficit justifies a penalty.
///   The finite-field group of RSA_DH (ffdhe3072, RFC 7919) has published, verifiable parameters.
/// - Bernstein curves (Curve25519, Curve448) rank one tier above their peers: auditable design choices,
///   constant time by design.
/// - The AesGcm and the ChaChaPoly policy of one curve share a tier.
///
/// **Policy tiers** (0 = not recommended):
///
/// | Tier | Category                               | Policies                                  |
/// |------|----------------------------------------|-------------------------------------------|
/// | 0    | None / deprecated / PubSub             | None, Basic128Rsa15, Basic256, PubSub-*   |
/// | 1    | legacy RSA, SHA-1 OAEP                 | Basic256Sha256                            |
/// | 2    | legacy RSA, AES-128                    | Aes128Sha256RsaOaep                       |
/// | 3    | legacy RSA, AES-256 (RSA key ~112-150) | Aes256Sha256RsaPss                        |
/// | 4    | enhanced ~128-bit, NIST                | EccNistP256*                              |
/// | 5    | enhanced ~128-bit, Brainpool / RSA_DH  | EccBrainpoolP256r1*, RsaDh*               |
/// | 6    | enhanced ~128-bit, Bernstein           | EccCurve25519*                            |
/// | 7    | enhanced ~192-bit, NIST                | EccNistP384*                              |
/// | 8    | enhanced ~192-bit, Brainpool           | EccBrainpoolP384r1*                       |
/// | 9    | enhanced ~224-bit, Bernstein           | EccCurve448*                              |
///
/// `*` stands for both the AesGcm and the ChaChaPoly policy.
///
/// **Resulting security level values:** Sign = 5 + 5 * tier, SignAndEncrypt = 50 + 5 * tier, so every
/// SignAndEncrypt endpoint outranks every Sign endpoint.
///
/// | Policy                          | Sign | SignAndEncrypt |
/// |---------------------------------|------|----------------|
/// | None, Basic128Rsa15, Basic256   |   0  |       0        |
/// | Basic256Sha256                  |  10  |      55        |
/// | Aes128Sha256RsaOaep             |  15  |      60        |
/// | Aes256Sha256RsaPss              |  20  |      65        |
/// | EccNistP256*                    |  25  |      70        |
/// | EccBrainpoolP256r1*, RsaDh*     |  30  |      75        |
/// | EccCurve25519*                  |  35  |      80        |
/// | EccNistP384*                    |  40  |      85        |
/// | EccBrainpoolP384r1*             |  45  |      90        |
/// | EccCurve448*                    |  50  |      95        |
///
/// @param[in] mode   Message security mode of the endpoint. Anything but `Sign` or `SignAndEncrypt`
///                   yields 0.
/// @param[in] policy Security policy of the endpoint. Unrecognised, deprecated, or PubSub-only
///                   policies always yield 0.
/// @return Security level byte in [0, 255]; higher is more secure, 0 means not recommended.
/// @ingroup security
uint8_t compute_security_level(MessageSecurityMode mode, SecurityPolicyId policy);

}  // namespace ua

#endif  //! UA_CRYPTO_TYPES_H
