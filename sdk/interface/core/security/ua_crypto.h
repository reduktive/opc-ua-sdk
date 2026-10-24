// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Cryptographic provider abstraction for OPC UA security: hashing, symmetric/asymmetric
///        cipher and signature operations, key derivation, and X.509 certificate/CRL handling.
/// @ingroup security

#ifndef UA_CRYPTO_H
#define UA_CRYPTO_H

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_utc_time.h"
#include "ua_trust_list_validation_options.h"
#include "ua_crypto_types.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_byte_string.h"
#include "ua_secure_string.h"
#include "ua_result.h"
#include "ua_status_code.h"

namespace asio = boost::asio;

namespace ua
{

class X509Certificate;
class X509Crl;
struct CertificateValidationRequest;

/// The trust material one certificate validation runs against: what the holder of the trust list
/// supplies to @ref Crypto::validate_certificate_async, as distinct from what the peer presented
/// (@ref CertificateValidationRequest).
///
/// A @ref CertificateStore fills it from its own lists, CRLs and options; the TrustList methods fill it
/// from the list being installed. The validator treats the two certificate lists differently: a
/// certificate in @ref trusted confers trust (OPC 10000-4 section 6.1.3 Table 106, Trust List Check),
/// a certificate in @ref issuers only completes a chain.
/// @ingroup security
struct CertificateValidationMaterial
{
  /// Trusted certificates (roots, intermediates and trusted peers), matched by thumbprint and DER
  /// encoding. Includes any certificate the application accepted for this connection only
  /// (@ref CertificateValidationRequest::trustedForThisConnection).
  std::vector<shared_ptr<const X509Certificate>> trusted;

  /// Issuer certificates used only to complete a chain; never trusted.
  std::vector<shared_ptr<const X509Certificate>> issuers;

  /// CRLs issued by the certificates of @ref trusted.
  std::vector<shared_ptr<const X509Crl>> trustedCrls;

  /// CRLs issued by the certificates of @ref issuers.
  std::vector<shared_ptr<const X509Crl>> issuerCrls;

  /// The resolved options: the request's options when it carries them, otherwise the trust list's.
  TrustListValidationOptions options;
};

/// An asymmetric public/private key pair, owned by a @ref Crypto provider.
///
/// Instances are produced by a @ref Crypto and shared as `shared_ptr<const AsymmetricKeyPair>`;
/// they are immutable and safe to share across threads. A key pair may be public-key-only (see
/// @ref Crypto::get_public_key_from_der), in which case the private-key accessors fail.
/// @ingroup security
class AsymmetricKeyPair
{
public:
  virtual ~AsymmetricKeyPair() = default;

  AsymmetricKeyPair(const AsymmetricKeyPair&) = delete;
  AsymmetricKeyPair& operator=(const AsymmetricKeyPair&) = delete;
  AsymmetricKeyPair(AsymmetricKeyPair&&) = delete;
  AsymmetricKeyPair& operator=(AsymmetricKeyPair&&) = delete;

  /// Returns the key algorithm (e.g. RSA or an elliptic-curve variant) of this pair.
  ///
  /// @return The key algorithm (RSA or an elliptic-curve variant) of this pair.
  virtual CertificateKeyAlgorithm algorithm() const = 0;

  /// Returns the DER-encoded SubjectPublicKeyInfo for the public key.
  ///
  /// @return The DER-encoded SubjectPublicKeyInfo of the public key.
  virtual ByteString public_key_der() const = 0;

  /// Returns the PEM-encoded private key.
  ///
  /// @return The private key in PEM encoding.
  /// @throws UaException if this pair holds no private key (e.g. a public-key-only pair) or the
  ///         private key is held in a secure element that does not export key material.
  virtual ByteString private_key_pem() const = 0;

protected:
  /// Default-constructs the base; only subclasses construct an @ref AsymmetricKeyPair.
  AsymmetricKeyPair() = default;
};

/// Result of an operation producing an @ref AsymmetricKeyPair; carries an @ref ErrorDetail on
/// failure.
using KeyPairResult = Result<shared_ptr<const AsymmetricKeyPair>>;

/// Result of an operation producing an @ref X509Certificate; carries an @ref ErrorDetail on
/// failure.
using CertificateResult = Result<shared_ptr<const X509Certificate>>;

/// Result of an operation producing an @ref X509Crl; carries an @ref ErrorDetail on failure.
using CrlResult = Result<shared_ptr<const X509Crl>>;

/// Result of creating a self-signed certificate: the generated key pair paired with its
/// certificate, or an @ref ErrorDetail on failure.
using SelfSignedCertResult =
  Result<std::pair<shared_ptr<const AsymmetricKeyPair>, shared_ptr<const X509Certificate>>>;

/// Cryptographic provider for OPC UA security operations.
///
/// `Crypto` is the abstraction over a concrete crypto backend (e.g. OpenSSL, or a hardware secure
/// element). It supplies entropy, hashing, symmetric and asymmetric cipher/signature primitives,
/// key derivation and agreement, and X.509 certificate/CRL creation, parsing, and validation.
///
/// Most operations expose an async variant (callback receives a @ref Result) plus a blocking
/// `_sync` convenience. The async callback runs on an unspecified worker thread and must not block.
/// Implementations are immutable after construction and safe to call concurrently from any thread;
/// instances are shared as `shared_ptr<const Crypto>`.
///
/// Buffer parameters passed as `span` are borrowed for the duration of the call only: for async
/// operations the caller must keep the referenced storage alive until the callback fires. Several
/// async overloads additionally take an owning `resource` handle whose sole purpose is to pin such
/// caller-owned storage for the lifetime of the operation.
/// @ingroup security
class Crypto : public std::enable_shared_from_this<Crypto>
{
public:
  Crypto(const Crypto&) = delete;
  Crypto& operator=(const Crypto&) = delete;
  Crypto(Crypto&&) = delete;
  Crypto& operator=(Crypto&&) = delete;

  /// An ephemeral (one-shot) key-agreement key pair, returned as raw key bytes.
  struct EphemeralKeyPair
  {
    ByteString publicKey;  ///< Public key to send to the peer.
    ByteString privateKey;  ///< Private key, retained locally to compute the shared secret.
  };

  /// Result of generating an @ref EphemeralKeyPair; carries an @ref ErrorDetail on failure.
  using EphemeralKeyPairResult = Result<EphemeralKeyPair>;

  /// Callback supplying the passphrase that protects private key material.
  ///
  /// Called each time a provider encrypts or decrypts a private key; it belongs to one key pair, so it
  /// takes no arguments. It returns a @ref SecureString, which wipes its bytes when it leaves scope, so
  /// the passphrase does not linger in freed memory (public API review D7). Provider-agnostic; some
  /// `Crypto` implementations may never invoke it.
  ///
  /// @return The passphrase. When a credential is required, this must be non-empty.
  using PrivateKeyCredentialCallback = std::function<SecureString()>;

  /// Completion callback for operations whose only outcome is success or an @ref ErrorDetail.
  using GenericCompleteCallback = std::function<void(VoidResult)>;

  /// Completion callback for @ref get_entropy_async; receives the random bytes or an @ref
  /// ErrorDetail.
  using GetEntropyCompleteCallback = std::function<void(ByteStringResult)>;

  /// Result of a digest computation: the input buffer that was hashed alongside the digest.
  struct CalculateDigestOutput
  {
    ByteString inputBuffer;  ///< The input buffer that was hashed (returned to the caller).
    ByteString digest;  ///< The computed digest.
  };

  /// Result of @ref calculate_digest_async; carries an @ref ErrorDetail on failure.
  using CalculateDigestOutputResult = Result<CalculateDigestOutput>;
  /// Completion callback for @ref calculate_digest_async.
  using CalculateDigestCompleteCallback = std::function<void(CalculateDigestOutputResult)>;

  /// Completion callback for @ref symmetric_encrypt_async; the ciphertext is written in place.
  using SymmetricEncryptCompleteCallback = GenericCompleteCallback;

  /// Completion callback for @ref symmetric_decrypt_async; the plaintext is written in place.
  using SymmetricDecryptCompleteCallback = GenericCompleteCallback;

  /// Result of authenticated symmetric encryption: the buffers operated on plus the signature.
  struct SymmetricEncryptAndSignOutput
  {
    ByteString plainTextBuffer;  ///< The plaintext buffer that was encrypted.
    optional<ByteString> cipherTextBuffer;  ///< Ciphertext buffer, when produced out of place.
    ByteString signature;  ///< The authentication signature (MAC).
  };

  /// Result of @ref symmetric_encrypt_and_sign_async; carries an @ref ErrorDetail on failure.
  using SymmetricEncryptAndSignOutputResult = Result<SymmetricEncryptAndSignOutput>;
  /// Completion callback for @ref symmetric_encrypt_and_sign_async.
  using SymmetricEncryptAndSignCompleteCallback = std::function<void(SymmetricEncryptAndSignOutputResult)>;

  /// Result of authenticated symmetric decryption: the input ciphertext plus the recovered
  /// plaintext.
  struct SymmetricVerifyAndDecryptOutput
  {
    ByteString cipherTextBuffer;  ///< The ciphertext buffer that was verified.
    optional<ByteString> plainTextBuffer;  ///< Recovered plaintext, when produced out of place.
  };

  /// Result of @ref symmetric_verify_and_decrypt_async; carries an @ref ErrorDetail on failure.
  using SymmetricVerifyAndDecryptOutputResult = Result<SymmetricVerifyAndDecryptOutput>;
  /// Completion callback for @ref symmetric_verify_and_decrypt_async.
  using SymmetricVerifyAndDecryptCompleteCallback =
    std::function<void(SymmetricVerifyAndDecryptOutputResult)>;

  /// Completion callback for @ref symmetric_sign_async; receives the signature or an @ref
  /// ErrorDetail.
  using SymmetricSignCompleteCallback = std::function<void(ByteStringResult)>;

  /// Completion callback for @ref symmetric_verify_async; success means the signature is valid.
  using SymmetricVerifyCompleteCallback = GenericCompleteCallback;

  /// Completion callback for @ref asymmetric_encrypt_async; the ciphertext is written in place.
  using AsymmetricEncryptCompleteCallback = GenericCompleteCallback;

  /// Result holding a borrowed view of bytes (a sub-span of a caller-supplied buffer).
  using ByteSpanResult = Result<span<const byte>>;
  /// Completion callback for @ref asymmetric_decrypt_async; receives the recovered plaintext view.
  using AsymmetricDecryptCompleteCallback = std::function<void(ByteSpanResult)>;

  /// Completion callback for @ref asymmetric_sign_async; receives the signature or an @ref
  /// ErrorDetail.
  using AsymmetricSignCompleteCallback = std::function<void(ByteStringResult)>;

  /// Completion callback for @ref asymmetric_verify_async; success means the signature is valid.
  using AsymmetricVerifyCompleteCallback = GenericCompleteCallback;

  /// Completion callback for @ref create_asymmetric_key_pair_async.
  using CreateAsymmetricKeyPairCompleteCallback = std::function<void(KeyPairResult)>;

  /// Completion callback for the @ref derive_symmetric_keys_async overloads.
  using DeriveSymmetricKeysCompleteCallback = std::function<void(ByteStringResult)>;

  /// Completion callback for @ref create_ephemeral_keys_async.
  using CreateEphemeralKeysCompleteCallback = std::function<void(EphemeralKeyPairResult)>;

  /// Completion callback for @ref calculate_shared_secret_async.
  using CalculateSharedSecretCompleteCallback = std::function<void(ByteStringResult)>;

  /// X.500 distinguished-name components used to identify a certificate subject or issuer.
  struct Name
  {
    std::string commonName;  ///< Common Name (CN).
    std::string organization;  ///< Organization (O).
    std::string organizationUnit;  ///< Organizational Unit (OU).
    std::string distinguishedName;  ///< Full distinguished name, when supplied verbatim.
    std::string locality;  ///< Locality / city (L).
    std::string state;  ///< State or province (ST).
    std::string country;  ///< Two-letter country code (C).
  };

  /// X.509 key-usage and extended-key-usage flags for a certificate.
  struct KeyUsage
  {
    bool digitalSignature{false};  ///< Key may verify digital signatures.
    bool nonRepudiation{false};  ///< Key may provide non-repudiation.
    bool keyEncipherment{false};  ///< Key may encipher other keys.
    bool dataEncipherment{false};  ///< Key may encipher raw data.
    bool keyAgreement{false};  ///< Key may be used for key agreement.
    bool keyCertSign{false};  ///< Key may sign certificates (CA).
    bool crlSign{false};  ///< Key may sign CRLs.
    bool encipherOnly{false};  ///< Key-agreement key may only encipher.
    bool decipherOnly{false};  ///< Key-agreement key may only decipher.

    bool clientAuth{false};  ///< Extended key usage: TLS/UA client authentication.
    bool serverAuth{false};  ///< Extended key usage: TLS/UA server authentication.
  };

  /// X.509 basic-constraints extension describing CA status and path-length limit.
  struct BasicConstraints
  {
    optional<bool> cA;  ///< Whether the subject is a CA; unset omits the extension.
    optional<uint32_t> pathLength;  ///< Maximum number of intermediate CAs below this one.
  };

  /// X.509 SubjectAlternativeName entries (IP addresses, hostnames, and application URIs).
  struct SubjectAlternateName
  {
    std::vector<asio::ip::address> ipAddresses;  ///< IP-address SAN entries.
    std::vector<std::string> hostnames;  ///< DNS-name SAN entries.
    std::vector<std::string> uris;  ///< URI SAN entries (e.g. the application URI).
  };

  /// Parameters for issuing an X.509 certificate via @ref create_certificate_async.
  struct CreateCertificateConfig
  {
    std::string serialNumber;  ///< Serial number assigned to the certificate.
    Name subject;  ///< Subject distinguished name.
    shared_ptr<const X509Certificate> issuer;  ///< Issuing CA certificate.
    shared_ptr<const AsymmetricKeyPair> issuerKeys;  ///< Issuer key pair used to sign.
    shared_ptr<const AsymmetricKeyPair> subjectKeys;  ///< Subject key pair to certify.
    CertificateSignatureAlgorithm certificateSignatureAlgorithm{
      CertificateSignatureAlgorithm::Invalid};  ///< Signature algorithm to use.
    UtcTime from;  ///< notBefore validity start.
    UtcTime to;  ///< notAfter validity end.
    KeyUsage keyUsage;  ///< Key-usage extension to set.
    BasicConstraints basicConstraint;  ///< Basic-constraints extension to set.
    SubjectAlternateName subjectAlternateName;  ///< SubjectAlternativeName entries to set.
  };

  /// Parameters for building a PKCS#10 certificate signing request via
  /// @ref create_certificate_signing_request_async.
  struct CreateCsrConfig
  {
    Name subject;  ///< Subject distinguished name.
    shared_ptr<const AsymmetricKeyPair> subjectKeys;  ///< Subject key pair whose CSR is built.
    CertificateSignatureAlgorithm certificateSignatureAlgorithm{
      CertificateSignatureAlgorithm::Invalid};  ///< Signature algorithm to use.
    KeyUsage keyUsage;  ///< Requested key-usage extension.
    BasicConstraints basicConstraint;  ///< Requested basic-constraints extension.
    SubjectAlternateName subjectAlternateName;  ///< Requested SubjectAlternativeName entries.
  };

  /// Completion callback for @ref create_certificate_async.
  using CreateCertificateCompleteCallback = std::function<void(CertificateResult)>;

  /// Completion callback for @ref create_self_signed_application_instance_certificate_async.
  using CreateSelfSignedApplicationInstanceCertificateCompleteCallback =
    std::function<void(SelfSignedCertResult)>;

  /// Completion callback for @ref create_certificate_signing_request_async; receives the DER CSR.
  using CreateCertificateSigningRequestCompleteCallback = std::function<void(ByteStringResult)>;

  /// Completion callback for @ref create_crl_async.
  using CreateCrlCompleteCallback = std::function<void(CrlResult)>;

  /// Completion callback for @ref validate_certificate_async; success means the certificate is
  /// trusted.
  using CertificateValidationCompleteCallback = std::function<void(VoidResult)>;

  /// Completion callback for @ref validate_crl_async; success means the CRL is valid.
  using CrlValidationCompleteCallback = std::function<void(VoidResult)>;

  /// Returns true if the provider uses a secure element (HSM/TPM) for private key storage.
  ///
  /// Software-only implementations (e.g. OpenSSL) return false.
  ///
  /// @return `true` if a secure element (HSM/TPM) backs private-key storage; `false` for
  ///         software-only providers.
  virtual bool has_secure_element() const = 0;

  virtual ~Crypto() = default;

  /// Generates cryptographically secure random bytes.
  ///
  /// @param numberOfBytes Number of random bytes to produce.
  /// @param callback      Receives the random bytes, or an @ref ErrorDetail on failure. Never
  ///                      throws.
  /// @see get_entropy_sync
  virtual void get_entropy_async(
    size_t numberOfBytes, GetEntropyCompleteCallback callback) const noexcept = 0;

  /// Generates cryptographically secure random bytes, blocking until complete.
  ///
  /// @param numberOfBytes Number of random bytes to produce.
  /// @return The random bytes.
  /// @throws UaException if entropy generation fails.
  /// @see get_entropy_async
  virtual ByteString get_entropy_sync(size_t numberOfBytes) const = 0;

  /// Computes a message digest over @p input using @p algorithm.
  ///
  /// @param algorithm   Hash algorithm to apply.
  /// @param inputBuffer Owning copy of the input that is returned alongside the digest, keeping
  ///                    the hashed bytes valid for the duration of the async call.
  /// @param input       View of the bytes to hash (typically a view into @p inputBuffer).
  /// @param callback    Receives the input buffer and digest, or an @ref ErrorDetail on failure.
  ///                    Never throws.
  /// @see calculate_digest_sync
  virtual void calculate_digest_async(HashAlgorithm algorithm, ByteString inputBuffer, span<const byte> input,
    CalculateDigestCompleteCallback callback) const noexcept = 0;

  /// Computes a message digest over @p input, blocking until complete.
  ///
  /// @param algorithm Hash algorithm to apply.
  /// @param input     Bytes to hash.
  /// @return The computed digest.
  /// @throws UaException if the digest computation fails.
  /// @see calculate_digest_async
  virtual ByteString calculate_digest_sync(HashAlgorithm algorithm, span<const byte> input) const = 0;

  /// Derives @p numberOfBytes of key material from a secret and seed (P-SHA pseudo-random
  /// function).
  ///
  /// @param algorithm     Key-derivation algorithm to use.
  /// @param numberOfBytes Length of the derived key material, in bytes.
  /// @param secret        Shared secret input (kept alive for the async call).
  /// @param seed          Seed input (kept alive for the async call).
  /// @param callback      Receives the derived key material, or an @ref ErrorDetail on failure.
  ///                      Never throws.
  /// @see derive_symmetric_keys_sync
  virtual void derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    ByteString secret, ByteString seed, DeriveSymmetricKeysCompleteCallback callback) const noexcept = 0;

  /// Derives key material from a secret and seed, blocking until complete.
  ///
  /// @param algorithm     Key-derivation algorithm to use.
  /// @param numberOfBytes Length of the derived key material, in bytes.
  /// @param secret        Shared secret input.
  /// @param seed          Seed input.
  /// @return The derived key material, of length @p numberOfBytes.
  /// @throws UaException if derivation fails.
  /// @see derive_symmetric_keys_async
  virtual ByteString derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm,
    size_t numberOfBytes, span<const byte> secret, span<const byte> seed) const = 0;

  /// Derives @p numberOfBytes of key material from a secret using an HKDF-style salt and info.
  ///
  /// @param algorithm     Key-derivation algorithm to use.
  /// @param numberOfBytes Length of the derived key material, in bytes.
  /// @param secret        Shared secret input (kept alive for the async call).
  /// @param salt          Salt input (kept alive for the async call).
  /// @param info          Context/info input binding the key to its use (kept alive for the call).
  /// @param callback      Receives the derived key material, or an @ref ErrorDetail on failure.
  ///                      Never throws.
  /// @see derive_symmetric_keys_sync
  virtual void derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    ByteString secret, ByteString salt, ByteString info,
    DeriveSymmetricKeysCompleteCallback callback) const noexcept = 0;

  /// Derives key material from a secret, salt, and info, blocking until complete.
  ///
  /// @param algorithm     Key-derivation algorithm to use.
  /// @param numberOfBytes Length of the derived key material, in bytes.
  /// @param secret        Shared secret input.
  /// @param salt          Salt input.
  /// @param info          Context/info input binding the key to its use.
  /// @return The derived key material, of length @p numberOfBytes.
  /// @throws UaException if derivation fails.
  /// @see derive_symmetric_keys_async
  virtual ByteString derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm,
    size_t numberOfBytes, span<const byte> secret, span<const byte> salt, span<const byte> info) const = 0;

  /// Encrypts @p plainText into @p cipherText using a symmetric cipher.
  ///
  /// @param resource   Owning handle that pins the caller-supplied buffers for the operation's
  ///                   lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm  Symmetric encryption algorithm.
  /// @param iv         Initialization vector.
  /// @param key        Symmetric key.
  /// @param plainText  Plaintext input.
  /// @param cipherText Output buffer; the ciphertext is written here in place and must be large
  ///                   enough to hold it.
  /// @param callback   Receives success or an @ref ErrorDetail on failure. Never throws.
  /// @see symmetric_encrypt_sync
  virtual void symmetric_encrypt_async(shared_ptr<const void> resource,
    SymmetricEncryptionAlgorithm algorithm, span<const byte> iv, span<const byte> key,
    span<const byte> plainText, span<byte> cipherText,
    SymmetricEncryptCompleteCallback callback) const noexcept = 0;

  /// Encrypts @p plainText into @p cipherText, blocking until complete.
  ///
  /// The caller owns all buffers and must keep them valid for the duration of the call; unlike the
  /// async overload there is no `resource` handle, because the call does not outlive the buffers.
  ///
  /// @param algorithm  Symmetric encryption algorithm.
  /// @param iv         Initialization vector.
  /// @param key        Symmetric key.
  /// @param plainText  Plaintext input.
  /// @param cipherText Output buffer written in place; must be large enough for the ciphertext.
  /// @throws UaException if encryption fails.
  /// @see symmetric_encrypt_async
  virtual void symmetric_encrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> plainText, span<byte> cipherText) const = 0;

  /// Decrypts @p cipherText into @p plainText using a symmetric cipher.
  ///
  /// @param resource   Owning handle that pins the caller-supplied buffers for the operation's
  ///                   lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm  Symmetric encryption algorithm.
  /// @param iv         Initialization vector.
  /// @param key        Symmetric key.
  /// @param cipherText Ciphertext input.
  /// @param plainText  Output buffer; the plaintext is written here in place.
  /// @param callback   Receives success or an @ref ErrorDetail on failure. Never throws.
  /// @see symmetric_decrypt_sync
  virtual void symmetric_decrypt_async(shared_ptr<const void> resource,
    SymmetricEncryptionAlgorithm algorithm, span<const byte> iv, span<const byte> key,
    span<const byte> cipherText, span<byte> plainText,
    SymmetricDecryptCompleteCallback callback) const noexcept = 0;

  /// Decrypts @p cipherText into @p plainText, blocking until complete.
  ///
  /// The caller owns all buffers and must keep them valid for the duration of the call.
  ///
  /// @param algorithm  Symmetric encryption algorithm.
  /// @param iv         Initialization vector.
  /// @param key        Symmetric key.
  /// @param cipherText Ciphertext input.
  /// @param plainText  Output buffer written in place.
  /// @throws UaException if decryption fails.
  /// @see symmetric_decrypt_async
  virtual void symmetric_decrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> cipherText, span<byte> plainText) const = 0;

  /// Encrypts and authenticates @p plainText, producing ciphertext and a signature (MAC).
  ///
  /// @param algorithm        Symmetric encryption algorithm.
  /// @param iv               Initialization vector (owning, kept alive for the async call).
  /// @param key              Symmetric key (owning, kept alive for the async call).
  /// @param plainTextBuffer  Owning copy of the plaintext, returned in the result.
  /// @param plainText        View of the plaintext to encrypt (typically into @p plainTextBuffer).
  /// @param additionalData   Additional authenticated data covered by the signature but not
  ///                         encrypted.
  /// @param cipherTextBuffer Optional owning output buffer for out-of-place ciphertext; pass empty
  ///                         for in-place encryption into @p cipherText.
  /// @param cipherText       Output view for the ciphertext when produced in place.
  /// @param callback         Receives the buffers and signature, or an @ref ErrorDetail on failure.
  ///                         Never throws.
  /// @see symmetric_encrypt_and_sign_sync
  virtual void symmetric_encrypt_and_sign_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv,
    ByteString key, ByteString plainTextBuffer, span<const byte> plainText, span<const byte> additionalData,
    optional<ByteString> cipherTextBuffer, span<byte> cipherText,
    SymmetricEncryptAndSignCompleteCallback callback) const = 0;

  /// Encrypts and authenticates @p plainText, blocking until complete.
  ///
  /// Encryption is performed in place into @p cipherText; the returned signature authenticates both
  /// the ciphertext and @p additionalData. @p algorithm is an AEAD cipher (ChaCha20-Poly1305,
  /// AES-128-GCM or AES-256-GCM): the IV is 12 bytes and the returned tag 16 bytes. An empty
  /// @p plainText is valid and yields a tag over @p additionalData alone; the Sign mode of an AEAD
  /// security policy depends on it (OPC 10000-6 section 6.7.2.1).
  ///
  /// @param algorithm      Symmetric encryption algorithm.
  /// @param iv             Initialization vector.
  /// @param key            Symmetric key.
  /// @param plainText      Plaintext input to encrypt.
  /// @param additionalData Additional authenticated data covered by the signature but not encrypted.
  /// @param cipherText     Output buffer written in place; must be large enough for the ciphertext.
  /// @return The authentication signature (MAC) over the ciphertext and additional data.
  /// @throws UaException if encryption or signing fails.
  /// @see symmetric_encrypt_and_sign_async
  virtual ByteString symmetric_encrypt_and_sign_sync(SymmetricEncryptionAlgorithm algorithm,
    span<const byte> iv, span<const byte> key, span<const byte> plainText, span<const byte> additionalData,
    span<byte> cipherText) const = 0;

  /// Verifies @p signature and, on success, decrypts @p cipherText into plaintext.
  ///
  /// @param algorithm        Symmetric encryption algorithm.
  /// @param iv               Initialization vector (owning, kept alive for the async call).
  /// @param key              Symmetric key (owning, kept alive for the async call).
  /// @param cipherTextBuffer Owning copy of the ciphertext, returned in the result.
  /// @param cipherText       View of the ciphertext to verify and decrypt.
  /// @param additionalData   Additional authenticated data covered by the signature.
  /// @param signature        Signature (MAC) to verify before decrypting.
  /// @param plainTextBuffer  Optional owning output buffer for out-of-place plaintext; pass empty
  ///                         for in-place decryption into @p plainText.
  /// @param plainText        Output view for the plaintext when produced in place.
  /// @param callback         Receives the buffers, or an @ref ErrorDetail if verification or
  ///                         decryption fails. Never throws.
  /// @see symmetric_verify_and_decrypt_sync
  virtual void symmetric_verify_and_decrypt_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv,
    ByteString key, ByteString cipherTextBuffer, span<const byte> cipherText, span<const byte> additionalData,
    span<const byte> signature, optional<ByteString> plainTextBuffer, span<byte> plainText,
    SymmetricVerifyAndDecryptCompleteCallback callback) const = 0;

  /// Verifies @p signature and decrypts @p cipherText, blocking until complete.
  ///
  /// This is an AEAD decrypt: the authentication tag is verified after the ciphertext is processed.
  /// On a verification failure the call throws Bad_SecurityChecksFailed and @p plainText is zeroed,
  /// so no unauthenticated byte reaches the caller. A tag that is not 16 bytes is refused the same way
  /// before anything is decrypted. An empty @p cipherText is valid: the tag then authenticates
  /// @p additionalData alone (the Sign mode of an AEAD security policy).
  ///
  /// @param algorithm      Symmetric encryption algorithm.
  /// @param iv             Initialization vector.
  /// @param key            Symmetric key.
  /// @param cipherText     Ciphertext input to verify and decrypt.
  /// @param additionalData Additional authenticated data covered by the signature.
  /// @param signature      Authentication tag (MAC) checked against the ciphertext and
  ///                       @p additionalData.
  /// @param plainText      Output buffer written in place; valid only if the call returns normally.
  /// @throws UaException Bad_SecurityChecksFailed if the tag does not verify; another status if the
  ///        input is malformed or decryption fails.
  /// @see symmetric_verify_and_decrypt_async
  virtual void symmetric_verify_and_decrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> cipherText, span<const byte> additionalData,
    span<const byte> signature, span<byte> plainText) const = 0;

  /// Computes a symmetric signature (MAC) over @p input.
  ///
  /// @param resource  Owning handle that pins the caller-supplied buffers for the operation's
  ///                  lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm Symmetric signature algorithm.
  /// @param key       Symmetric key.
  /// @param input     Data to sign.
  /// @param callback  Receives the signature, or an @ref ErrorDetail on failure. Never throws.
  /// @see symmetric_sign_sync
  virtual void symmetric_sign_async(shared_ptr<const void> resource, SymmetricSignatureAlgorithm algorithm,
    span<const byte> key, span<const byte> input, SymmetricSignCompleteCallback callback) const = 0;

  /// Computes a symmetric signature (MAC) over @p input, blocking until complete.
  ///
  /// @param algorithm Symmetric signature algorithm.
  /// @param key       Symmetric key.
  /// @param input     Data to sign.
  /// @return The signature.
  /// @throws UaException if signing fails.
  /// @see symmetric_sign_async
  virtual ByteString symmetric_sign_sync(
    SymmetricSignatureAlgorithm algorithm, span<const byte> key, span<const byte> input) const = 0;

  /// Verifies a symmetric signature (MAC) over @p input.
  ///
  /// @param resource  Owning handle that pins the caller-supplied buffers for the operation's
  ///                  lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm Symmetric signature algorithm.
  /// @param key       Symmetric key.
  /// @param input     Data the signature covers.
  /// @param signature Signature to verify.
  /// @param callback  Receives success if the signature is valid, or an @ref ErrorDetail otherwise.
  ///                  Never throws.
  /// @see symmetric_verify_sync
  virtual void symmetric_verify_async(shared_ptr<const void> resource, SymmetricSignatureAlgorithm algorithm,
    span<const byte> key, span<const byte> input, span<const byte> signature,
    SymmetricVerifyCompleteCallback callback) const = 0;

  /// Verifies a symmetric signature (MAC) over @p input, blocking until complete.
  ///
  /// @param algorithm Symmetric signature algorithm.
  /// @param key       Symmetric key.
  /// @param input     Data the signature covers.
  /// @param signature Signature to verify.
  /// @throws UaException if the signature is invalid or verification fails.
  /// @see symmetric_verify_async
  virtual void symmetric_verify_sync(SymmetricSignatureAlgorithm algorithm, span<const byte> key,
    span<const byte> input, span<const byte> signature) const = 0;

  /// Encrypts @p plainText into @p cipherText with a public key.
  ///
  /// @param resource   Owning handle that pins the caller-supplied buffers for the operation's
  ///                   lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm  Asymmetric encryption algorithm (and padding).
  /// @param publicKey  Recipient's public key.
  /// @param plainText  Plaintext input.
  /// @param cipherText Output buffer written in place; must be large enough for the ciphertext.
  /// @param callback   Receives success or an @ref ErrorDetail on failure. Never throws.
  /// @see asymmetric_encrypt_sync
  virtual void asymmetric_encrypt_async(shared_ptr<const void> resource,
    AsymmetricEncryptionAlgorithm algorithm, span<const byte> publicKey, span<const byte> plainText,
    span<byte> cipherText, AsymmetricEncryptCompleteCallback callback) const = 0;

  /// Encrypts @p plainText into @p cipherText with a public key, blocking until complete.
  ///
  /// @param algorithm  Asymmetric encryption algorithm (and padding).
  /// @param publicKey  Recipient's public key.
  /// @param plainText  Plaintext input.
  /// @param cipherText Output buffer written in place; must be large enough for the ciphertext.
  /// @throws UaException if encryption fails.
  /// @see asymmetric_encrypt_async
  virtual void asymmetric_encrypt_sync(AsymmetricEncryptionAlgorithm algorithm, span<const byte> publicKey,
    span<const byte> plainText, span<byte> cipherText) const = 0;

  /// Decrypts @p cipherText with a private key, writing the plaintext into @p plainText.
  ///
  /// @param resource   Owning handle that pins the caller-supplied buffers for the operation's
  ///                   lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm  Asymmetric encryption algorithm (and padding).
  /// @param privateKey Key pair holding the private key to decrypt with.
  /// @param cipherText Ciphertext input.
  /// @param plainText  Output buffer the plaintext is written into.
  /// @param callback   Receives a view of the recovered plaintext within @p plainText, or an
  ///                   @ref ErrorDetail on failure. Never throws.
  /// @see asymmetric_decrypt_sync
  virtual void asymmetric_decrypt_async(shared_ptr<const void> resource,
    AsymmetricEncryptionAlgorithm algorithm, shared_ptr<const AsymmetricKeyPair> privateKey,
    span<const byte> cipherText, span<byte> plainText, AsymmetricDecryptCompleteCallback callback) const = 0;

  /// Decrypts @p cipherText with a private key, blocking until complete.
  ///
  /// @param algorithm  Asymmetric encryption algorithm (and padding).
  /// @param privateKey Key pair holding the private key to decrypt with.
  /// @param cipherText Ciphertext input.
  /// @param plainText  Output buffer the plaintext is written into.
  /// @return A view of the recovered plaintext within @p plainText.
  /// @throws UaException if decryption fails.
  /// @see asymmetric_decrypt_async
  virtual span<const byte> asymmetric_decrypt_sync(AsymmetricEncryptionAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> cipherText,
    span<byte> plainText) const = 0;

  /// Signs @p input with a private key.
  ///
  /// @param resource   Owning handle that pins the caller-supplied buffers for the operation's
  ///                   lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm  Asymmetric signature algorithm.
  /// @param privateKey Key pair holding the private key to sign with.
  /// @param input      Data to sign.
  /// @param callback   Receives the signature, or an @ref ErrorDetail on failure. Never throws.
  /// @see asymmetric_sign_sync
  virtual void asymmetric_sign_async(shared_ptr<const void> resource, AsymmetricSignatureAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> input,
    AsymmetricSignCompleteCallback callback) const = 0;

  /// Signs @p input with a private key, blocking until complete.
  ///
  /// @param algorithm  Asymmetric signature algorithm.
  /// @param privateKey Key pair holding the private key to sign with.
  /// @param input      Data to sign.
  /// @return The signature.
  /// @throws UaException if signing fails.
  /// @see asymmetric_sign_async
  virtual ByteString asymmetric_sign_sync(AsymmetricSignatureAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> input) const = 0;

  /// Verifies @p signature over @p input against a public key.
  ///
  /// @param resource  Owning handle that pins the caller-supplied buffers for the operation's
  ///                  lifetime; may be empty if the caller guarantees the spans outlive the call.
  /// @param algorithm Asymmetric signature algorithm.
  /// @param publicKey Signer's public key.
  /// @param input     Data the signature covers.
  /// @param signature Signature to verify.
  /// @param callback  Receives success if the signature is valid, or an @ref ErrorDetail otherwise.
  ///                  Never throws.
  /// @see asymmetric_verify_sync
  virtual void asymmetric_verify_async(shared_ptr<const void> resource,
    AsymmetricSignatureAlgorithm algorithm, span<const byte> publicKey, span<const byte> input,
    span<const byte> signature, AsymmetricVerifyCompleteCallback callback) const = 0;

  /// Verifies @p signature over @p input against a public key, blocking until complete.
  ///
  /// @param algorithm Asymmetric signature algorithm.
  /// @param publicKey Signer's public key.
  /// @param input     Data the signature covers.
  /// @param signature Signature to verify.
  /// @throws UaException if the signature is invalid or verification fails.
  /// @see asymmetric_verify_async
  virtual void asymmetric_verify_sync(AsymmetricSignatureAlgorithm algorithm, span<const byte> publicKey,
    span<const byte> input, span<const byte> signature) const = 0;

  /// Generates a new long-term asymmetric key pair.
  ///
  /// @param algorithm       Key algorithm to generate.
  /// @param keyLengthInBits Key length in bits; unset selects the algorithm's default (and is
  ///                        ignored for fixed-size elliptic curves).
  /// @param callback        Receives the new key pair, or an @ref ErrorDetail on failure. Never
  ///                        throws.
  /// @see create_asymmetric_key_pair_sync
  virtual void create_asymmetric_key_pair_async(CertificateKeyAlgorithm algorithm,
    optional<size_t> keyLengthInBits, CreateAsymmetricKeyPairCompleteCallback callback) const = 0;

  /// Generates a new long-term asymmetric key pair, blocking until complete.
  ///
  /// @param algorithm       Key algorithm to generate.
  /// @param keyLengthInBits Key length in bits; unset selects the algorithm's default (and is
  ///                        ignored for fixed-size elliptic curves).
  /// @return The generated key pair.
  /// @throws UaException if key generation fails.
  /// @see create_asymmetric_key_pair_async
  virtual shared_ptr<const AsymmetricKeyPair> create_asymmetric_key_pair_sync(
    CertificateKeyAlgorithm algorithm, optional<size_t> keyLengthInBits) const = 0;

  /// Generates an ephemeral key-agreement key pair for a single handshake.
  ///
  /// @param algorithm Ephemeral key-agreement algorithm.
  /// @param callback  Receives the ephemeral key pair, or an @ref ErrorDetail on failure. Never
  ///                  throws.
  /// @see create_ephemeral_keys_sync
  virtual void create_ephemeral_keys_async(
    EphemeralKeyAlgorithm algorithm, CreateEphemeralKeysCompleteCallback callback) const = 0;

  /// Generates an ephemeral key-agreement key pair, blocking until complete.
  ///
  /// The public key is the wire nonce of OPC 10000-6 section 6.8.1: raw X || Y for the ECDH curves, the
  /// RFC 7748 encoding for Curve25519 and Curve448, and for @ref EphemeralKeyAlgorithm::RsaDhFfdhe3072 the
  /// 384-byte zero-padded big-endian value (section 6.9, Table 72); its private key is the 275-bit
  /// exponent as 35 big-endian bytes.
  ///
  /// @param algorithm Ephemeral key-agreement algorithm.
  /// @return The ephemeral key pair.
  /// @throws UaException if generation fails.
  /// @see create_ephemeral_keys_async
  virtual EphemeralKeyPair create_ephemeral_keys_sync(EphemeralKeyAlgorithm algorithm) const = 0;

  /// Computes the shared secret from a local private key and the peer's public key.
  ///
  /// @param algorithm       Key-agreement algorithm.
  /// @param localPrivateKey Local ephemeral private key (kept alive for the async call).
  /// @param remotePublicKey Peer's ephemeral public key (kept alive for the async call).
  /// @param callback        Receives the shared secret, or an @ref ErrorDetail on failure. Never
  ///                        throws.
  /// @see calculate_shared_secret_sync
  virtual void calculate_shared_secret_async(EphemeralKeyAlgorithm algorithm, ByteString localPrivateKey,
    ByteString remotePublicKey, CalculateSharedSecretCompleteCallback callback) const = 0;

  /// Computes the key-agreement shared secret, blocking until complete.
  ///
  /// @p remotePublicKey is a wire nonce in the encoding @ref create_ephemeral_keys_sync produces. For
  /// @ref EphemeralKeyAlgorithm::RsaDhFfdhe3072 a peer value that is not 384 bytes, or lies outside
  /// 2 to p - 2, is refused with Bad_NonceInvalid, and the secret is 384 bytes, zero-padded big-endian.
  ///
  /// @param algorithm       Key-agreement algorithm.
  /// @param localPrivateKey Local ephemeral private key.
  /// @param remotePublicKey Peer's ephemeral public key.
  /// @return The shared secret.
  /// @throws UaException if the computation fails.
  /// @see calculate_shared_secret_async
  virtual ByteString calculate_shared_secret_sync(EphemeralKeyAlgorithm algorithm,
    span<const byte> localPrivateKey, span<const byte> remotePublicKey) const = 0;

  /// Parses a single DER-encoded X.509 certificate.
  ///
  /// For genuinely single-certificate inputs such as a certificate file. Not for an OPC UA
  /// certificate field, which may carry a chain (OPC 10000-6 section 6.2.6): parse those with
  /// @ref read_certificates_from_der.
  ///
  /// @param der DER bytes of exactly one certificate.
  /// @return The parsed certificate.
  /// @throws UaException Bad_CertificateInvalid if the bytes are not a valid certificate or hold
  ///         bytes after it.
  virtual shared_ptr<const X509Certificate> read_certificate_from_der(span<const byte> der) const = 0;

  /// Parses a concatenation of DER-encoded X.509 certificates (e.g. a certificate chain).
  ///
  /// @param der DER bytes of one or more concatenated certificates; every byte must belong to a
  ///            complete certificate.
  /// @return The parsed certificates, in encounter order (empty for empty input). Never a partial
  ///         result.
  /// @throws UaException Bad_CertificateInvalid if any certificate fails to parse or bytes follow the
  ///         last complete certificate.
  virtual std::vector<shared_ptr<const X509Certificate>> read_certificates_from_der(
    span<const byte> der) const = 0;

  /// Parses a single DER-encoded X.509 CRL.
  ///
  /// @param der DER bytes of exactly one CRL.
  /// @return The parsed CRL.
  /// @throws UaException Bad_CertificateInvalid if the bytes are not a valid CRL or hold bytes after
  ///         it.
  virtual shared_ptr<const X509Crl> read_crl_from_der(span<const byte> der) const = 0;

  /// Parses a concatenation of DER-encoded X.509 CRLs.
  ///
  /// @param der DER bytes of one or more concatenated CRLs; every byte must belong to a complete CRL.
  /// @return The parsed CRLs, in encounter order (empty for empty input). Never a partial result.
  /// @throws UaException Bad_CertificateInvalid if any CRL fails to parse or bytes follow the last
  ///         complete CRL.
  virtual std::vector<shared_ptr<const X509Crl>> read_crls_from_der(span<const byte> der) const = 0;

  /// Loads a key pair (including its private key) from PEM-encoded bytes.
  ///
  /// @param keyAlgorithm Expected key algorithm of the PEM key.
  /// @param pem          Mutable PEM bytes; the buffer may be scrubbed in place after parsing so
  ///                     private-key material does not linger in caller memory.
  /// @return The loaded key pair.
  /// @throws UaException if the PEM cannot be parsed or does not match @p keyAlgorithm.
  virtual shared_ptr<const AsymmetricKeyPair> get_private_key_from_pem(
    CertificateKeyAlgorithm keyAlgorithm, span<byte> pem) const = 0;

  /// Issues an X.509 certificate signed by the issuer described in @p parameters.
  ///
  /// @param parameters Subject, issuer, validity, and extension parameters for the certificate.
  /// @param callback   Receives the issued certificate, or an @ref ErrorDetail on failure. Never
  ///                   throws.
  virtual void create_certificate_async(
    const CreateCertificateConfig& parameters, CreateCertificateCompleteCallback callback) const = 0;

  /// Generates a key pair and a matching self-signed application instance certificate.
  ///
  /// Generates a fresh key pair of the type implied by @p certificateType, then issues a
  /// self-signed certificate over it suitable for use as an OPC UA application instance
  /// certificate.
  ///
  /// @param subject              Subject distinguished name for the certificate.
  /// @param expiry               notAfter validity end (validity starts at issuance).
  /// @param subjectAlternateName SubjectAlternativeName entries, including the application URI.
  /// @param certificateType      Certificate/key type to generate (e.g. RSA or an ECC variant).
  /// @param keyLengthInBits      Key length in bits; unset uses the type's default.
  /// @param callback             Receives the generated key pair and certificate with the code
  ///                             create_certificate_async() answered (a Good subcode or an Uncertain
  ///                             code is kept), or an @ref ErrorDetail on failure. A key pair answered
  ///                             Uncertain is not used: the call fails with Bad_InternalError, that code
  ///                             as the cause. Never throws.
  /// @see try_create_self_signed_application_instance_certificate_sync,
  ///      create_self_signed_application_instance_certificate_sync
  void create_self_signed_application_instance_certificate_async(Name subject, UtcTime expiry,
    SubjectAlternateName subjectAlternateName, CertificateType certificateType,
    optional<size_t> keyLengthInBits,
    CreateSelfSignedApplicationInstanceCertificateCompleteCallback callback) const;

  /// Generates a self-signed application instance certificate, blocking until complete.
  ///
  /// @param subject              Subject distinguished name for the certificate.
  /// @param expiry               notAfter validity end (validity starts at issuance).
  /// @param subjectAlternateName SubjectAlternativeName entries, including the application URI.
  /// @param certificateType      Certificate/key type to generate (e.g. RSA or an ECC variant).
  /// @param keyLengthInBits      Key length in bits; unset uses the type's default.
  /// @return The generated key pair and certificate, or an @ref ErrorDetail on failure. Never
  ///         throws.
  /// @see create_self_signed_application_instance_certificate_async,
  ///      create_self_signed_application_instance_certificate_sync
  SelfSignedCertResult try_create_self_signed_application_instance_certificate_sync(Name subject,
    UtcTime expiry, SubjectAlternateName subjectAlternateName, CertificateType certificateType,
    optional<size_t> keyLengthInBits) const noexcept;

  /// Generates a self-signed application instance certificate, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned;
  /// try_create_self_signed_application_instance_certificate_sync() returns it.
  ///
  /// @param subject              Subject distinguished name for the certificate.
  /// @param expiry               notAfter validity end (validity starts at issuance).
  /// @param subjectAlternateName SubjectAlternativeName entries, including the application URI.
  /// @param certificateType      Certificate/key type to generate (e.g. RSA or an ECC variant).
  /// @param keyLengthInBits      Key length in bits; unset uses the type's default.
  /// @return The generated key pair and certificate.
  /// @throws UaException if generation fails, or when the answer is not Good (an Uncertain one included).
  /// @see create_self_signed_application_instance_certificate_async,
  ///      try_create_self_signed_application_instance_certificate_sync
  std::pair<shared_ptr<const AsymmetricKeyPair>, shared_ptr<const X509Certificate>>
    create_self_signed_application_instance_certificate_sync(Name subject, UtcTime expiry,
      SubjectAlternateName subjectAlternateName, CertificateType certificateType,
      optional<size_t> keyLengthInBits) const;

  /// Builds a PKCS#10 certificate signing request (CSR) from @p parameters.
  ///
  /// @param parameters Subject, key, and extension parameters for the CSR.
  /// @param callback   Receives the DER-encoded CSR, or an @ref ErrorDetail on failure. Never
  ///                   throws.
  virtual void create_certificate_signing_request_async(
    const CreateCsrConfig& parameters, CreateCertificateSigningRequestCompleteCallback callback) const = 0;

  /// Loads a public-key-only @ref AsymmetricKeyPair from DER-encoded public key bytes.
  ///
  /// The returned key pair has no private key; calling its private-key accessors throws. Intended
  /// for CSR signing, where only the subject's public key is needed.
  ///
  /// @param keyAlgorithm Expected key algorithm of the encoded public key.
  /// @param der          DER-encoded public key (SubjectPublicKeyInfo).
  /// @return A public-key-only key pair.
  /// @throws UaException if the bytes cannot be parsed or do not match @p keyAlgorithm.
  virtual shared_ptr<const AsymmetricKeyPair> get_public_key_from_der(
    CertificateKeyAlgorithm keyAlgorithm, span<const byte> der) const = 0;

  /// Parameters for signing a PKCS#10 certificate signing request.
  struct SignCsrConfig
  {
    ByteString csrDer;  ///< DER-encoded CSR to sign.
    shared_ptr<const X509Certificate> issuer;  ///< Issuing CA certificate.
    shared_ptr<const AsymmetricKeyPair> issuerKeys;  ///< Issuer key pair used to sign.
    CertificateSignatureAlgorithm signatureAlgorithm;  ///< Signature algorithm to use.
    UtcTime from;  ///< notBefore validity start.
    UtcTime to;  ///< notAfter validity end.
    SubjectAlternateName subjectAlternateName;  ///< SubjectAlternativeName entries to set.
  };

  /// Completion callback for @ref sign_certificate_request_async.
  using SignCsrCompleteCallback = std::function<void(CertificateResult)>;

  /// Signs a PKCS#10 CSR, issuing the requested certificate.
  ///
  /// @param parameters CSR, issuer, validity, and extension parameters.
  /// @param callback   Receives the issued certificate, or an @ref ErrorDetail on failure. Never
  ///                   throws.
  /// @see try_sign_certificate_request_sync, sign_certificate_request_sync
  virtual void sign_certificate_request_async(
    const SignCsrConfig& parameters, SignCsrCompleteCallback callback) const = 0;

  /// Signs a PKCS#10 CSR, blocking until complete.
  ///
  /// @param parameters CSR, issuer, validity, and extension parameters.
  /// @return The issued certificate, or an @ref ErrorDetail on failure. Never throws.
  /// @see sign_certificate_request_async, sign_certificate_request_sync
  CertificateResult try_sign_certificate_request_sync(const SignCsrConfig& parameters) const noexcept;

  /// Signs a PKCS#10 CSR, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_sign_certificate_request_sync() returns it.
  ///
  /// @param parameters CSR, issuer, validity, and extension parameters.
  /// @return The issued certificate.
  /// @throws UaException if signing fails, or when the answer is not Good (an Uncertain one included).
  /// @see sign_certificate_request_async, try_sign_certificate_request_sync
  shared_ptr<const X509Certificate> sign_certificate_request_sync(const SignCsrConfig& parameters) const;

  /// Creates an X.509 CRL revoking the given serial numbers, signed by the issuer.
  ///
  /// @param issuer               Issuing CA certificate.
  /// @param issuerKeys           Issuer key pair used to sign the CRL.
  /// @param revokedSerialNumbers Serial numbers (as strings) to mark revoked.
  /// @param callback             Receives the new CRL, or an @ref ErrorDetail on failure. Never
  ///                             throws.
  /// @see create_crl_sync, try_create_crl_sync
  virtual void create_crl_async(shared_ptr<const X509Certificate> issuer,
    shared_ptr<const AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers,
    CreateCrlCompleteCallback callback) const = 0;

  /// Creates an X.509 CRL, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_create_crl_sync() returns it.
  ///
  /// @param issuer               Issuing CA certificate.
  /// @param issuerKeys           Issuer key pair used to sign the CRL.
  /// @param revokedSerialNumbers Serial numbers (as strings) to mark revoked.
  /// @return The new CRL.
  /// @throws UaException if CRL creation fails, or when the answer is not Good (an Uncertain one included).
  /// @see create_crl_async, try_create_crl_sync
  shared_ptr<const X509Crl> create_crl_sync(shared_ptr<const X509Certificate> issuer,
    shared_ptr<const AsymmetricKeyPair> issuerKeys,
    const std::vector<std::string>& revokedSerialNumbers) const;

  /// Creates an X.509 CRL, blocking until complete.
  ///
  /// @param issuer               Issuing CA certificate.
  /// @param issuerKeys           Issuer key pair used to sign the CRL.
  /// @param revokedSerialNumbers Serial numbers (as strings) to mark revoked.
  /// @return The new CRL, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_crl_async, create_crl_sync
  CrlResult try_create_crl_sync(shared_ptr<const X509Certificate> issuer,
    shared_ptr<const AsymmetricKeyPair> issuerKeys,
    const std::vector<std::string>& revokedSerialNumbers) const noexcept;

  /// Validates a certificate against a trust list and the configured validation options.
  ///
  /// This is the single certificate validator: every path that validates a certificate - a
  /// @ref CertificateStore on behalf of a SecureChannel, a session or a user token, and the TrustList
  /// methods validating the list being installed - reaches it through this one call.
  ///
  /// Runs the steps of OPC 10000-4 section 6.1.3 Table 106 that apply to a certificate: chain building,
  /// signature, security policy, trust list, validity period, host name, URI, usage and revocation (per
  /// the material's options), optionally binding the certificate to an expected application URI and
  /// endpoint URL. Every step's faults are found; the faults whose Part 12 suppression bit is set in
  /// the options do not decide the verdict, and the remaining fault of the EARLIEST step is reported
  /// (on one step, the certificate's own fault before an issuer's).
  ///
  /// The chain is built from the material's issuer and trusted lists and the request's presented
  /// issuers, and must reach a self-signed root, which may be in any of them. It is trusted when the
  /// certificate or any certificate of its chain is in @ref CertificateValidationMaterial::trusted,
  /// matched by thumbprint and DER encoding; a trusted certificate that is not self-signed is never a
  /// chain end, so trusting an intermediate or the leaf itself does not shorten the chain. Neither the
  /// issuer list nor the presented issuers ever confer trust.
  ///
  /// @param request  What is validated and how: the certificate, the issuers the peer presented
  ///                 (chain material only), the requested use (OPC 10000-4 Table 106, Certificate
  ///                 Usage; @ref CertificateUse::ApplicationInstance when empty), the security policy
  ///                 the certificate must comply with (none when null), and the expected application
  ///                 URI and endpoint URL, when set. The request's own options and
  ///                 @ref CertificateValidationRequest::trustedForThisConnection are not read here: the
  ///                 caller resolves them into @p material.
  /// @param material The trust material: trusted and issuer certificates, their CRLs and the resolved
  ///                 options.
  /// @param callback             Receives success if the certificate is trusted, or an
  ///                             @ref ErrorDetail describing the rejection. A certificate whose
  ///                             issuer is in neither list reports Bad_CertificateChainIncomplete,
  ///                             with the missing issuer named in the ErrorDetail. A certificate
  ///                             requested as a CA without basicConstraints cA TRUE reports
  ///                             Bad_CertificateUseNotAllowed; a fault of an issuer reports the issuer
  ///                             variant of its step's code. Never throws.
  virtual void validate_certificate_async(const CertificateValidationRequest& request,
    CertificateValidationMaterial material, CertificateValidationCompleteCallback callback) const = 0;

  /// Validates a CRL before it is installed in a trust list (OPC 10000-12 section 7.8.2.1: the Server
  /// "will validate all new Certificates and CRLs").
  ///
  /// The CRL's issuer must be one of @p issuerCandidates (matched by subject name), the CRL's
  /// signature must verify with that certificate's public key, and - unless @p validationOptions
  /// carries SuppressRevocationStatusUnknown or SuppressIssuerRevocationStatusUnknown, the
  /// suppressions for a revocation list that cannot be used - the current time must lie within the
  /// CRL's thisUpdate/nextUpdate window (a CRL without nextUpdate has no end).
  ///
  /// @param validationOptions Options of the certificate group the CRL is installed in.
  /// @param crl               CRL to validate.
  /// @param issuerCandidates  The certificates that may have issued the CRL (the trust list's
  ///                          trusted and issuer certificates).
  /// @param callback          Receives success, or the cause with an @ref ErrorDetail whose context
  ///                          names the CRL's issuer: Bad_CertificateChainIncomplete when no
  ///                          candidate is the issuer, Bad_SecurityChecksFailed when the signature
  ///                          does not verify, Bad_CertificateRevocationUnknown when the CRL is
  ///                          outside its validity window. Never throws.
  virtual void validate_crl_async(TrustListValidationOptions validationOptions, shared_ptr<const X509Crl> crl,
    std::vector<shared_ptr<const X509Certificate>> issuerCandidates,
    CrlValidationCompleteCallback callback) const = 0;

protected:
  /// Default-constructs the base; only subclasses construct a @ref Crypto.
  Crypto() = default;
};

/// Creates the SDK's default @ref ua::Crypto implementation.
///
/// Lets higher-level code (e.g. a `Server`) obtain a usable crypto provider without naming a
/// concrete provider type. The returned instance is shared and immutable; ownership is shared with
/// the caller and the object outlives all copies of the returned pointer.
///
/// This overload supplies no private-key credential callback. Operations that require credential
/// material to access private keys will observe no credential available; use the
/// callback-accepting overload when such material may be needed.
///
/// @return A shared, immutable default crypto provider. Never null.
/// @see create_default_crypto(Crypto::PrivateKeyCredentialCallback)
shared_ptr<const Crypto> create_default_crypto();

/// Creates the SDK's default @ref ua::Crypto implementation with a private-key credential callback.
///
/// The returned instance is shared and immutable; ownership is shared with the caller. The callback
/// is invoked by the provider when it needs credential material to access private-key material
/// (for example when importing or exporting a private key); see
/// `Crypto::PrivateKeyCredentialCallback`. It is provider-agnostic - some providers may never
/// invoke it.
///
/// @param privateKeyCredentialCallback Supplies credential material on demand. May be empty if no
///                                     credential is ever required.
/// @return A shared, immutable default crypto provider. Never null.
/// @see create_default_crypto()
shared_ptr<const Crypto> create_default_crypto(
  Crypto::PrivateKeyCredentialCallback privateKeyCredentialCallback);

}  // namespace ua

#endif  //! UA_CRYPTO_H
