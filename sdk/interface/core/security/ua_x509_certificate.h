// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Read-only accessor interface for a parsed X.509 certificate.
/// @ingroup security

#ifndef UA_X509_CERTIFICATE_H
#define UA_X509_CERTIFICATE_H

#include <boost/asio/ip/tcp.hpp>
#include "ua_includes.h"
#include "ua_crypto_types.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_byte_string.h"
#include "ua_utc_time.h"

namespace asio = boost::asio;

namespace ua
{

/// A parsed, read-only X.509 v3 certificate.
///
/// Exposes the fields and extensions of a DER-encoded certificate (per RFC 5280)
/// as already-decoded accessors: subject and issuer distinguished-name components,
/// validity window, public key, key-usage / extended-key-usage flags, subject
/// alternative names, and basic constraints. Instances are immutable once parsed
/// and the accessors are pure (side-effect-free) - they are safe to call
/// concurrently from any thread.
///
/// This is an abstract interface; a concrete certificate is produced by the
/// security backend (for example from a @ref ByteString DER blob). Implementations
/// own the underlying parsed certificate for their lifetime.
/// @ingroup security
class X509Certificate
{
public:
  virtual ~X509Certificate() = default;

  X509Certificate(const X509Certificate&) = delete;
  X509Certificate& operator=(const X509Certificate&) = delete;
  X509Certificate(X509Certificate&&) = delete;
  X509Certificate& operator=(X509Certificate&&) = delete;

  /// Compares two certificates for equality.
  ///
  /// Two certificates are equal when they represent the same encoded certificate.
  ///
  /// @param obj Certificate to compare against.
  /// @return @c true if the certificates are equal.
  virtual bool operator==(const X509Certificate& obj) const = 0;

  /// Returns the zero-indexed X.509 format version: 0 for v1, 1 for v2, 2 for v3.
  ///
  /// This is the raw encoded version number, so an X.509 v3 certificate reports 2.
  ///
  /// @return The zero-indexed X.509 version (0=v1, 1=v2, 2=v3).
  virtual int version() const = 0;

  /// Returns the certificate serial number as a base-10 decimal string.
  ///
  /// @return The serial number as a base-10 decimal string.
  virtual std::string serial_number() const = 0;

  /// Returns the raw signature value over the certificate's TBS data.
  ///
  /// @return The raw signature value over the certificate's TBS data.
  virtual ByteString signature() const = 0;

  /// Returns the issuer name as the raw DER encoding of the X.509 Name (bytes in a string).
  ///
  /// This is the whole issuer Name structure, not a human-readable rendering; use
  /// the per-attribute accessors (@ref issuer_common_name and friends) for individual
  /// RDN components.
  ///
  /// @return The issuer Name as its raw DER encoding.
  virtual std::string issuer() const = 0;

  /// Returns the issuer country (C) attribute, or an empty string if absent.
  ///
  /// @return The issuer country (C) attribute, or empty if absent.
  virtual std::string issuer_country() const = 0;

  /// Returns the issuer organization (O) attribute, or an empty string if absent.
  ///
  /// @return The issuer organization (O) attribute, or empty if absent.
  virtual std::string issuer_organization() const = 0;

  /// Returns the issuer organizational unit (OU) attribute, or an empty string if absent.
  ///
  /// @return The issuer organizational unit (OU) attribute, or empty if absent.
  virtual std::string issuer_organizational_unit() const = 0;

  /// Returns the issuer distinguishedName (DN, OID 2.5.4.49) attribute, or empty if absent.
  ///
  /// This is the single `distinguishedName` naming attribute, not the whole issuer
  /// DN - for that, use @ref issuer.
  ///
  /// @return The issuer distinguishedName (DN) attribute, or empty if absent.
  virtual std::string issuer_distinguished_name() const = 0;

  /// Returns the issuer state or province (ST) attribute, or an empty string if absent.
  ///
  /// @return The issuer state or province (ST) attribute, or empty if absent.
  virtual std::string issuer_state() const = 0;

  /// Returns the issuer common name (CN) attribute, or an empty string if absent.
  ///
  /// @return The issuer common name (CN) attribute, or empty if absent.
  virtual std::string issuer_common_name() const = 0;

  /// Returns the issuer domain component (DC) attribute, or an empty string if absent.
  ///
  /// @return The issuer domain component (DC) attribute, or empty if absent.
  virtual std::string issuer_domain_component() const = 0;

  /// Returns the issuer locality (L) attribute, or an empty string if absent.
  ///
  /// @return The issuer locality (L) attribute, or empty if absent.
  virtual std::string issuer_locality() const = 0;

  /// Returns the start of the validity window (notBefore) in UTC.
  ///
  /// @return The start of the validity window (notBefore) in UTC.
  virtual UtcTime validity_from() const = 0;

  /// Returns the end of the validity window (notAfter) in UTC.
  ///
  /// @return The end of the validity window (notAfter) in UTC.
  virtual UtcTime validity_to() const = 0;

  /// Returns the subject name as the raw DER encoding of the X.509 Name (bytes in a string).
  ///
  /// This is the whole subject Name structure, not a human-readable rendering; use
  /// the per-attribute accessors (@ref subject_common_name and friends) for individual
  /// RDN components.
  ///
  /// @return The subject Name as its raw DER encoding.
  virtual std::string subject() const = 0;

  /// Returns the subject country (C) attribute, or an empty string if absent.
  ///
  /// @return The subject country (C) attribute, or empty if absent.
  virtual std::string subject_country() const = 0;

  /// Returns the subject organization (O) attribute, or an empty string if absent.
  ///
  /// @return The subject organization (O) attribute, or empty if absent.
  virtual std::string subject_organization() const = 0;

  /// Returns the subject organizational unit (OU) attribute, or an empty string if absent.
  ///
  /// @return The subject organizational unit (OU) attribute, or empty if absent.
  virtual std::string subject_organizational_unit() const = 0;

  /// Returns the subject distinguishedName (DN, OID 2.5.4.49) attribute, or empty if absent.
  ///
  /// This is the single `distinguishedName` naming attribute, not the whole subject
  /// DN - for that, use @ref subject.
  ///
  /// @return The subject distinguishedName (DN) attribute, or empty if absent.
  virtual std::string subject_distinguished_name() const = 0;

  /// Returns the subject state or province (ST) attribute, or an empty string if absent.
  ///
  /// @return The subject state or province (ST) attribute, or empty if absent.
  virtual std::string subject_state() const = 0;

  /// Returns the subject common name (CN) attribute, or an empty string if absent.
  ///
  /// @return The subject common name (CN) attribute, or empty if absent.
  virtual std::string subject_common_name() const = 0;

  /// Returns the subject domain component (DC) attribute, or an empty string if absent.
  ///
  /// @return The subject domain component (DC) attribute, or empty if absent.
  virtual std::string subject_domain_component() const = 0;

  /// Returns the subject locality (L) attribute, or an empty string if absent.
  ///
  /// @return The subject locality (L) attribute, or empty if absent.
  virtual std::string subject_locality() const = 0;

  /// Returns the subject public key in DER-encoded form.
  ///
  /// @return The subject public key in DER-encoded form.
  virtual ByteString public_key() const = 0;

  /// Returns the size of the subject public key in bits.
  ///
  /// For an RSA key this is the modulus size; for an ECC key it is the field
  /// (curve) size. EdDSA keys follow the OPC UA profile database convention:
  /// 256 for Ed25519 and 456 for Ed448.
  ///
  /// @return The subject public key size in bits.
  virtual size_t public_key_bit_length() const = 0;

  /// Returns the public-key algorithm of the subject key.
  ///
  /// @return The public-key algorithm of the subject key.
  /// @see CertificateKeyAlgorithm
  virtual CertificateKeyAlgorithm key_algorithm() const = 0;

  /// Returns the Authority Key Identifier extension value.
  ///
  /// Identifies the issuer's public key; empty if the extension is absent.
  ///
  /// @return The Authority Key Identifier extension value, or empty if absent.
  virtual ByteString authority_key_identifier() const = 0;

  /// Returns the Subject Key Identifier extension value.
  ///
  /// Identifies this certificate's public key; empty if the extension is absent.
  ///
  /// @return The Subject Key Identifier extension value, or empty if absent.
  virtual ByteString subject_key_identifier() const = 0;

  /// Returns @c true if the digitalSignature key-usage bit is set.
  ///
  /// @return @c true if the digitalSignature key-usage bit is set.
  virtual bool key_usage_digital_signature() const = 0;

  /// Returns @c true if the nonRepudiation (contentCommitment) key-usage bit is set.
  ///
  /// @return @c true if the nonRepudiation (contentCommitment) key-usage bit is set.
  virtual bool key_usage_non_repudiation() const = 0;

  /// Returns @c true if the keyEncipherment key-usage bit is set.
  ///
  /// @return @c true if the keyEncipherment key-usage bit is set.
  virtual bool key_usage_key_encipherment() const = 0;

  /// Returns @c true if the dataEncipherment key-usage bit is set.
  ///
  /// @return @c true if the dataEncipherment key-usage bit is set.
  virtual bool key_usage_data_encipherment() const = 0;

  /// Returns @c true if the keyAgreement key-usage bit is set.
  ///
  /// @return @c true if the keyAgreement key-usage bit is set.
  virtual bool key_usage_key_agreement() const = 0;

  /// Returns @c true if the keyCertSign key-usage bit is set.
  ///
  /// When set, the public key may be used to verify certificate signatures.
  ///
  /// @return @c true if the keyCertSign key-usage bit is set.
  virtual bool key_usage_key_cert_sign() const = 0;

  /// Returns @c true if the cRLSign key-usage bit is set.
  ///
  /// When set, the public key may be used to verify CRL signatures.
  ///
  /// @return @c true if the cRLSign key-usage bit is set.
  virtual bool key_usage_crl_sign() const = 0;

  /// Returns @c true if the encipherOnly key-usage bit is set.
  ///
  /// @return @c true if the encipherOnly key-usage bit is set.
  virtual bool key_usage_encipher_only() const = 0;

  /// Returns @c true if the decipherOnly key-usage bit is set.
  ///
  /// @return @c true if the decipherOnly key-usage bit is set.
  virtual bool key_usage_decipher_only() const = 0;

  /// Returns the IP addresses listed in the Subject Alternative Name extension.
  ///
  /// @return The IP addresses from the Subject Alternative Name extension.
  virtual std::vector<asio::ip::address> san_ip_addresses() const = 0;

  /// Returns the DNS host names listed in the Subject Alternative Name extension.
  ///
  /// @return The DNS host names from the Subject Alternative Name extension.
  virtual std::vector<std::string> san_hostnames() const = 0;

  /// Returns the URIs listed in the Subject Alternative Name extension.
  ///
  /// For OPC UA application certificates this carries the application URI.
  ///
  /// @return The URIs from the Subject Alternative Name extension.
  virtual std::vector<std::string> san_uris() const = 0;

  /// Returns @c true if the Basic Constraints cA flag marks this as a CA certificate.
  ///
  /// @return @c true if the Basic Constraints cA flag is set.
  virtual bool basic_constraints_ca() const = 0;

  /// Returns the Basic Constraints pathLenConstraint value.
  ///
  /// The maximum number of intermediate CA certificates that may follow this one
  /// in a certification path. Meaningful only when @ref basic_constraints_ca is
  /// @c true. When the constraint is absent (unconstrained) the value is
  /// @c UINT32_MAX.
  ///
  /// @return The Basic Constraints pathLenConstraint value, or @c UINT32_MAX when absent.
  virtual uint32_t basic_constraints_path_length() const = 0;

  /// Returns @c true if the Extended Key Usage extension permits TLS client authentication.
  ///
  /// A certificate without an Extended Key Usage extension reports @c false here and
  /// from @ref extended_key_usage_server_auth "extended_key_usage_server_auth": an absent extension declares
  /// neither purpose.
  ///
  /// @return @c true if Extended Key Usage permits TLS client authentication.
  virtual bool extended_key_usage_client_auth() const = 0;

  /// Returns @c true if the Extended Key Usage extension permits TLS server authentication.
  ///
  /// @c false when the certificate has no Extended Key Usage extension.
  ///
  /// @return @c true if Extended Key Usage permits TLS server authentication.
  virtual bool extended_key_usage_server_auth() const = 0;

  /// Returns the certificate thumbprint (SHA-1 digest of the DER encoding).
  ///
  /// @return The certificate thumbprint (SHA-1 digest of the DER encoding).
  virtual ByteString thumbprint() const = 0;

  /// Returns the full DER encoding of the certificate.
  ///
  /// @return The full DER encoding of the certificate.
  virtual ByteString der_encoding() const = 0;

  /// Returns @c true if this certificate was issued (signed) by @p issuer.
  ///
  /// The issuer name of this certificate must equal @p issuer's subject, the
  /// authorityKeyIdentifier must equal @p issuer's subjectKeyIdentifier when both are
  /// present, and @p issuer's public key must verify this certificate's signature.
  /// Validity, revocation and trust are not considered.
  ///
  /// @param issuer Candidate issuing certificate.
  /// @return @c true if this certificate was issued (signed) by @p issuer.
  /// @see issuer_of
  virtual bool issued_by(const X509Certificate& issuer) const = 0;

  /// Returns @c true if this certificate issued (signed) @p issued.
  ///
  /// The exact inverse of @ref issued_by "issued_by": `a.issuer_of(b) == b.issued_by(a)`.
  ///
  /// @param issued Candidate certificate signed by this one.
  /// @return @c true if this certificate issued (signed) @p issued.
  /// @see issued_by
  virtual bool issuer_of(const X509Certificate& issued) const = 0;

  /// Returns @c true if the certificate is self-signed: subject equals issuer, the key
  /// identifiers agree when present, and the certificate's own public key verifies
  /// its signature.
  ///
  /// @return @c true if the certificate is self-signed.
  virtual bool self_signed() const = 0;

  /// Returns the algorithm with which the issuer signed this certificate.
  ///
  /// @return The algorithm with which the issuer signed this certificate.
  /// @see CertificateSignatureAlgorithm
  virtual CertificateSignatureAlgorithm signature_algorithm() const = 0;

protected:
  /// Default-constructs the base; only subclasses construct an @ref X509Certificate.
  X509Certificate() = default;
};

}  // namespace ua

#endif  //! UA_X509_CERTIFICATE_H
