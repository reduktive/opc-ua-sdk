// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstract handle to a parsed X.509 Certificate Revocation List (CRL).
/// @ingroup security

#ifndef UA_X509_CRL_H
#define UA_X509_CRL_H

#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

/// A parsed X.509 Certificate Revocation List.
///
/// Models a CRL issued by a certificate authority that enumerates the
/// certificates the authority has revoked. The interface is read-only:
/// implementations wrap an already-parsed CRL and expose its canonical
/// encoding and identity. Construction and parsing are performed by the crypto
/// backend (see @ref Crypto); this type is the value handle passed around the
/// SDK. Instances are immutable and the accessors are safe to call from any
/// thread.
/// @ingroup security
/// @see X509Certificate, CertificateStore
class X509Crl
{
public:
  virtual ~X509Crl() = default;

  X509Crl(const X509Crl&) = delete;
  X509Crl& operator=(const X509Crl&) = delete;
  X509Crl(X509Crl&&) = delete;
  X509Crl& operator=(X509Crl&&) = delete;

  /// Returns whether this CRL is byte-for-byte equal to @p obj.
  ///
  /// Equality compares the underlying DER encodings; two handles wrapping the
  /// same CRL bytes compare equal regardless of implementation.
  ///
  /// @param obj CRL to compare against.
  /// @return `true` if both CRLs have identical DER encodings.
  virtual bool operator==(const X509Crl& obj) const = 0;

  /// Returns the canonical DER (binary) encoding of the CRL.
  ///
  /// This is the wire/storage form suitable for transmission or persistence.
  ///
  /// @return The DER-encoded CRL bytes.
  virtual ByteString der_encoding() const = 0;

  /// Returns the thumbprint (digest) identifying the CRL.
  ///
  /// The thumbprint is a hash of the DER encoding used as a compact identity
  /// for lookups and comparison.
  ///
  /// @return The CRL thumbprint bytes.
  virtual ByteString thumbprint() const = 0;

protected:
  /// Default-constructs the base; only subclasses construct an @ref X509Crl.
  X509Crl() = default;
};

}  // namespace ua

#endif  //! UA_X509_CRL_H
