// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief File-system-backed @ref ua::CertificateStore for application, trust, and CRL material.
/// @ingroup security

#ifndef UA_CERTIFICATE_STORE_FILES_H
#define UA_CERTIFICATE_STORE_FILES_H

#include "ua_certificate_store.h"
#include "ua_logger.h"

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <optional>

namespace ua
{

/// The settings of a file-system-backed certificate store (@ref CertificateStoreFiles::create).
/// @ingroup security
struct CertificateStoreFilesConfig
{
  /// Root directory holding the store's subdirectories; created if missing.
  std::filesystem::path trustListPath{};
  /// Initial trust-list validation options.
  TrustListValidationOptions validationOptions{};
  /// Interval between automatic file system re-scans; unset or a non-positive value disables automatic
  /// refresh.
  std::optional<std::chrono::seconds> refreshPeriod{};
  /// When `true`, certificates that fail validation are persisted to the rejected store; otherwise they
  /// are tracked only in memory.
  bool storeRejectedCertificates{true};
  /// Upper bound on the rejected-certificate store. A pre-auth peer can present unlimited distinct
  /// certificates during OpenSecureChannel; once this many are held the store evicts oldest-first, so it
  /// cannot grow without bound (disk and memory). 0 disables the bound.
  size_t maxRejectedCertificates{100};
  /// The use this store's certificates are validated for when a request does not name one (OPC 10000-4
  /// Table 106, Certificate Usage). @ref CertificateUse::ApplicationInstance is what an application trust
  /// list holds; a DefaultUserTokenGroup trust list uses @ref CertificateUse::User, so the Table 44 rules
  /// apply to its user certificates rather than Table 43's.
  CertificateUse use{CertificateUse::ApplicationInstance};
  /// Logger for diagnostics; a no-op logger by default.
  Logger logger{};
};

/// A @ref CertificateStore that persists each store as a directory tree on the file system.
///
/// Application certificates and keys, trusted certificates, issuer certificates, rejected
/// certificates, and their CRLs are each kept in a dedicated subdirectory beneath a single trust
/// list root path. The store reads those directories into an in-memory cache and, when a non-zero
/// refresh period is configured, periodically re-scans the file system so that out-of-band changes
/// (certificates dropped in or removed by an operator or by the OPC UA TrustList file type) are
/// picked up automatically.
///
/// This is a strand-serialized component: every public method posts its work to a private strand,
/// so callers may invoke it from any thread and the store serializes all access to its caches and
/// to the file system internally. The `*_async` overloads deliver their outcome on an unspecified
/// worker thread; do not block that thread.
///
/// Created through @ref create and owned as a `shared_ptr<CertificateStore>`; the concrete type is private
/// to the SDK. The store keeps the injected executor and @ref Crypto alive for as long as it lives.
///
/// @see CertificateStore
/// @ingroup security
class CertificateStoreFiles
{
public:
  CertificateStoreFiles() = delete;

  /// Creates a file-system-backed certificate store rooted at `config.trustListPath`.
  ///
  /// Creates any missing store subdirectories under the root, loads existing certificates and CRLs
  /// into the cache, and, when `config.refreshPeriod` holds a non-zero duration, starts a background
  /// timer that periodically re-scans the file system for out-of-band changes.
  ///
  /// @param executor Executor on which the store's strand and background refresh run; kept alive for
  ///                 the store's lifetime.
  /// @param crypto   Cryptographic provider used for parsing and validation; kept alive for the
  ///                 store's lifetime; must not be null.
  /// @param config   The store's settings; see @ref CertificateStoreFilesConfig.
  /// @return A shared, ready-to-use @ref CertificateStore.
  ///
  /// Layout of the own certificates: `TrustList/ApplicationCertificates/ApplicationCert<Type>.der`
  /// holds the DER leaf of each @ref CertificateType, and
  /// `TrustList/ApplicationCertificates/ApplicationCertChain<Type>.der`, when present, its
  /// issuer chain (@ref CertificateStore::ApplicationCertificate::issuerCertificates) as the
  /// consecutive DER encodings of the issuers, the leaf's issuer first - the encoding OPC 10000-6
  /// section 6.2.6 uses for a certificate chain. The chain file is written with the leaf and removed
  /// when the stored chain is empty.
  [[nodiscard]] static shared_ptr<CertificateStore> create(boost::asio::any_io_executor executor,
    shared_ptr<const Crypto> crypto, CertificateStoreFilesConfig config);
};

}  // namespace ua

#endif  //! UA_CERTIFICATE_STORE_FILES_H
