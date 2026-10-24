// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The file-system-backed CertificateStore behind ua::CertificateStoreFiles::create. Private to the
// implementation (public API review item 9, API-9.4): applications hold it as a CertificateStore.

#ifndef UA_CERTIFICATE_STORE_FILES_IMPL_H
#define UA_CERTIFICATE_STORE_FILES_IMPL_H

#include "ua_certificate_store.h"
#include "ua_certificate_store_files.h"
#include "ua_logger.h"
#include "ua_timer.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <vector>

namespace ua
{

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
/// Instances are created through @ref CertificateStoreFiles::create and are owned via `shared_ptr`. The store
/// keeps the injected executor and @ref Crypto alive for as long as it lives.
///
/// @see CertificateStore
/// @ingroup security
class CertificateStoreFilesImpl : public CertificateStore
{
public:
  /// The executor the store's file operations complete on.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept override
  {
    return mExecutor;
  }

  /// Destroys the store, cancelling any pending background refresh.
  ///
  /// @note Prefer calling @ref shutdown before releasing the last `shared_ptr` so that background
  ///       work is stopped deterministically rather than during destruction.
  ~CertificateStoreFilesImpl();

  CertificateStoreFilesImpl(const CertificateStoreFilesImpl&) = delete;
  CertificateStoreFilesImpl& operator=(const CertificateStoreFilesImpl&) = delete;
  CertificateStoreFilesImpl(CertificateStoreFilesImpl&&) = delete;
  CertificateStoreFilesImpl& operator=(CertificateStoreFilesImpl&&) = delete;

  /// Gracefully shuts down the store, cancelling the background refresh timer.
  ///
  /// Safe to call more than once and from any thread. After shutdown no further automatic file
  /// system re-scans occur; explicit `*_async` calls still operate on the current cache.
  void shutdown() override;

  /// Stores an application certificate together with its key pair, writing them to disk.
  ///
  /// The certificate is written to the application certificates directory and its private key to
  /// the application keys directory, then added to the in-memory cache.
  ///
  /// @param certificate Application certificate plus key pair to persist; the key material is
  ///                    written to the application keys directory.
  /// @param callback    Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                    @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_application_certificates_sync,
  ///      CertificateStore::try_add_to_application_certificates_sync
  void add_to_application_certificates_async(
    ApplicationCertificate certificate, CompleteCallback callback) noexcept override;

  /// Retrieves the application certificate (and key pair) for a given certificate type.
  ///
  /// @param certificateType Selects which application certificate to return.
  /// @param callback        Receives the outcome: on success the Result holds the matching
  ///                        @ref CertificateStore::ApplicationCertificate; on failure it carries an
  ///                        @ref ErrorDetail (e.g. when no certificate of that type is present).
  ///                        Never throws.
  /// @see CertificateStore::get_application_certificate_sync,
  ///      CertificateStore::try_get_application_certificate_sync
  void get_application_certificate_async(
    CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept override;

  /// Retrieves all stored application certificates.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of
  ///                 @ref CertificateStore::ApplicationCertificate entries (possibly empty); on
  ///                 failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see CertificateStore::get_application_certificates_sync,
  ///      CertificateStore::try_get_application_certificates_sync
  void get_application_certificates_async(
    GetApplicationCertificatesCallback callback) const noexcept override;

  /// Adds a single certificate to the trusted certificates store, writing it to disk.
  ///
  /// @param certificate Certificate to trust; must not be null.
  /// @param callback    Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                    @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_trusted_certificates_sync,
  ///      CertificateStore::try_add_to_trusted_certificates_sync
  void add_to_trusted_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override;

  /// Adds several certificates to the trusted certificates store in one operation.
  ///
  /// @param certificates Certificates to trust; entries must not be null.
  /// @param callback     Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                     @ref ErrorDetail if any write fails. This overload never throws.
  /// @see CertificateStore::add_to_trusted_certificates_sync,
  ///      CertificateStore::try_add_to_trusted_certificates_sync
  void add_to_trusted_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept override;

  /// Retrieves all certificates in the trusted certificates store.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of trusted
  ///                 certificates (possibly empty); on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see CertificateStore::get_trusted_certificates_sync,
  ///      CertificateStore::try_get_trusted_certificates_sync
  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override;

  /// Adds a single certificate to the issuer certificates store, writing it to disk.
  ///
  /// Issuer certificates are used only to complete certificate chains during validation; they are
  /// not themselves trust anchors.
  ///
  /// @param certificate Issuer certificate to store; must not be null.
  /// @param callback    Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                    @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_issuer_certificates_sync,
  ///      CertificateStore::try_add_to_issuer_certificates_sync
  void add_to_issuer_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override;

  /// Adds several certificates to the issuer certificates store in one operation.
  ///
  /// @param certificates Issuer certificates to store; entries must not be null.
  /// @param callback     Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                     @ref ErrorDetail if any write fails. This overload never throws.
  /// @see CertificateStore::add_to_issuer_certificates_sync,
  ///      CertificateStore::try_add_to_issuer_certificates_sync
  void add_to_issuer_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept override;

  /// Retrieves all certificates in the issuer certificates store.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of issuer
  ///                 certificates (possibly empty); on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see CertificateStore::get_issuer_certificates_sync,
  ///      CertificateStore::try_get_issuer_certificates_sync
  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override;

  /// Adds a certificate to the rejected certificates store.
  ///
  /// The rejected store records certificates that failed validation so an operator can review and
  /// optionally promote them to the trusted store. This explicit call always persists the entry to
  /// disk; the storeRejectedCertificates flag passed to create() only suppresses the automatic
  /// recording that validate_certificate_async performs on a validation failure, not this add.
  ///
  /// @param certificate Rejected certificate to record; must not be null.
  /// @param callback    Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                    @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_rejected_certificates_sync,
  ///      CertificateStore::try_add_to_rejected_certificates_sync
  void add_to_rejected_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override;

  /// Retrieves all certificates in the rejected certificates store.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of rejected
  ///                 certificates (possibly empty); on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see CertificateStore::get_rejected_certificates_sync,
  ///      CertificateStore::try_get_rejected_certificates_sync
  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override;

  /// Adds a single certificate revocation list to the trusted CRL store, writing it to disk.
  ///
  /// @param crl      CRL to store; must not be null.
  /// @param callback Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                 @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_trusted_crls_sync,
  ///      CertificateStore::try_add_to_trusted_crls_sync
  void add_to_trusted_crls_async(shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept override;

  /// Adds several certificate revocation lists to the trusted CRL store in one operation.
  ///
  /// @param crls     CRLs to store; entries must not be null.
  /// @param callback Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                 @ref ErrorDetail if any write fails. This overload never throws.
  /// @see CertificateStore::add_to_trusted_crls_sync,
  ///      CertificateStore::try_add_to_trusted_crls_sync
  void add_to_trusted_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept override;

  /// Retrieves all certificate revocation lists in the trusted CRL store.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of trusted CRLs
  ///                 (possibly empty); on failure it carries an @ref ErrorDetail. This overload
  ///                 never throws.
  /// @see CertificateStore::get_trusted_crls_sync, CertificateStore::try_get_trusted_crls_sync
  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override;

  /// Adds a single certificate revocation list to the issuer CRL store, writing it to disk.
  ///
  /// @param crl      CRL to store; must not be null.
  /// @param callback Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                 @ref ErrorDetail if the write fails. This overload never throws.
  /// @see CertificateStore::add_to_issuer_crls_sync,
  ///      CertificateStore::try_add_to_issuer_crls_sync
  void add_to_issuer_crls_async(shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept override;

  /// Adds several certificate revocation lists to the issuer CRL store in one operation.
  ///
  /// @param crls     CRLs to store; entries must not be null.
  /// @param callback Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                 @ref ErrorDetail if any write fails. This overload never throws.
  /// @see CertificateStore::add_to_issuer_crls_sync,
  ///      CertificateStore::try_add_to_issuer_crls_sync
  void add_to_issuer_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept override;

  /// Retrieves all certificate revocation lists in the issuer CRL store.
  ///
  /// @param callback Receives the outcome: on success the Result holds the list of issuer CRLs
  ///                 (possibly empty); on failure it carries an @ref ErrorDetail. This overload
  ///                 never throws.
  /// @see CertificateStore::get_issuer_crls_sync, CertificateStore::try_get_issuer_crls_sync
  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override;

  /// Atomically replaces the entire trusted certificate and CRL set on disk and in the cache.
  ///
  /// Backs the OPC UA `TrustListType::CloseAndUpdate` operation when the TrustedCertificates and/or
  /// TrustedCrls masks are set: the existing trusted directories are emptied and the supplied
  /// contents written in their place.
  ///
  /// @param certificates New trusted certificate set, replacing the current one.
  /// @param crls         New trusted CRL set, replacing the current one.
  /// @param callback     Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                     @ref ErrorDetail if the update fails. This overload never throws.
  /// @see CertificateStore::replace_trusted_certificates_sync,
  ///      CertificateStore::try_replace_trusted_certificates_sync
  void replace_trusted_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept override;

  /// Atomically replaces the entire issuer certificate and CRL set on disk and in the cache.
  ///
  /// Backs the OPC UA `TrustListType::CloseAndUpdate` operation when the IssuerCertificates and/or
  /// IssuerCrls masks are set: the existing issuer directories are emptied and the supplied
  /// contents written in their place.
  ///
  /// @param certificates New issuer certificate set, replacing the current one.
  /// @param crls         New issuer CRL set, replacing the current one.
  /// @param callback     Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                     @ref ErrorDetail if the update fails. This overload never throws.
  /// @see CertificateStore::replace_issuer_certificates_sync,
  ///      CertificateStore::try_replace_issuer_certificates_sync
  void replace_issuer_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept override;

  /// Removes one certificate from the trusted certificates store by SHA-1 thumbprint.
  ///
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @param callback   Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                   @ref ErrorDetail if no such certificate exists or the removal fails. This
  ///                   overload never throws.
  /// @see CertificateStore::remove_from_trusted_certificates_sync,
  ///      CertificateStore::try_remove_from_trusted_certificates_sync
  void remove_from_trusted_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override;

  /// Removes one certificate from the issuer certificates store by SHA-1 thumbprint.
  ///
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @param callback   Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                   @ref ErrorDetail if no such certificate exists or the removal fails. This
  ///                   overload never throws.
  /// @see CertificateStore::remove_from_issuer_certificates_sync,
  ///      CertificateStore::try_remove_from_issuer_certificates_sync
  void remove_from_issuer_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override;

  /// Sets the validation options applied to subsequent certificate validations.
  ///
  /// Replaces the options supplied at construction. The new options take effect for validations
  /// started after this call; in-flight validations keep the options they captured.
  ///
  /// @param validationOptions Trust-list validation behaviour to use from now on.
  void set_validation_options(TrustListValidationOptions validationOptions) override;

  /// Returns the options last set with @ref set_validation_options (or given at construction),
  /// including a change the store's strand has not applied yet. Safe to call from any thread.
  ///
  /// @return The store's current default validation options.
  TrustListValidationOptions validation_options() const override;

  /// Re-scans the trust list directories and rebuilds the in-memory cache.
  ///
  /// Picks up certificates and CRLs added to or removed from the file system out of band. This is
  /// the same work performed automatically on the configured refresh period; call it to force an
  /// immediate refresh.
  ///
  /// @param callback Receives the outcome: a successful @ref VoidResult, or one carrying an
  ///                 @ref ErrorDetail if the rescan fails. This overload never throws.
  void refresh_cache(CompleteCallback callback) override;

  /// Validates the certificate of @p request against this store's trust and issuer material.
  ///
  /// Fills what the request leaves open - the options configured on the store when
  /// @ref CertificateValidationRequest::options is empty, the store's @ref CertificateUse when
  /// @ref CertificateValidationRequest::use is empty - and builds the trust material: the trusted
  /// list plus @ref CertificateValidationRequest::trustedForThisConnection as trusted, the issuer list
  /// as issuers, and both CRL lists. The presented issuers stay in the request as chain material.
  /// Calls @ref Crypto::validate_certificate_async once and delivers its verdict.
  ///
  /// When configured to store rejected certificates, a refused leaf the administrator could choose to
  /// trust (untrusted, issuer unknown, application URI mismatch, or a suppressible fault whose
  /// suppression is configured) is recorded in the rejected store; an expired, revoked or
  /// policy-violating certificate is not, and a presented issuer never is.
  ///
  /// @param request  The certificate to validate (must not be null) and how to validate it.
  /// @param callback Receives the validation outcome; carries an @ref ErrorDetail describing the
  ///                 reason on rejection. This overload never throws.
  /// @see CertificateStore::validate_certificate_sync,
  ///      CertificateStore::try_validate_certificate_sync
  void validate_certificate_async(CertificateValidationRequest request,
    Crypto::CertificateValidationCompleteCallback callback) noexcept override;

  /// Creates the store from @p config; see @ref CertificateStoreFilesImpl::create.
  /// @param executor Executor for the store's strand and background refresh.
  /// @param crypto   Cryptographic provider; must not be null.
  /// @param config   The store's settings.
  /// @return The ready store.
  static shared_ptr<CertificateStore> create(boost::asio::any_io_executor executor,
    shared_ptr<const Crypto> crypto, CertificateStoreFilesConfig config);

private:
  std::filesystem::path mTrustListPath;
  shared_ptr<const Crypto> mCrypto;
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  TrustListValidationOptions mValidationOptions;
  /// The options last set, readable from any thread (@ref validation_options); mValidationOptions is
  /// the strand's copy.
  std::atomic<TrustListValidationOptions::UnderlyingType> mPublishedValidationOptions;
  bool mStoreRejectedCertificates{true};
  /// Upper bound on the retained rejected-certificate set (and the on-disk RejectedCertificates/ dir).
  /// The rejected list is meant to be a finite, operator-reviewed set (Part 12 GetRejectedList), not
  /// an attacker-growable log; the store evicts oldest-first once this many are held. 0 = unbounded.
  size_t mMaxRejectedCertificates{100};
  /// The use a request without its own is validated for. A server's application trust list and its
  /// DefaultUserTokenGroup trust list are separate stores, so the use (Table 43 or Table 44) is a
  /// property of the store holding the list.
  CertificateUse mUse{CertificateUse::ApplicationInstance};
  Logger mLogger;

  Timer mRefreshTimer;
  std::multimap<std::string, std::filesystem::file_time_type> mLastFilesystemStatus;

  std::vector<ApplicationCertificate> mApplicationCertificates;
  std::vector<shared_ptr<const X509Certificate>> mTrustedCertificates;
  std::vector<shared_ptr<const X509Certificate>> mIssuerCertificates;
  std::vector<shared_ptr<const X509Certificate>> mRejectedCertificates;
  std::vector<shared_ptr<const X509Crl>> mTrustedCrls;
  std::vector<shared_ptr<const X509Crl>> mIssuerCrls;

  CertificateStoreFilesImpl(std::filesystem::path trustListPath, boost::asio::any_io_executor executor,
    shared_ptr<const Crypto> crypto, TrustListValidationOptions validationOptions,
    bool storeRejectedCertificates, Logger logger = Logger{}, size_t maxRejectedCertificates = 100,
    CertificateUse use = CertificateUse::ApplicationInstance);

  void create_missing_directories();

  void initialise_file_system_monitoring(optional<std::chrono::seconds> refreshPeriod);

  void test_filesystem_for_changes();

  void refresh_cache_internal();

  shared_ptr<const X509Certificate> read_cert(const std::filesystem::path& filepath) const;
  shared_ptr<const X509Crl> read_crl(const std::filesystem::path& filepath) const;
  void report_unreadable_file(const std::filesystem::path& filepath, std::exception_ptr error) const;
  shared_ptr<const AsymmetricKeyPair> read_key(CertificateType type) const;

  void read_certs(auto& list, const std::filesystem::path& folder);
  void read_crls(auto& list, const std::filesystem::path& folder, std::exception_ptr& unreadable);
  void read_application_certs();
  void read_trusted_certs();
  void read_trusted_crls(std::exception_ptr& unreadable);
  void read_issuer_certs();
  void read_issuer_crls(std::exception_ptr& unreadable);
  void read_rejected_certs();

  std::filesystem::path trusted_certs_path() const;
  std::filesystem::path trusted_crls_path() const;
  std::filesystem::path issuer_certs_path() const;
  std::filesystem::path issuer_crls_path() const;
  std::filesystem::path rejected_certs_path() const;
  std::filesystem::path application_certs_path() const;
  std::filesystem::path application_keys_path() const;

  void write_cert(const X509Certificate& certificate, const std::filesystem::path& filepath);
  void write_crl(const X509Crl& crl, const std::filesystem::path& filepath);
  void write_key(CertificateType type, const AsymmetricKeyPair& keyPair);

  void write_file(ByteString content, const std::filesystem::path& filepath);
  ByteString read_file(const std::filesystem::path& filepath) const;

  std::string cert_filename(const X509Certificate& certificate) const;
  /// The file name an earlier release gave @p certificate (each thumbprint byte without zero padding).
  std::string legacy_cert_filename(const X509Certificate& certificate) const;
  /// Removes @p certificate's file from @p directory, under its name or, failing that, under the name an
  /// earlier release gave it when that file holds this certificate. Throws when a file cannot be removed.
  void remove_cert_file(const std::filesystem::path& directory, const X509Certificate& certificate) const;
  std::string crl_filename(const X509Crl& crl) const;
  std::string cert_filename(CertificateType certificateType) const;
  std::string chain_filename(CertificateType certificateType) const;
  std::string key_filename(CertificateType certificateType) const;

  void add_to_application_certificates_internal(
    ApplicationCertificate certificate, CompleteCallback callback);

  void get_application_certificate_internal(
    CertificateType certificateType, GetApplicationCertificateCallback callback) const;

  void get_application_certificates_internal(GetApplicationCertificatesCallback callback) const;

  void add_to_trusted_certificates_internal(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback);

  void get_trusted_certificates_internal(GetCertificatesCallback callback) const;

  void add_to_issuer_certificates_internal(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback);

  void get_issuer_certificates_internal(GetCertificatesCallback callback) const;

  void add_to_rejected_certificates_internal(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback);

  void get_rejected_certificates_internal(GetCertificatesCallback callback) const;

  void add_to_trusted_crls_internal(std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback);

  void get_trusted_crls_internal(GetCrlsCallback callback) const;

  void add_to_issuer_crls_internal(std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback);

  void get_issuer_crls_internal(GetCrlsCallback callback) const;

  void replace_trusted_certificates_internal(
    CertificateList certificates, CrlList crls, CompleteCallback callback);

  void replace_issuer_certificates_internal(
    CertificateList certificates, CrlList crls, CompleteCallback callback);

  void remove_from_trusted_certificates_internal(const std::string& thumbprint, CompleteCallback callback);

  void remove_from_issuer_certificates_internal(const std::string& thumbprint, CompleteCallback callback);

  void set_validation_options_internal(const TrustListValidationOptions& validationOptions);

  template<typename T>
  bool exists(const T& item, const std::vector<shared_ptr<const T>>& collection) const;

  static bool store_to_rejected(Status status, const TrustListValidationOptions& options);
};

}  // namespace ua

#endif  // UA_CERTIFICATE_STORE_FILES_IMPL_H
