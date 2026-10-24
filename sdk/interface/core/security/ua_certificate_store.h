// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Asynchronous PKI certificate and CRL store for the security stack.
/// @ingroup security

#ifndef UA_CERTIFICATE_STORE_H
#define UA_CERTIFICATE_STORE_H

#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"
#include "ua_crypto.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_trust_list_validation_options.h"
#include "ua_result.h"

namespace ua
{

class SecurityPolicy;

/// An ordered list of immutable X.509 certificates.
using CertificateList = std::vector<shared_ptr<const X509Certificate>>;

/// The outcome of an operation yielding a @ref CertificateList, or an @ref ErrorDetail on failure.
using CertificateListResult = Result<CertificateList>;

/// An ordered list of immutable certificate revocation lists.
using CrlList = std::vector<shared_ptr<const X509Crl>>;

/// The outcome of an operation yielding a @ref CrlList, or an @ref ErrorDetail on failure.
using CrlListResult = Result<CrlList>;

/// What one certificate validation is asked to establish (OPC 10000-4 section 6.1.3 Table 106): the
/// certificate, the chain its holder presented, the use and security policy it is validated for and
/// the identity it must carry.
///
/// Every path that validates a certificate builds one request and hands it to
/// @ref CertificateStore::validate_certificate_async; the store supplies the trust material
/// (@ref CertificateValidationMaterial) and the validator applies the steps. A member left empty is
/// filled by the store or skipped, as each member states.
/// @ingroup security
struct CertificateValidationRequest
{
  /// The certificate to validate (the leaf of a presented chain). Must be non-null.
  shared_ptr<const X509Certificate> certificate;

  /// The issuer certificates presented with @ref certificate, in the order received (leaf excluded).
  /// They complete the chain only and never confer trust; a refusal never records them as rejected.
  std::vector<shared_ptr<const X509Certificate>> presentedIssuers;

  /// The use requested for the certificate (Table 106, Certificate Usage). When empty, the store's
  /// own @ref CertificateUse applies (the use the store was created for).
  optional<CertificateUse> use;

  /// The security policy the certificate and its chain must comply with (Table 106, Security Policy
  /// Check): key type and length, and signature algorithms, for the leaf and every issuer. Empty means
  /// no policy check, for a path with no policy to check against (for example a discovery lookup).
  /// An ID that names no policy fails the check with Bad_CertificatePolicyCheckFailed.
  optional<SecurityPolicyId> policyId;

  /// The application URI the certificate's subjectAltName must carry, when set.
  optional<std::string> applicationUri;

  /// The endpoint URL whose host name the certificate must carry, when set (the client side of a
  /// connection).
  optional<std::string> endpointUrl;

  /// Options for this validation. When empty, the store's options apply
  /// (@ref CertificateStore::validation_options).
  optional<TrustListValidationOptions> options;

  /// Certificates the application accepted for this connection only (client trust prompt,
  /// CL-SECADMIN-003 `AcceptForThisSession`). Each satisfies the Trust List Check like an entry of the
  /// trusted list; every other step still applies, and the chain must still reach a self-signed root.
  /// Never used on the server side.
  std::vector<shared_ptr<const X509Certificate>> trustedForThisConnection;
};

/// Asynchronous PKI store of trusted, issuer, rejected and application certificates plus their CRLs.
///
/// Holds the four OPC UA trust-list groups (trusted, issuer, rejected) together with the
/// application's own certificate/key pairs, and validates peer certificates against them. All
/// mutating and querying operations are exposed as a `*_async` / `*_sync` / `try_*_sync` trio: the
/// `*_async` overloads are the canonical, never-throwing surface that deliver a @ref Result to a
/// callback; the `*_sync` and `try_*_sync` wrappers block until the async operation completes.
///
/// Implementations serialize access internally, so callers may invoke any method from any thread.
/// Callbacks run on an unspecified worker thread and must not block. Certificates and CRLs are held
/// by `shared_ptr<const>`; ownership is shared and the stored objects are immutable.
/// @note Instances are managed by `shared_ptr` (`enable_shared_from_this`); construct accordingly.
/// @ingroup security
class CertificateStore : public std::enable_shared_from_this<CertificateStore>
{
public:
  /// The executor this store's operations complete on, which a `*_sync` call must not wait on from one
  /// of its threads (it refuses with Bad_WouldBlock instead). Empty for a store that completes on the
  /// calling thread; a store that completes elsewhere overrides it.
  /// @return The executor used for this store's asynchronous completions.
  [[nodiscard]] virtual boost::asio::any_io_executor executor() const noexcept
  {
    return {};
  }

  /// Callback receiving the outcome of a mutating operation; carries an @ref ErrorDetail on failure.
  using CompleteCallback = std::function<void(VoidResult)>;

  /// Callback receiving a @ref CertificateList, or an @ref ErrorDetail on failure.
  using GetCertificatesCallback = std::function<void(CertificateListResult)>;

  /// Callback receiving a @ref CrlList, or an @ref ErrorDetail on failure.
  using GetCrlsCallback = std::function<void(CrlListResult)>;

  /// An application instance certificate together with its private key and certificate type.
  struct ApplicationCertificate
  {
    CertificateType certificateType{CertificateType::Invalid};  ///< Cryptographic profile of the certificate.
    shared_ptr<const X509Certificate> certificate;  ///< The application instance certificate.
    shared_ptr<const AsymmetricKeyPair> keys;  ///< The matching public/private key pair.
    /// The issuer chain of @ref certificate, leaf excluded, in order (the certificate that signed
    /// the leaf first). Sent after the leaf in every outgoing certificate field (OPC 10000-6 section
    /// 6.2.6: a partial or complete chain may accompany a Certificate), so a peer that lacks the
    /// intermediates can still build the chain. Empty for a self-signed certificate.
    std::vector<shared_ptr<const X509Certificate>> issuerCertificates;
  };

  /// A single @ref ApplicationCertificate, or an @ref ErrorDetail on failure.
  using ApplicationCertificateResult = Result<ApplicationCertificate>;

  /// A list of the store's @ref ApplicationCertificate entries.
  using ApplicationCertificateList = std::vector<ApplicationCertificate>;

  /// An @ref ApplicationCertificateList, or an @ref ErrorDetail on failure.
  using ApplicationCertificateListResult = Result<ApplicationCertificateList>;

  /// Callback receiving a single @ref ApplicationCertificate, or an @ref ErrorDetail on failure.
  using GetApplicationCertificateCallback = std::function<void(ApplicationCertificateResult)>;

  /// Callback receiving an @ref ApplicationCertificateList, or an @ref ErrorDetail on failure.
  using GetApplicationCertificatesCallback = std::function<void(ApplicationCertificateListResult)>;

  virtual ~CertificateStore() = default;

  CertificateStore(const CertificateStore&) = delete;
  CertificateStore& operator=(const CertificateStore&) = delete;
  CertificateStore(CertificateStore&&) = delete;
  CertificateStore& operator=(CertificateStore&&) = delete;

  /// Gracefully shuts down the store, cancelling any background work such as refresh timers.
  ///
  /// The default implementation is a no-op. Subclasses that own background work (timers, file
  /// watchers) must override this to release it before destruction.
  virtual void shutdown()
  {}

  /// Adds an application instance certificate and its key pair to the store.
  ///
  /// @param certificate The certificate, key pair and type to store; consumed by value.
  /// @param callback     Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_application_certificates_sync, add_to_application_certificates_sync
  virtual void add_to_application_certificates_async(
    ApplicationCertificate certificate, CompleteCallback callback) noexcept = 0;

  /// Retrieves the application certificate matching the given certificate type.
  ///
  /// @param certificateType Cryptographic profile to look up.
  /// @param callback         Receives the matching @ref ApplicationCertificate, or an
  ///                         @ref ErrorDetail if none is found. Never throws.
  /// @see try_get_application_certificate_sync, get_application_certificate_sync
  virtual void get_application_certificate_async(
    CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept = 0;

  /// Retrieves all application certificates held by the store.
  ///
  /// @param callback Receives the @ref ApplicationCertificateList, or an @ref ErrorDetail on
  ///                 failure. Never throws.
  /// @see try_get_application_certificates_sync, get_application_certificates_sync
  virtual void get_application_certificates_async(
    GetApplicationCertificatesCallback callback) const noexcept = 0;

  /// Adds a certificate to the trusted list.
  ///
  /// @param certificate Certificate to trust; must be non-null.
  /// @param callback     Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_trusted_certificates_sync, add_to_trusted_certificates_sync
  virtual void add_to_trusted_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept = 0;

  /// Adds several certificates to the trusted list in one operation.
  ///
  /// @param certificates Certificates to trust; consumed by value.
  /// @param callback      Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_trusted_certificates_sync, add_to_trusted_certificates_sync
  virtual void add_to_trusted_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept = 0;

  /// Retrieves the current trusted certificate list.
  ///
  /// @param callback Receives the @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_trusted_certificates_sync, get_trusted_certificates_sync
  virtual void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept = 0;

  /// Adds a certificate to the issuer (intermediate CA) list.
  ///
  /// Issuer certificates are used to build chains during validation but are not themselves a basis
  /// for trust.
  ///
  /// @param certificate Issuer certificate to store; must be non-null.
  /// @param callback     Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_issuer_certificates_sync, add_to_issuer_certificates_sync
  virtual void add_to_issuer_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept = 0;

  /// Adds several certificates to the issuer (intermediate CA) list in one operation.
  ///
  /// @param certificates Issuer certificates to store; consumed by value.
  /// @param callback      Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_issuer_certificates_sync, add_to_issuer_certificates_sync
  virtual void add_to_issuer_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept = 0;

  /// Retrieves the current issuer certificate list.
  ///
  /// @param callback Receives the @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_issuer_certificates_sync, get_issuer_certificates_sync
  virtual void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept = 0;

  /// Records a certificate that failed validation in the rejected list.
  ///
  /// @param certificate Certificate to record as rejected; must be non-null.
  /// @param callback     Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_rejected_certificates_sync, add_to_rejected_certificates_sync
  virtual void add_to_rejected_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept = 0;

  /// Retrieves the current rejected certificate list.
  ///
  /// @param callback Receives the @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_rejected_certificates_sync, get_rejected_certificates_sync
  virtual void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept = 0;

  /// Adds a CRL to the trusted CRL set.
  ///
  /// @param crl      Revocation list to store; must be non-null.
  /// @param callback Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_trusted_crls_sync, add_to_trusted_crls_sync
  virtual void add_to_trusted_crls_async(
    shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept = 0;

  /// Adds several CRLs to the trusted CRL set in one operation.
  ///
  /// @param crls     Revocation lists to store; consumed by value.
  /// @param callback Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_trusted_crls_sync, add_to_trusted_crls_sync
  virtual void add_to_trusted_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept = 0;

  /// Retrieves the current trusted CRL set.
  ///
  /// @param callback Receives the @ref CrlList, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_trusted_crls_sync, get_trusted_crls_sync
  virtual void get_trusted_crls_async(GetCrlsCallback callback) const noexcept = 0;

  /// Adds a CRL to the issuer CRL set.
  ///
  /// @param crl      Revocation list to store; must be non-null.
  /// @param callback Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_issuer_crls_sync, add_to_issuer_crls_sync
  virtual void add_to_issuer_crls_async(
    shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept = 0;

  /// Adds several CRLs to the issuer CRL set in one operation.
  ///
  /// @param crls     Revocation lists to store; consumed by value.
  /// @param callback Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_to_issuer_crls_sync, add_to_issuer_crls_sync
  virtual void add_to_issuer_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept = 0;

  /// Retrieves the current issuer CRL set.
  ///
  /// @param callback Receives the @ref CrlList, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_issuer_crls_sync, get_issuer_crls_sync
  virtual void get_issuer_crls_async(GetCrlsCallback callback) const noexcept = 0;

  /// Atomically replaces the entire trusted certificate and CRL set.
  ///
  /// Backs `TrustListType::CloseAndUpdate` when the TrustedCertificates and TrustedCrls masks are
  /// set: both lists are swapped together so no validation ever observes a partial update.
  ///
  /// @param certificates Replacement trusted certificate list; consumed by value.
  /// @param crls          Replacement trusted CRL set; consumed by value.
  /// @param callback      Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_replace_trusted_certificates_sync, replace_trusted_certificates_sync
  virtual void replace_trusted_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept = 0;

  /// Atomically replaces the entire issuer certificate and CRL set.
  ///
  /// Backs `TrustListType::CloseAndUpdate` when the IssuerCertificates and IssuerCrls masks are
  /// set: both lists are swapped together so no validation ever observes a partial update.
  ///
  /// @param certificates Replacement issuer certificate list; consumed by value.
  /// @param crls          Replacement issuer CRL set; consumed by value.
  /// @param callback      Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_replace_issuer_certificates_sync, replace_issuer_certificates_sync
  virtual void replace_issuer_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept = 0;

  /// Removes a single certificate from the trusted list by its SHA-1 thumbprint.
  ///
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @param callback    Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_from_trusted_certificates_sync, remove_from_trusted_certificates_sync
  virtual void remove_from_trusted_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept = 0;

  /// Removes a single certificate from the issuer list by its SHA-1 thumbprint.
  ///
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @param callback    Receives the outcome; carries an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_from_issuer_certificates_sync, remove_from_issuer_certificates_sync
  virtual void remove_from_issuer_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept = 0;

  /// Sets the default validation options applied by @ref validate_certificate_async.
  ///
  /// The options take effect for validations whose request does not carry its own
  /// (@ref CertificateValidationRequest::options).
  ///
  /// @param validationOptions Trust-list validation policy to use as the store default.
  virtual void set_validation_options(TrustListValidationOptions validationOptions) = 0;

  /// Returns the default validation options: the last ones set with @ref set_validation_options,
  /// or those the store was created with. Safe to call from any thread.
  ///
  /// A component that validates certificates for this store's certificate group outside
  /// @ref validate_certificate_async (the TrustList methods validate the list being installed)
  /// reads the options here when each validation starts, so it follows a later change.
  ///
  /// @return The store's current default validation options.
  virtual TrustListValidationOptions validation_options() const = 0;

  /// Refreshes any cached view of the trust lists from the underlying backing store.
  ///
  /// @param callback Receives the outcome; carries an @ref ErrorDetail on failure.
  virtual void refresh_cache(CompleteCallback callback) = 0;

  /// Validates the certificate of @p request: the store's single validation entry point.
  ///
  /// The store fills what the request leaves open - its trusted and issuer lists and their CRLs, its
  /// validation options (@ref set_validation_options) when @ref CertificateValidationRequest::options
  /// is empty, and the @ref CertificateUse it was created for when
  /// @ref CertificateValidationRequest::use is empty - and calls @ref Crypto::validate_certificate_async
  /// once; the verdict is the validator's, unchanged. The store checks nothing itself. The
  /// certificates of @ref CertificateValidationRequest::trustedForThisConnection count as trusted for
  /// this call only; @ref CertificateValidationRequest::presentedIssuers complete the chain and never
  /// confer trust.
  ///
  /// A refused certificate the administrator could choose to trust (untrusted, issuer unknown,
  /// application URI mismatch) is recorded in the rejected list, when the store records rejections;
  /// only the leaf is recorded, never a presented issuer, and an expired, revoked or
  /// policy-violating certificate is not recorded.
  ///
  /// @param request  The certificate to validate (must be non-null) and how to validate it.
  /// @param callback Receives the outcome on an unspecified worker thread; carries an @ref ErrorDetail
  ///                 with the rejection reason on failure. Never throws.
  /// @see try_validate_certificate_sync, validate_certificate_sync
  virtual void validate_certificate_async(CertificateValidationRequest request,
    Crypto::CertificateValidationCompleteCallback callback) noexcept = 0;

  /// Adds an application instance certificate, blocking until complete.
  /// @param certificate Certificate, key pair and type to store; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_application_certificates_async, add_to_application_certificates_sync
  VoidResult try_add_to_application_certificates_sync(ApplicationCertificate certificate) noexcept;

  /// Adds an application instance certificate, blocking until complete.
  /// @param certificate Certificate, key pair and type to store; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see add_to_application_certificates_async, try_add_to_application_certificates_sync
  void add_to_application_certificates_sync(ApplicationCertificate certificate);

  /// Retrieves the application certificate of the given type, blocking until complete.
  /// @param certificateType Cryptographic profile to look up.
  /// @return The matching @ref ApplicationCertificate, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_application_certificate_async, get_application_certificate_sync
  ApplicationCertificateResult try_get_application_certificate_sync(
    CertificateType certificateType) const noexcept;

  /// Retrieves the application certificate of the given type, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_application_certificate_sync() returns it.
  /// @param certificateType Cryptographic profile to look up.
  /// @return The matching @ref ApplicationCertificate.
  /// @throws UaException if no matching certificate is found, or when the answer is not Good (an Uncertain
  /// one included).
  /// @see get_application_certificate_async, try_get_application_certificate_sync
  ApplicationCertificate get_application_certificate_sync(CertificateType certificateType) const;

  /// Retrieves all application certificates, blocking until complete.
  /// @return The @ref ApplicationCertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_application_certificates_async, get_application_certificates_sync
  ApplicationCertificateListResult try_get_application_certificates_sync() const noexcept;

  /// Retrieves all application certificates, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_application_certificates_sync() returns it.
  /// @return The @ref ApplicationCertificateList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_application_certificates_async, try_get_application_certificates_sync
  ApplicationCertificateList get_application_certificates_sync() const;

  /// Adds a certificate to the trusted list, blocking until complete.
  /// @param certificate Certificate to trust; must be non-null.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_trusted_certificates_async, add_to_trusted_certificates_sync
  VoidResult try_add_to_trusted_certificates_sync(shared_ptr<const X509Certificate> certificate) noexcept;

  /// Adds a certificate to the trusted list, blocking until complete.
  /// @param certificate Certificate to trust; must be non-null.
  /// @throws UaException if the operation fails.
  /// @see add_to_trusted_certificates_async, try_add_to_trusted_certificates_sync
  void add_to_trusted_certificates_sync(shared_ptr<const X509Certificate> certificate);

  /// Adds several certificates to the trusted list, blocking until complete.
  /// @param certificates Certificates to trust; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_trusted_certificates_async, add_to_trusted_certificates_sync
  VoidResult try_add_to_trusted_certificates_sync(
    std::vector<shared_ptr<const X509Certificate>> certificates) noexcept;

  /// Adds several certificates to the trusted list, blocking until complete.
  /// @param certificates Certificates to trust; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see add_to_trusted_certificates_async, try_add_to_trusted_certificates_sync
  void add_to_trusted_certificates_sync(std::vector<shared_ptr<const X509Certificate>> certificates);

  /// Retrieves the trusted certificate list, blocking until complete.
  /// @return The @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_trusted_certificates_async, get_trusted_certificates_sync
  CertificateListResult try_get_trusted_certificates_sync() const noexcept;

  /// Retrieves the trusted certificate list, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_trusted_certificates_sync() returns it.
  /// @return The @ref CertificateList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_trusted_certificates_async, try_get_trusted_certificates_sync
  CertificateList get_trusted_certificates_sync() const;

  /// Adds a certificate to the issuer list, blocking until complete.
  /// @param certificate Issuer certificate to store; must be non-null.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_issuer_certificates_async, add_to_issuer_certificates_sync
  VoidResult try_add_to_issuer_certificates_sync(shared_ptr<const X509Certificate> certificate) noexcept;

  /// Adds a certificate to the issuer list, blocking until complete.
  /// @param certificate Issuer certificate to store; must be non-null.
  /// @throws UaException if the operation fails.
  /// @see add_to_issuer_certificates_async, try_add_to_issuer_certificates_sync
  void add_to_issuer_certificates_sync(shared_ptr<const X509Certificate> certificate);

  /// Adds several certificates to the issuer list, blocking until complete.
  /// @param certificates Issuer certificates to store; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_issuer_certificates_async, add_to_issuer_certificates_sync
  VoidResult try_add_to_issuer_certificates_sync(
    std::vector<shared_ptr<const X509Certificate>> certificates) noexcept;

  /// Adds several certificates to the issuer list, blocking until complete.
  /// @param certificates Issuer certificates to store; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see add_to_issuer_certificates_async, try_add_to_issuer_certificates_sync
  void add_to_issuer_certificates_sync(std::vector<shared_ptr<const X509Certificate>> certificates);

  /// Retrieves the issuer certificate list, blocking until complete.
  /// @return The @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_issuer_certificates_async, get_issuer_certificates_sync
  CertificateListResult try_get_issuer_certificates_sync() const noexcept;

  /// Retrieves the issuer certificate list, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_issuer_certificates_sync() returns it.
  /// @return The @ref CertificateList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_issuer_certificates_async, try_get_issuer_certificates_sync
  CertificateList get_issuer_certificates_sync() const;

  /// Records a rejected certificate, blocking until complete.
  /// @param certificate Certificate to record as rejected; must be non-null.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_rejected_certificates_async, add_to_rejected_certificates_sync
  VoidResult try_add_to_rejected_certificates_sync(shared_ptr<const X509Certificate> certificate) noexcept;

  /// Records a rejected certificate, blocking until complete.
  /// @param certificate Certificate to record as rejected; must be non-null.
  /// @throws UaException if the operation fails.
  /// @see add_to_rejected_certificates_async, try_add_to_rejected_certificates_sync
  void add_to_rejected_certificates_sync(shared_ptr<const X509Certificate> certificate);

  /// Retrieves the rejected certificate list, blocking until complete.
  /// @return The @ref CertificateList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_rejected_certificates_async, get_rejected_certificates_sync
  CertificateListResult try_get_rejected_certificates_sync() const noexcept;

  /// Retrieves the rejected certificate list, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_rejected_certificates_sync() returns it.
  /// @return The @ref CertificateList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_rejected_certificates_async, try_get_rejected_certificates_sync
  CertificateList get_rejected_certificates_sync() const;

  /// Adds a CRL to the trusted CRL set, blocking until complete.
  /// @param crl Revocation list to store; must be non-null.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_trusted_crls_async, add_to_trusted_crls_sync
  VoidResult try_add_to_trusted_crls_sync(shared_ptr<const X509Crl> crl) noexcept;

  /// Adds a CRL to the trusted CRL set, blocking until complete.
  /// @param crl Revocation list to store; must be non-null.
  /// @throws UaException if the operation fails.
  /// @see add_to_trusted_crls_async, try_add_to_trusted_crls_sync
  void add_to_trusted_crls_sync(shared_ptr<const X509Crl> crl);

  /// Adds several CRLs to the trusted CRL set, blocking until complete.
  /// @param crls Revocation lists to store; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_trusted_crls_async, add_to_trusted_crls_sync
  VoidResult try_add_to_trusted_crls_sync(std::vector<shared_ptr<const X509Crl>> crls) noexcept;

  /// Adds several CRLs to the trusted CRL set, blocking until complete.
  /// @param crls Revocation lists to store; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see add_to_trusted_crls_async, try_add_to_trusted_crls_sync
  void add_to_trusted_crls_sync(std::vector<shared_ptr<const X509Crl>> crls);

  /// Retrieves the trusted CRL set, blocking until complete.
  /// @return The @ref CrlList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_trusted_crls_async, get_trusted_crls_sync
  CrlListResult try_get_trusted_crls_sync() const noexcept;

  /// Retrieves the trusted CRL set, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_trusted_crls_sync() returns it.
  /// @return The @ref CrlList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_trusted_crls_async, try_get_trusted_crls_sync
  CrlList get_trusted_crls_sync() const;

  /// Adds a CRL to the issuer CRL set, blocking until complete.
  /// @param crl Revocation list to store; must be non-null.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_issuer_crls_async, add_to_issuer_crls_sync
  VoidResult try_add_to_issuer_crls_sync(shared_ptr<const X509Crl> crl) noexcept;

  /// Adds a CRL to the issuer CRL set, blocking until complete.
  /// @param crl Revocation list to store; must be non-null.
  /// @throws UaException if the operation fails.
  /// @see add_to_issuer_crls_async, try_add_to_issuer_crls_sync
  void add_to_issuer_crls_sync(shared_ptr<const X509Crl> crl);

  /// Adds several CRLs to the issuer CRL set, blocking until complete.
  /// @param crls Revocation lists to store; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see add_to_issuer_crls_async, add_to_issuer_crls_sync
  VoidResult try_add_to_issuer_crls_sync(std::vector<shared_ptr<const X509Crl>> crls) noexcept;

  /// Adds several CRLs to the issuer CRL set, blocking until complete.
  /// @param crls Revocation lists to store; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see add_to_issuer_crls_async, try_add_to_issuer_crls_sync
  void add_to_issuer_crls_sync(std::vector<shared_ptr<const X509Crl>> crls);

  /// Retrieves the issuer CRL set, blocking until complete.
  /// @return The @ref CrlList, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_issuer_crls_async, get_issuer_crls_sync
  CrlListResult try_get_issuer_crls_sync() const noexcept;

  /// Retrieves the issuer CRL set, blocking until complete.
  /// A Good subcode on the answer is not returned; try_get_issuer_crls_sync() returns it.
  /// @return The @ref CrlList.
  /// @throws UaException if the operation fails, or when the answer is not Good (an Uncertain one included).
  /// @see get_issuer_crls_async, try_get_issuer_crls_sync
  CrlList get_issuer_crls_sync() const;

  /// Atomically replaces the trusted certificate and CRL set, blocking until complete.
  /// @param certificates Replacement trusted certificate list; consumed by value.
  /// @param crls          Replacement trusted CRL set; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see replace_trusted_certificates_async, replace_trusted_certificates_sync
  VoidResult try_replace_trusted_certificates_sync(CertificateList certificates, CrlList crls) noexcept;

  /// Atomically replaces the trusted certificate and CRL set, blocking until complete.
  /// @param certificates Replacement trusted certificate list; consumed by value.
  /// @param crls          Replacement trusted CRL set; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see replace_trusted_certificates_async, try_replace_trusted_certificates_sync
  void replace_trusted_certificates_sync(CertificateList certificates, CrlList crls);

  /// Atomically replaces the issuer certificate and CRL set, blocking until complete.
  /// @param certificates Replacement issuer certificate list; consumed by value.
  /// @param crls          Replacement issuer CRL set; consumed by value.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see replace_issuer_certificates_async, replace_issuer_certificates_sync
  VoidResult try_replace_issuer_certificates_sync(CertificateList certificates, CrlList crls) noexcept;

  /// Atomically replaces the issuer certificate and CRL set, blocking until complete.
  /// @param certificates Replacement issuer certificate list; consumed by value.
  /// @param crls          Replacement issuer CRL set; consumed by value.
  /// @throws UaException if the operation fails.
  /// @see replace_issuer_certificates_async, try_replace_issuer_certificates_sync
  void replace_issuer_certificates_sync(CertificateList certificates, CrlList crls);

  /// Removes a trusted certificate by SHA-1 thumbprint, blocking until complete.
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_from_trusted_certificates_async, remove_from_trusted_certificates_sync
  VoidResult try_remove_from_trusted_certificates_sync(const std::string& thumbprint) noexcept;

  /// Removes a trusted certificate by SHA-1 thumbprint, blocking until complete.
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @throws UaException if the operation fails.
  /// @see remove_from_trusted_certificates_async, try_remove_from_trusted_certificates_sync
  void remove_from_trusted_certificates_sync(const std::string& thumbprint);

  /// Removes an issuer certificate by SHA-1 thumbprint, blocking until complete.
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @return A @ref VoidResult that carries an @ref ErrorDetail on failure. Never throws.
  /// @see remove_from_issuer_certificates_async, remove_from_issuer_certificates_sync
  VoidResult try_remove_from_issuer_certificates_sync(const std::string& thumbprint) noexcept;

  /// Removes an issuer certificate by SHA-1 thumbprint, blocking until complete.
  /// @param thumbprint Hex-encoded SHA-1 thumbprint of the certificate to remove.
  /// @throws UaException if the operation fails.
  /// @see remove_from_issuer_certificates_async, try_remove_from_issuer_certificates_sync
  void remove_from_issuer_certificates_sync(const std::string& thumbprint);

  /// Validates the certificate of @p request as @ref validate_certificate_async does, blocking until
  /// complete.
  /// @param request The certificate to validate (must be non-null) and how to validate it.
  /// @return A @ref VoidResult that carries the rejection reason as an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see validate_certificate_async, validate_certificate_sync
  VoidResult try_validate_certificate_sync(CertificateValidationRequest request) noexcept;

  /// Validates the certificate of @p request as @ref validate_certificate_async does, blocking until
  /// complete.
  /// @param request The certificate to validate (must be non-null) and how to validate it.
  /// @throws UaException if validation fails, carrying the rejection reason.
  /// @see validate_certificate_async, try_validate_certificate_sync
  void validate_certificate_sync(CertificateValidationRequest request);

protected:
  /// Default-constructs the base; only subclasses construct a @ref CertificateStore.
  CertificateStore() = default;
};

}  // namespace ua

#endif  //! UA_CERTIFICATE_STORE_H
