// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_TRUST_STORE_H
#define UA_SESSION_TRUST_STORE_H

/// @file
/// @brief A one-certificate trust override that lives only for a single Connection
///        (client design section 7.3A, `TrustDecision::AcceptForThisSession`).
/// @ingroup client

#include "ua_certificate_store.h"

#include <memory>
#include <string>

namespace ua::client::detail
{

/// Decorates a runtime @ref ua::CertificateStore so that ONE additional certificate validates as
/// trusted, without writing anything to the underlying store.
///
/// This is what `TrustDecision::AcceptForThisSession` installs on the resolved
/// @ref ua::client::ConnectionConfig as its `trustStoreOverride`: the user answered "yes, trust this
/// server, just for now", so the certificate must pass validation for this Connection and leave no
/// trace afterwards. Every other operation - issuer lists, CRLs, rejected list, validation options -
/// forwards to the real store unchanged, so the decorated store keeps the full trust material rather
/// than validating against a bare, CRL-less list.
///
/// Matching is by **thumbprint**, so a different certificate presented by the same endpoint (a
/// rotation, or a substitution attempt) is NOT covered by the user's answer and falls through to
/// normal validation.
///
/// @note The accepted certificate is trusted for *validation* only; it is deliberately NOT added to
///       `get_trusted_certificates_async`, because a caller enumerating the trust list should see
///       what is actually persisted, not a per-connection exception.
class SessionTrustStore final : public ua::CertificateStore
{
public:
  SessionTrustStore(const SessionTrustStore&) = delete;
  SessionTrustStore& operator=(const SessionTrustStore&) = delete;
  SessionTrustStore(SessionTrustStore&&) = delete;
  SessionTrustStore& operator=(SessionTrustStore&&) = delete;

  /// @param inner    The runtime store to delegate to; must not be null.
  /// @param accepted The certificate the user accepted for this session; must not be null.
  SessionTrustStore(
    std::shared_ptr<ua::CertificateStore> inner, std::shared_ptr<const ua::X509Certificate> accepted);

  ~SessionTrustStore() override = default;

  /// When the request's certificate is the accepted one (by thumbprint), adds the accepted certificate
  /// to @ref ua::CertificateValidationRequest::trustedForThisConnection and validates through the inner
  /// store: its chain must still reach a self-signed root and every other check (validity, host name,
  /// URI, usage, revocation) still decides; the verdict is the inner store's. Any other request is
  /// delegated unchanged.
  void validate_certificate_async(ua::CertificateValidationRequest request,
    ua::Crypto::CertificateValidationCompleteCallback callback) noexcept override;

  // --- Everything below forwards verbatim to the inner store ---

  void shutdown() override;
  void add_to_application_certificates_async(
    ApplicationCertificate certificate, CompleteCallback callback) noexcept override;
  void get_application_certificate_async(
    ua::CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept override;
  void get_application_certificates_async(
    GetApplicationCertificatesCallback callback) const noexcept override;
  void add_to_trusted_certificates_async(
    shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept override;
  void add_to_trusted_certificates_async(std::vector<shared_ptr<const ua::X509Certificate>> certificates,
    CompleteCallback callback) noexcept override;
  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override;
  void add_to_issuer_certificates_async(
    shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept override;
  void add_to_issuer_certificates_async(std::vector<shared_ptr<const ua::X509Certificate>> certificates,
    CompleteCallback callback) noexcept override;
  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override;
  void add_to_rejected_certificates_async(
    shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept override;
  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override;
  void add_to_trusted_crls_async(
    shared_ptr<const ua::X509Crl> crl, CompleteCallback callback) noexcept override;
  void add_to_trusted_crls_async(
    std::vector<shared_ptr<const ua::X509Crl>> crls, CompleteCallback callback) noexcept override;
  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override;
  void add_to_issuer_crls_async(
    shared_ptr<const ua::X509Crl> crl, CompleteCallback callback) noexcept override;
  void add_to_issuer_crls_async(
    std::vector<shared_ptr<const ua::X509Crl>> crls, CompleteCallback callback) noexcept override;
  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override;
  void replace_trusted_certificates_async(
    ua::CertificateList certificates, ua::CrlList crls, CompleteCallback callback) noexcept override;
  void replace_issuer_certificates_async(
    ua::CertificateList certificates, ua::CrlList crls, CompleteCallback callback) noexcept override;
  void remove_from_trusted_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override;
  void remove_from_issuer_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override;
  void set_validation_options(ua::TrustListValidationOptions validationOptions) override;
  ua::TrustListValidationOptions validation_options() const override;
  void refresh_cache(CompleteCallback callback) override;

private:
  std::shared_ptr<ua::CertificateStore> mInner;
  std::shared_ptr<const ua::X509Certificate> mAccepted;
  std::string mAcceptedThumbprint;
};

}  // namespace ua::client::detail

#endif  // !UA_SESSION_TRUST_STORE_H
