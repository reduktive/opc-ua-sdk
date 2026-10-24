// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// One-certificate, single-Connection trust override (client design section 7.3A,
// TrustDecision::AcceptForThisSession).

#include "ua_session_trust_store.h"

#include "ua_error_detail.h"
#include "ua_x509_certificate.h"

#include <string>
#include <utility>

namespace ua::client::detail
{
namespace
{
constexpr std::string_view source = "client.tier1.easy_connect.session_trust";

/// Hex-encodes a thumbprint so two certificates can be compared as strings.
std::string to_hex(const ua::ByteString& bytes)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto byte : bytes)
  {
    const auto value = static_cast<unsigned char>(byte);
    out.push_back(digits[value >> 4]);
    out.push_back(digits[value & 0x0F]);
  }
  return out;
}

std::string thumbprint_of(const std::shared_ptr<const ua::X509Certificate>& certificate)
{
  if (!certificate)
  {
    return {};
  }
  try
  {
    return to_hex(certificate->thumbprint());
  }
  catch (...)
  {
    return {};
  }
}
}  // namespace

SessionTrustStore::SessionTrustStore(
  std::shared_ptr<ua::CertificateStore> inner, std::shared_ptr<const ua::X509Certificate> accepted)
  : mInner(std::move(inner)), mAccepted(std::move(accepted)), mAcceptedThumbprint(thumbprint_of(mAccepted))
{}

void SessionTrustStore::validate_certificate_async(ua::CertificateValidationRequest request,
  ua::Crypto::CertificateValidationCompleteCallback callback) noexcept
{
  if (!mInner)
  {
    if (callback)
    {
      callback(ua::VoidResult{ua::Status::BadInvalidState,
        ua::make_error_detail("SessionTrustStoreNoInner",
          "the session trust override has no underlying certificate store",
          std::string{source})});
    }
    return;
  }

  // The user's answer covers exactly the certificate they were shown. A different certificate from
  // the same endpoint - a rotation, or a substitution attempt - is NOT covered and goes to the real
  // store unchanged. The answer is a TRUST decision only (CL-SECADMIN-003, owner decision 22.5): the
  // accepted certificate is carried in the request as trusted for this connection, and the real store
  // validates it - chain building, expiry, revocation, host name, application URI and usage still run
  // and still fail; the verdict is the inner store's, verbatim.
  if (!mAcceptedThumbprint.empty() && thumbprint_of(request.certificate) == mAcceptedThumbprint)
  {
    request.trustedForThisConnection.push_back(mAccepted);
  }
  mInner->validate_certificate_async(std::move(request), std::move(callback));
}

// --- Forwarding ---------------------------------------------------------------------------------
// Everything else delegates unchanged, so the decorated store keeps the real trust material (issuer
// chain, CRLs, validation options) rather than validating against a bare list.

void SessionTrustStore::shutdown()
{
  if (mInner)
  {
    mInner->shutdown();
  }
}

void SessionTrustStore::add_to_application_certificates_async(
  ApplicationCertificate certificate, CompleteCallback callback) noexcept
{
  mInner->add_to_application_certificates_async(std::move(certificate), std::move(callback));
}

void SessionTrustStore::get_application_certificate_async(
  ua::CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept
{
  mInner->get_application_certificate_async(certificateType, std::move(callback));
}

void SessionTrustStore::get_application_certificates_async(
  GetApplicationCertificatesCallback callback) const noexcept
{
  mInner->get_application_certificates_async(std::move(callback));
}

void SessionTrustStore::add_to_trusted_certificates_async(
  shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept
{
  mInner->add_to_trusted_certificates_async(std::move(certificate), std::move(callback));
}

void SessionTrustStore::add_to_trusted_certificates_async(
  std::vector<shared_ptr<const ua::X509Certificate>> certificates, CompleteCallback callback) noexcept
{
  mInner->add_to_trusted_certificates_async(std::move(certificates), std::move(callback));
}

void SessionTrustStore::get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept
{
  mInner->get_trusted_certificates_async(std::move(callback));
}

void SessionTrustStore::add_to_issuer_certificates_async(
  shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept
{
  mInner->add_to_issuer_certificates_async(std::move(certificate), std::move(callback));
}

void SessionTrustStore::add_to_issuer_certificates_async(
  std::vector<shared_ptr<const ua::X509Certificate>> certificates, CompleteCallback callback) noexcept
{
  mInner->add_to_issuer_certificates_async(std::move(certificates), std::move(callback));
}

void SessionTrustStore::get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept
{
  mInner->get_issuer_certificates_async(std::move(callback));
}

void SessionTrustStore::add_to_rejected_certificates_async(
  shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept
{
  mInner->add_to_rejected_certificates_async(std::move(certificate), std::move(callback));
}

void SessionTrustStore::get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept
{
  mInner->get_rejected_certificates_async(std::move(callback));
}

void SessionTrustStore::add_to_trusted_crls_async(
  shared_ptr<const ua::X509Crl> crl, CompleteCallback callback) noexcept
{
  mInner->add_to_trusted_crls_async(std::move(crl), std::move(callback));
}

void SessionTrustStore::add_to_trusted_crls_async(
  std::vector<shared_ptr<const ua::X509Crl>> crls, CompleteCallback callback) noexcept
{
  mInner->add_to_trusted_crls_async(std::move(crls), std::move(callback));
}

void SessionTrustStore::get_trusted_crls_async(GetCrlsCallback callback) const noexcept
{
  mInner->get_trusted_crls_async(std::move(callback));
}

void SessionTrustStore::add_to_issuer_crls_async(
  shared_ptr<const ua::X509Crl> crl, CompleteCallback callback) noexcept
{
  mInner->add_to_issuer_crls_async(std::move(crl), std::move(callback));
}

void SessionTrustStore::add_to_issuer_crls_async(
  std::vector<shared_ptr<const ua::X509Crl>> crls, CompleteCallback callback) noexcept
{
  mInner->add_to_issuer_crls_async(std::move(crls), std::move(callback));
}

void SessionTrustStore::get_issuer_crls_async(GetCrlsCallback callback) const noexcept
{
  mInner->get_issuer_crls_async(std::move(callback));
}

void SessionTrustStore::replace_trusted_certificates_async(
  ua::CertificateList certificates, ua::CrlList crls, CompleteCallback callback) noexcept
{
  mInner->replace_trusted_certificates_async(std::move(certificates), std::move(crls), std::move(callback));
}

void SessionTrustStore::replace_issuer_certificates_async(
  ua::CertificateList certificates, ua::CrlList crls, CompleteCallback callback) noexcept
{
  mInner->replace_issuer_certificates_async(std::move(certificates), std::move(crls), std::move(callback));
}

void SessionTrustStore::remove_from_trusted_certificates_async(
  const std::string& thumbprint, CompleteCallback callback) noexcept
{
  mInner->remove_from_trusted_certificates_async(thumbprint, std::move(callback));
}

void SessionTrustStore::remove_from_issuer_certificates_async(
  const std::string& thumbprint, CompleteCallback callback) noexcept
{
  mInner->remove_from_issuer_certificates_async(thumbprint, std::move(callback));
}

void SessionTrustStore::set_validation_options(ua::TrustListValidationOptions validationOptions)
{
  mInner->set_validation_options(std::move(validationOptions));
}

ua::TrustListValidationOptions SessionTrustStore::validation_options() const
{
  return mInner->validation_options();
}

void SessionTrustStore::refresh_cache(CompleteCallback callback)
{
  mInner->refresh_cache(std::move(callback));
}

}  // namespace ua::client::detail
