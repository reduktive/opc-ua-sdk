// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_certificate_store.h"

#include "ua_result.h"
#include "ua_to_result.h"

#include <mutex>
#include <future>

namespace ua
{

VoidResult CertificateStore::try_add_to_application_certificates_sync(
  ApplicationCertificate certificate) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_application_certificates_async(certificate, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_application_certificates_sync(ApplicationCertificate certificate)
{
  try_add_to_application_certificates_sync(std::move(certificate)).value();
}

CertificateStore::ApplicationCertificateResult CertificateStore::try_get_application_certificate_sync(
  CertificateType certificateType) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ApplicationCertificateResult>(executor(),
      [&](std::function<void(ApplicationCertificateResult)> complete)
      {
        get_application_certificate_async(certificateType,

          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CertificateStore::ApplicationCertificate CertificateStore::get_application_certificate_sync(
  CertificateType certificateType) const
{
  return ua::detail::good_value(try_get_application_certificate_sync(certificateType));
}

CertificateStore::ApplicationCertificateListResult
  CertificateStore::try_get_application_certificates_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ApplicationCertificateListResult>(executor(),
      [&](std::function<void(ApplicationCertificateListResult)> complete)
      { get_application_certificates_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CertificateStore::ApplicationCertificateList CertificateStore::get_application_certificates_sync() const
{
  return ua::detail::good_value(try_get_application_certificates_sync());
}

VoidResult CertificateStore::try_add_to_trusted_certificates_sync(
  shared_ptr<const X509Certificate> certificate) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_trusted_certificates_async(certificate, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_trusted_certificates_sync(shared_ptr<const X509Certificate> certificate)
{
  try_add_to_trusted_certificates_sync(std::move(certificate)).value();
}

VoidResult CertificateStore::try_add_to_trusted_certificates_sync(
  std::vector<shared_ptr<const X509Certificate>> certificates) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_trusted_certificates_async(std::move(certificates), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_trusted_certificates_sync(
  std::vector<shared_ptr<const X509Certificate>> certificates)
{
  try_add_to_trusted_certificates_sync(std::move(certificates)).value();
}

CertificateListResult CertificateStore::try_get_trusted_certificates_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateListResult>(executor(),
      [&](std::function<void(CertificateListResult)> complete)
      { get_trusted_certificates_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CertificateList CertificateStore::get_trusted_certificates_sync() const
{
  return ua::detail::good_value(try_get_trusted_certificates_sync());
}

VoidResult CertificateStore::try_add_to_issuer_certificates_sync(
  shared_ptr<const X509Certificate> certificate) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_issuer_certificates_async(certificate, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_issuer_certificates_sync(shared_ptr<const X509Certificate> certificate)
{
  try_add_to_issuer_certificates_sync(std::move(certificate)).value();
}

VoidResult CertificateStore::try_add_to_issuer_certificates_sync(
  std::vector<shared_ptr<const X509Certificate>> certificates) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_issuer_certificates_async(std::move(certificates), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_issuer_certificates_sync(
  std::vector<shared_ptr<const X509Certificate>> certificates)
{
  try_add_to_issuer_certificates_sync(std::move(certificates)).value();
}

CertificateListResult CertificateStore::try_get_issuer_certificates_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateListResult>(executor(),
      [&](std::function<void(CertificateListResult)> complete)
      { get_issuer_certificates_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CertificateList CertificateStore::get_issuer_certificates_sync() const
{
  return ua::detail::good_value(try_get_issuer_certificates_sync());
}

VoidResult CertificateStore::try_add_to_rejected_certificates_sync(
  shared_ptr<const X509Certificate> certificate) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_rejected_certificates_async(certificate, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_rejected_certificates_sync(shared_ptr<const X509Certificate> certificate)
{
  try_add_to_rejected_certificates_sync(std::move(certificate)).value();
}

CertificateListResult CertificateStore::try_get_rejected_certificates_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateListResult>(executor(),
      [&](std::function<void(CertificateListResult)> complete)
      { get_rejected_certificates_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CertificateList CertificateStore::get_rejected_certificates_sync() const
{
  return ua::detail::good_value(try_get_rejected_certificates_sync());
}

VoidResult CertificateStore::try_add_to_trusted_crls_sync(shared_ptr<const X509Crl> crl) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete) { add_to_trusted_crls_async(crl, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_trusted_crls_sync(shared_ptr<const X509Crl> crl)
{
  try_add_to_trusted_crls_sync(std::move(crl)).value();
}

VoidResult CertificateStore::try_add_to_trusted_crls_sync(
  std::vector<shared_ptr<const X509Crl>> crls) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_trusted_crls_async(std::move(crls), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_trusted_crls_sync(std::vector<shared_ptr<const X509Crl>> crls)
{
  try_add_to_trusted_crls_sync(std::move(crls)).value();
}

CrlListResult CertificateStore::try_get_trusted_crls_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CrlListResult>(executor(),
      [&](std::function<void(CrlListResult)> complete) { get_trusted_crls_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CrlList CertificateStore::get_trusted_crls_sync() const
{
  return ua::detail::good_value(try_get_trusted_crls_sync());
}

VoidResult CertificateStore::try_add_to_issuer_crls_sync(shared_ptr<const X509Crl> crl) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete) { add_to_issuer_crls_async(crl, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_issuer_crls_sync(shared_ptr<const X509Crl> crl)
{
  try_add_to_issuer_crls_sync(std::move(crl)).value();
}

VoidResult CertificateStore::try_add_to_issuer_crls_sync(std::vector<shared_ptr<const X509Crl>> crls) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { add_to_issuer_crls_async(std::move(crls), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::add_to_issuer_crls_sync(std::vector<shared_ptr<const X509Crl>> crls)
{
  try_add_to_issuer_crls_sync(std::move(crls)).value();
}

CrlListResult CertificateStore::try_get_issuer_crls_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CrlListResult>(executor(),
      [&](std::function<void(CrlListResult)> complete) { get_issuer_crls_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CrlList CertificateStore::get_issuer_crls_sync() const
{
  return ua::detail::good_value(try_get_issuer_crls_sync());
}

VoidResult CertificateStore::try_replace_trusted_certificates_sync(
  CertificateList certificates, CrlList crls) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { replace_trusted_certificates_async(std::move(certificates), std::move(crls), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::replace_trusted_certificates_sync(CertificateList certificates, CrlList crls)
{
  try_replace_trusted_certificates_sync(std::move(certificates), std::move(crls)).value();
}

VoidResult CertificateStore::try_replace_issuer_certificates_sync(
  CertificateList certificates, CrlList crls) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { replace_issuer_certificates_async(std::move(certificates), std::move(crls), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::replace_issuer_certificates_sync(CertificateList certificates, CrlList crls)
{
  try_replace_issuer_certificates_sync(std::move(certificates), std::move(crls)).value();
}

VoidResult CertificateStore::try_remove_from_trusted_certificates_sync(const std::string& thumbprint) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { remove_from_trusted_certificates_async(thumbprint, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::remove_from_trusted_certificates_sync(const std::string& thumbprint)
{
  try_remove_from_trusted_certificates_sync(thumbprint).value();
}

VoidResult CertificateStore::try_remove_from_issuer_certificates_sync(const std::string& thumbprint) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { remove_from_issuer_certificates_async(thumbprint, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::remove_from_issuer_certificates_sync(const std::string& thumbprint)
{
  try_remove_from_issuer_certificates_sync(thumbprint).value();
}

VoidResult CertificateStore::try_validate_certificate_sync(CertificateValidationRequest request) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(executor(),
      [&](std::function<void(VoidResult)> complete)
      { validate_certificate_async(std::move(request), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateStore::validate_certificate_sync(CertificateValidationRequest request)
{
  try_validate_certificate_sync(std::move(request)).value();
}

}  // namespace ua
