// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FAKE_CERTIFICATE_STORE_H
#define FAKE_CERTIFICATE_STORE_H

#include "ua_certificate_store.h"
#include "ua_fmt.h"

#include <fmt/format.h>
#include <fmt/ranges.h>

#include "ua_byte_format.h"

#include <atomic>
#include <functional>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>

namespace ua::test_helpers
{

/// Minimal in-memory CertificateStore for unit tests.
class InMemoryFakeCertificateStore : public CertificateStore
{
public:
  CertificateList trustedCerts;
  CrlList trustedCrls;
  CertificateList issuerCerts;
  CrlList issuerCrls;
  CertificateList rejectedCerts;
  std::vector<ApplicationCertificate> appCerts;

  mutable std::deque<CertificateListResult> rejectedCertificateResults;
  // Ordered results let prerequisite tests distinguish repeated current-certificate lookups in
  // one operation (for example existing keys first, then an omitted CSR subject).
  mutable std::deque<ApplicationCertificateResult> applicationCertificateResults;
  mutable std::deque<ApplicationCertificateListResult> applicationCertificateListResults;
  mutable std::deque<std::pair<GetApplicationCertificatesCallback, ApplicationCertificateListResult>>
    deferredApplicationCertificateListResults;
  mutable std::deque<CertificateListResult> trustedCertificateResults;
  std::deque<VoidResult> addToTrustedCertificateResults;
  std::deque<VoidResult> replaceTrustedCertificateResults;
  std::deque<VoidResult> removeFromTrustedCertificateResults;
  bool deferApplicationCertificateListResults{false};
  mutable size_t rejectedCertificateCallCount{0};
  mutable size_t applicationCertificateCallCount{0};
  mutable size_t applicationCertificateListCallCount{0};
  mutable size_t trustedCertificateCallCount{0};
  size_t addToTrustedCertificateCallCount{0};
  size_t replaceTrustedCertificateCallCount{0};
  size_t removeFromTrustedCertificateCallCount{0};
  std::atomic<size_t> replaceIssuerCertificateCallCount{0};  // read while a removal may still run

  size_t deferred_application_certificate_list_count() const
  {
    std::lock_guard lock(mDeferredApplicationCertificateListMutex);
    return deferredApplicationCertificateListResults.size();
  }

  bool complete_next_application_certificate_list()
  {
    std::optional<std::pair<GetApplicationCertificatesCallback, ApplicationCertificateListResult>> deferred;
    {
      std::lock_guard lock(mDeferredApplicationCertificateListMutex);
      if (deferredApplicationCertificateListResults.empty())
        return false;
      deferred.emplace(std::move(deferredApplicationCertificateListResults.front()));
      deferredApplicationCertificateListResults.pop_front();
    }
    auto replayResult = deferred->second;
    deferred->first(std::move(deferred->second));
    deferred->second = std::move(replayResult);
    {
      std::lock_guard lock(mDeferredApplicationCertificateListMutex);
      mCompletedApplicationCertificateListResults.emplace_back(std::move(*deferred));
    }
    return true;
  }

  bool repeat_last_application_certificate_list()
  {
    std::lock_guard lock(mDeferredApplicationCertificateListMutex);
    if (mCompletedApplicationCertificateListResults.empty())
      return false;
    auto& completed = mCompletedApplicationCertificateListResults.back();
    completed.first(completed.second);
    return true;
  }

  // Test failure injection: when set bad, add_to_application_certificates_async
  // returns this status instead of committing (exercises ApplyChanges commit
  // failure / TransactionDiagnostics error paths).
  StatusCode addToApplicationCertificatesStatus{Status::Good};

  // Test failure injection: when set bad, validate_certificate_async returns this
  // status. Lets a test make a certificate that validated at UpdateCertificate
  // time fail the ApplyChanges verify-before-commit pass (Part 12 section 7.10.1
  // all-or-nothing).
  StatusCode validateCertificateStatus{Status::Good};
  size_t validateCertificateCallCount{0};
  // The ApplicationUri the last validate_certificate_async call was asked to match.
  optional<std::string> lastValidatedApplicationUri;
  // The whole request the last validate_certificate_async call carried, so a wiring test asserts what the
  // production path built: the parsed presented chain, the use, the endpoint policy (UpdateCertificate).
  optional<CertificateValidationRequest> lastValidationRequest;

  // Test failure injection for the post-commit cache refresh. A bad result must abort every
  // post-ApplyChanges side effect while preserving the rich status for the caller.
  StatusCode refreshCacheStatus{Status::Good};
  size_t refreshCacheCallCount{0};
  bool refreshCacheThrows{false};

  // --- Trusted certificates ---

  /// When set, the next single-certificate add_to_trusted_certificates_async is parked, unwritten, until
  /// release_parked_add_to_trusted(), so a test can act while an AddCertificate's store write is in flight.
  bool parkAddToTrusted{false};
  std::function<void()> parkedAddToTrusted;
  std::atomic<bool> addToTrustedIsParked{false};  // polled from the test thread

  void release_parked_add_to_trusted()
  {
    auto parked = std::move(parkedAddToTrusted);
    parkedAddToTrusted = nullptr;
    if (parked)
      parked();
  }

  void add_to_trusted_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override
  {
    ++addToTrustedCertificateCallCount;
    if (parkAddToTrusted && !parkedAddToTrusted)
    {
      parkedAddToTrusted =
        [this, certificate = std::move(certificate), callback = std::move(callback)]() mutable
      {
        trustedCerts.push_back(std::move(certificate));
        callback(VoidResult{});
      };
      addToTrustedIsParked.store(true);
      return;
    }
    if (!addToTrustedCertificateResults.empty())
    {
      auto scriptedResult = std::move(addToTrustedCertificateResults.front());
      addToTrustedCertificateResults.pop_front();
      callback(std::move(scriptedResult));
      return;
    }
    trustedCerts.push_back(std::move(certificate));
    callback(VoidResult{});
  }

  void add_to_trusted_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept override
  {
    for (auto& c : certificates)
      trustedCerts.push_back(std::move(c));
    callback(VoidResult{});
  }

  /// When set, the next get_trusted_certificates_async is parked until release_parked_trusted_read(),
  /// so a test can act while a CloseAndUpdate merge waits on the store.
  bool parkTrustedRead{false};
  mutable std::function<void()> parkedTrustedRead;
  mutable std::atomic<bool> trustedReadIsParked{false};  // polled from the test thread

  void release_parked_trusted_read()
  {
    auto parked = std::move(parkedTrustedRead);
    parkedTrustedRead = nullptr;
    if (parked)
      parked();
  }

  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    ++trustedCertificateCallCount;
    if (parkTrustedRead && !parkedTrustedRead)
    {
      parkedTrustedRead = [callback = std::move(callback), certificates = trustedCerts]() mutable
      {
        callback(std::move(certificates));
      };
      trustedReadIsParked.store(true);
      return;
    }
    if (!trustedCertificateResults.empty())
    {
      auto scriptedResult = std::move(trustedCertificateResults.front());
      trustedCertificateResults.pop_front();
      callback(std::move(scriptedResult));
      return;
    }
    callback(trustedCerts);
  }

  // --- Trusted CRLs ---

  void add_to_trusted_crls_async(shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept override
  {
    trustedCrls.push_back(std::move(crl));
    callback(VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept override
  {
    for (auto& c : crls)
      trustedCrls.push_back(std::move(c));
    callback(VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(trustedCrls);
  }

  // --- Issuer certificates ---

  void add_to_issuer_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override
  {
    issuerCerts.push_back(std::move(certificate));
    callback(VoidResult{});
  }

  void add_to_issuer_certificates_async(
    std::vector<shared_ptr<const X509Certificate>> certificates, CompleteCallback callback) noexcept override
  {
    for (auto& c : certificates)
      issuerCerts.push_back(std::move(c));
    callback(VoidResult{});
  }

  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(issuerCerts);
  }

  // --- Issuer CRLs ---

  void add_to_issuer_crls_async(shared_ptr<const X509Crl> crl, CompleteCallback callback) noexcept override
  {
    issuerCrls.push_back(std::move(crl));
    callback(VoidResult{});
  }

  void add_to_issuer_crls_async(
    std::vector<shared_ptr<const X509Crl>> crls, CompleteCallback callback) noexcept override
  {
    for (auto& c : crls)
      issuerCrls.push_back(std::move(c));
    callback(VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override
  {
    if (beforeIssuerCrlsAnswer)
      beforeIssuerCrlsAnswer();
    if (keepIssuerCrlsCallback)
      keptIssuerCrlsCallbacks.push_back(callback);  // answered below; this copy (and what it holds) stays
    callback(issuerCrls);
  }

  /// When set, get_issuer_crls_async answers and keeps a copy of its callback until the test clears
  /// keptIssuerCrlsCallbacks: a store that holds on to a continuation after answering it.
  bool keepIssuerCrlsCallback{false};
  mutable std::vector<GetCrlsCallback> keptIssuerCrlsCallbacks;

  // Test hook: runs before get_issuer_crls_async answers - the last of the four list reads a TrustList
  // AddCertificate makes before it validates - so a test can change the list in between.
  std::function<void()> beforeIssuerCrlsAnswer;

  // --- Replace operations ---

  /// When set, the next replace_trusted_certificates_async is parked, unwritten, until
  /// release_parked_replace_trusted(), so a test can act while an ApplyChanges writes the TrustLists.
  bool parkReplaceTrusted{false};
  std::function<void()> parkedReplaceTrusted;
  std::atomic<bool> replaceTrustedIsParked{false};  // polled from the test thread

  void release_parked_replace_trusted()
  {
    auto parked = std::move(parkedReplaceTrusted);
    parkedReplaceTrusted = nullptr;
    if (parked)
      parked();
  }

  void replace_trusted_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept override
  {
    if (parkReplaceTrusted && !parkedReplaceTrusted)
    {
      parkedReplaceTrusted = [this,
                               certificates = std::move(certificates),
                               crls = std::move(crls),
                               callback = std::move(callback)]() mutable
      {
        parkReplaceTrusted = false;
        replace_trusted_certificates_async(std::move(certificates), std::move(crls), std::move(callback));
      };
      replaceTrustedIsParked.store(true);
      return;
    }
    ++replaceTrustedCertificateCallCount;
    if (!replaceTrustedCertificateResults.empty())
    {
      auto scriptedResult = std::move(replaceTrustedCertificateResults.front());
      replaceTrustedCertificateResults.pop_front();
      callback(std::move(scriptedResult));
      return;
    }
    trustedCerts = std::move(certificates);
    trustedCrls = std::move(crls);
    callback(VoidResult{});
  }

  void replace_issuer_certificates_async(
    CertificateList certificates, CrlList crls, CompleteCallback callback) noexcept override
  {
    ++replaceIssuerCertificateCallCount;
    issuerCerts = std::move(certificates);
    issuerCrls = std::move(crls);
    callback(VoidResult{});
  }

  // --- Remove operations ---

  void remove_from_trusted_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override
  {
    ++removeFromTrustedCertificateCallCount;
    if (!removeFromTrustedCertificateResults.empty())
    {
      auto scriptedResult = std::move(removeFromTrustedCertificateResults.front());
      removeFromTrustedCertificateResults.pop_front();
      callback(std::move(scriptedResult));
      return;
    }
    auto it = std::find_if(trustedCerts.begin(),
      trustedCerts.end(),
      [&](const shared_ptr<const X509Certificate>& cert)
      { return fmt::format("{:02X}", fmt::join(cert->thumbprint(), "")) == thumbprint; });

    if (it != trustedCerts.end())
    {
      trustedCerts.erase(it);
      callback(VoidResult{});
    }
    else
    {
      callback(VoidResult{StatusCode{Status::BadNotFound}});
    }
  }

  void remove_from_issuer_certificates_async(
    const std::string& thumbprint, CompleteCallback callback) noexcept override
  {
    auto it = std::find_if(issuerCerts.begin(),
      issuerCerts.end(),
      [&](const shared_ptr<const X509Certificate>& cert)
      { return fmt::format("{:02X}", fmt::join(cert->thumbprint(), "")) == thumbprint; });

    if (it != issuerCerts.end())
    {
      issuerCerts.erase(it);
      callback(VoidResult{});
    }
    else
    {
      callback(VoidResult{StatusCode{Status::BadNotFound}});
    }
  }

  // --- Rejected certificates ---

  void add_to_rejected_certificates_async(
    shared_ptr<const X509Certificate> certificate, CompleteCallback callback) noexcept override
  {
    rejectedCerts.push_back(std::move(certificate));
    callback(VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    ++rejectedCertificateCallCount;
    if (!rejectedCertificateResults.empty())
    {
      auto result = std::move(rejectedCertificateResults.front());
      rejectedCertificateResults.pop_front();
      callback(std::move(result));
      return;
    }
    callback(rejectedCerts);
  }

  // --- Application certificates ---

  void add_to_application_certificates_async(
    ApplicationCertificate certificate, CompleteCallback callback) noexcept override
  {
    if (addToApplicationCertificatesStatus.is_bad())
    {
      callback(VoidResult{addToApplicationCertificatesStatus});
      return;
    }
    appCerts.push_back(std::move(certificate));
    callback(VoidResult{});
  }

  void get_application_certificate_async(
    CertificateType certificateType, GetApplicationCertificateCallback callback) const noexcept override
  {
    ++applicationCertificateCallCount;
    if (!applicationCertificateResults.empty())
    {
      auto result = std::move(applicationCertificateResults.front());
      applicationCertificateResults.pop_front();
      callback(std::move(result));
      return;
    }
    for (auto& ac : appCerts)
    {
      if (ac.certificateType == certificateType)
      {
        callback(ApplicationCertificate{ac});
        return;
      }
    }
    callback(ApplicationCertificateResult{StatusCode{Status::BadNotFound}});
  }

  void get_application_certificates_async(GetApplicationCertificatesCallback callback) const noexcept override
  {
    ++applicationCertificateListCallCount;
    ApplicationCertificateListResult result{appCerts};
    if (!applicationCertificateListResults.empty())
    {
      result = std::move(applicationCertificateListResults.front());
      applicationCertificateListResults.pop_front();
    }
    if (deferApplicationCertificateListResults)
    {
      std::lock_guard lock(mDeferredApplicationCertificateListMutex);
      deferredApplicationCertificateListResults.emplace_back(std::move(callback), std::move(result));
      return;
    }
    callback(std::move(result));
  }

  // --- Validation / utility stubs ---

  /// Records the options, as a real store does, so a component reading validation_options() follows
  /// them.
  void set_validation_options(TrustListValidationOptions validationOptions) override
  {
    mValidationOptions.store(validationOptions.as_underlying_type());
  }

  TrustListValidationOptions validation_options() const override
  {
    return TrustListValidationOptions{mValidationOptions.load()};
  }

  void refresh_cache(CompleteCallback callback) override
  {
    ++refreshCacheCallCount;
    if (refreshCacheThrows)
      throw std::runtime_error{"injected cache refresh failure"};
    callback(refreshCacheStatus.is_bad() ? VoidResult{refreshCacheStatus} : VoidResult{});
  }

  void validate_certificate_async(CertificateValidationRequest request,
    Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    ++validateCertificateCallCount;
    lastValidatedApplicationUri = request.applicationUri;
    lastValidationRequest = std::move(request);
    callback(validateCertificateStatus.is_bad() ? VoidResult{validateCertificateStatus} : VoidResult{});
  }

private:
  std::atomic<TrustListValidationOptions::UnderlyingType> mValidationOptions{0};
  mutable std::mutex mDeferredApplicationCertificateListMutex;
  mutable std::deque<std::pair<GetApplicationCertificatesCallback, ApplicationCertificateListResult>>
    mCompletedApplicationCertificateListResults;
};

}  // namespace ua::test_helpers

#endif  // FAKE_CERTIFICATE_STORE_H
