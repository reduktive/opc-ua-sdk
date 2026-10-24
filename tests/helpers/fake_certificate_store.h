// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_FAKE_CERTIFICATE_STORE_H
#define UA_TEST_HELPERS_FAKE_CERTIFICATE_STORE_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "ua_certificate_store.h"

namespace ua::test_helpers
{

/// One deferrable completion of a fake asynchronous operation: while `defer` is set, the operation hands
/// its callback to hold() instead of invoking it, and the test delivers it later with release(), so it can
/// interleave other work before the completion (the real store completes off-strand, on a later turn).
template<typename Callback>
class DeferredCompletion
{
public:
  /// When set, hold() keeps the callback for release().
  std::atomic<bool> defer{false};

  /// Keeps @p callback and returns true when deferral is on; otherwise leaves it and returns false.
  bool hold(Callback& callback)
  {
    if (!defer.load())
    {
      return false;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    mPending = std::move(callback);
    return true;
  }

  /// Whether a callback is held.
  bool has_pending() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return static_cast<bool>(mPending);
  }

  /// Invokes the held callback, if any, with @p args, outside the lock.
  template<typename... Args>
  void release(Args&&... args)
  {
    Callback callback;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      callback = std::move(mPending);
      mPending = nullptr;
    }
    if (callback)
    {
      callback(std::forward<Args>(args)...);
    }
  }

private:
  mutable std::mutex mMutex;
  Callback mPending;
};

/// Minimal `CertificateStore` for tests that need a non-null instance but don't
/// exercise certificate behaviour.
///
/// All getters return empty success. All setters/adders return success. Validation
/// returns success. This is sufficient for tests that traverse code paths needing
/// a `CertificateStore` instance (e.g. `Discovery::get_endpoints_coro`'s null check)
/// without actually verifying any certificate-related behaviour.
class FakeCertificateStore final : public ua::CertificateStore
{
public:
  static std::shared_ptr<FakeCertificateStore> create()
  {
    return std::shared_ptr<FakeCertificateStore>(new FakeCertificateStore());
  }

  /// Scriptable server-certificate validation result. Defaults to Good (the historical always-trusted
  /// behaviour); set bad to make validate_certificate_async (a request without connection trust) report a
  /// trust failure - e.g. to exercise the CL-IDENT-006 None-channel token-encryption trust gate - or
  /// Uncertain to make it answer Uncertain.
  ua::StatusCode validateCertificateStatus{ua::Status::Good};

  /// Identity arguments captured from the most recent validate_certificate_async call, so a test can assert
  /// the caller threaded the intended-server identity (not just a chain-to-CA trust check) - CL-IDENT-006.
  ua::optional<std::string> lastValidatedEndpointUrl;
  ua::optional<std::string> lastValidatedApplicationUri;
  std::shared_ptr<const ua::X509Certificate> lastValidatedCertificate;
  std::atomic<int> validateCallCount{0};

  /// Scriptable result of a validation whose request carries trustedForThisConnection (defaults to Good) and
  /// what the most recent such call carried, so a test can assert the caller widened trust rather than
  /// skipped validation (CL-SECADMIN-003).
  ua::StatusCode validateWithAdditionalTrustStatus{ua::Status::Good};
  std::vector<std::shared_ptr<const ua::X509Certificate>> lastAdditionalTrustedCertificates;
  ua::optional<std::string> lastAdditionalTrustEndpointUrl;
  std::atomic<int> validateWithAdditionalTrustCallCount{0};

  /// When deferred, validate_certificate_async holds the completion callback instead of invoking it, so a
  /// test can interleave other work (e.g. a session teardown) before the verdict is delivered via
  /// release_pending_validation().
  DeferredCompletion<ua::Crypto::CertificateValidationCompleteCallback> validationDeferral;

  /// Delivers a held validation verdict (validateCertificateStatus), if any.
  void release_pending_validation()
  {
    validationDeferral.release(
      validateCertificateStatus.is_good() ? ua::VoidResult{} : ua::VoidResult{validateCertificateStatus});
  }

  void add_to_application_certificates_async(
    ApplicationCertificate, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  /// Scriptable application instance certificate. Empty by default - the historical behaviour, which
  /// makes every staged endpoint carry an empty serverCertificate. Set it when a test needs the
  /// certificate half of an obligation (e.g. that a rewritten endpointUrl names a HostName the
  /// certificate declares), which cannot be observed against a store that holds none.
  ApplicationCertificate applicationCertificate;

  /// Optional exact result for application-certificate enumeration. When unset, the fake retains
  /// its historical behavior of returning applicationCertificate (when present) as a successful list.
  ua::optional<ApplicationCertificateListResult> getApplicationCertificatesResult;

  void get_application_certificate_async(
    ua::CertificateType, GetApplicationCertificateCallback callback) const noexcept override
  {
    callback(ApplicationCertificateResult{applicationCertificate});
  }

  void get_application_certificates_async(GetApplicationCertificatesCallback callback) const noexcept override
  {
    if (getApplicationCertificatesResult)
    {
      callback(*getApplicationCertificatesResult);
      return;
    }
    ApplicationCertificateList list;
    if (applicationCertificate.certificate)
      list.push_back(applicationCertificate);
    callback(ApplicationCertificateListResult{std::move(list)});
  }

  /// Certificates handed to add_to_trusted_certificates_async, so a test can assert that a flow
  /// actually PERSISTED trust rather than only claiming to (easy-connect `AcceptAndPersist` vs
  /// `AcceptForThisSession`). Recording only: `get_trusted_certificates_async` still reports an
  /// empty list, as it always has.
  std::vector<std::shared_ptr<const ua::X509Certificate>> trustedCertificates;

  /// When set, add_to_trusted_certificates_async reports this instead of Good, so a test can drive
  /// the "the store refused the write" branch.
  ua::StatusCode addToTrustedStatus{ua::Status::Good};

  void add_to_trusted_certificates_async(
    std::shared_ptr<const ua::X509Certificate> certificate, CompleteCallback callback) noexcept override
  {
    if (addToTrustedStatus.is_bad())
    {
      callback(ua::VoidResult{addToTrustedStatus});
      return;
    }
    trustedCertificates.push_back(std::move(certificate));
    callback(ua::VoidResult{});
  }

  void add_to_trusted_certificates_async(std::vector<std::shared_ptr<const ua::X509Certificate>> certificates,
    CompleteCallback callback) noexcept override
  {
    if (addToTrustedStatus.is_bad())
    {
      callback(ua::VoidResult{addToTrustedStatus});
      return;
    }
    trustedCertificates.insert(trustedCertificates.end(), certificates.begin(), certificates.end());
    callback(ua::VoidResult{});
  }

  /// When deferred, get_trusted_certificates_async holds its callback until release_pending_trusted_read(),
  /// so a test can act while a reader of the trust list is waiting on the store.
  mutable DeferredCompletion<GetCertificatesCallback> trustedReadDeferral;

  /// Delivers a held trust-list read (an empty list), if any.
  void release_pending_trusted_read()
  {
    trustedReadDeferral.release(ua::CertificateListResult{ua::CertificateList{}});
  }

  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    if (trustedReadDeferral.hold(callback))
    {
      return;
    }
    callback(ua::CertificateListResult{ua::CertificateList{}});
  }

  void add_to_issuer_certificates_async(
    std::shared_ptr<const ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void add_to_issuer_certificates_async(
    std::vector<std::shared_ptr<const ua::X509Certificate>>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  /// Scriptable issuer list used by chain-building consumers. The optional exact result supports
  /// rich dependency-failure tests; otherwise the configured list is returned successfully.
  ua::CertificateList issuerCertificates;
  ua::optional<ua::CertificateListResult> getIssuerCertificatesResult;

  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    if (getIssuerCertificatesResult)
    {
      callback(*getIssuerCertificatesResult);
      return;
    }
    callback(ua::CertificateListResult{issuerCertificates});
  }

  void add_to_rejected_certificates_async(
    std::shared_ptr<const ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(ua::CertificateListResult{ua::CertificateList{}});
  }

  void add_to_trusted_crls_async(
    std::shared_ptr<const ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<std::shared_ptr<const ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(ua::CrlListResult{ua::CrlList{}});
  }

  void add_to_issuer_crls_async(
    std::shared_ptr<const ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void add_to_issuer_crls_async(
    std::vector<std::shared_ptr<const ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(ua::CrlListResult{ua::CrlList{}});
  }

  void replace_trusted_certificates_async(
    ua::CertificateList, ua::CrlList, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void replace_issuer_certificates_async(
    ua::CertificateList, ua::CrlList, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void remove_from_trusted_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void remove_from_issuer_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  void set_validation_options(ua::TrustListValidationOptions validationOptions) override
  {
    mValidationOptions = validationOptions;
  }

  /// The options last set with set_validation_options (none by default). A consumer that reads the
  /// store's default options (e.g. the client's CreateSession HostName check) observes them.
  ua::TrustListValidationOptions validation_options() const override
  {
    return mValidationOptions;
  }

  void refresh_cache(CompleteCallback callback) override
  {
    callback(ua::VoidResult{});
  }

  /// The single validation entry point (owner review 2026-10-02, item 5). A request carrying certificates
  /// accepted for this connection only is the former additional-trust form and is scripted and recorded
  /// separately (CL-SECADMIN-003); every other request is the plain form. The whole request is recorded so a
  /// wiring test asserts what the production path built (chain, use, policy, URI, URL, connection trust).
  void validate_certificate_async(ua::CertificateValidationRequest request,
    ua::Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    {
      std::lock_guard<std::mutex> lock(mRequestMutex);
      mLastValidationRequest = request;
      mValidationRequests.push_back(request);
    }
    lastValidatedCertificate = request.certificate;
    lastValidatedApplicationUri = request.applicationUri;
    if (!request.trustedForThisConnection.empty())
    {
      lastAdditionalTrustEndpointUrl = request.endpointUrl;
      lastAdditionalTrustedCertificates = request.trustedForThisConnection;
      ++validateWithAdditionalTrustCallCount;
      callback(validateWithAdditionalTrustStatus.is_bad() ? ua::VoidResult{validateWithAdditionalTrustStatus}
                                                          : ua::VoidResult{});
      return;
    }
    lastValidatedEndpointUrl = request.endpointUrl;
    if (validationDeferral.hold(callback))
    {
      ++validateCallCount;
      return;
    }
    ++validateCallCount;
    callback(
      validateCertificateStatus.is_good() ? ua::VoidResult{} : ua::VoidResult{validateCertificateStatus});
  }

  /// Every request this store was asked to validate, in arrival order, and the most recent one.
  std::vector<ua::CertificateValidationRequest> validation_requests() const
  {
    std::lock_guard<std::mutex> lock(mRequestMutex);
    return mValidationRequests;
  }

  ua::optional<ua::CertificateValidationRequest> last_validation_request() const
  {
    std::lock_guard<std::mutex> lock(mRequestMutex);
    return mLastValidationRequest;
  }

private:
  FakeCertificateStore() = default;

  mutable std::mutex mRequestMutex;
  ua::optional<ua::CertificateValidationRequest> mLastValidationRequest;
  std::vector<ua::CertificateValidationRequest> mValidationRequests;
  ua::TrustListValidationOptions mValidationOptions;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_FAKE_CERTIFICATE_STORE_H
