// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Phase-4.5b-local CertificateStore for pin tests.
//
// The pins exercise three modes of `get_application_certificates_async`:
//   * Inline-good    - completes synchronously with an empty cert list. The default
//                       Discovery success path emits SecurityPolicy::None endpoints
//                       (which do not require certificates), so an empty list is
//                       sufficient for FS-A / GE-A / GE-B / GE-C / GE-G.
//   * Inline-fail    - completes synchronously with a configured Status + ErrorDetail
//                       so FS-D / GE-D / GE-E can drive the catch-block of
//                       `process_request_impl(...)` (`ua_discovery_service_set.cpp:130-135`
//                       and `:189-194`) and observe service-level diagnostics.
//   * Async-deferred - parks the callback on an internal queue serviced by a dedicated
//                       worker thread. The pins drive completion via
//                       `pump_pending_with_failure(...)` from the test main thread, so
//                       the parked callback fires from a thread that is neither the test
//                       main thread nor the service strand pool thread. Used by the
//                       timeout pin (FS-E / GE-G) and the destructor-during-flight pin
//                       (DISABLED_*).
//
// Per the runbook section 9.5.1 sub-phase-local-fakes rule: this file is local to
// `tests/behaviour_pins/phase_4_5b_discovery/` and not promoted to `tests/helpers/`.

#ifndef PHASE_4_5B_PIN_CERTIFICATE_STORE_H
#define PHASE_4_5B_PIN_CERTIFICATE_STORE_H

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ua_certificate_store.h"
#include "ua_error_detail.h"
#include "ua_status_code.h"

namespace ua::test::behaviour_pins::discovery
{

class PinCertificateStore final : public ua::CertificateStore
{
public:
  enum class Mode
  {
    InlineGood,
    InlineFail,
    AsyncDeferred,
  };

  static std::shared_ptr<PinCertificateStore> create()
  {
    return std::shared_ptr<PinCertificateStore>(new PinCertificateStore());
  }

  ~PinCertificateStore() override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mShuttingDown = true;
    }
    mCv.notify_all();
    if (mWorker.joinable())
    {
      mWorker.join();
    }
  }

  // --- Configuration knobs (call before issuing the request) ---

  void set_mode(Mode mode)
  {
    mMode = mode;
  }

  void set_inline_failure(::ua::StatusCode status, std::shared_ptr<const ::ua::ErrorDetail> detail)
  {
    mFailureStatus = status;
    mFailureDetail = std::move(detail);
  }

  // Drive the async-deferred mode: the worker thread pulls a single parked callback
  // and fires it with a configured failure (BadInternalError + the detail returned
  // from `inline_failure_detail()` if set, else nullptr).
  void complete_pending_with_failure()
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mDriveSignal.failure = true;
      ++mDriveSignal.count;
    }
    mCv.notify_all();
  }

  // Number of parked callbacks observed (for sanity assertions).
  size_t parked_count() const noexcept
  {
    return mParkedCount.load(std::memory_order_relaxed);
  }

  // --- CertificateStore interface ---

  void get_application_certificates_async(GetApplicationCertificatesCallback callback) const noexcept override
  {
    if (mMode == Mode::InlineGood)
    {
      callback(ApplicationCertificateListResult{ApplicationCertificateList{}});
      return;
    }
    if (mMode == Mode::InlineFail)
    {
      callback(ApplicationCertificateListResult{mFailureStatus, mFailureDetail});
      return;
    }
    park_callback(std::move(callback));
  }

  void get_application_certificate_async(
    ::ua::CertificateType, GetApplicationCertificateCallback callback) const noexcept override
  {
    callback(ApplicationCertificateResult{ApplicationCertificate{}});
  }

  // --- Stub remainder of the interface (Discovery does not call them) ---

  void add_to_application_certificates_async(
    ApplicationCertificate, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void add_to_trusted_certificates_async(
    std::shared_ptr<const ::ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void add_to_trusted_certificates_async(
    std::vector<std::shared_ptr<const ::ua::X509Certificate>>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void get_trusted_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(::ua::CertificateListResult{::ua::CertificateList{}});
  }

  void add_to_issuer_certificates_async(
    std::shared_ptr<const ::ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void add_to_issuer_certificates_async(
    std::vector<std::shared_ptr<const ::ua::X509Certificate>>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void get_issuer_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(::ua::CertificateListResult{::ua::CertificateList{}});
  }

  void add_to_rejected_certificates_async(
    std::shared_ptr<const ::ua::X509Certificate>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback callback) const noexcept override
  {
    callback(::ua::CertificateListResult{::ua::CertificateList{}});
  }

  void add_to_trusted_crls_async(
    std::shared_ptr<const ::ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<std::shared_ptr<const ::ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(::ua::CrlListResult{::ua::CrlList{}});
  }

  void add_to_issuer_crls_async(
    std::shared_ptr<const ::ua::X509Crl>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void add_to_issuer_crls_async(
    std::vector<std::shared_ptr<const ::ua::X509Crl>>, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback callback) const noexcept override
  {
    callback(::ua::CrlListResult{::ua::CrlList{}});
  }

  void replace_trusted_certificates_async(
    ::ua::CertificateList, ::ua::CrlList, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void replace_issuer_certificates_async(
    ::ua::CertificateList, ::ua::CrlList, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void remove_from_trusted_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void remove_from_issuer_certificates_async(const std::string&, CompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

  void set_validation_options(::ua::TrustListValidationOptions) override
  {}

  ::ua::TrustListValidationOptions validation_options() const override
  {
    return {};
  }

  void refresh_cache(CompleteCallback callback) override
  {
    callback(::ua::VoidResult{});
  }

  void validate_certificate_async(::ua::CertificateValidationRequest,
    ::ua::Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    callback(::ua::VoidResult{});
  }

private:
  PinCertificateStore() = default;

  void park_callback(GetApplicationCertificatesCallback callback) const
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mPending.emplace_back(std::move(callback));
      mParkedCount.fetch_add(1, std::memory_order_relaxed);
      if (!mWorker.joinable())
      {
        const_cast<PinCertificateStore*>(this)->start_worker();
      }
    }
    mCv.notify_all();
  }

  void start_worker()
  {
    mWorker = std::thread(
      [this]()
      {
        for (;;)
        {
          GetApplicationCertificatesCallback parked;
          bool deliverFailure = false;

          {
            std::unique_lock<std::mutex> lock(mMutex);
            mCv.wait(
              lock, [this]() { return mShuttingDown || (mDriveSignal.count > 0 && !mPending.empty()); });
            if (mShuttingDown && mPending.empty())
            {
              return;
            }
            if (mDriveSignal.count > 0 && !mPending.empty())
            {
              parked = std::move(mPending.front());
              mPending.pop_front();
              deliverFailure = mDriveSignal.failure;
              --mDriveSignal.count;
            }
            else
            {
              continue;
            }
          }

          if (parked)
          {
            if (deliverFailure)
            {
              parked(ApplicationCertificateListResult{mFailureStatus, mFailureDetail});
            }
            else
            {
              parked(ApplicationCertificateListResult{ApplicationCertificateList{}});
            }
          }
        }
      });
  }

  Mode mMode{Mode::InlineGood};
  ::ua::StatusCode mFailureStatus{::ua::Status::BadInternalError};
  std::shared_ptr<const ::ua::ErrorDetail> mFailureDetail;

  mutable std::mutex mMutex;
  mutable std::condition_variable mCv;
  mutable std::deque<GetApplicationCertificatesCallback> mPending;
  mutable std::atomic<size_t> mParkedCount{0};

  struct DriveSignal
  {
    size_t count{0};
    bool failure{false};
  };

  DriveSignal mDriveSignal;

  bool mShuttingDown{false};
  mutable std::thread mWorker;
};

}  // namespace ua::test::behaviour_pins::discovery

#endif  // PHASE_4_5B_PIN_CERTIFICATE_STORE_H
