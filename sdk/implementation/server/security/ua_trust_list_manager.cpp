// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_trust_list_manager.h"

#include "ua_certificate_thumbprint.h"
#include "ua_certificate_validation_paths.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_callback_safety.h"
#include "ua_on_strand.h"
#include "ua_security_policy_internal.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_trust_list_data_type.h"
#include "ua_utc_time.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_date_time.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include <atomic>
#include <future>
#include <utility>

namespace ua
{

namespace
{

/// Accumulates the four certificate/CRL lists fetched from the CertificateStore.
using ReadState = detail::TrustListContent;

/// What a TrustList Method answers for a store answer it cannot use: a Bad answer as it is, an Uncertain
/// one, with or without its list, refused with Bad_InternalError (CertificateStoreAnswerUncertain). A
/// Method reads, adds or removes nothing on a list the store answered Uncertain.
///
/// @param answer The store's status; not Good.
/// @return The failure the Method answers.
StatusCode store_answer_failure(const StatusCode& answer)
{
  return security_internal::not_good_store_answer(answer, Status::BadInternalError, "TrustListManager");
}

/// Reads the store's four lists, in turn, into one ReadState. Touches no manager state, so the store
/// may answer on any thread; @p done receives the first failure, or the lists. A store that throws
/// instead of answering answers with the exception's status, and one that answers and then throws
/// answers once.
void fetch_store_lists_async(const std::shared_ptr<CertificateStore>& store,
  std::function<void(Result<std::shared_ptr<ReadState>>)> done)
{
  auto answer = detail::make_fire_once<Result<std::shared_ptr<ReadState>>>(std::move(done));
  auto state = std::make_shared<ReadState>();
  const auto guarded = [answer](auto&& call)
  {
    try
    {
      call();
    }
    catch (...)
    {
      answer(ua::exception_to_status_code(std::current_exception()));
    }
  };
  guarded(
    [&]
    {
      store->get_trusted_certificates_async(
        [store, state, answer, guarded](CertificateListResult trusted) mutable
        {
          if (!trusted.is_good())
          {
            answer(store_answer_failure(trusted.status_code()));
            return;
          }
          state->trustedCerts = std::move(trusted).value();
          guarded(
            [&]
            {
              store->get_trusted_crls_async(
                [store, state, answer, guarded](CrlListResult trustedCrls) mutable
                {
                  if (!trustedCrls.is_good())
                  {
                    answer(store_answer_failure(trustedCrls.status_code()));
                    return;
                  }
                  state->trustedCrls = std::move(trustedCrls).value();
                  guarded(
                    [&]
                    {
                      store->get_issuer_certificates_async(
                        [store, state, answer, guarded](CertificateListResult issuers) mutable
                        {
                          if (!issuers.is_good())
                          {
                            answer(store_answer_failure(issuers.status_code()));
                            return;
                          }
                          state->issuerCerts = std::move(issuers).value();
                          guarded(
                            [&]
                            {
                              store->get_issuer_crls_async(
                                [state, answer](CrlListResult issuerCrls) mutable
                                {
                                  if (!issuerCrls.is_good())
                                  {
                                    answer(store_answer_failure(issuerCrls.status_code()));
                                    return;
                                  }
                                  state->issuerCrls = std::move(issuerCrls).value();
                                  answer(state);
                                });
                            });
                        });
                    });
                });
            });
        });
    });
}

/// One run of trust-list validation: every certificate of @ref certificates, then every CRL of
/// @ref crls, through the Part 4 validator, with @ref anchors (the whole trust list being installed)
/// as the trust anchors and the chain material, and the list's CRLs.
struct TrustListValidationRun
{
  std::shared_ptr<const Crypto> crypto;
  boost::asio::any_io_executor executor;
  Logger logger;  ///< Records a throw out of a unit's posted turn.
  TrustListValidationOptions options;
  CertificateList certificates;
  /// certificates[0, issuerBegin) are trusted-list entries, the rest issuer-list entries.
  size_t issuerBegin{0};
  CertificateList anchors;
  CrlList trustedCrls;
  CrlList issuerCrls;
  /// The CRLs to validate (the new list's trusted and issuer CRLs); empty for an AddCertificate.
  CrlList crls;
  /// The unit in progress; written by the one unit in flight, read by the next after the post.
  size_t next{0};
  /// Taken with exchange: a validator that answers and then throws cannot finish the run twice.
  std::atomic<bool> finished{false};
  std::function<void(StatusCode)> done;
};

void finish_validation(TrustListValidationRun& run, StatusCode verdict)
{
  if (run.finished.exchange(true))
    return;
  auto done = std::move(run.done);
  detail::invoke_user_callback(done, std::move(verdict));
}

/// Part 12 7.8.2.3 names the failure Bad_CertificateInvalid; the validator's Part 4 status (7.8.2.1's
/// "appropriate Certificate error code") is its cause, and the certificate is named.
StatusCode trust_list_certificate_refusal(const X509Certificate& certificate, StatusCode cause)
{
  return StatusCode{Status::BadCertificateInvalid,
    // The summary names the certificate too: a Summary-level DiagnosticInfo carries the summary but not the
    // context (owner decision D-b, OPC 10000-12 7.8.2.3).
    ErrorDetail::build("TrustListCertificateInvalid",
      "the trust list certificate '" + certificate.subject_common_name() +
        "' failed Part 4 validation; the trust list is not changed",
      "TrustListManager")
      .cause(std::move(cause))
      .context(ua::ContextKeys::certificateSubject, certificate.subject_common_name())
      .context(ua::ContextKeys::certificateThumbprint,
        utils::bytes_to_hex_string(span<const byte>{certificate.thumbprint()}))};
}

/// Part 12 7.8.2.5: "It returns Bad_InvalidArgument if the thumbprint does not match a Certificate in the
/// Trust List". @p cause is the store's own refusal, when the store found nothing.
StatusCode certificate_not_in_list(
  const std::string& thumbprint, std::optional<StatusCode> cause = std::nullopt)
{
  auto detail = ErrorDetail::build(
    "TrustListCertificateNotFound", "no certificate in the list has this thumbprint", "TrustListManager")
                  .context(ua::ContextKeys::certificateThumbprint, thumbprint);
  if (cause)
    detail.cause(std::move(*cause));
  return StatusCode{Status::BadInvalidArgument, std::move(detail)};
}

/// RemoveCertificate's single-certificate store call (no CRL changes). The store's Bad_NotFound (the list
/// changed since it was read) is answered with the spec's Bad_InvalidArgument, the store's refusal its cause.
void remove_one_certificate(CertificateStore& store, bool isTrustedCertificate, const std::string& thumbprint,
  std::function<void(VoidResult)> onComplete)
{
  auto answer = [thumbprint, onComplete = std::move(onComplete)](VoidResult result) mutable
  {
    if (result.status_code() == StatusCode{Status::BadNotFound})
      result = VoidResult{certificate_not_in_list(thumbprint, result.status_code())};
    onComplete(std::move(result));
  };
  if (isTrustedCertificate)
    store.remove_from_trusted_certificates_async(thumbprint, std::move(answer));
  else
    store.remove_from_issuer_certificates_async(thumbprint, std::move(answer));
}

/// The removal of a CA (Part 12 7.8.2.5): the list's CRLs are checked one at a time, one per executor turn,
/// for being the CA's, then the CA leaves - with its CRLs, in one replace - or alone. A store or crypto that
/// never answers loses the removal (the caller is not answered, as with any dropped callback) but, the
/// in-flight token dying with the scan, does not lock the TrustList.
struct CaCrlScan
{
  std::shared_ptr<CertificateStore> store;
  std::shared_ptr<const Crypto> crypto;
  boost::asio::any_io_executor executor;
  Logger logger;  ///< Records a throw out of a CRL's posted turn.
  bool isTrustedCertificate{false};
  std::string thumbprint;
  std::vector<std::shared_ptr<const X509Certificate>> ca;  // the one issuer candidate
  CertificateList certificates;  // the list without the CA
  CrlList crls;  // the list's CRLs, scanned in order
  CrlList kept;  // those that stay
  size_t next{0};
  std::function<void(VoidResult)> onComplete;  // fire-once; holds the claim and the in-flight token
};

// The CRL check: issuer name is a candidate's subject and that candidate's key verifies the signature (so two
// CAs sharing a subject name are told apart). SuppressRevocationStatusUnknown: a CRL outside its validity
// window still matches (Crypto::validate_crl_async), so an expired CRL of the CA goes too.
const TrustListValidationOptions crlOwnership{
  TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown};

void scan_next_ca_crl(std::shared_ptr<CaCrlScan> scan);

/// Posts the next CRL to its own executor turn: the scan never recurses and one turn checks one CRL
/// (a crypto that answers inline would otherwise run the whole list on one stack and one turn).
// By reference: a throw here leaves the caller's scan intact, so its catch can still answer.
void continue_ca_crl_scan(const std::shared_ptr<CaCrlScan>& scan, bool keep)
{
  if (keep)
    scan->kept.push_back(scan->crls[scan->next]);
  ++scan->next;
  boost::asio::post(scan->executor,
    ua::async::guarded(scan->logger, [scan]() mutable { scan_next_ca_crl(std::move(scan)); }));
}

void scan_next_ca_crl(std::shared_ptr<CaCrlScan> scan)
{
  try
  {
    if (scan->next >= scan->crls.size())
    {
      if (scan->kept.size() == scan->crls.size())
      {
        remove_one_certificate(*scan->store, scan->isTrustedCertificate, scan->thumbprint, scan->onComplete);
        return;
      }
      // One swap: the CA and its CRLs leave together, so no validation sees one without the other.
      auto& store = *scan->store;
      if (scan->isTrustedCertificate)
        store.replace_trusted_certificates_async(
          std::move(scan->certificates), std::move(scan->kept), scan->onComplete);
      else
        store.replace_issuer_certificates_async(
          std::move(scan->certificates), std::move(scan->kept), scan->onComplete);
      return;
    }
    auto crl = scan->crls[scan->next];
    auto crypto = scan->crypto;
    auto ca = scan->ca;
    // Cost per CRL: a name comparison, a signature verification when it names the CA, and a second one when
    // it is the CA's (whether a certificate that stays also issued it).
    crypto->validate_crl_async(crlOwnership,
      crl,
      std::move(ca),
      // Fire-once: a crypto that answers twice cannot advance the scan past a CRL it did not check.
      detail::make_fire_once<VoidResult>(
        [scan, crl](VoidResult issuedByCa) mutable
        {
          try
          {
            if (issuedByCa.is_bad())
            {
              continue_ca_crl_scan(scan, /*keep=*/true);
              return;
            }
            // A CRL that a certificate staying in the list also issued (a renewed CA with the same subject
            // and key) is that certificate's too, and stays (Mantis 6796: only CRLs for the removed CA go).
            auto crypto2 = scan->crypto;
            auto remaining = scan->certificates;
            crypto2->validate_crl_async(crlOwnership,
              std::move(crl),
              std::move(remaining),
              detail::make_fire_once<VoidResult>(
                [scan](VoidResult issuedByRemaining) mutable
                {
                  try
                  {
                    continue_ca_crl_scan(scan, /*keep=*/issuedByRemaining.is_good());
                  }
                  catch (...)
                  {
                    scan->onComplete(VoidResult{ua::exception_to_status_code(std::current_exception())});
                  }
                }));
          }
          catch (...)
          {
            scan->onComplete(VoidResult{ua::exception_to_status_code(std::current_exception())});
          }
        }));
  }
  catch (...)
  {
    scan->onComplete(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

/// Part 12 7.8.2.1: the Server "will validate all new Certificates and CRLs". A CRL that fails refuses
/// the update with Bad_CertificateInvalid; the validator's status is the cause, and the CRL's issuer
/// (from the validator's detail) names it.
StatusCode trust_list_crl_refusal(StatusCode cause)
{
  std::string issuer;
  if (const auto& causeDetail = cause.shared_detail())
  {
    for (const auto& entry : causeDetail->context)
    {
      if (entry.key == ua::ContextKeys::crlIssuer.value())
        issuer = entry.value;
    }
  }
  return StatusCode{Status::BadCertificateInvalid,
    ErrorDetail::build("TrustListCrlInvalid",
      "a CRL of the trust list failed validation; the trust list is not changed",
      "TrustListManager")
      .cause(std::move(cause))
      .context(ua::ContextKeys::crlIssuer, std::move(issuer))};
}

/// Part 4 Table 106 Certificate Usage: an issuer-list entry is a CA certificate (Part 6 Table 45); a
/// trusted-list entry is one when it declares itself a CA, and an end-entity certificate otherwise.
CertificateUse use_of_trust_list_entry(const X509Certificate& certificate, bool inIssuerList)
{
  return (inIssuerList || certificate.basic_constraints_ca()) ? CertificateUse::CertificateAuthority
                                                              : CertificateUse::ApplicationInstance;
}

void validate_unit(const std::shared_ptr<TrustListValidationRun>& run);

/// Hands the run's next unit to the executor (post, never dispatch): each certificate and each CRL is
/// validated in its own turn, so neither the manager's strand nor a pool thread is held for the whole
/// list (R18). Cost per unit: one chain validation, which builds an X509_STORE from the list's
/// anchors - O(N) per unit, O(N^2) over a list of N, bounded by maxTrustListSize, administrative only.
void schedule_unit(const std::shared_ptr<TrustListValidationRun>& run)
{
  try
  {
    boost::asio::post(run->executor, ua::async::guarded(run->logger, [run]() { validate_unit(run); }));
  }
  catch (...)
  {
    finish_validation(*run, ua::exception_to_status_code(std::current_exception()));
  }
}

/// Validates the run's unit @ref TrustListValidationRun::next: a certificate, then the CRLs once every
/// certificate passed. The validator may answer inline or later, on any thread; its answer schedules
/// the next unit.
void validate_unit(const std::shared_ptr<TrustListValidationRun>& run)
{
  if (run->finished.load())
    return;
  const size_t index = run->next;
  if (index == run->certificates.size() + run->crls.size())
  {
    finish_validation(*run, StatusCode{Status::Good});
    return;
  }
  try
  {
    if (index < run->certificates.size())
    {
      auto certificate = run->certificates[index];
      if (!certificate)
      {
        finish_validation(*run,
          StatusCode{Status::BadCertificateInvalid,
            make_error_detail(
              "TrustListCertificateMissing", "the trust list holds a null certificate", "TrustListManager")});
        return;
      }
      const auto use = use_of_trust_list_entry(*certificate, index >= run->issuerBegin);
      CertificateValidationRequest request;
      request.certificate = certificate;
      request.use = use;
      CertificateValidationMaterial material;
      material.trusted = run->anchors;
      material.trustedCrls = run->trustedCrls;
      material.issuerCrls = run->issuerCrls;
      material.options = run->options;
      run->crypto->validate_certificate_async(request,
        std::move(material),
        // Fire-once: a validator that answers twice cannot advance the run past a unit it never validated.
        detail::make_fire_once<VoidResult>(
          [run, certificate](VoidResult result)
          {
            if (result.is_bad())
            {
              finish_validation(*run, trust_list_certificate_refusal(*certificate, result.status_code()));
              return;
            }
            ++run->next;
            schedule_unit(run);
          }));
      return;
    }
    run->crypto->validate_crl_async(run->options,
      run->crls[index - run->certificates.size()],
      run->anchors,
      detail::make_fire_once<VoidResult>(
        [run](VoidResult result)
        {
          if (result.is_bad())
          {
            finish_validation(*run, trust_list_crl_refusal(result.status_code()));
            return;
          }
          ++run->next;
          schedule_unit(run);
        }));
  }
  catch (...)
  {
    // The validator threw instead of answering: that is the verdict for this unit.
    finish_validation(*run, ua::exception_to_status_code(std::current_exception()));
  }
}

/// Validates trust-list entries under @p options exactly as a peer certificate is validated against the
/// store - except that no host name or ApplicationUri is checked (a trust list entry is not a peer),
/// each certificate is validated for its use (an issuer-list entry, or a trusted one that declares cA
/// TRUE, as a CA), and the anchors are the trust list being installed, not the store's current one
/// (Part 12 7.8.2.3, Part 4 6.1.3). @p anchors is that whole list's certificates and the two CRL lists
/// its CRLs; @p trustedToValidate and @p issuersToValidate are the certificates validated, then each of
/// @p crlsToValidate is checked against @p anchors (Part 12 7.8.2.1). @p done receives Good, or
/// Bad_CertificateInvalid naming the first certificate or CRL that failed.
void validate_trust_list_async(std::shared_ptr<const Crypto> crypto, boost::asio::any_io_executor executor,
  Logger logger, TrustListValidationOptions options, CertificateList anchors, CrlList trustedCrls,
  CrlList issuerCrls, CertificateList trustedToValidate, const CertificateList& issuersToValidate,
  CrlList crlsToValidate, std::function<void(StatusCode)> done)
{
  auto run = std::make_shared<TrustListValidationRun>();
  run->crypto = std::move(crypto);
  run->executor = std::move(executor);
  run->logger = std::move(logger);
  run->options = options;
  run->anchors = std::move(anchors);
  run->trustedCrls = std::move(trustedCrls);
  run->issuerCrls = std::move(issuerCrls);
  run->certificates = std::move(trustedToValidate);
  run->issuerBegin = run->certificates.size();
  run->certificates.insert(run->certificates.end(), issuersToValidate.begin(), issuersToValidate.end());
  run->crls = std::move(crlsToValidate);
  run->done = std::move(done);
  schedule_unit(run);
}

}  // namespace

// ---------------------------------------------------------------------------
// Factory + constructor
// ---------------------------------------------------------------------------

std::shared_ptr<TrustListManager> TrustListManager::create(
  Dependencies deps, TrustListModifiedCallback onModified)
{
  auto mgr = std::shared_ptr<TrustListManager>(new TrustListManager(std::move(deps), std::move(onModified)));
  return mgr;
}

TrustListManager::TrustListManager(Dependencies deps, TrustListModifiedCallback onModified)
  : mStrand(std::move(deps.strand)), mCertificateStore(std::move(deps.certificateStore)),
    mCrypto(std::move(deps.crypto)), mExecutor(deps.executor), mOnModified(std::move(onModified)),
    mModificationClaim(std::move(deps.modificationClaim)),
    mImmediateModificationClaim(std::move(deps.immediateModificationClaim)),
    mOnOpenedForWrite(std::move(deps.openedForWrite)), mResetWaitLimit(deps.resetWaitLimit),
    mLogger(std::move(deps.logger)), mStageUntilApply(deps.stageUntilApply),
    mActivityTimeout(deps.activityTimeout), mMaxTrustListSize(deps.maxTrustListSize)
{}

// ---------------------------------------------------------------------------
// Helpers (must run on strand)
// ---------------------------------------------------------------------------

StatusCode TrustListManager::validate_handle(
  const OpenHandle& handle, const NodeId& sessionId, uint32_t fileHandle) const
{
  if (handle.fileHandle != fileHandle)
  {
    return StatusCode{Status::BadInvalidArgument};
  }
  if (handle.sessionId != sessionId)
  {
    return StatusCode{Status::BadInvalidArgument};
  }
  return StatusCode{Status::Good};
}

void TrustListManager::close_handle()
{
  mOpenHandle.reset();
  mInfo->openCount.store(0);
  if (mActivityTimer)
  {
    mActivityTimer->cancel();
    mActivityTimer.reset();
  }
}

void TrustListManager::reset_activity_timer()
{
  if (mActivityTimer)
  {
    mActivityTimer->cancel();
    mActivityTimer.reset();
  }

  auto me = weak_from_this();
  mActivityTimer.emplace(Timer::schedule_after(mStrand,
    mActivityTimeout,
    [me](boost::system::error_code ec)
    {
      if (ec)
      {
        return;  // Cancelled
      }
      auto self = me.lock();
      if (!self)
      {
        return;
      }
      // Already on our strand (schedule_after with strand parameter)
      self->on_activity_timeout();
    }));
}

void TrustListManager::on_activity_timeout()
{
  if (mOpenHandle)
  {
    mLogger.warning(
      "TrustListManager activity timeout - closing stale file handle {}", mOpenHandle->fileHandle);
    close_handle();
  }
}

// ---------------------------------------------------------------------------
// FileType: Open
// ---------------------------------------------------------------------------

void TrustListManager::open_async(
  NodeId sessionId, uint8_t mode, std::function<void(Result<uint32_t>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), mode](
      TrustListManager& self, std::function<void(Result<uint32_t>)> callback) mutable
    {
      try
      {
        // Part 12 7.8.2.1: Read, or Write with EraseExisting; no other mode.
        if (mode != sOpenRead && mode != sOpenWriteEraseExisting)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        if (mode == sOpenWriteEraseExisting)
        {
          // Part 12 Figure 22: Open with the write bit creates the push transaction or continues the
          // Session's own, and returns Bad_TransactionPending while another Session holds it (7.8.2.1) -
          // asked before the one-handle check, since another Session's write handle is its transaction. The
          // claim refuses or reserves it; the push service turns it into the transaction, notified before
          // the answer, so it is recorded before any later call of the Session reaches the service. Cost:
          // one claim under the push service lock and one post to its strand.
          StatusCode refusal{Status::Good};
          auto claim = self.take_claim(sessionId, refusal);
          if (!claim)
          {
            detail::invoke_user_callback(self.mLogger, callback, refusal);
            return;
          }
          if (self.mOpenHandle.has_value())
          {
            detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadNotWritable});
            return;
          }
          // Write mode: open with empty buffer
          auto handle = self.mNextFileHandle++;
          self.mOpenHandle.emplace(handle, sessionId, /*writeMode=*/true, sMaskAll, self.mMaxTrustListSize);
          self.mOpenHandle->transactionGeneration = claim->transaction_generation();
          self.mInfo->openCount.store(1);
          self.reset_activity_timer();
          if (self.mOnOpenedForWrite)
          {
            detail::invoke_user_callback(
              self.mLogger, self.mOnOpenedForWrite, std::move(sessionId), std::move(claim));
          }
          detail::invoke_user_callback(self.mLogger, callback, handle);
          return;
        }

        // Only one handle open at a time
        if (self.mOpenHandle.has_value())
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadNotWritable});
          return;
        }

        // Read mode: fetch all trust list data, encode, and return handle.
        // Already on strand - call internal helper directly. open_for_read_on_strand owns its own
        // error handling (it has a total try/catch that always consumes its callback), so it never
        // throws back here; pass a copy so the original callback stays valid for the catch below,
        // which guards only the pre-call code in this try block.
        self.open_for_read_on_strand(std::move(sessionId), sMaskAll, callback);
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// FileType: Close
// ---------------------------------------------------------------------------

void TrustListManager::close_async(
  NodeId sessionId, uint32_t fileHandle, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle](
      TrustListManager& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        self.close_handle();
        detail::invoke_user_callback(self.mLogger, callback, VoidResult{});
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// FileType: Read
// ---------------------------------------------------------------------------

void TrustListManager::read_async(NodeId sessionId, uint32_t fileHandle, int32_t length,
  std::function<void(Result<ByteString>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle, length](
      TrustListManager& self, std::function<void(Result<ByteString>)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        self.reset_activity_timer();

        // The caller's length is a request, not an allocation: it is clamped to what the encoded
        // trust list still holds past the current position, so a Read of INT32_MAX costs the
        // remainder, not 2 GiB of zero-filled memory (security review B3-10).
        const auto encodedSize = self.mOpenHandle->device.get_data().size();
        const auto position = numeric_cast<size_t>(self.mOpenHandle->stream.get_position());
        const size_t remaining = position < encodedSize ? encodedSize - position : 0;
        const auto readLength = std::min(numeric_cast<size_t>(length > 0 ? length : 0), remaining);
        std::vector<byte> buffer(readLength);
        auto bytesRead = self.mOpenHandle->stream.read(span<byte>{buffer});
        buffer.resize(bytesRead);

        detail::invoke_user_callback(self.mLogger, callback, ByteString{span<const byte>{buffer}});
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// FileType: Write
// ---------------------------------------------------------------------------

void TrustListManager::write_async(
  NodeId sessionId, uint32_t fileHandle, ByteString data, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle, data = std::move(data)](
      TrustListManager& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        if (!self.mOpenHandle->isWriteMode)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }

        self.reset_activity_timer();

        auto dataSpan = span<const byte>{reinterpret_cast<const byte*>(data.data()), data.size()};
        self.mOpenHandle->stream.write_all(dataSpan);

        detail::invoke_user_callback(self.mLogger, callback, VoidResult{});
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// FileType: GetPosition
// ---------------------------------------------------------------------------

void TrustListManager::get_position_async(
  NodeId sessionId, uint32_t fileHandle, std::function<void(Result<uint64_t>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle](
      TrustListManager& self, std::function<void(Result<uint64_t>)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        auto position = numeric_cast<uint64_t>(self.mOpenHandle->stream.get_position());
        detail::invoke_user_callback(self.mLogger, callback, position);
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// FileType: SetPosition
// ---------------------------------------------------------------------------

void TrustListManager::set_position_async(
  NodeId sessionId, uint32_t fileHandle, uint64_t position, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle, position](
      TrustListManager& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        self.mOpenHandle->stream.seek_from_start(numeric_cast<size_t>(position));
        detail::invoke_user_callback(self.mLogger, callback, VoidResult{});
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// TrustListManager: OpenWithMasks (always read mode)
// ---------------------------------------------------------------------------

void TrustListManager::open_with_masks_async(
  NodeId sessionId, uint32_t masks, std::function<void(Result<uint32_t>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), masks](
      TrustListManager& self, std::function<void(Result<uint32_t>)> callback) mutable
    {
      // Only one handle open at a time
      if (self.mOpenHandle.has_value())
      {
        detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadNotWritable});
        return;
      }

      self.open_for_read_on_strand(std::move(sessionId), masks, std::move(callback));
    })();
}

// Internal helper - must already be running on the strand.
void TrustListManager::open_for_read_on_strand(
  NodeId sessionId, uint32_t masks, std::function<void(Result<uint32_t>)> completionHandler)
{
  auto me = weak_from_this();

  try
  {
    // If masks is 0 or kMaskAll, fetch everything
    const uint32_t effectiveMasks = (masks == 0) ? sMaskAll : masks;

    // Chain sequential fetches from the CertificateStore.
    // Each step callback re-posts to the strand before touching strand-owned state.
    auto state = std::make_shared<ReadState>();

    // Step 1: Trusted certificates
    auto step1 = [me, sessionId, effectiveMasks, state, completionHandler](
                   CertificateListResult trustedCertsResult) mutable
    {
      auto lockedManager1 = me.lock();
      if (!lockedManager1)
      {
        detail::invoke_user_callback(completionHandler, StatusCode{Status::BadInternalError});
        return;
      }
      ua::async::post_borrowing(lockedManager1.get(),
        lockedManager1->mStrand,
        lockedManager1->mLogger,
        std::move(completionHandler),
        StatusCode{Status::BadInternalError},
        [me, sessionId, effectiveMasks, state, result = std::move(trustedCertsResult)](
          TrustListManager& self, std::function<void(Result<uint32_t>)> callback) mutable
        {
          if (!result.is_good())
          {
            detail::invoke_user_callback(self.mLogger, callback, store_answer_failure(result.status_code()));
            return;
          }
          if (effectiveMasks & sMaskTrustedCertificates)
          {
            state->trustedCerts = std::move(result).value();
          }

          // Step 2: Trusted CRLs
          auto step2 = [me, sessionId, effectiveMasks, state, callback](
                         CrlListResult trustedCrlsResult) mutable
          {
            auto lockedManager2 = me.lock();
            if (!lockedManager2)
            {
              detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
              return;
            }
            ua::async::post_borrowing(lockedManager2.get(),
              lockedManager2->mStrand,
              lockedManager2->mLogger,
              std::move(callback),
              StatusCode{Status::BadInternalError},
              [me, sessionId, effectiveMasks, state, result2 = std::move(trustedCrlsResult)](
                TrustListManager& self2, std::function<void(Result<uint32_t>)> callback2) mutable
              {
                if (!result2.is_good())
                {
                  detail::invoke_user_callback(
                    self2.mLogger, callback2, store_answer_failure(result2.status_code()));
                  return;
                }
                if (effectiveMasks & sMaskTrustedCrls)
                {
                  state->trustedCrls = std::move(result2).value();
                }

                // Step 3: Issuer certificates
                auto step3 = [me, sessionId, effectiveMasks, state, callback2](
                               CertificateListResult issuerCertsResult) mutable
                {
                  auto lockedManager3 = me.lock();
                  if (!lockedManager3)
                  {
                    detail::invoke_user_callback(callback2, StatusCode{Status::BadInternalError});
                    return;
                  }
                  ua::async::post_borrowing(lockedManager3.get(),
                    lockedManager3->mStrand,
                    lockedManager3->mLogger,
                    std::move(callback2),
                    StatusCode{Status::BadInternalError},
                    [me, sessionId, effectiveMasks, state, result3 = std::move(issuerCertsResult)](
                      TrustListManager& self3, std::function<void(Result<uint32_t>)> callback3) mutable
                    {
                      if (!result3.is_good())
                      {
                        detail::invoke_user_callback(
                          self3.mLogger, callback3, store_answer_failure(result3.status_code()));
                        return;
                      }
                      if (effectiveMasks & sMaskIssuerCertificates)
                      {
                        state->issuerCerts = std::move(result3).value();
                      }

                      // Step 4: Issuer CRLs
                      auto step4 = [me, sessionId, effectiveMasks, state, callback3](
                                     CrlListResult issuerCrlsResult) mutable
                      {
                        auto lockedManager4 = me.lock();
                        if (!lockedManager4)
                        {
                          detail::invoke_user_callback(callback3, StatusCode{Status::BadInternalError});
                          return;
                        }
                        ua::async::post_borrowing(lockedManager4.get(),
                          lockedManager4->mStrand,
                          lockedManager4->mLogger,
                          std::move(callback3),
                          StatusCode{Status::BadInternalError},
                          [sessionId = std::move(sessionId),
                            effectiveMasks,
                            state,
                            result4 = std::move(issuerCrlsResult)](
                            TrustListManager& self4, std::function<void(Result<uint32_t>)> callback4) mutable
                          {
                            try
                            {
                              if (!result4.is_good())
                              {
                                detail::invoke_user_callback(
                                  self4.mLogger, callback4, store_answer_failure(result4.status_code()));
                                return;
                              }
                              if (effectiveMasks & sMaskIssuerCrls)
                              {
                                state->issuerCrls = std::move(result4).value();
                              }

                              // Build TrustListDataType from accumulated state
                              TrustListDataType trustList;
                              trustList.specified_lists() = effectiveMasks;

                              for (auto& cert : state->trustedCerts)
                              {
                                trustList.trusted_certificates().push_back(cert->der_encoding());
                              }
                              for (auto& crl : state->trustedCrls)
                              {
                                trustList.trusted_crls().push_back(crl->der_encoding());
                              }
                              for (auto& cert : state->issuerCerts)
                              {
                                trustList.issuer_certificates().push_back(cert->der_encoding());
                              }
                              for (auto& crl : state->issuerCrls)
                              {
                                trustList.issuer_crls().push_back(crl->der_encoding());
                              }

                              // Encode to UA Binary
                              memory_stream_device::Dynamic encDevice(
                                self4.mMaxTrustListSize, /*reserve=*/true);
                              MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
                              UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
                              encoder.encode(EncodingLimits{}.stack_depth(), trustList);

                              auto encoded = encDevice.get_data();
                              if (encoded.size() > self4.mMaxTrustListSize)
                              {
                                detail::invoke_user_callback(
                                  self4.mLogger, callback4, StatusCode{Status::BadOutOfRange});
                                return;
                              }

                              // Create read-mode OpenHandle and populate with encoded data
                              auto handle = self4.mNextFileHandle++;
                              self4.mOpenHandle.emplace(handle,
                                std::move(sessionId),
                                /*writeMode=*/false,
                                effectiveMasks,
                                encoded.size());
                              self4.mOpenHandle->stream.write_all(encoded);
                              self4.mOpenHandle->stream.seek_from_start(0);
                              self4.mInfo->openCount.store(1);
                              self4.reset_activity_timer();

                              detail::invoke_user_callback(self4.mLogger, callback4, handle);
                            }
                            catch (...)
                            {
                              detail::invoke_user_callback(self4.mLogger,
                                callback4,
                                ua::exception_to_status_code(std::current_exception()));
                            }
                          })();
                      };

                      self3.mCertificateStore->get_issuer_crls_async(std::move(step4));
                    })();
                };

                self2.mCertificateStore->get_issuer_certificates_async(std::move(step3));
              })();
          };

          self.mCertificateStore->get_trusted_crls_async(std::move(step2));
        })();
    };

    mCertificateStore->get_trusted_certificates_async(std::move(step1));
  }
  catch (...)
  {
    detail::invoke_user_callback(
      mLogger, completionHandler, ua::exception_to_status_code(std::current_exception()));
  }
}

// ---------------------------------------------------------------------------
// TrustListManager: CloseAndUpdate
// ---------------------------------------------------------------------------

void TrustListManager::close_and_update_async(
  NodeId sessionId, uint32_t fileHandle, std::function<void(Result<bool>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), fileHandle](
      TrustListManager& self, std::function<void(Result<bool>)> callback) mutable
    {
      try
      {
        if (!self.mOpenHandle)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
          return;
        }

        auto status = self.validate_handle(*self.mOpenHandle, sessionId, fileHandle);
        if (status.is_bad())
        {
          detail::invoke_user_callback(self.mLogger, callback, status);
          return;
        }

        if (!self.mOpenHandle->isWriteMode)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }
        // One update at a time on the handle, refused before its data is even decoded: an update still
        // merging or replacing owns the claim, which a failing second call must not release. A
        // RemoveCertificate rewriting the list would be overwritten by the lists this update fetches.
        if (self.mUpdateClaim || self.list_writes_blocked())
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }

        // Read the complete buffer and decode
        auto data = self.mOpenHandle->device.get_data();
        if (data.empty())
        {
          // Empty trust list written - just close
          self.close_handle();
          detail::invoke_user_callback(self.mLogger, callback, true);
          return;
        }

        memory_stream_device::ExternalReadOnly readDevice(data);
        MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
        UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});

        TrustListDataType trustList;
        decoder.decode(EncodingLimits{}.stack_depth(), trustList);

        const uint32_t specifiedLists = trustList.specified_lists();

        // Convert ByteStrings to X509Certificate/X509Crl objects
        CertificateList trustedCerts;
        CrlList trustedCrls;
        CertificateList issuerCerts;
        CrlList issuerCrls;

        if (specifiedLists & sMaskTrustedCertificates)
        {
          for (auto& certDer : trustList.trusted_certificates())
          {
            auto certData = span<const byte>{reinterpret_cast<const byte*>(certDer.data()), certDer.size()};
            trustedCerts.push_back(self.mCrypto->read_certificate_from_der(certData));
          }
        }

        if (specifiedLists & sMaskTrustedCrls)
        {
          for (auto& crlDer : trustList.trusted_crls())
          {
            auto crlData = span<const byte>{reinterpret_cast<const byte*>(crlDer.data()), crlDer.size()};
            trustedCrls.push_back(self.mCrypto->read_crl_from_der(crlData));
          }
        }

        if (specifiedLists & sMaskIssuerCertificates)
        {
          for (auto& certDer : trustList.issuer_certificates())
          {
            auto certData = span<const byte>{reinterpret_cast<const byte*>(certDer.data()), certDer.size()};
            issuerCerts.push_back(self.mCrypto->read_certificate_from_der(certData));
          }
        }

        if (specifiedLists & sMaskIssuerCrls)
        {
          for (auto& crlDer : trustList.issuer_crls())
          {
            auto crlData = span<const byte>{reinterpret_cast<const byte*>(crlDer.data()), crlDer.size()};
            issuerCrls.push_back(self.mCrypto->read_crl_from_der(crlData));
          }
        }

        // Part 12 7.8.2.3: the change is refused up front while another session owns the push
        // transaction (it would otherwise be applied and left out of that transaction's
        // re-evaluation), the unmasked lists are kept as they are, and every uploaded certificate
        // is validated before anything is written (security review B3-3).
        StatusCode refusal{Status::Good};
        auto claim = self.take_claim(sessionId, refusal);
        if (!claim)
        {
          self.close_handle();
          detail::invoke_user_callback(self.mLogger, callback, refusal);
          return;
        }
        // The upload belongs to the transaction the handle was opened in (Figure 22); once that has ended
        // (CancelChanges, ApplyChanges) it is not carried into another one (owner decision Q2).
        if (claim->transaction_generation() != self.mOpenHandle->transactionGeneration)
        {
          self.close_handle();
          detail::invoke_user_callback(self.mLogger,
            callback,
            StatusCode{Status::BadInvalidState,
              make_error_detail("TrustListTransactionEnded",
                "the transaction this TrustList was opened in has ended; nothing was changed",
                "TrustListManager")});
          return;
        }
        auto pending = std::make_shared<PendingUpdate>();
        pending->sessionId = std::move(sessionId);
        pending->specifiedLists = specifiedLists;
        pending->trustedCerts = std::move(trustedCerts);
        pending->trustedCrls = std::move(trustedCrls);
        pending->issuerCerts = std::move(issuerCerts);
        pending->issuerCrls = std::move(issuerCrls);
        pending->callback = std::move(callback);
        pending->fileHandle = fileHandle;
        // The update's list write: held until the update ends (a staged update writes no store, but a reset
        // must not clear lists that the merge then stages again).
        pending->writeToken = self.begin_list_write();
        self.mUpdateClaim = std::move(claim);
        self.mUpdateFileHandle = fileHandle;
        try
        {
          self.merge_pending_update_on_strand(pending, 0);
        }
        catch (...)
        {
          self.abandon_pending_update(*pending, ua::exception_to_status_code(std::current_exception()));
        }
        return;
      }
      catch (...)
      {
        // Reached only before this call took a claim or after it handed the claim to the pending
        // update's own error path, so an update in flight is never released from here.
        self.close_handle();
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// TrustListManager: CloseAndUpdate - merge, validate, replace (all on the strand)
// ---------------------------------------------------------------------------

std::shared_ptr<TrustListModificationClaim> TrustListManager::take_claim(
  const NodeId& sessionId, StatusCode& refusal, bool immediate)
{
  refusal = StatusCode{Status::Good};
  const auto& gate =
    immediate && mImmediateModificationClaim ? mImmediateModificationClaim : mModificationClaim;
  if (!gate)
  {
    return std::make_shared<TrustListModificationClaim>(nullptr);
  }
  auto granted = gate(sessionId);
  if (!granted.is_good())
  {
    refusal = granted.status_code();
    return nullptr;
  }
  auto claim = std::move(granted).value();
  return claim ? claim : std::make_shared<TrustListModificationClaim>(nullptr);
}

void TrustListManager::close_update_handle()
{
  if (mOpenHandle && mOpenHandle->fileHandle == mUpdateFileHandle)
  {
    close_handle();
  }
}

void TrustListManager::merge_pending_update_on_strand(std::shared_ptr<PendingUpdate> pending, unsigned step)
{
  // Part 12 7.8.2.3: "If a bit is not set then the associated field is not changed". Each unmasked
  // list is read from the store so the replacement below installs it unchanged. Store callbacks may
  // arrive on any thread; every continuation re-posts to this strand through the completion-owning
  // post, so a manager gone before the turn, or a throw inside it, still completes the method.
  auto me = weak_from_this();
  const auto continueWith = [me, pending](unsigned next, auto assign)
  {
    return [me, pending, next, assign](auto result) mutable
    {
      auto locked = me.lock();
      if (!locked)
      {
        detail::invoke_user_callback(pending->callback, StatusCode{Status::BadInternalError});
        return;
      }
      auto callback = pending->callback;
      ua::async::post_borrowing(locked.get(),
        locked->mStrand,
        locked->mLogger,
        std::move(callback),
        StatusCode{Status::BadInternalError},
        [pending, next, assign, result = std::move(result)](
          TrustListManager& self, std::function<void(Result<bool>)> completion) mutable
        {
          pending->callback = std::move(completion);
          try
          {
            if (!result.is_good())
            {
              self.abandon_pending_update(*pending, store_answer_failure(result.status_code()));
              return;
            }
            assign(*pending, std::move(result).value());
            self.merge_pending_update_on_strand(pending, next);
          }
          catch (...)
          {
            self.abandon_pending_update(*pending, ua::exception_to_status_code(std::current_exception()));
          }
        })();
    };
  };

  if (step == 0 && mStaged && mUpdateClaim && mStagedGeneration != mUpdateClaim->transaction_generation())
  {
    // Staged in a transaction that has ended (cancelled or applied while that CloseAndUpdate ran, its
    // discard not yet here): none of it belongs to this one, so the merge starts from the store.
    mStaged.reset();
    ++mModificationCount;
  }
  if (step == 0 && mStaged && mStagedSessionId != pending->sessionId)
  {
    // Staged lists belong to one Session's transaction; the push gate refuses every other Session, so
    // this is a backstop (review BR-13).
    abandon_pending_update(*pending, StatusCode{Status::BadTransactionPending});
    return;
  }
  if (step == 0 && mStaged)
  {
    // Part 12 7.8.2.3: inside a transaction the TrustList is the staged one, so an unmasked list is kept
    // as the transaction has it, not as the store has it.
    if (!(pending->specifiedLists & sMaskTrustedCertificates))
      pending->trustedCerts = mStaged->trustedCerts;
    if (!(pending->specifiedLists & sMaskTrustedCrls))
      pending->trustedCrls = mStaged->trustedCrls;
    if (!(pending->specifiedLists & sMaskIssuerCertificates))
      pending->issuerCerts = mStaged->issuerCerts;
    if (!(pending->specifiedLists & sMaskIssuerCrls))
      pending->issuerCrls = mStaged->issuerCrls;
    validate_and_replace_on_strand(std::move(pending));
    return;
  }
  if (step <= 0 && !(pending->specifiedLists & sMaskTrustedCertificates))
  {
    mCertificateStore->get_trusted_certificates_async(
      continueWith(1, [](PendingUpdate& u, CertificateList list) { u.trustedCerts = std::move(list); }));
    return;
  }
  if (step <= 1 && !(pending->specifiedLists & sMaskTrustedCrls))
  {
    mCertificateStore->get_trusted_crls_async(
      continueWith(2, [](PendingUpdate& u, CrlList list) { u.trustedCrls = std::move(list); }));
    return;
  }
  if (step <= 2 && !(pending->specifiedLists & sMaskIssuerCertificates))
  {
    mCertificateStore->get_issuer_certificates_async(
      continueWith(3, [](PendingUpdate& u, CertificateList list) { u.issuerCerts = std::move(list); }));
    return;
  }
  if (step <= 3 && !(pending->specifiedLists & sMaskIssuerCrls))
  {
    mCertificateStore->get_issuer_crls_async(
      continueWith(4, [](PendingUpdate& u, CrlList list) { u.issuerCrls = std::move(list); }));
    return;
  }

  validate_and_replace_on_strand(std::move(pending));
}

void TrustListManager::validate_and_replace_on_strand(std::shared_ptr<PendingUpdate> pending)
{
  // Part 12 7.8.2.3: "The Server shall verify that every Certificate in the new TrustList is valid
  // using the validation process defined in OPC 10000-4. If an invalid Certificate is found the Server
  // shall return an error and shall not replace the existing TrustList." Every certificate of the NEW
  // list - uploaded and kept halves, trusted and issuer - is validated with the new list as its anchors
  // and chain material and the new list's CRLs, under the group's validation options as the store holds
  // them now; then every CRL of the new list (Part 12 7.8.2.1: "will validate all new Certificates and
  // CRLs"). A kept certificate that has since expired or been revoked therefore refuses the update until
  // it is removed or replaced, or the matching suppression is configured. The lists are copied: the
  // validator may answer on any thread and must not touch the pending update.
  CertificateList anchors = pending->trustedCerts;
  anchors.insert(anchors.end(), pending->issuerCerts.begin(), pending->issuerCerts.end());
  CrlList crls = pending->trustedCrls;
  crls.insert(crls.end(), pending->issuerCrls.begin(), pending->issuerCrls.end());
  auto me = weak_from_this();
  validate_trust_list_async(mCrypto,
    mExecutor,
    mLogger,
    mCertificateStore->validation_options(),
    std::move(anchors),
    pending->trustedCrls,
    pending->issuerCrls,
    pending->trustedCerts,
    pending->issuerCerts,
    std::move(crls),
    [me, pending](StatusCode verdict) mutable
    {
      auto locked = me.lock();
      if (!locked)
      {
        detail::invoke_user_callback(pending->callback, StatusCode{Status::BadInternalError});
        return;
      }
      auto callback = pending->callback;
      ua::async::post_borrowing(locked.get(),
        locked->mStrand,
        locked->mLogger,
        std::move(callback),
        StatusCode{Status::BadInternalError},
        [pending, verdict = std::move(verdict)](
          TrustListManager& self, std::function<void(Result<bool>)> completion) mutable
        {
          pending->callback = std::move(completion);
          try
          {
            if (verdict.is_bad())
            {
              // The operator needs to know which certificate or CRL refused the update: the Method result
              // carries only the status (Part 12 7.8.2.3).
              const std::string reason = ua::describe(verdict);
              self.mLogger.warning({{"error", std::string_view{reason}}},
                "TrustList update refused: the new TrustList is not valid and was not applied");
              self.abandon_pending_update(*pending, std::move(verdict));
              return;
            }
            // The merge and the validation spanned asynchronous steps: the write handle must still be
            // this session's (the activity timer or a Close may have closed it meanwhile) before the
            // lists fetched then are written back, or a stale list would overwrite a change made in
            // between.
            if (!self.mOpenHandle || !self.mOpenHandle->isWriteMode ||
                self.mOpenHandle->sessionId != pending->sessionId ||
                self.mOpenHandle->fileHandle != pending->fileHandle)
            {
              self.abandon_pending_update(*pending, StatusCode{Status::BadInvalidState});
              return;
            }
            self.replace_lists_on_strand(pending);
          }
          catch (...)
          {
            self.abandon_pending_update(*pending, ua::exception_to_status_code(std::current_exception()));
          }
        })();
    });
}

void TrustListManager::abandon_pending_update(PendingUpdate& pending, StatusCode status)
{
  close_update_handle();
  mUpdateClaim.reset();  // released: the modification did not go through
  pending.writeToken.reset();  // the update is over, whoever still holds the PendingUpdate
  auto callback = std::move(pending.callback);
  if (callback)
  {
    detail::invoke_user_callback(mLogger, callback, status);
  }
}

void TrustListManager::replace_lists_on_strand(std::shared_ptr<PendingUpdate> pending)
{
  // Apply changes to the CertificateStore.
  // Chain: replace trusted -> replace issuer -> update time -> close -> notify.
  ++mModificationCount;  // an AddCertificate validated against the lists before this is refused
  const bool hasTrusted = (pending->specifiedLists & (sMaskTrustedCertificates | sMaskTrustedCrls)) != 0;
  const bool hasIssuer = (pending->specifiedLists & (sMaskIssuerCertificates | sMaskIssuerCrls)) != 0;
  auto& self = *this;
  auto sessionId = std::move(pending->sessionId);
  auto callback = std::move(pending->callback);
  auto trustedCerts = std::move(pending->trustedCerts);
  auto trustedCrls = std::move(pending->trustedCrls);
  auto issuerCerts = std::move(pending->issuerCerts);
  auto issuerCrls = std::move(pending->issuerCrls);
  // The update's list write, carried to each answer below and released there: a copy of the PendingUpdate
  // that a crypto or store callback still holds then holds no token.
  auto writing = std::move(pending->writeToken);

  if (mStageUntilApply)
  {
    // Part 12 7.8.2.3: the new lists are the transaction's until ApplyChanges writes them (the merge
    // made them complete, so they replace everything staged before).
    mStaged = detail::TrustListContent{.trustedCerts = std::move(trustedCerts),
      .trustedCrls = std::move(trustedCrls),
      .issuerCerts = std::move(issuerCerts),
      .issuerCrls = std::move(issuerCrls)};
    mStagedSessionId = sessionId;
    mStagedGeneration = mUpdateClaim ? mUpdateClaim->transaction_generation() : 0;
    close_update_handle();
    writing.reset();  // staging writes no store
    auto claim = std::exchange(mUpdateClaim, nullptr);  // the modified callback's transaction takes it over
    // Notified before the caller is answered: the push service records the transaction on its strand,
    // where the client's ApplyChanges also runs, so it is recorded before the client can act on the
    // response (answering first let an immediate ApplyChanges find no transaction: Bad_NothingToDo).
    if (mOnModified)
    {
      detail::invoke_user_callback(mLogger, mOnModified, std::move(sessionId), std::move(claim));
    }
    detail::invoke_user_callback(mLogger, callback, true);
    return;
  }

  // Step: replace issuer certificates (final store operation)
  // This lambda is called as a CertificateStore callback, so it re-posts to strand.
  auto me = self.weak_from_this();
  auto replaceIssuer = [me,
                         sessionId,
                         hasIssuer,
                         issuerCerts = std::move(issuerCerts),
                         issuerCrls = std::move(issuerCrls),
                         writing = std::move(writing),
                         callback](VoidResult trustedResult) mutable
  {
    auto lockedManager1 = me.lock();
    if (!lockedManager1)
    {
      detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
      return;
    }
    ua::async::post_borrowing(lockedManager1.get(),
      lockedManager1->mStrand,
      lockedManager1->mLogger,
      std::move(callback),
      StatusCode{Status::BadInternalError},
      [me,
        sessionId = std::move(sessionId),
        hasIssuer,
        issuerCerts = std::move(issuerCerts),
        issuerCrls = std::move(issuerCrls),
        writing = std::move(writing),
        trustedResult = std::move(trustedResult)](
        TrustListManager& self2, std::function<void(Result<bool>)> callback2) mutable
      {
        if (trustedResult.is_bad())
        {
          writing.reset();
          self2.close_update_handle();
          self2.mUpdateClaim.reset();
          detail::invoke_user_callback(self2.mLogger, callback2, trustedResult.status_code());
          return;
        }

        if (!hasIssuer)
        {
          // No issuer replacement needed - finalize
          writing.reset();
          self2.mInfo->lastUpdateTime.store(DateTime::now().value().time_since_epoch().count());
          auto onModified = self2.mOnModified;
          auto sid = std::move(sessionId);
          self2.close_update_handle();
          auto claim =
            std::exchange(self2.mUpdateClaim, nullptr);  // the modified callback's transaction takes it over
          // Notified before the caller is answered: the push service records the transaction on its strand,
          // where the client's ApplyChanges also runs, so it is recorded before the client can act on the
          // response (answering first let an immediate ApplyChanges find no transaction: Bad_NothingToDo).
          if (onModified)
          {
            detail::invoke_user_callback(self2.mLogger, onModified, std::move(sid), std::move(claim));
          }
          detail::invoke_user_callback(self2.mLogger, callback2, true);
          return;
        }

        self2.mCertificateStore->replace_issuer_certificates_async(std::move(issuerCerts),
          std::move(issuerCrls),

          [me, sessionId = std::move(sessionId), writing = std::move(writing), callback2](
            VoidResult issuerResult) mutable
          {
            auto lockedManager2 = me.lock();
            if (!lockedManager2)
            {
              detail::invoke_user_callback(callback2, StatusCode{Status::BadInternalError});
              return;
            }
            ua::async::post_borrowing(lockedManager2.get(),
              lockedManager2->mStrand,
              lockedManager2->mLogger,
              std::move(callback2),
              StatusCode{Status::BadInternalError},
              [sessionId = std::move(sessionId),
                writing = std::move(writing),
                issuerResult = std::move(issuerResult)](
                TrustListManager& self3, std::function<void(Result<bool>)> callback3) mutable
              {
                writing.reset();  // both lists are written (or the write failed)
                if (issuerResult.is_bad())
                {
                  self3.close_update_handle();
                  self3.mUpdateClaim.reset();
                  detail::invoke_user_callback(self3.mLogger, callback3, issuerResult.status_code());
                  return;
                }

                self3.mInfo->lastUpdateTime.store(DateTime::now().value().time_since_epoch().count());
                auto onModified = self3.mOnModified;
                auto sid = std::move(sessionId);
                self3.close_update_handle();
                // The modified callback's transaction takes the claim over.
                auto claim = std::exchange(self3.mUpdateClaim, nullptr);
                // Notified before the caller is answered: the push service records the transaction on its
                // strand, where the client's ApplyChanges also runs, so it is recorded before the client can
                // act on the response (answering first let an immediate ApplyChanges find no transaction:
                // Bad_NothingToDo).
                if (onModified)
                {
                  detail::invoke_user_callback(self3.mLogger, onModified, std::move(sid), std::move(claim));
                }
                detail::invoke_user_callback(self3.mLogger, callback3, true);
              })();
          });
      })();
  };

  if (hasTrusted)
  {
    self.mCertificateStore->replace_trusted_certificates_async(
      std::move(trustedCerts), std::move(trustedCrls), std::move(replaceIssuer));
  }
  else
  {
    // No trusted replacement - go directly to issuer step
    replaceIssuer(VoidResult{});
  }
}

// ---------------------------------------------------------------------------
// TrustListManager: AddCertificate
// ---------------------------------------------------------------------------

void TrustListManager::add_certificate_async(NodeId sessionId, ByteString certificate,
  bool isTrustedCertificate, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), certificate = std::move(certificate), isTrustedCertificate](
      TrustListManager& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        // Part 12 7.8.2.4: a certificate that is not to be trusted is refused (Bad_CertificateInvalid)
        // rather than quietly added as an issuer - whatever else holds, so it is tested first; a
        // TrustList open for write refuses AddCertificate (Bad_InvalidState); the push transaction's
        // owner is the only session that may modify; the certificate is validated before it is stored
        // (security review B3-4).
        if (!isTrustedCertificate)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadCertificateInvalid});
          return;
        }
        if (self.mOpenHandle && self.mOpenHandle->isWriteMode)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }
        if (self.mUpdateClaim || self.list_writes_blocked())
        {
          // A CloseAndUpdate is merging or replacing, or a RemoveCertificate is rewriting the list: a
          // change now would be overwritten by the lists they fetched.
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }
        if (self.mStaged)
        {
          // Part 12 7.8.2.4 / 7.8.2.5: a staged CloseAndUpdate is a transaction in progress (its push
          // transaction may not have been recorded yet), and ApplyChanges would write over this change.
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadTransactionPending});
          return;
        }
        StatusCode refusal{Status::Good};
        auto claim = self.take_claim(sessionId, refusal, /*immediate=*/true);
        if (!claim)
        {
          detail::invoke_user_callback(self.mLogger, callback, refusal);
          return;
        }
        auto certData =
          span<const byte>{reinterpret_cast<const byte*>(certificate.data()), certificate.size()};
        shared_ptr<const X509Certificate> cert = self.mCrypto->read_certificate_from_der(certData);
        // OPC 10000-12 7.8.2.4: AddCertificate cannot provide CRLs, so it cannot add an issuer; a CA
        // certificate is refused (CA certificates and their CRLs are managed with Write). The one exception
        // is a self-signed ApplicationInstance Certificate that carries cA TRUE, which OPC 10000-6 Table 43
        // requires to be accepted "to ensure backward interoperability" (other and older stacks issue them;
        // the SDK's own carry cA FALSE): it must name an application (a SubjectAltName URI, which a root CA
        // does not carry) and pass the ApplicationInstance usage rules, which hold it to pathLength 0 (or
        // none, owner decision 25) and keyCertSign. It is then a trusted peer, not an issuer. Cost: a few
        // accessor calls, once per call.
        const bool selfSignedApplicationMarkedCa =
          cert->basic_constraints_ca() && cert->self_signed() && !cert->san_uris().empty() &&
          ::ua::detail::check_certificate_usage(*cert, CertificateUse::ApplicationInstance).is_good();
        if (cert->basic_constraints_ca() && !selfSignedApplicationMarkedCa)
        {
          detail::invoke_user_callback(self.mLogger,
            callback,
            StatusCode{Status::BadCertificateInvalid,
              make_error_detail("AddCertificateCannotAddACaCertificate",
                "AddCertificate cannot add a CA certificate; manage CA certificates and their CRLs with "
                "Write",
                "TrustListManager")});
          return;
        }

        auto me = self.weak_from_this();
        auto onComplete = [me, callback, claim](VoidResult result) mutable
        {
          auto lockedManager = me.lock();
          if (!lockedManager)
          {
            detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
            return;
          }
          ua::async::post_borrowing(lockedManager.get(),
            lockedManager->mStrand,
            lockedManager->mLogger,
            std::move(callback),
            StatusCode{Status::BadInternalError},
            [result = std::move(result), claim = std::move(claim)](
              TrustListManager& self2, std::function<void(VoidResult)> callback2) mutable
            {
              if (result.is_bad())
              {
                claim.reset();  // released before the caller hears of the failure
                detail::invoke_user_callback(self2.mLogger, callback2, std::move(result));
                return;
              }

              self2.mInfo->lastUpdateTime.store(DateTime::now().value().time_since_epoch().count());
              // Part 12 7.8.2.4 / 7.8.2.5: applied at once, outside any transaction; the claim is released
              // before the caller hears of it, and the caller re-evaluates the open Sessions.
              claim.reset();
              detail::invoke_user_callback(self2.mLogger, callback2, VoidResult{});
            })();
        };

        // Part 12 7.8.2.4: "The Server shall verify that the Certificate using the validation process
        // defined in OPC 10000-4" and "will return a validation error if the Certificate is issued by a
        // CA and the Certificate for the issuer is not in the Trust List". The anchors are the trust
        // list as it would be with the certificate added (the store's lists and the certificate), under
        // the group's validation options as the store holds them now. A refusal goes through `finishAdd`,
        // which releases the claim. One instance on every path, answered at most once (a store that
        // answers and then throws cannot complete it twice): the claim it carries moves out on its single
        // call, so no copy of a continuation keeps a refused modification's claim alive.
        auto finishAdd = std::make_shared<std::function<void(VoidResult)>>(
          detail::make_fire_once<VoidResult>(std::move(onComplete)));
        auto crypto = self.mCrypto;
        auto executor = self.mExecutor;
        auto logger = self.mLogger;
        const auto options = self.mCertificateStore->validation_options();
        // The lists validated against are the store's as of now: a change applied before the commit
        // makes the verdict stale, and the commit refuses (TOCTOU).
        const auto modificationCountAtStart = self.mModificationCount;
        fetch_store_lists_async(self.mCertificateStore,
          [me, crypto, executor, logger, options, cert, finishAdd, modificationCountAtStart](
            Result<std::shared_ptr<ReadState>> fetched) mutable
          {
            if (!fetched.is_good() || !fetched.value())
            {
              (*finishAdd)(VoidResult{
                !fetched.is_good() ? fetched.status_code() : StatusCode{Status::BadInternalError}});
              return;
            }
            auto lists = std::move(fetched).value();
            CertificateList anchors = std::move(lists->trustedCerts);
            anchors.insert(anchors.end(), lists->issuerCerts.begin(), lists->issuerCerts.end());
            anchors.push_back(cert);
            validate_trust_list_async(std::move(crypto),
              std::move(executor),
              std::move(logger),
              options,
              std::move(anchors),
              std::move(lists->trustedCrls),
              std::move(lists->issuerCrls),
              CertificateList{cert},
              CertificateList{},
              CrlList{},
              [me, cert, finishAdd, modificationCountAtStart](StatusCode verdict) mutable
              {
                if (verdict.is_bad())
                {
                  (*finishAdd)(VoidResult{std::move(verdict)});
                  return;
                }
                auto locked = me.lock();
                if (!locked)
                {
                  (*finishAdd)(VoidResult{StatusCode{Status::BadInternalError}});
                  return;
                }
                // Back on the strand before the store is changed: a CloseAndUpdate that began while the
                // certificate was validated would replace the lists it fetched over this addition.
                ua::async::post_borrowing(locked.get(),
                  locked->mStrand,
                  locked->mLogger,
                  std::function<void(VoidResult)>{[finishAdd](VoidResult result)
                    {
                      (*finishAdd)(std::move(result));
                    }},
                  StatusCode{Status::BadInternalError},
                  [cert, modificationCountAtStart](
                    TrustListManager& self2, std::function<void(VoidResult)> complete) mutable
                  {
                    try
                    {
                      if ((self2.mOpenHandle && self2.mOpenHandle->isWriteMode) || self2.mUpdateClaim ||
                          self2.list_writes_blocked())
                      {
                        complete(VoidResult{StatusCode{Status::BadInvalidState}});
                        return;
                      }
                      if (self2.mStaged)
                      {
                        complete(VoidResult{StatusCode{Status::BadTransactionPending}});
                        return;
                      }
                      if (self2.mModificationCount != modificationCountAtStart)
                      {
                        complete(VoidResult{StatusCode{Status::BadInvalidState,
                          make_error_detail("TrustListChangedDuringValidation",
                            "the trust list changed while the certificate was validated against it; the "
                            "certificate is not added",
                            "TrustListManager")}});
                        return;
                      }
                      ++self2.mModificationCount;
                      // Held until the store has written the certificate (one list write at a time).
                      auto writing = self2.begin_list_write();
                      self2.mCertificateStore->add_to_trusted_certificates_async(std::move(cert),
                        [complete, writing = std::move(writing)](VoidResult result) mutable
                        {
                          writing.reset();
                          complete(std::move(result));
                        });
                    }
                    catch (...)
                    {
                      // `complete` reaches the fire-once `finishAdd`, so a store that answered and then
                      // threw is not answered twice.
                      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
                    }
                  })();
              });
          });
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// TrustListManager: RemoveCertificate
// ---------------------------------------------------------------------------

void TrustListManager::remove_certificate_async(NodeId sessionId, std::string thumbprint,
  bool isTrustedCertificate, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), thumbprint = std::move(thumbprint), isTrustedCertificate](
      TrustListManager& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        // Part 12 7.8.2.5: refused while the TrustList is open for write, and while another session
        // owns the push transaction (security review B3-3/B3-4).
        if (self.mOpenHandle && self.mOpenHandle->isWriteMode)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }
        if (self.mUpdateClaim || self.list_writes_blocked())
        {
          // A CloseAndUpdate is merging or replacing, or another RemoveCertificate is rewriting the list:
          // a change now would be overwritten by the lists they fetched.
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidState});
          return;
        }
        if (self.mStaged)
        {
          // Part 12 7.8.2.4 / 7.8.2.5: a staged CloseAndUpdate is a transaction in progress (its push
          // transaction may not have been recorded yet), and ApplyChanges would write over this change.
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadTransactionPending});
          return;
        }
        // Decision 28: the thumbprint is 40 hexadecimal digits, compared as bytes.
        auto wanted = detail::decode_thumbprint(thumbprint);
        if (!wanted)
        {
          detail::invoke_user_callback(self.mLogger,
            callback,
            StatusCode{Status::BadInvalidArgument,
              make_error_detail("ThumbprintMalformed",
                "The thumbprint is not 40 hexadecimal digits (a SHA-1 thumbprint)",
                "TrustListManager")});
          return;
        }
        StatusCode refusal{Status::Good};
        auto claim = self.take_claim(sessionId, refusal, /*immediate=*/true);
        if (!claim)
        {
          detail::invoke_user_callback(self.mLogger, callback, refusal);
          return;
        }
        auto me = self.weak_from_this();
        // The list is read, then rewritten, while this token lives: AddCertificate, CloseAndUpdate and
        // another RemoveCertificate are refused until then. It travels with the completion, so a store or
        // crypto that drops its callback cannot leave the manager refusing every change.
        auto inFlight = self.begin_list_write();
        // Every outcome ends here, on the strand: the list rewrite is over, and the claim is released
        // before the caller hears of it. Fire-once: every error path may call it.
        auto onComplete = detail::make_fire_once<VoidResult>(
          [me, callback, claim, inFlight](VoidResult result) mutable
          {
            auto lockedManager = me.lock();
            if (!lockedManager)
            {
              detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
              return;
            }
            ua::async::post_borrowing(lockedManager.get(),
              lockedManager->mStrand,
              lockedManager->mLogger,
              std::move(callback),
              StatusCode{Status::BadInternalError},
              [result = std::move(result), claim = std::move(claim), inFlight = std::move(inFlight)](
                TrustListManager& self2, std::function<void(VoidResult)> callback2) mutable
              {
                inFlight.reset();
                if (result.is_bad())
                {
                  claim.reset();  // released before the caller hears of the failure
                  detail::invoke_user_callback(self2.mLogger, callback2, std::move(result));
                  return;
                }

                self2.mInfo->lastUpdateTime.store(DateTime::now().value().time_since_epoch().count());
                // Part 12 7.8.2.4 / 7.8.2.5: applied at once, outside any transaction; the claim is released
                // before the caller hears of it, and the caller re-evaluates the open Sessions.
                claim.reset();
                detail::invoke_user_callback(self2.mLogger, callback2, VoidResult{});
              })();
          });

        ++self.mModificationCount;  // an AddCertificate validated against the lists before this is refused
        inFlight.reset();  // the completion holds it now
        self.read_list_for_removal(isTrustedCertificate, std::move(*wanted), thumbprint, onComplete);
      }
      catch (...)
      {
        detail::invoke_user_callback(
          self.mLogger, callback, ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

void TrustListManager::read_list_for_removal(bool isTrustedCertificate, std::vector<uint8_t> wanted,
  std::string thumbprint, std::function<void(VoidResult)> onComplete)
{
  // Part 12 7.8.2.5: "If the Certificate is a CA Certificate that has CRLs then all CRLs for that CA are
  // removed as well" (Mantis 6796: only that CA's). The list the certificate is removed from is read with
  // its CRLs, so the certificate is found here (an unknown thumbprint is Bad_InvalidArgument) and a CA's
  // CRLs leave in the same store swap as the CA. Cost: two store reads per RemoveCertificate (an
  // administrative Method) and one CRL scan.
  auto store = mCertificateStore;
  auto crypto = mCrypto;
  auto executor = mExecutor;
  auto logger = mLogger;
  // onComplete is fire-once: once it fires it has moved the claim and the in-flight token to the strand, so
  // a copy left in a finished callback holds neither.
  auto onCertificates = [store,
                          crypto,
                          executor,
                          logger,
                          isTrustedCertificate,
                          wanted = std::move(wanted),
                          thumbprint = std::move(thumbprint),
                          onComplete = std::move(onComplete)](CertificateListResult certificates) mutable
  {
    if (!certificates.is_good())
    {
      onComplete(VoidResult{store_answer_failure(certificates.status_code())});
      return;
    }
    auto onCrls = [store,
                    crypto,
                    executor,
                    logger,
                    isTrustedCertificate,
                    wanted = std::move(wanted),
                    thumbprint = std::move(thumbprint),
                    certificates = std::move(certificates).value(),
                    onComplete](CrlListResult crls) mutable
    {
      try
      {
        if (!crls.is_good())
        {
          onComplete(VoidResult{store_answer_failure(crls.status_code())});
          return;
        }
        auto list = std::move(crls).value();
        const auto it = std::ranges::find_if(certificates,
          [&](const auto& certificate)
          { return certificate && detail::thumbprint_matches(*certificate, wanted); });
        if (it == certificates.end())
        {
          onComplete(VoidResult{certificate_not_in_list(thumbprint)});
          return;
        }
        if (!(*it)->basic_constraints_ca() || list.empty())
        {
          // Not a CA, or no CRLs in the list: the single-certificate removal, as before.
          remove_one_certificate(*store, isTrustedCertificate, thumbprint, onComplete);
          return;
        }
        auto scan = std::make_shared<CaCrlScan>();
        scan->store = store;
        scan->crypto = crypto;
        scan->executor = executor;
        scan->logger = logger;
        scan->isTrustedCertificate = isTrustedCertificate;
        scan->thumbprint = std::move(thumbprint);
        scan->ca = {*it};
        certificates.erase(it);
        scan->certificates = std::move(certificates);
        scan->crls = std::move(list);
        scan->onComplete = onComplete;
        scan_next_ca_crl(std::move(scan));
      }
      catch (...)
      {
        onComplete(VoidResult{ua::exception_to_status_code(std::current_exception())});
      }
    };
    if (isTrustedCertificate)
      store->get_trusted_crls_async(std::move(onCrls));
    else
      store->get_issuer_crls_async(std::move(onCrls));
  };
  if (isTrustedCertificate)
    mCertificateStore->get_trusted_certificates_async(std::move(onCertificates));
  else
    mCertificateStore->get_issuer_certificates_async(std::move(onCertificates));
}

// ---------------------------------------------------------------------------
// ApplyChanges / CancelChanges: the staged lists
// ---------------------------------------------------------------------------

void TrustListManager::apply_staged_async(std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [](TrustListManager& self, std::function<void(VoidResult)> callback)
    {
      // Answered once: a store that answers and then throws cannot complete the apply twice.
      self.apply_staged_on_strand(detail::make_fire_once<VoidResult>(std::move(callback)));
    })();
}

void TrustListManager::apply_staged_on_strand(std::function<void(VoidResult)> finish)
{
  try
  {
    if (list_writes_blocked())
    {
      // The ApplyChanges preflight refuses while a list write is in progress (is_write_open_async); this is
      // the narrow gap after it. Refused, not waited for: the lists were verified as they are now.
      finish(VoidResult{StatusCode{Status::BadInvalidState,
        make_error_detail("TrustListWriteInProgress",
          "a TrustList write is in progress; ApplyChanges writes nothing",
          "TrustListManager")}});
      return;
    }
    if (!mStaged)
    {
      finish(VoidResult{});
      return;
    }
    auto staged = std::move(*mStaged);
    mStaged.reset();
    ++mModificationCount;  // an AddCertificate validated against the staged lists is refused
    auto me = weak_from_this();
    auto writing = begin_list_write();  // held until both lists are written
    // Trusted, then issuer: the two store calls the immediate (untransacted) update makes.
    mCertificateStore->replace_trusted_certificates_async(std::move(staged.trustedCerts),
      std::move(staged.trustedCrls),
      [me,
        store = mCertificateStore,
        issuerCerts = std::move(staged.issuerCerts),
        issuerCrls = std::move(staged.issuerCrls),
        writing,
        finish](VoidResult trustedResult) mutable
      {
        if (trustedResult.is_bad())
        {
          writing.reset();
          finish(std::move(trustedResult));
          return;
        }
        store->replace_issuer_certificates_async(std::move(issuerCerts),
          std::move(issuerCrls),
          [me, writing = std::move(writing), finish](VoidResult issuerResult) mutable
          {
            if (issuerResult.is_good())
            {
              if (auto locked = me.lock())
                locked->mInfo->lastUpdateTime.store(DateTime::now().value().time_since_epoch().count());
            }
            writing.reset();
            finish(std::move(issuerResult));
          });
      });
  }
  catch (...)
  {
    finish(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void TrustListManager::clear_lists_async(std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [](TrustListManager& self, std::function<void(VoidResult)> callback)
    {
      auto request = std::make_shared<ClearRequest>();
      request->finish = detail::make_fire_once<VoidResult>(std::move(callback));
      self.clear_lists_on_strand(std::move(request));
    })();
}

void TrustListManager::clear_lists_on_strand(std::shared_ptr<ClearRequest> request)
{
  if (request->started)
    return;  // the wait limit already cleared
  if (list_write_in_flight())
  {
    // Part 12 7.10.10 leaves the reset no way to refuse: it waits for the write in progress, and no new
    // write starts meanwhile (list_writes_blocked).
    mAfterListWrite.push_back([request](TrustListManager& self) { self.clear_lists_on_strand(request); });
    if (!request->followUp && !request->waitTimer)
    {
      auto me = weak_from_this();
      std::weak_ptr<ClearRequest> weakRequest = request;  // the request owns its timer: no cycle
      request->waitTimer.emplace(Timer::schedule_after(mStrand,
        mResetWaitLimit,
        [me, weakRequest](boost::system::error_code ec)
        {
          auto self = me.lock();
          auto waiting = weakRequest.lock();
          if (!self || ec || !waiting || waiting->started)
          {
            return;
          }
          self->mLogger.warning("TrustListManager: a list write did not complete; the reset clears anyway");
          waiting->forced = true;
          self->clear_lists_now(waiting);
          // The late write may still land over the cleared lists: clear again once it has ended.
          auto followUp = std::make_shared<ClearRequest>();
          followUp->followUp = true;
          // The reset was answered; a failed follow-up leaves the late write's lists in place, so say so.
          // Fire-once, as every ClearRequest's: the request's destructor answers it again otherwise.
          followUp->finish = detail::make_fire_once<VoidResult>(std::function<void(VoidResult)>(
            [logger = self->mLogger](VoidResult cleared)
            {
              if (cleared.is_bad())
              {
                const std::string reason = ua::describe(cleared.status_code());
                logger.warning({{"error", std::string_view{reason}}},
                  "TrustListManager: clearing again after a late list write failed; the reset is incomplete");
              }
            }));
          self->clear_lists_on_strand(std::move(followUp));
        }));
    }
    return;
  }
  clear_lists_now(std::move(request));
}

void TrustListManager::clear_lists_now(std::shared_ptr<ClearRequest> request)
{
  request->started = true;
  auto& waitTimer = request->waitTimer;
  if (waitTimer)
  {
    waitTimer.value().cancel();
    request->waitTimer.reset();
  }
  try
  {
    // A handle open for write would otherwise CloseAndUpdate the old lists back after the reset.
    if (mOpenHandle && mOpenHandle->isWriteMode)
      close_handle();
    mStaged.reset();
    ++mModificationCount;  // an AddCertificate validated against the old lists is refused
    auto writing = begin_list_write();
    auto store = mCertificateStore;
    store->replace_trusted_certificates_async({},
      {},
      [store, writing, request](VoidResult trustedResult) mutable
      {
        store->replace_issuer_certificates_async({},
          {},
          [writing = std::move(writing), request, trustedResult = std::move(trustedResult)](
            VoidResult issuerResult) mutable
          {
            writing.reset();
            if (trustedResult.is_bad())
              request->finish(std::move(trustedResult));
            else if (issuerResult.is_bad() || !request->forced)
              request->finish(std::move(issuerResult));
            else
              // Cleared, but beside a write that has not ended and may land over the cleared lists before the
              // follow-up clear: not the Good of a clear that is known to hold.
              request->finish(VoidResult{StatusCode{Status::BadTimeout,
                make_error_detail("TrustListWriteOutlastedTheReset",
                  "a TrustList write did not end within the reset's wait limit; the lists were cleared and "
                  "are "
                  "cleared again when it ends",
                  "TrustListManager")}});
          });
      });
  }
  catch (...)
  {
    request->finish(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

TrustListManager::ClearRequest::~ClearRequest()
{
  // Dropped unanswered (the manager gone while the reset waited): answered, so the reset reaches its
  // shutdown. finish is fire-once, so an answered request is not answered again.
  try
  {
    if (finish)
      finish(VoidResult{StatusCode{Status::BadInternalError}});
  }
  catch (...)
  {
    // A destructor never throws.
    ua::detail::ignore_expected_exception();
  }
}

TrustListManager::ListWriteToken::~ListWriteToken()
{
  // Released on whichever thread the write's last continuation ends; the queued work resumes on the strand.
  try
  {
    if (auto locked = manager.lock())
      ua::async::post_borrowing(locked.get(),
        locked->mStrand,
        locked->mLogger,
        [](TrustListManager& self) { self.run_after_list_write(); })();
  }
  catch (...)
  {
    // A destructor never throws: the queued reset then clears at its wait limit.
    try
    {
      logger.warning("TrustListManager: work queued behind a list write could not be resumed");
    }
    catch (...)
    {
      // Nothing more to do: the logger itself failed.
      ua::detail::ignore_expected_exception();
    }
  }
}

std::shared_ptr<TrustListManager::ListWriteToken> TrustListManager::begin_list_write()
{
  auto token = std::make_shared<ListWriteToken>();
  token->manager = weak_from_this();
  token->logger = mLogger;
  std::erase_if(mWritesInFlight, [](const auto& held) { return held.expired(); });
  mWritesInFlight.push_back(token);
  return token;
}

bool TrustListManager::list_write_in_flight() const
{
  return std::ranges::any_of(mWritesInFlight, [](const auto& held) { return !held.expired(); });
}

bool TrustListManager::list_writes_blocked() const
{
  return list_write_in_flight() || !mAfterListWrite.empty();
}

void TrustListManager::run_after_list_write()
{
  while (!list_write_in_flight() && !mAfterListWrite.empty())
  {
    auto next = std::move(mAfterListWrite.front());
    mAfterListWrite.erase(mAfterListWrite.begin());
    try
    {
      next(*this);
    }
    catch (...)
    {
      const std::string reason = ua::describe(ua::exception_to_status_code(std::current_exception()));
      mLogger.warning({{"error", std::string_view{reason}}}, "TrustListManager: queued list work failed");
    }
  }
}

void TrustListManager::staged_lists_async(
  std::function<void(std::optional<detail::TrustListContent>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::optional<detail::TrustListContent>{},
    [](TrustListManager& self, std::function<void(std::optional<detail::TrustListContent>)> callback)
    { detail::invoke_user_callback(self.mLogger, callback, self.mStaged); })();
}

void TrustListManager::discard_staged_async(
  std::optional<NodeId> stagedBy, std::optional<uint64_t> generation)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [stagedBy = std::move(stagedBy), generation](TrustListManager& self)
    {
      if (self.mStaged && (!stagedBy || *stagedBy == self.mStagedSessionId) &&
          (!generation || self.mStagedGeneration == 0 || *generation == self.mStagedGeneration))
      {
        self.mStaged.reset();
        ++self.mModificationCount;  // an AddCertificate validated against the dropped lists is refused
      }
    })();
}

// ---------------------------------------------------------------------------
// Query: is_write_open_async
// ---------------------------------------------------------------------------

void TrustListManager::is_write_open_async(std::function<void(Result<bool>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [](TrustListManager& self, std::function<void(Result<bool>)> callback)
    {
      const bool writeOpen =
        (self.mOpenHandle.has_value() && self.mOpenHandle->isWriteMode) || self.list_writes_blocked();
      detail::invoke_user_callback(self.mLogger, callback, writeOpen);
    })();
}

// ---------------------------------------------------------------------------
// Session cleanup
// ---------------------------------------------------------------------------

void TrustListManager::on_session_closed_async(NodeId sessionId)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [sessionId = std::move(sessionId)](TrustListManager& self)
    {
      if (self.mOpenHandle && self.mOpenHandle->sessionId == sessionId)
      {
        self.mLogger.info("TrustListManager: closing handle for disconnected session");
        self.close_handle();
      }
      // Part 12 7.10.6: "If a Session is closed or abandoned then the transaction is closed and all
      // pending changes are discarded" - also when its CloseAndUpdate staged before its transaction was
      // recorded (review BR-13).
      if (self.mStaged && self.mStagedSessionId == sessionId)
      {
        self.mStaged.reset();
        ++self.mModificationCount;
      }
    })();
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

VoidResult TrustListManager::shutdown()
{
  // Synchronous teardown barrier: the calling thread blocks until the body has run, which keeps
  // `this` alive for the duration, so a raw `this` capture is correct here (neither weak nor strong
  // self-capture fits a fire-once join). A throw from the body is answered as the result, so the
  // caller is never left waiting; guarded stays as the post-discipline backstop.
  return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
    [this](std::function<void(VoidResult)> complete)
    {
      boost::asio::post(mStrand,
        ua::async::guarded(mLogger,
          [this, complete = std::move(complete)]()
          {
            try
            {
              if (mActivityTimer)
              {
                mActivityTimer->cancel();
                mActivityTimer.reset();
              }
              mOpenHandle.reset();
              mInfo->openCount.store(0);
              // A reset still waiting is answered (ClearRequest), so its push service reaches the shutdown.
              mAfterListWrite.clear();
              complete(VoidResult{});
            }
            catch (...)
            {
              complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
            }
          }));
    });
}

// ---------------------------------------------------------------------------
// Properties (thread-safe atomic reads)
// ---------------------------------------------------------------------------

UtcTime TrustListInfo::last_update_time() const
{
  auto ticks = lastUpdateTime.load();
  if (ticks == 0)
  {
    return UtcTime{};
  }
  return UtcTime{
    std::chrono::sys_time<datetime::OneHundredNanoSeconds>{datetime::OneHundredNanoSeconds{ticks}}};
}

uint16_t TrustListInfo::open_count() const
{
  return openCount.load();
}

UtcTime TrustListManager::last_update_time() const
{
  return mInfo->last_update_time();
}

uint16_t TrustListManager::open_count() const
{
  return mInfo->open_count();
}

}  // namespace ua
