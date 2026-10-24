// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the strand-bearing @ref ua::client::detail::PullCertificateManagerImpl (client
///        design section 8.1A): the section 8.1A.4 cycle FSM (GDS bootstrap  to  TrustList refresh  to
///        per-group cert-renewal Start/Finish poll loop  to  atomic persist  to  revalidation broadcast), the
///        renew/retry-backoff timers, the CL-PULLCRT-001..006 behavioural contracts, and the `mGeneration`
///        stale-callback guard. Plus the public @ref ua::client::PullCertificateManager shared-handle
///        forwarding.

#include "ua_pull_certificate_manager_impl.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_on_strand.h"
#include "ua_status.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <cmath>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::client::detail
{

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using State = ua::client::PullCertManagementState;
using LifecycleEvent = ua::client::PullCertLifecycleEvent;

// Source-tag prefix (CL-DIAG-002 / CL-DIAG-015). Every advisory / Bad path carries
// `client.tier1.pull_cert_manager.*`; the atomic-persist failure chains the host's `host.persistence`.
constexpr std::string_view srcCycle = "client.tier1.pull_cert_manager.cycle";
constexpr std::string_view srcBootstrap = "client.tier1.pull_cert_manager.bootstrap";
constexpr std::string_view srcPersistedLoad = "client.tier1.pull_cert_manager.persisted_requests_load";
constexpr std::string_view srcTrustListLastUpdate = "client.tier1.pull_cert_manager.trust_list_last_update";
constexpr std::string_view srcTrustListDownload = "client.tier1.pull_cert_manager.trust_list_download";
constexpr std::string_view srcStartRequest = "client.tier1.pull_cert_manager.start_request";
constexpr std::string_view srcFinishRequest = "client.tier1.pull_cert_manager.finish_request";
constexpr std::string_view srcCertChangedMidPoll = "client.tier1.pull_cert_manager.cert_changed_mid_poll";
constexpr std::string_view srcPersist = "host.persistence";
constexpr std::string_view srcSecurityModeForced = "client.tier1.pull_cert_manager.security_mode_forced";
constexpr std::string_view srcSecurityPolicyForced = "client.tier1.pull_cert_manager.security_policy_forced";
constexpr std::string_view srcStopped = "client.tier1.pull_cert_manager.stopped";
constexpr std::string_view srcRevalidate = "client.tier1.pull_cert_manager.revalidate";
constexpr std::string_view srcCertBinding = "client.tier1.pull_cert_manager.cert_binding";
constexpr std::string_view srcCertificateStatus = "client.tier1.pull_cert_manager.certificate_status";

std::string_view state_name(State state)
{
  switch (state)
  {
  case State::Idle:
    return "Idle";
  case State::BootstrappingGds:
    return "BootstrappingGds";
  case State::RefreshingTrustList:
    return "RefreshingTrustList";
  case State::RequestingCert:
    return "RequestingCert";
  case State::Polling:
    return "Polling";
  case State::Persisting:
    return "Persisting";
  case State::Revalidating:
    return "Revalidating";
  case State::Failed:
    return "Failed";
  case State::Closed:
    return "Closed";
  }
  return "Unknown";
}

}  // namespace

// ================= construction =================

std::shared_ptr<PullCertificateManagerImpl> PullCertificateManagerImpl::create(
  boost::asio::any_io_executor executor, std::shared_ptr<PullCertificateManagerHost> host, ua::Logger logger,
  ua::client::PullCertManagementConfig config)
{
  auto impl = std::shared_ptr<PullCertificateManagerImpl>(new PullCertificateManagerImpl(
    std::move(executor), std::move(host), std::move(logger), std::move(config)));
  // section 8.1A.3: run the bootstrap on the strand. Posted here  -  NOT in the ctor  -  because
  // `weak_from_this()` is only valid once the owning shared_ptr exists.
  ua::async::post_borrowing(impl.get(),
    impl->mStrand,
    impl->mLogger,
    [](PullCertificateManagerImpl& self) { self.begin_bootstrap(); })();
  return impl;
}

PullCertificateManagerImpl::PullCertificateManagerImpl(boost::asio::any_io_executor executor,
  std::shared_ptr<PullCertificateManagerHost> host, ua::Logger logger,
  ua::client::PullCertManagementConfig config)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)), mHost(std::move(host)),
    mLogger(std::move(logger)), mPolicy(std::move(config)), mCycleTimer(mStrand), mPollTimer(mStrand)
{
  mCertificateGroups = mPolicy.certificateGroups;
  if (mCertificateGroups.empty())
  {
    mCertificateGroups.push_back(ua::client::CertificateGroupConfig{});  // a single default group.
  }
  publish_snapshot();
}

PullCertificateManagerImpl::~PullCertificateManagerImpl()
{
  // M5(c): if the last owner drops the manager before a posted do_stop ran, a pending force_cycle / stop ack
  // would be dropped unfired. Fire them synchronously on the destroying thread (the strand is gone) rather
  // than silently drop them  -  Cancelled-by-client because no cycle / stop completed. A do_stop that DID run
  // already moved these out (finalize_stop), so this is a no-op in that case (no double-fire).
  for (const auto& ack : mForceCycleAcks)
  {
    if (ack)
    {
      ack(VoidResult{StatusCode{Status::BadRequestCancelledByClient,
        ua::make_error_detail("PULL_CERT_DESTROYED",
          "pull-cert manager destroyed before the pending force_cycle completed",
          std::string{srcStopped})}});
    }
  }
  mForceCycleAcks.clear();
  if (mStopAck)
  {
    auto ack = std::move(mStopAck);
    mStopAck = nullptr;
    ack(VoidResult{StatusCode{Status::BadRequestCancelledByClient,
      ua::make_error_detail("PULL_CERT_DESTROYED",
        "pull-cert manager destroyed before the pending stop completed",
        std::string{srcStopped})}});
  }
}

// ================= cross-strand reads (Rule 4; lock-free) =================

std::shared_ptr<const ua::client::PullCertManagementInfo>
  PullCertificateManagerImpl::pull_cert_info() const noexcept
{
  return mInfoSnapshot.load(std::memory_order_acquire);
}

// ================= consumer entry points (all hop to mStrand) =================

void PullCertificateManagerImpl::force_cycle_async(std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](PullCertificateManagerImpl& self, std::function<void(VoidResult)> cb)
    { self.do_force_cycle(std::move(cb)); })();
}

void PullCertificateManagerImpl::stop_async(std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](PullCertificateManagerImpl& self, std::function<void(VoidResult)> cb)
    { self.do_stop(std::move(cb)); })();
}

void PullCertificateManagerImpl::notify_own_cert_rotated_async(
  std::string newThumbprintSha1, std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [thumbprint = std::move(newThumbprintSha1)](
      PullCertificateManagerImpl& self, std::function<void(VoidResult)> cb) mutable
    {
      self.do_notify_own_cert_rotated(std::move(thumbprint));
      self.deliver_void(std::move(cb), VoidResult{});
    })();
}

// ================= bootstrap (section 8.1A.3) =================

void PullCertificateManagerImpl::begin_bootstrap()
{
  set_state(State::BootstrappingGds);
  const std::uint64_t generation = mGeneration;
  mHost->read_persisted_requests_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](PullCertificateManagerImpl& self, Result<std::vector<PersistedRequest>> loaded)
    { self.on_persisted_loaded(generation, std::move(loaded)); }));
}

void PullCertificateManagerImpl::on_persisted_loaded(
  std::uint64_t generation, Result<std::vector<PersistedRequest>> loaded)
{
  if (!is_current(generation))
  {
    return;
  }
  if (loaded.is_good())
  {
    // Bound the loaded set to at most one pending request per CONFIGURED group and type. A corrupt / hostile
    // persistence file must not blow up memory; a stale request for an unconfigured group is dropped.
    std::vector<PersistedRequest> capped;
    for (PersistedRequest& request : loaded.value())
    {
      const bool known = std::any_of(mCertificateGroups.begin(),
        mCertificateGroups.end(),
        [&](const ua::client::CertificateGroupConfig& group)
        {
          return group.certificateGroupId == request.certificateGroupId &&
                 group.certificateTypeId == request.certificateTypeId;
        });
      const bool duplicate = std::any_of(capped.begin(),
        capped.end(),
        [&](const PersistedRequest& kept)
        {
          return kept.certificateGroupId == request.certificateGroupId &&
                 kept.certificateTypeId == request.certificateTypeId;
        });
      if (known && !duplicate)
      {
        capped.push_back(std::move(request));
      }
    }
    mPendingRequests = std::move(capped);
  }
  else
  {
    // section 8.1A.6: a corrupt persistence file is advisory  -  clear it and run a fresh cycle  -  but the
    // advisory must NOT be dropped. Carried on the `Started` event once the GDS connection is up.
    mPendingRequests.clear();
    mBootstrapAdvisory = ua::make_error_detail("PULL_CERT_PERSISTED_REQUESTS_LOAD_FAILED",
      "failed to load persisted certificate requests; clearing and proceeding with a fresh cycle",
      std::string{srcPersistedLoad},
      loaded.status_code());
    persist_pending_requests();  // M8: best-effort write-back of the cleared file (advisory on failure).
  }
  publish_snapshot();
  open_gds(generation);
}

void PullCertificateManagerImpl::open_gds(std::uint64_t generation)
{
  if (mPolicy.bootstrapTrustStore == nullptr)
  {
    // H4(a): a null bootstrap trust store means "accept any GDS server cert"  -  a MITM opening. Refuse to
    // open; the GDS channel MUST be validated against an explicit bootstrap trust anchor (CL-PULLCRT-001).
    std::shared_ptr<const ua::ErrorDetail> chain =
      ua::make_error_detail("PULL_CERT_BOOTSTRAP_TRUST_STORE_MISSING",
        "refusing to open the GDS connection without a bootstrap trust store (would accept any server cert)",
        std::string{srcBootstrap});
    mLastError = chain;
    ++mFailureCount;
    set_state(State::Failed);
    lifecycle(LifecycleEvent::CycleFailed, chain);
    arm_cycle_timer(
      generation, std::chrono::duration_cast<std::chrono::milliseconds>(mPolicy.minCycleBackoff));
    return;
  }
  mGdsOpenRequested =
    true;  // M5(a): track the open so a stop always closes, even if the open never completes.
  PullCertificateManagerHost::GdsConnectionRequest request;
  request.endpointUrl = mPolicy.gdsEndpointUrl;
  request.bootstrapTrustStore = mPolicy.bootstrapTrustStore;
  request.securityMode = ua::MessageSecurityMode::SignAndEncrypt;  // CL-PULLCRT-001: hard-coded.
  request.securityPolicyId = mPolicy.gdsSecurityPolicyId;  // concrete policy for the secured GDS channel.
  request.serverCertificate = mPolicy.gdsServerCertificate;  // SignAndEncrypt OPN target (ExactUrl connect).
  request.anonymousIdentity = true;  // CL-PULLCRT-002: forced Anonymous.
  if (mPolicy.gdsSecurityPolicyId == ua::SecurityPolicyId::None)
  {
    // CL-PULLCRT-001: SignAndEncrypt with a `None` SecurityPolicy is contradictory and would yield an
    // UNENCRYPTED, server-cert-UNVALIDATED channel (defeating both encryption AND the bootstrap-trust OPN
    // validation). Force a secure policy (mirrors the SecurityMode-forced guard above); the channel is always
    // secured regardless of a misconfigured policy.
    request.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    advisory("PULL_CERT_SECURITY_POLICY_FORCED",
      "requested GDS SecurityPolicy is None; forcing Basic256Sha256 (CL-PULLCRT-001 requires a non-None "
      "SecurityPolicy for the secured GDS channel)",
      srcSecurityPolicyForced);
  }
  if (mPolicy.requestedGdsSecurityMode.has_value() &&
      *mPolicy.requestedGdsSecurityMode != ua::MessageSecurityMode::SignAndEncrypt)
  {
    // CL-PULLCRT-001: reject any attempt to weaken the GDS channel below SignAndEncrypt.
    advisory("PULL_CERT_SECURITY_MODE_FORCED",
      "requested GDS SecurityMode is weaker than SignAndEncrypt; forcing SignAndEncrypt",
      srcSecurityModeForced);
  }
  mHost->open_gds_connection_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, VoidResult result)
      { self.on_gds_opened(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_gds_opened(std::uint64_t generation, VoidResult result)
{
  if (!is_current(generation))
  {
    return;
  }
  if (!result.is_good())
  {
    // BootstrappingGds conn bad  to  Failed; advisory via CycleFailed; retry on minCycleBackoff.
    auto builder = ua::ErrorDetail::build("PULL_CERT_GDS_BOOTSTRAP_FAILED",
      "opening the GDS connection failed; deferring the first cycle",
      std::string{srcBootstrap});
    builder.cause(result.status_code());  // numeric inner status + the GDS-open detail chain.
    if (mBootstrapAdvisory)
    {
      // M7: don't lose the corrupt-persistence advisory when the bootstrap ALSO fails  -  keep the numeric
      // bootstrap status but surface the persisted-load advisory in the cause chain.
      builder.cause(mBootstrapAdvisory);
      mBootstrapAdvisory = nullptr;
    }
    std::shared_ptr<const ua::ErrorDetail> chain = builder;
    mLastError = chain;
    ++mFailureCount;  // H2: a bootstrap failure trips the diagnostics failure count.
    set_state(State::Failed);
    lifecycle(LifecycleEvent::CycleFailed, chain);
    arm_cycle_timer(
      generation, std::chrono::duration_cast<std::chrono::milliseconds>(mPolicy.minCycleBackoff));
    return;
  }
  mGdsConnected = true;
  set_state(State::Idle);
  lifecycle(LifecycleEvent::Started, mBootstrapAdvisory);
  mBootstrapAdvisory = nullptr;
  if (!mPendingRequests.empty() || !mForceCycleAcks.empty())
  {
    start_cycle(generation);  // resume an unfinished renewal / honour a force_cycle that arrived early.
    return;
  }
  arm_cycle_timer(generation, regular_cycle_delay());
}

// ================= cycle FSM (section 8.1A.4) =================

void PullCertificateManagerImpl::start_cycle(std::uint64_t generation)
{
  // H2 / spec-gap: section 8.1A.4 has no Failed to BootstrappingGds edge, but a bootstrap that failed leaves
  // the GDS connection down; a retry cycle must RE-OPEN it rather than run RPCs against a dead connection.
  if (!mGdsConnected)
  {
    open_gds(generation);
    return;
  }
  mCycleTimer.cancel();  // a scheduled cycle is now running.
  clear_cycle_scratch();  // reset per-cycle scratch.
  lifecycle(LifecycleEvent::CycleStarted, nullptr);

  mGroupIndex = 0;
  begin_group(generation);
}

void PullCertificateManagerImpl::begin_group(std::uint64_t generation)
{
  if (mGroupIndex >= mCertificateGroups.size())
  {
    end_of_cycle(generation);
    return;
  }
  clear_group_scratch();
  const ua::client::CertificateGroupConfig& group = current_group();
  mCurrentGroupId = group.certificateGroupId;
  // Figure 16 SigningRequestPending: a request already made is finished, not made again.
  if (find_current_pending() != mPendingRequests.end())
  {
    enter_polling(generation);
    return;
  }
  if (!mPolicy.renewApplicationCertificate)
  {
    after_certificate(generation);
    return;
  }
  // OPC 10000-12 7.6 Table 21: GetCertificateStatus decides whether a certificate is requested at all; a
  // cycle that asked for a new certificate every time would have the CertificateManager issue one per cycle.
  set_state(State::RequestingCert);
  mAwaitingCertificateStatus = true;
  mHost->get_certificate_status_async(mPolicy.applicationId,
    group.certificateGroupId,
    group.certificateTypeId,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, Result<bool> result)
      { self.on_certificate_status(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_certificate_status(std::uint64_t generation, Result<bool> result)
{
  if (!is_current(generation))
  {
    return;
  }
  mAwaitingCertificateStatus = false;
  if (!result.is_good())
  {
    // No certificate is requested for this type, but the group's TrustList (with its CRLs) is still refreshed
    // and so is every later group's: a CertificateManager that cannot answer the status must not stop
    // revocation updates. The cycle ends Failed with this status.
    if (!mCycleStatusFailure)
    {
      mCycleStatusFailure.emplace(mCurrentGroupId,
        StatusCode{result.status_code().value(),
          ua::make_error_detail("PULL_CERT_GET_CERTIFICATE_STATUS_FAILED",
            "GetCertificateStatus failed",
            std::string{srcCertificateStatus},
            result.status_code())});
    }
    after_certificate(generation);
    return;
  }
  if (!result.value())
  {
    after_certificate(generation);  // the certificate is current: only the TrustList is refreshed.
    return;
  }
  enter_requesting_cert(generation);
}

void PullCertificateManagerImpl::after_certificate(std::uint64_t generation)
{
  enter_refreshing_trust_list(generation);
}

void PullCertificateManagerImpl::next_group(std::uint64_t generation)
{
  ++mGroupIndex;
  begin_group(generation);
}

void PullCertificateManagerImpl::end_of_cycle(std::uint64_t generation)
{
  if (mCycleStatusFailure)
  {
    // enter_failed revalidates whatever this cycle committed.
    auto [groupId, status] = std::move(*mCycleStatusFailure);
    mCycleStatusFailure.reset();
    mCurrentGroupId = std::move(groupId);
    enter_failed(State::RequestingCert, std::move(status));
    return;
  }
  if (mCycleOwnCertChanged || mCycleTrustListChanged)
  {
    enter_revalidating(generation);
    return;
  }
  finish_cycle_success(generation, mCycleAdvisory);
}

void PullCertificateManagerImpl::enter_refreshing_trust_list(std::uint64_t generation)
{
  // Several certificate types of one group share its TrustList: it is refreshed once per cycle.
  if (std::find(mCycleTrustListGroupsDone.begin(), mCycleTrustListGroupsDone.end(), mCurrentGroupId) !=
      mCycleTrustListGroupsDone.end())
  {
    continue_after_trust_list(generation);
    return;
  }
  mCycleTrustListGroupsDone.push_back(mCurrentGroupId);
  set_state(State::RefreshingTrustList);
  if (!mPolicy.checkLastUpdateTimeBeforeDownload)
  {
    download_trust_list(generation);
    return;
  }
  mHost->read_trust_list_last_update_time_async(mPolicy.applicationId,
    mCurrentGroupId,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, Result<std::optional<ua::DateTime>> result)
      { self.on_last_update_time(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_last_update_time(
  std::uint64_t generation, Result<std::optional<ua::DateTime>> result)
{
  if (!is_current(generation))
  {
    return;
  }
  if (!result.is_good())
  {
    enter_failed(State::RefreshingTrustList,
      StatusCode{result.status_code().value(),
        ua::make_error_detail("PULL_CERT_TRUST_LIST_LAST_UPDATE_FAILED",
          "reading TrustListType.LastUpdateTime failed",
          std::string{srcTrustListLastUpdate},
          result.status_code())});
    return;
  }
  const std::optional<ua::DateTime> lastUpdate = result.value();
  if (!lastUpdate.has_value())
  {
    // CL-PULLCRT-005: no LastUpdateTime published.
    if (mPolicy.treatLastUpdateTimeMissingAsForceDownload)
    {
      download_trust_list(generation);
    }
    else
    {
      continue_after_trust_list(generation);
    }
    return;
  }
  const auto committed = std::find_if(mLastTrustListUpdates.begin(),
    mLastTrustListUpdates.end(),
    [this](const auto& entry) { return entry.first == mCurrentGroupId; });
  if (committed != mLastTrustListUpdates.end() && committed->second == *lastUpdate)
  {
    // CL-PULLCRT-005: unchanged and a local cache exists  to  skip the download.
    continue_after_trust_list(generation);
    return;
  }
  mCycleTrustListLastUpdate = lastUpdate;  // remember the target time for the commit.
  download_trust_list(generation);
}

void PullCertificateManagerImpl::download_trust_list(std::uint64_t generation)
{
  mHost->read_trust_list_async(mPolicy.applicationId,
    mCurrentGroupId,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, Result<ua::TrustListDataType> result)
      { self.on_trust_list(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_trust_list(std::uint64_t generation, Result<ua::TrustListDataType> result)
{
  if (!is_current(generation))
  {
    return;
  }
  if (!result.is_good())
  {
    // Cache preserved (mLastTrustListUpdates untouched); next cycle retries.
    enter_failed(State::RefreshingTrustList,
      StatusCode{result.status_code().value(),
        ua::make_error_detail("PULL_CERT_TRUST_LIST_DOWNLOAD_FAILED",
          "GetTrustList / Open(Read) of the trust list failed",
          std::string{srcTrustListDownload},
          result.status_code())});
    return;
  }
  mCycleTrustList = std::move(result.value());
  continue_after_trust_list(generation);
}

void PullCertificateManagerImpl::continue_after_trust_list(std::uint64_t generation)
{
  // The group's certificate and TrustList are committed together (Table 21 "Persist TrustList").
  if (mCycleNewCert != nullptr || mCycleTrustList.has_value())
  {
    enter_persisting(generation);
    return;
  }
  next_group(generation);
}

void PullCertificateManagerImpl::enter_requesting_cert(std::uint64_t generation)
{
  set_state(State::RequestingCert);
  // Resume, don't re-issue: an already-persisted request for this group is polled rather than duplicated.
  if (find_current_pending() != mPendingRequests.end())
  {
    enter_polling(generation);
    return;
  }
  const ua::client::CertificateGroupConfig& group = current_group();
  PullCertificateManagerHost::CertRequestParams params;
  params.applicationId = mPolicy.applicationId;
  params.certificateGroupId = group.certificateGroupId;
  params.certificateTypeId = group.certificateTypeId;
  params.newKeyPair = group.useNewKeyPair;
  params.certificateRequest = group.certificateRequest;
  params.subjectName = group.subjectName;
  params.domainNames = group.domainNames;
  params.privateKeyFormat = group.privateKeyFormat;
  mHost->start_certificate_request_async(std::move(params),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, Result<ua::NodeId> result)
      { self.on_start_request(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_start_request(std::uint64_t generation, Result<ua::NodeId> result)
{
  if (!is_current(generation))
  {
    return;
  }
  if (!result.is_good())
  {
    enter_failed(State::RequestingCert,
      StatusCode{result.status_code().value(),
        ua::make_error_detail("PULL_CERT_START_REQUEST_FAILED",
          "StartSigningRequest / StartNewKeyPairRequest failed",
          std::string{srcStartRequest},
          result.status_code())});
    return;
  }
  // CL-PULLCRT-004: stamp the on-channel own-cert thumbprint onto the request, persist it, then poll.
  PersistedRequest request;
  request.certificateGroupId = current_group().certificateGroupId;
  request.certificateTypeId = current_group().certificateTypeId;
  request.requestId = std::move(result.value());
  request.certThumbprintSha1 = mHost->current_own_cert_thumbprint_sha1();
  request.persistedAt = mNowFn();
  mPendingRequests.push_back(std::move(request));
  persist_pending_requests();
  publish_snapshot();
  enter_polling(generation);
}

void PullCertificateManagerImpl::enter_polling(std::uint64_t generation)
{
  set_state(State::Polling);
  const auto pending = find_current_pending();
  if (pending == mPendingRequests.end())
  {
    after_certificate(generation);  // defensive: nothing to poll.
    return;
  }
  // CL-PULLCRT-004: the on-channel cert must match the thumbprint stamped when the request was issued.
  const std::string current = mHost->current_own_cert_thumbprint_sha1();
  if (!pending->certThumbprintSha1.empty() && current != pending->certThumbprintSha1)
  {
    advisory("PULL_CERT_CERT_CHANGED_MID_POLL",
      "on-channel certificate thumbprint no longer matches the persisted request; dropping it",
      srcCertChangedMidPoll);
    mPendingRequests.erase(pending);
    persist_pending_requests();
    publish_snapshot();
    enter_requesting_cert(generation);  // re-request with the new cert.
    return;
  }
  mCurrentRequestId = pending->requestId;
  mPollAttempt = 0;
  arm_poll_timer(generation);
}

void PullCertificateManagerImpl::do_poll(std::uint64_t generation)
{
  if (!is_current(generation) || mState != State::Polling)
  {
    return;
  }
  // CL-PULLCRT-004 (M3): re-check the on-channel thumbprint on EVERY poll, not just on Polling entry  -  the
  // own cert can rotate between polls without an explicit notify. Drop the stale request rather than poll it.
  const auto pending = find_current_pending();
  if (pending != mPendingRequests.end() && !pending->certThumbprintSha1.empty() &&
      mHost->current_own_cert_thumbprint_sha1() != pending->certThumbprintSha1)
  {
    advisory("PULL_CERT_CERT_CHANGED_MID_POLL",
      "on-channel certificate thumbprint changed between polls; dropping the stale request",
      srcCertChangedMidPoll);
    mPendingRequests.erase(pending);
    persist_pending_requests();
    publish_snapshot();
    enter_requesting_cert(generation);
    return;
  }
  mHost->finish_certificate_request_async(mPolicy.applicationId,
    mCurrentRequestId,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](
        PullCertificateManagerImpl& self, Result<PullCertificateManagerHost::FinishCertificateResult> result)
      { self.on_finish_request(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_finish_request(
  std::uint64_t generation, Result<PullCertificateManagerHost::FinishCertificateResult> result)
{
  if (!is_current(generation) || mState != State::Polling)
  {
    return;
  }
  if (result.is_good())
  {
    // H4(b): a Good FinishRequest with no certificate is malformed  -  the cert<=>request binding cannot be
    // established, so drop it rather than commit a null cert. (Cryptographic key/issuer-chain binding is the
    // runtime store's contract  -  see PullCertificateManagerHost::apply_cert_update_async.)
    if (result.value().certificate == nullptr)
    {
      if (const auto it = find_current_pending(); it != mPendingRequests.end())
      {
        mPendingRequests.erase(it);
      }
      persist_pending_requests();
      enter_failed(State::Polling,
        StatusCode{Status::BadCertificateInvalid,
          ua::make_error_detail("PULL_CERT_CERT_BINDING_INVALID",
            "FinishRequest returned no certificate; cannot bind the cert to the request",
            std::string{srcCertBinding})});
      return;
    }
    // Cert delivered  to  drop the fulfilled request, persist the removal, commit.
    mCycleNewCert = result.value().certificate;
    mCycleNewKey = result.value().privateKey;
    mCycleIssuerChain = result.value().issuerChain;  // M9: thread the issuer chain into the atomic commit.
    if (const auto it = find_current_pending(); it != mPendingRequests.end())
    {
      mPendingRequests.erase(it);
    }
    persist_pending_requests();
    publish_snapshot();
    after_certificate(generation);  // the group's TrustList, then both are committed together.
    return;
  }

  const StatusCode code = result.status_code();
  if (code.as_status() == Status::BadNothingToDo)
  {
    // CL-PULLCRT-003: still in the approval queue  -  not a failure.
    if (mPollAttempt + 1 < mPolicy.pollMaxRepeat)
    {
      ++mPollAttempt;
      arm_poll_timer(generation);
      publish_snapshot();
      return;
    }
    // Bounded burst exhausted. The requestId is already persisted (at issuance)  -  resume next cycle. M1:
    // the group's TrustList is still refreshed, so a request stuck in approval never starves the CRL refresh
    // (Figure 16 moves to the next group here; decision D6 keeps the refresh).
    mCycleAdvisory = ua::make_error_detail("PULL_CERT_REQUEST_PENDING_APPROVAL",
      "certificate request still pending server approval; will resume next cycle",
      std::string{srcFinishRequest});
    after_certificate(generation);
    return;
  }

  // CL-PULLCRT-003: any other Bad terminates the cycle; the requestId is server-side-invalid now.
  if (const auto it = find_current_pending(); it != mPendingRequests.end())
  {
    mPendingRequests.erase(it);
  }
  persist_pending_requests();
  enter_failed(State::Polling,
    StatusCode{code.value(),
      ua::make_error_detail("PULL_CERT_FINISH_REQUEST_FAILED",
        "FinishRequest returned a terminal Bad; dropping the request",
        std::string{srcFinishRequest},
        code)});
}

void PullCertificateManagerImpl::enter_persisting(std::uint64_t generation)
{
  set_state(State::Persisting);
  PullCertificateManagerHost::CertUpdate update;
  update.newOwnCert = mCycleNewCert;
  update.newPrivateKey = mCycleNewKey;
  update.newTrustList = mCycleTrustList;
  update.trustListLastUpdate = mCycleTrustListLastUpdate;
  update.newIssuerChain = mCycleIssuerChain;  // M9: the runtime store validates the leaf against this chain.
  mHost->apply_cert_update_async(std::move(update),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, VoidResult result)
      { self.on_apply(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_apply(std::uint64_t generation, VoidResult result)
{
  if (!is_current(generation))
  {
    return;
  }
  if (result.is_bad())
  {
    // CL-PULLCRT-005 atomicity: the host discarded staging; the runtime store is untouched, so
    // mLastTrustListUpdates is NOT advanced  -  the next cycle retries.
    enter_failed(State::Persisting,
      StatusCode{result.status_code().value(),
        ua::make_error_detail("PULL_CERT_APPLY_FAILED",
          "atomic persist of the cert / trust list failed; runtime store untouched",
          std::string{srcPersist},
          result.status_code())});
    return;
  }
  const bool ownCertChanged = (mCycleNewCert != nullptr);
  const bool trustListChanged = mCycleTrustList.has_value();
  const ua::DateTime now = mNowFn();
  if (trustListChanged)
  {
    const auto committed = std::find_if(mLastTrustListUpdates.begin(),
      mLastTrustListUpdates.end(),
      [this](const auto& entry) { return entry.first == mCurrentGroupId; });
    if (committed != mLastTrustListUpdates.end())
    {
      mLastTrustListUpdates.erase(committed);
    }
    if (mCycleTrustListLastUpdate.has_value())
    {
      mLastTrustListUpdates.emplace_back(mCurrentGroupId, *mCycleTrustListLastUpdate);
    }
    mCycleTrustListChanged = true;
    mLastTrustListCommitAt = now;
    lifecycle(LifecycleEvent::TrustListCommitted, nullptr);
  }
  if (ownCertChanged)
  {
    mCycleOwnCertChanged = true;
    mLastCertCommitAt = now;
    lifecycle(LifecycleEvent::CertificateCommitted, nullptr);
    // CL-RECONN-006: announce an own-cert rotation to observers BEFORE the revalidation broadcast (spec
    // sequence section 8.1A.7); the broadcast follows the last group.
    if (mHost)
    {
      mHost->fire_observer_certificate_rotated(mCycleNewCert);
    }
  }
  std::uint64_t nextGeneration = generation;
  if (ownCertChanged)
  {
    ++mGeneration;  // drop any stale tier-1 callback that still references the old cert.
    nextGeneration = mGeneration;
  }
  publish_snapshot();
  next_group(nextGeneration);
}

void PullCertificateManagerImpl::enter_revalidating(std::uint64_t generation)
{
  const bool ownCertChanged = mCycleOwnCertChanged;
  if (!mPolicy.revalidateImmediatelyOnCommit && !ownCertChanged)
  {
    // CL-SECADMIN-004: defer to the SecurityToken-renewal revalidation alone.
    finish_cycle_success(generation, mCycleAdvisory);
    return;
  }
  set_state(State::Revalidating);
  publish_snapshot();
  mHost->revalidate_connections_async(ownCertChanged,
    mPolicy.revalidateImmediatelyOnCommit,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](PullCertificateManagerImpl& self, VoidResult result)
      { self.on_revalidated(generation, std::move(result)); }));
}

void PullCertificateManagerImpl::on_revalidated(std::uint64_t generation, VoidResult result)
{
  // H3: never drop the broadcast result. A failed revalidation does NOT fail the cycle (the cert / trust-list
  // commit stands  -  section 8.1A.6), but the drop must be surfaced as an advisory on the cycle outcome +
  // mLastError.
  std::shared_ptr<const ua::ErrorDetail> advisoryChain;
  if (result.is_bad())
  {
    advisoryChain = ua::make_error_detail("PULL_CERT_REVALIDATE_FAILED",
      "revalidation broadcast to open connections failed; the committed cert / trust-list stand but "
      "stale-trust connections may not have been revalidated",
      std::string{srcRevalidate},
      result.status_code());
    mLastError = advisoryChain;
  }
  // C1 hardening: honour a stop queued during Revalidating even if the generation moved on (e.g. a concurrent
  // own-cert rotation bumped it)  -  otherwise the stop ack is stranded (section 8.1A.6).
  if (mStopPending && mState == State::Revalidating)
  {
    mStopPending = false;
    lifecycle(LifecycleEvent::RevalidationCompleted, advisoryChain);
    finalize_stop(std::move(mStopAck));
    return;
  }
  if (!is_current(generation))
  {
    return;
  }
  lifecycle(LifecycleEvent::RevalidationCompleted, advisoryChain);
  finish_cycle_success(generation, advisoryChain ? advisoryChain : mCycleAdvisory);
}

void PullCertificateManagerImpl::finish_cycle_success(
  std::uint64_t generation, std::shared_ptr<const ua::ErrorDetail> advisoryChain)
{
  mFailureCount = 0;
  mLastSuccessfulCycleAt = mNowFn();
  mLastError = advisoryChain;
  clear_cycle_scratch();  // M6: wipe cert/key/trust-list scratch at the cycle terminus (secrets hygiene).
  set_state(State::Idle);
  lifecycle(LifecycleEvent::CycleSucceeded, advisoryChain);
  fire_force_cycle_acks(VoidResult{});
  arm_cycle_timer(generation, regular_cycle_delay());
}

void PullCertificateManagerImpl::enter_failed(State failedState, StatusCode stepStatus)
{
  std::string summary = "Pull cycle failed in " + std::string{state_name(failedState)} + ": " +
                        ua::to_string(stepStatus.as_status());
  // M2: carry the section 8.1A.5 structured context map (failed_state / failure_count / group_id /
  // gds_request_id).
  ua::ErrorDetailBuilder builder{"PULL_CERT_CYCLE_FAILED", std::move(summary), std::string{srcCycle}};
  builder.context(ua::ContextKeys::pullFailedState, std::string{state_name(failedState)})
    .context(ua::ContextKeys::pullFailureCount, mFailureCount + 1)  // +1: this failure trips the count.
    .context(ua::ContextKeys::pullGroupId, mCurrentGroupId);
  if (!mCurrentRequestId.is_null())
  {
    builder.context(ua::ContextKeys::pullGdsRequestId, ua::to_string(mCurrentRequestId));
  }
  builder.cause(stepStatus);  // numeric inner status + the step's detail chain.
  std::shared_ptr<const ua::ErrorDetail> chain = builder;
  mLastError = chain;
  ++mFailureCount;  // consecutive failed cycles  -  clamps the exponential retry backoff.
  // CL-PULLCRT-006: a group committed earlier in this cycle is revalidated even though a later group failed;
  // its commit stands, and the next cycle will not commit it again.
  const bool ownCertChanged = mCycleOwnCertChanged;
  if ((mCycleOwnCertChanged || mCycleTrustListChanged) && mHost &&
      (mPolicy.revalidateImmediatelyOnCommit || ownCertChanged))
  {
    mHost->revalidate_connections_async(ownCertChanged,
      mPolicy.revalidateImmediatelyOnCommit,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [](PullCertificateManagerImpl& self, VoidResult result)
        {
          if (result.is_bad())
          {
            self.mLogger.warning({{"status", ua::to_string(result.status_code())}},
              "Revalidation after a partially committed pull cycle failed; the committed groups stand");
          }
        }));
  }
  mAwaitingCertificateStatus = false;
  clear_cycle_scratch();  // M6: wipe cert/key/trust-list scratch at the (failed) cycle terminus.
  set_state(State::Failed);
  lifecycle(LifecycleEvent::CycleFailed, chain);
  fire_force_cycle_acks(
    VoidResult{});  // force_cycle resolves Good even when the cycle failed (section 8.1A.1).
  arm_cycle_timer(mGeneration, next_cycle_backoff());
}

// ================= force_cycle / stop / cert-rotation (section 8.1A.4) =================

void PullCertificateManagerImpl::do_force_cycle(std::function<void(VoidResult)> callback)
{
  if (mState == State::Closed)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadRequestCancelledByClient,
        ua::make_error_detail(
          "PULL_CERT_STOPPED", "force_cycle rejected: the manager is stopped", std::string{srcStopped})}});
    return;
  }
  mForceCycleAcks.push_back(std::move(callback));  // fired Good at the next cycle terminus.
  if (mState == State::Idle || mState == State::Failed)
  {
    start_cycle(mGeneration);
  }
  // BootstrappingGds  to  started at bootstrap end; a running cycle  to  coalesced into the in-flight cycle.
}

void PullCertificateManagerImpl::do_stop(std::function<void(VoidResult)> callback)
{
  if (mState == State::Closed)
  {
    deliver_void(std::move(callback), VoidResult{});  // idempotent.
    return;
  }
  if (mState == State::Revalidating)
  {
    // section 8.1A.6: await the broadcast, then close. A prior queued stop (if any) completes Good.
    if (mStopAck)
    {
      deliver_void(std::move(mStopAck), VoidResult{});
    }
    mStopPending = true;
    mStopAck = std::move(callback);
    return;
  }
  finalize_stop(std::move(callback));
}

void PullCertificateManagerImpl::finalize_stop(std::function<void(VoidResult)> callback)
{
  ++mGeneration;  // invalidate every in-flight tier-1 callback.
  mCycleTimer.cancel();
  mPollTimer.cancel();
  fire_force_cycle_acks(VoidResult{StatusCode{Status::BadRequestCancelledByClient,
    ua::make_error_detail(
      "PULL_CERT_STOPPED", "force_cycle cancelled: the manager is stopping", std::string{srcStopped})}});
  clear_cycle_scratch();  // M6: wipe cert/key/trust-list scratch on stop (secrets hygiene).
  if (mGdsOpenRequested)
  {
    // M5(a): close even if the open never completed / the bootstrap failed. M8: the close is best-effort
    // during teardown  -  a failure changes nothing (we are stopping) so its result is intentionally dropped.
    mHost->close_gds_connection_async([](VoidResult) {});
    mGdsOpenRequested = false;
  }
  mGdsConnected = false;
  set_state(State::Closed);  // final publish through mHost.
  lifecycle(LifecycleEvent::Stopped, nullptr);
  deliver_void(std::move(callback), VoidResult{});
  // M5(b): release the host after the final Closed publish (mirror RedundancyManager::do_close)  -
  // structurally breaks the latent host and manager cycle. Every post-close handler early-returns via
  // is_current() (Closed) before it would touch mHost, and the mHost-using helpers guard with `if (mHost)`.
  mHost.reset();
}

void PullCertificateManagerImpl::do_notify_own_cert_rotated(std::string newThumbprintSha1)
{
  if (mState == State::Closed)
  {
    return;
  }
  // Drop every persisted request bound to the OLD cert (its stamped thumbprint no longer matches).
  bool droppedAny = false;
  for (auto it = mPendingRequests.begin(); it != mPendingRequests.end();)
  {
    if (it->certThumbprintSha1 != newThumbprintSha1)
    {
      it = mPendingRequests.erase(it);
      droppedAny = true;
    }
    else
    {
      ++it;
    }
  }
  if (droppedAny)
  {
    persist_pending_requests();
  }
  advisory("PULL_CERT_CERT_CHANGED_MID_POLL",
    "own certificate rotated mid-cycle; invalidated stale certificate requests",
    srcCertChangedMidPoll);

  // C1 (CRITICAL): the generation bump drops in-flight callbacks bound to the OLD cert's thumbprint-stamped
  // requestId  -  a binding that ONLY exists in RequestingCert / Polling. In those states we bump + restart
  // the renewal with the new cert. In the other in-flight states (BootstrappingGds / RefreshingTrustList /
  // Persisting / Revalidating) the in-flight work is NOT cert-bound; bumping there would strand the
  // commit / broadcast / bootstrap AND orphan the generation-guarded cycle/poll timer  -  a PERMANENT brick
  // of renewal + trust-list refresh  -  so we DON'T bump. In Idle / Failed there is no in-flight cert
  // callback, but the armed cycle timer IS generation-guarded, so we bump and RE-ARM at the new generation (a
  // short recheck) to pick up the rotated cert without bricking.
  switch (mState)
  {
  case State::Polling:
  case State::RequestingCert:
    ++mGeneration;
    mPollTimer.cancel();
    if (mAwaitingCertificateStatus)
    {
      // The CertificateManager has not answered yet: ask again rather than request a certificate it may not
      // require (Table 21).
      mAwaitingCertificateStatus = false;
      begin_group(mGeneration);
      return;
    }
    enter_requesting_cert(mGeneration);  // restart the renewal with the new cert.
    return;
  case State::Idle:
  case State::Failed:
    ++mGeneration;
    mCycleTimer.cancel();
    arm_cycle_timer(
      mGeneration, std::chrono::duration_cast<std::chrono::milliseconds>(mPolicy.minCycleBackoff));
    return;
  default:
    // In-flight, non-cert-bound state: keep the current generation so the commit / broadcast / bootstrap
    // completes and its generation-guarded continuation still fires (a queued stop is honoured by
    // on_revalidated even so). The dropped requests already took effect above.
    return;
  }
}

// ================= timers =================

void PullCertificateManagerImpl::arm_cycle_timer(std::uint64_t generation, std::chrono::milliseconds delay)
{
  mLastArmedCycleDelay = delay;
  mLastArmedCycleGeneration = generation;
  mCycleTimer.expires_after(delay);
  mCycleTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](PullCertificateManagerImpl& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (cancel / re-arm / stop).
      }
      if (!self.is_current(generation) || (self.mState != State::Idle && self.mState != State::Failed))
      {
        return;
      }
      self.start_cycle(self.mGeneration);
    }));
}

void PullCertificateManagerImpl::arm_poll_timer(std::uint64_t generation)
{
  const std::chrono::milliseconds delay = poll_delay();
  mLastArmedPollDelay = delay;
  mPollTimer.expires_after(delay);
  mPollTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](PullCertificateManagerImpl& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (cancel / re-arm / stop).
      }
      if (!self.is_current(generation) || self.mState != State::Polling)
      {
        return;
      }
      self.do_poll(generation);
    }));
}

// ================= helpers =================

bool PullCertificateManagerImpl::is_current(std::uint64_t generation) const noexcept
{
  return mGeneration == generation && mState != State::Closed;
}

void PullCertificateManagerImpl::set_state(State state)
{
  mState = state;
  publish_snapshot();
}

void PullCertificateManagerImpl::publish_snapshot()
{
  auto info = std::make_shared<ua::client::PullCertManagementInfo>();
  info->state = mState;
  info->lastSuccessfulCycleAt = mLastSuccessfulCycleAt;
  info->lastTrustListCommitAt = mLastTrustListCommitAt;
  info->lastCertCommitAt = mLastCertCommitAt;
  info->failureCount = mFailureCount;
  info->lastError = mLastError;
  info->pendingRequests.reserve(mPendingRequests.size());
  for (const PersistedRequest& request : mPendingRequests)
  {
    ua::client::PendingRequestInfo entry;
    entry.certificateGroupId = request.certificateGroupId;
    entry.certificateTypeId = request.certificateTypeId;
    entry.requestId = request.requestId;
    entry.persistedAt = request.persistedAt;
    info->pendingRequests.push_back(std::move(entry));
  }

  std::shared_ptr<const ua::client::PullCertManagementInfo> shared = std::move(info);
  mInfoSnapshot.store(shared, std::memory_order_release);
  if (mHost)  // M5(b): the host is released after the final Closed publish (finalize_stop).
  {
    mHost->publish_info_snapshot(shared);
  }
}

void PullCertificateManagerImpl::deliver_void(std::function<void(VoidResult)> callback, VoidResult result)
{
  if (!callback)
  {
    return;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger,
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

void PullCertificateManagerImpl::fire_force_cycle_acks(VoidResult result)
{
  if (mForceCycleAcks.empty())
  {
    return;
  }
  std::vector<std::function<void(VoidResult)>> acks;
  acks.swap(mForceCycleAcks);
  for (auto& ack : acks)
  {
    deliver_void(std::move(ack), result);
  }
}

void PullCertificateManagerImpl::lifecycle(
  LifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail)
{
  if (mHost)  // M5(b): the host is released after the final Closed publish (finalize_stop).
  {
    mHost->fire_observer_pull_cert_lifecycle(event, std::move(detail));
  }
}

void PullCertificateManagerImpl::advisory(std::string code, std::string summary, std::string_view source,
  std::shared_ptr<const ua::ErrorDetail> cause)
{
  // The host interface has no generic advisory channel (section 8.1A carries advisories on lifecycle events);
  // a non-lifecycle advisory is recorded on the snapshot's lastError and logged so it is never dropped.
  mLastError =
    ua::ErrorDetail::build(std::move(code), "Pull certificate manager advisory", std::string{source})
      .context(ua::ContextKeys::errorMessage, summary)
      .cause(std::move(cause));
  publish_snapshot();
}

void PullCertificateManagerImpl::persist_pending_requests()
{
  if (!mHost)  // M5(b): the host is released after the final Closed publish (finalize_stop).
  {
    return;
  }
  // M8: the write is best-effort for THIS cycle (the requestId also lives in mPendingRequests in memory), but
  // a failure must NOT be silent  -  a lost persist means a restart cannot resume the poll. Surface an
  // advisory (never drop the ErrorDetail).
  mHost->write_persisted_requests_async(mPendingRequests,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [](PullCertificateManagerImpl& self, VoidResult result)
      {
        if (result.is_bad())
        {
          self.mLastError = ua::make_error_detail("PULL_CERT_PERSIST_WRITE_FAILED",
            "persisting the pending certificate requests failed; a restart may not resume the poll",
            std::string{srcPersist},
            result.status_code());
          self.publish_snapshot();
        }
      }));
}

void PullCertificateManagerImpl::clear_group_scratch()
{
  // M6: wipe the cert / key / trust-list scratch (secrets hygiene)  -  a committed private key must not
  // linger in memory once its group is done.
  mCycleTrustList.reset();
  mCycleTrustListLastUpdate.reset();
  mCycleNewCert.reset();
  mCycleNewKey.reset();
  mCycleIssuerChain.clear();
  mCurrentRequestId = ua::NodeId{};
}

void PullCertificateManagerImpl::clear_cycle_scratch()
{
  clear_group_scratch();
  mGroupIndex = 0;
  mCycleTrustListGroupsDone.clear();
  mCycleOwnCertChanged = false;
  mCycleTrustListChanged = false;
  mCycleAdvisory.reset();
  mCycleStatusFailure.reset();
}

const ua::client::CertificateGroupConfig& PullCertificateManagerImpl::current_group() const
{
  return mCertificateGroups[std::min(mGroupIndex, mCertificateGroups.size() - 1)];
}

std::vector<PersistedRequest>::iterator PullCertificateManagerImpl::find_current_pending()
{
  const ua::client::CertificateGroupConfig& group = current_group();
  return std::find_if(mPendingRequests.begin(),
    mPendingRequests.end(),
    [&group](const PersistedRequest& request)
    {
      return request.certificateGroupId == group.certificateGroupId &&
             request.certificateTypeId == group.certificateTypeId;
    });
}

std::chrono::milliseconds PullCertificateManagerImpl::next_cycle_backoff()
{
  const std::uint32_t exponent = mFailureCount > 0 ? mFailureCount - 1 : 0;
  double base = static_cast<double>(mPolicy.minCycleBackoff.count()) * std::pow(2.0, exponent);
  const double ceiling = static_cast<double>(mPolicy.maxCycleBackoff.count());
  base = std::min(base, ceiling);
  double seconds = base;
  if (mPolicy.cycleBackoffJitterPct > 0.0)
  {
    std::uniform_real_distribution<double> jitter(
      1.0 - mPolicy.cycleBackoffJitterPct, 1.0 + mPolicy.cycleBackoffJitterPct);
    seconds = base * jitter(mJitterRng);
    seconds = std::min(seconds, ceiling);  // clamp jitter to the ceiling.
  }
  auto millis = static_cast<std::int64_t>(std::llround(seconds * 1000.0));
  return std::chrono::milliseconds{millis};
}

std::chrono::milliseconds PullCertificateManagerImpl::regular_cycle_delay()
{
  constexpr std::int64_t millisPerSecond = 1'000;
  const std::int64_t periodSeconds = mPolicy.updateFrequency.count();
  if (periodSeconds <= 0)
  {
    return std::chrono::milliseconds{1};
  }
  const std::int64_t maximumMillis = std::chrono::milliseconds::max().count();
  if (periodSeconds > maximumMillis / millisPerSecond)
  {
    return std::chrono::milliseconds::max();
  }
  const auto period = std::chrono::duration_cast<std::chrono::milliseconds>(mPolicy.updateFrequency);
  const std::int64_t periodMillis = period.count();
  // Part 12 section 6.3 requires the second cyclic PullManagement action to start with a random delay between
  // 1% and at least 10% of its cycle period. Keep updateFrequency as the nominal cadence and add the
  // anti-synchronisation delay; replacing the period with the jitter would make a 24h cycle run in minutes.
  const std::int64_t minimumJitterMillis =
    std::max<std::int64_t>(1, periodMillis / 100 + (periodMillis % 100 != 0 ? 1 : 0));
  const std::int64_t maximumJitterMillis = std::max(minimumJitterMillis, periodMillis / 10);
  std::uniform_int_distribution<std::int64_t> jitter(minimumJitterMillis, maximumJitterMillis);
  const std::int64_t selectedJitterMillis = jitter(mJitterRng);
  if (periodMillis > maximumMillis - selectedJitterMillis)
  {
    return std::chrono::milliseconds::max();
  }
  return period + std::chrono::milliseconds{selectedJitterMillis};
}

std::chrono::milliseconds PullCertificateManagerImpl::poll_delay()
{
  const double base = static_cast<double>(mPolicy.pollInitialDelay.count()) *
                      std::pow(mPolicy.pollBackoffMultiplier, static_cast<double>(mPollAttempt));
  double millis = base;
  if (mPolicy.pollJitterPct > 0.0)
  {
    // M4: apply the configured poll jitter band (mirrors next_cycle_backoff) so bursts of clients do not poll
    // FinishRequest in lockstep.
    std::uniform_real_distribution<double> jitter(1.0 - mPolicy.pollJitterPct, 1.0 + mPolicy.pollJitterPct);
    millis = base * jitter(mJitterRng);
  }
  return std::chrono::milliseconds{static_cast<std::int64_t>(std::llround(millis))};
}

}  // namespace ua::client::detail

// ================= public PullCertificateManager shared-handle facade (section 8.1A.1) =================

namespace ua::client
{

PullCertificateManager::PullCertificateManager(
  std::shared_ptr<detail::PullCertificateManagerImpl> impl) noexcept
  : mImpl(std::move(impl))
{}

PullCertificateManager::~PullCertificateManager()
{
  // Best-effort stop on the manager's own strand. The blocking-join dtor semantics (section 8.1A.3) are
  // deferred to the Client-wiring slice (a contained join needs the Client-owned runtime); here the
  // strand-core drops its in-flight work by generation and closes the GDS connection.
  if (mImpl)
  {
    mImpl->stop_async([](ua::VoidResult) {});
  }
}

std::shared_ptr<const PullCertManagementInfo> PullCertificateManager::pull_cert_info() const noexcept
{
  if (!mImpl)
  {
    return std::make_shared<const PullCertManagementInfo>();
  }
  return mImpl->pull_cert_info();
}

void PullCertificateManager::force_cycle_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
    return;
  }
  mImpl->force_cycle_async(std::move(callback));
}

void PullCertificateManager::stop_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
    return;
  }
  mImpl->stop_async(std::move(callback));
}

}  // namespace ua::client
