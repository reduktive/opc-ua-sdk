// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PULL_CERTIFICATE_MANAGER_CLIENT_HOST_H
#define UA_PULL_CERTIFICATE_MANAGER_CLIENT_HOST_H

/// @file
/// @brief The concrete tier-1 @ref ua::client::detail::PullCertificateManagerHost shim (client design
/// section 8.1A,
///        Slice W6-wire): a leaf that IMPLEMENTS the narrow host interface the own-strand
///        @ref ua::client::detail::PullCertificateManagerImpl consumes for ALL external I/O, by
///        weak-referencing @ref ua::client::CoreClientImpl. The strand-core never touches a raw GDS
///        `Connection`, `CertificateStore`, `Crypto`, or observer directly  -  every primitive is an abstract
///        host method, which this shim rehydrates against the real Client machinery: the in-process
///        persisted-request store, the atomic cert/trust-list staging (with the H4(b) cert<=>key/issuer
///        binding validation), the server-cert revalidation broadcast (@ref
///        CoreClientImpl::revalidate_connections_async, W5), the Client-scoped observer fan-out (@ref
///        ClientObserverSink, J58/W1), and the Rule-4 cross-strand snapshot all live here.
///
/// ## Ownership (the ONE intentional cycle-exception, mirroring the W4 redundancy host)
/// @ref PullCertificateManagerImpl holds THIS host STRONG (`shared_ptr<PullCertificateManagerHost>`)  -  the
/// single intentional exception to the "no strong cycle" rule  -  so a late reply always lands somewhere.
/// This shim holds @ref CoreClientImpl WEAK and the @ref ClientObserverSink STRONG (the sink outlives the
/// host and posts every hook to the executor, the design specification), so no cycle re-forms back into the
/// orchestrator (the design specification). The latent manager to host edge is severed by `stop_async`
/// (`do_stop`  to  `mHost.reset()`) before the pair is torn down, so no leak forms (the section 8.1A.3
/// close-order note).
///
/// ## GDS transport
/// `open_gds_connection_async` drives a real `Client::connect_async`  -  a SignAndEncrypt + Anonymous
/// channel validated against the bootstrap trust store (CL-PULLCRT-001/002)  -  and stashes the resulting
/// `Connection` in `mGdsConnection`; `close_gds_connection_async` closes it (and latches the stop-races-open
/// guard). The GDS-RPC primitives (TrustList download / cert-request) still null-guard `mGdsConnection` and
/// complete a source-tagged `Bad` when it is null  -  those RPCs (CL-PULLCRT-003/004/005) ride the stashed
/// Connection in their own slices. @ref set_gds_connection_for_test injects a real/fake `Connection` so the
/// RPC tests can drive the present-branch orchestration without a live open.
/// @ingroup client

#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_pull_certificate_manager_host.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ua
{
class X509Certificate;
}  // namespace ua

namespace ua::client
{
class CoreClientImpl;
class Connection;
}  // namespace ua::client

namespace ua::client::detail
{

class ClientObserverSink;

/// The concrete @ref PullCertificateManagerHost bound to one @ref CoreClientImpl (section 8.1A, W6). A leaf:
/// it owns no strand, holds an in-memory persisted-request store, forwards revalidation to `CoreClientImpl`,
/// stages cert / trust-list updates through `CoreClientImpl::certificate_store()` (after the H4(b) binding
/// validation via `CoreClientImpl::crypto()`), routes observer fan-out to the Client-scoped @ref
/// ClientObserverSink, and owns the atomic @ref ua::client::PullCertManagementInfo backing store. Every
/// manufactured failure carries a `client.tier1.pull_cert.*` source-tagged @ref ua::ErrorDetail (the design
/// specification  -  never a silent no-op).
class PullCertificateManagerClientHost final
  : public PullCertificateManagerHost,
    public std::enable_shared_from_this<PullCertificateManagerClientHost>
{
public:
  /// @param client   The orchestrator this host reaches for crypto / cert-store / revalidation (WEAK; the
  ///                 host must not own it).
  /// @param executor The executor boundary failures + posted completions are delivered on (the Client
  ///                 executor; outlives the manager).
  /// @param sink     The Client-scoped observer fan-out sink (STRONG; the sink posts each hook to the
  ///                 executor, the design specification).
  /// @param ownCert  The on-channel own-cert snapshot for @ref current_own_cert_thumbprint_sha1 (may be null;
  ///                 the live GDS-connection cert-rotation tracking is the deferred W6b wiring).
  /// @param logger   Logger for the guarded async boundaries.
  PullCertificateManagerClientHost(std::weak_ptr<CoreClientImpl> client,
    boost::asio::any_io_executor executor, std::shared_ptr<ClientObserverSink> sink,
    std::shared_ptr<const ua::X509Certificate> ownCert, ua::Logger logger);

  PullCertificateManagerClientHost(const PullCertificateManagerClientHost&) = delete;
  PullCertificateManagerClientHost& operator=(const PullCertificateManagerClientHost&) = delete;
  PullCertificateManagerClientHost(PullCertificateManagerClientHost&&) = delete;
  PullCertificateManagerClientHost& operator=(PullCertificateManagerClientHost&&) = delete;
  /// Best-effort backstop: closes any still-stashed GDS Connection on the drop-without-explicit-stop path
  /// (the reliable close is `close_gds_connection_async` via `stop_async`). See the .cpp.
  ~PullCertificateManagerClientHost() override;

  // -------- Runtime --------
  [[nodiscard]] boost::asio::any_io_executor executor() override;
  [[nodiscard]] std::string current_own_cert_thumbprint_sha1() const override;

  // -------- GDS bootstrap (DEFER-STUB, W6b) --------
  void open_gds_connection_async(
    GdsConnectionRequest request, std::function<void(ua::VoidResult)> callback) override;
  void close_gds_connection_async(std::function<void(ua::VoidResult)> callback) override;

  // -------- TrustList (GDS RPC; null-guarded until W6b) --------
  void read_trust_list_last_update_time_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<std::optional<ua::DateTime>>)> callback) override;
  void read_trust_list_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<ua::TrustListDataType>)> callback) override;

  // -------- Cert renewal (GDS RPC; null-guarded until W6b) --------
  void get_certificate_status_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    ua::NodeId certificateTypeId, std::function<void(ua::Result<bool>)> callback) override;
  void start_certificate_request_async(
    CertRequestParams params, std::function<void(ua::Result<ua::NodeId>)> callback) override;
  void finish_certificate_request_async(ua::NodeId applicationId, ua::NodeId requestId,
    std::function<void(ua::Result<FinishCertificateResult>)> callback) override;

  // -------- Atomic persistence (H4(b) binding validation + CertificateStore staging) --------
  /// Validates the H4(b) cert<=>key/issuer binding, then stages the update to the runtime CertificateStore.
  ///
  /// ATOMICITY LIMITATION (flagged): @ref ua::CertificateStore has NO batch / transactional apply API, so
  /// this commits step-by-step and is NOT truly cross-set atomic  -  a mid-sequence failure leaves a
  /// partially applied store. Until a transactional store API lands (a follow-up), the scope of change is
  /// bounded by ordering the own-cert swap LAST (least-reversible-last) behind the idempotent trust-list /
  /// issuer replaces, plus the manager's non-advancing retry. See the impl's run_store_steps.
  void apply_cert_update_async(CertUpdate update, std::function<void(ua::VoidResult)> callback) override;

  // -------- PersistedRequest IO (in-memory store, J59) --------
  void read_persisted_requests_async(
    std::function<void(ua::Result<std::vector<PersistedRequest>>)> callback) override;
  void write_persisted_requests_async(
    std::vector<PersistedRequest> requests, std::function<void(ua::VoidResult)> callback) override;

  // -------- Revalidation broadcast ( to  CoreClientImpl::revalidate_connections_async, W5) --------
  void revalidate_connections_async(bool ownCertificateChanged, bool revalidateServerCertificate,
    std::function<void(ua::VoidResult)> callback) override;

  // -------- Observer fan-out (routed to the Client-scoped sink; the sink posts to the executor) --------
  void fire_observer_certificate_rotated(std::shared_ptr<const ua::X509Certificate> newCert) override;
  void fire_observer_pull_cert_lifecycle(
    ua::client::PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail) override;

  // -------- Rule 4 cross-strand snapshot (host owns the atomic backing store) --------
  void publish_info_snapshot(std::shared_ptr<const ua::client::PullCertManagementInfo> info) override;

  /// The last published cross-strand snapshot (lock-free load; Rule 4). Never a strand read. Used by the
  /// wiring layer + tests to read the host's backing store without touching a strand.
  [[nodiscard]] std::shared_ptr<const ua::client::PullCertManagementInfo> info_snapshot() const noexcept;

  /// TEST-INJECT interface (W6b prerequisite): sets the owned GDS `Connection` the GDS-RPC primitives drive.
  /// In production the DEFER-STUB `open_gds_connection_async` never sets it (it stays null); a test injects a
  /// real/fake `Connection` here to exercise the present-branch RPC orchestration.
  void set_gds_connection_for_test(std::shared_ptr<ua::client::Connection> connection);

  /// TEST interface: overrides the own-cert snapshot @ref current_own_cert_thumbprint_sha1 reads.
  void set_own_cert_for_test(std::shared_ptr<const ua::X509Certificate> ownCert);

private:
  void complete_gds_open(std::shared_ptr<ua::client::Connection> connection,
    std::shared_ptr<const ua::X509Certificate> ownCert, std::function<void(ua::VoidResult)> callback);

  std::weak_ptr<CoreClientImpl> mClient;  // WEAK  -  the host must not own the orchestrator.
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<ClientObserverSink> mSink;  // STRONG  -  outlives the host; posts hooks to the executor.
  ua::Logger mLogger;

  // The on-channel own-cert snapshot for the synchronous thumbprint read (CL-PULLCRT-004). Atomic because the
  // read is a cross-strand snapshot with no strand of its own.
  std::atomic<std::shared_ptr<const ua::X509Certificate>> mOwnCert;

  // The owned GDS Connection (null in production  -  open is DEFER-STUB W6b; a test injects one). Guarded by
  // mGdsMutex so a test-inject / RPC read never races.
  mutable std::mutex mGdsMutex;
  std::shared_ptr<ua::client::Connection> mGdsConnection;  // guarded by mGdsMutex
  // Latched by close_gds_connection_async (the stop path): once set, a late-completing open_gds must NOT
  // stash its Connection (it closes it instead), so a stop racing an in-flight open never leaves an un-closed
  // GDS session lingering on the server. Guarded by mGdsMutex.
  bool mGdsClosing = false;

  // In-memory persisted-request store (J59; a file-backed store surviving restart is a follow-up).
  mutable std::mutex mPersistMutex;
  std::vector<PersistedRequest> mPersistedRequests;  // guarded by mPersistMutex

  std::atomic<std::shared_ptr<const ua::client::PullCertManagementInfo>> mInfoSnapshot{
    std::make_shared<const ua::client::PullCertManagementInfo>()};
};

}  // namespace ua::client::detail

#endif  // UA_PULL_CERTIFICATE_MANAGER_CLIENT_HOST_H
