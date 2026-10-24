// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 Pull-Model certificate + trust-list management surface (client design section 8.1A, Phase
/// F): the
///        public @ref ua::client::PullCertificateManager handle, its @ref
///        ua::client::PullCertManagementConfig knobs, the @ref ua::client::PullCertManagementInfo diagnostics
///        snapshot, and the @ref ua::client::PullCertManagementState / @ref
///        ua::client::PullCertLifecycleEvent enums. The strand-bearing engine that drives the Part 12
///        section 7.6 Pull Management workflow (GDS-backed cert renewal + TrustList refresh + atomic persist
///        + revalidation broadcast) lives on the private `ua::client::detail::PullCertificateManagerImpl`
///        (section 8.1A.2), which this shared handle forwards to.
/// @ingroup client

#ifndef UA_PULL_CERTIFICATE_MANAGER_H
#define UA_PULL_CERTIFICATE_MANAGER_H

#include "ua_byte_string.h"
#include "ua_crypto_types.h"  // ua::SecurityPolicyId (the GDS channel policy)
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_result.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua
{
class CertificateStore;  // tier-0 trust/own-cert store (injected via the config)
class X509Certificate;  // the GDS server certificate (for the SignAndEncrypt OPN)
}  // namespace ua

namespace ua::client
{

namespace detail
{
class PullCertificateManagerImpl;
struct PullCertificateManagerFactory;
struct PullCertificateManagerTestAccess;
}  // namespace detail

/// One certificate group the manager renews (section 8.1A.1). A group pairs a GDS certificate-group Object
/// with the certificate type to request under it.
/// @ingroup client
struct CertificateGroupConfig
{
  /// The CertificateGroup on the GDS. Null (the default) lets the CertificateManager choose its
  /// DefaultApplicationGroup (OPC 10000-12 7.9.3); a GDS's own group NodeIds live in its namespace, so the
  /// local server's `ServerConfiguration` group ids do not name them.
  ua::NodeId certificateGroupId{};
  /// The certificate type Object NodeId (default: RSA-SHA256 application certificate).
  ua::NodeId certificateTypeId = ua::NodeId{ua::ObjectTypeId::RsaSha256ApplicationCertificateType};
  /// When `true`, drive `StartNewKeyPairRequest` (server generates the key pair); otherwise
  /// `StartSigningRequest` (client-generated CSR). Default: signing request.
  bool useNewKeyPair = false;
  /// DER-encoded PKCS #10 request for `StartSigningRequest`. Required when @ref useNewKeyPair is false.
  ua::ByteString certificateRequest;
  /// Subject for `StartNewKeyPairRequest`. Empty lets the CertificateManager derive a suitable default.
  std::string subjectName;
  /// DNS names for `StartNewKeyPairRequest`. Empty lets the CertificateManager use registered discovery URLs.
  std::vector<std::string> domainNames;
  /// Requested private-key encoding for `StartNewKeyPairRequest` (Part 12 mandates PEM and PFX support).
  std::string privateKeyFormat{"PEM"};
  // No password field: the manager requests the new key unprotected (OPC 10000-12 7.9.4: the password is the
  // client's option; 7.9.5: without one the key is returned unprotected). The SignAndEncrypt channel protects
  // it in transit and the application's credential protects it at rest.
};

/// Configuration for a @ref PullCertificateManager (section 8.1A.1). Const after the manager is constructed.
/// @ingroup client
struct PullCertManagementConfig
{
  // ---- GDS endpoint + bootstrap trust (CL-PULLCRT-001) ----
  /// The gds endpoint url.
  std::string gdsEndpointUrl;
  /// Validates the GDS server cert during OPN. Distinct from @ref runtimeCertStore; never mutated by the
  /// pull cycle (CL-PULLCRT-001).
  std::shared_ptr<ua::CertificateStore> bootstrapTrustStore;
  /// Destination of the pulled own-cert + TrustList (CL-PULLCRT-005 / CL-PULLCRT-006).
  ///
  /// When this is a server's certificate store, the application must turn the server's push management off
  /// (`ServerConfig::pushCertificateManagementEnabled = false`; nothing detects it): otherwise the
  /// server's Part 12 TrustList and this pull cycle would both write the store's trust lists, and one could
  /// overwrite the other's change.
  std::shared_ptr<ua::CertificateStore> runtimeCertStore;
  /// Application record identifier assigned by the GDS and passed to every Start/Finish request.
  ua::NodeId applicationId;

  /// Optional override of the GDS channel SecurityMode. The manager hard-codes `SignAndEncrypt`
  /// (CL-PULLCRT-001) and rejects any attempt to weaken it to `None` / `Sign`  -  a rejected override raises
  /// an advisory and the manager still uses `SignAndEncrypt`. `nullopt` = use the hard-coded default.
  std::optional<ua::MessageSecurityMode> requestedGdsSecurityMode;

  /// The security policy for the GDS channel. `SignAndEncrypt` requires a concrete policy, and the SDK
  /// connect is ExactUrl-only (no GetEndpoints discovery), so the caller supplies it. Default
  /// `Basic256Sha256`.
  ua::SecurityPolicyId gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  /// The GDS server's application-instance certificate, encrypted to during the SignAndEncrypt OPN and
  /// validated against @ref bootstrapTrustStore. Required for a secured GDS connect (the SDK does not yet
  /// discover it via GetEndpoints  -  a follow-up); null only for a non-conformant `None` override.
  std::shared_ptr<const ua::X509Certificate> gdsServerCertificate;

  // ---- Cycle scheduling ----
  std::chrono::seconds updateFrequency{24 * 60 * 60};  ///< section 3.13.6 default: full cycle cadence.
  std::chrono::seconds minCycleBackoff{60};  ///< floor after a cycle failure.
  std::chrono::seconds maxCycleBackoff{24 * 60 * 60};  ///< ceiling of the exponential retry backoff.
  /// The cycle backoff jitter pct.
  double cycleBackoffJitterPct = 0.25;

  // ---- Poll loop (CL-PULLCRT-003) ----
  std::chrono::milliseconds pollInitialDelay{1'000};  ///< first `FinishRequest` poll delay.
  std::size_t pollMaxRepeat = 4;  ///< bounded burst before persisting + deferring to the next cycle.
  double pollBackoffMultiplier = 2.0;  ///< Multiplier applied to successive FinishRequest poll delays.
  double pollJitterPct = 0.20;  ///< Fractional jitter applied to successive poll delays.

  // ---- TrustList refresh (CL-PULLCRT-005) ----
  /// The check last update time before download.
  bool checkLastUpdateTimeBeforeDownload = true;
  /// The treat last update time missing as force download.
  bool treatLastUpdateTimeMissingAsForceDownload = true;

  /// Whether each cycle also requests a renewed Application Instance Certificate.
  /// Set false for a TrustList-only deployment; changed TrustLists are still
  /// committed and immediately revalidated.
  bool renewApplicationCertificate = true;

  // ---- Revalidation (CL-PULLCRT-006 / CL-SECADMIN-004) ----
  /// Immediate revalidation pass after every commit; `false` defers to the SecurityToken-renewal
  /// revalidation alone (CL-SECADMIN-004).
  bool revalidateImmediatelyOnCommit = true;

  // ---- Groups ----
  std::vector<CertificateGroupConfig> certificateGroups;  ///< empty  to  a single default group.
};

/// @ingroup client
/// The lifecycle state of the manager's cycle FSM (section 8.1A.4). Surfaced in
/// @ref ua::client::PullCertManagementInfo::state; the transition table is the authority.
enum class PullCertManagementState
{
  Idle,  ///< Cycle armed via the update-frequency timer; no I/O in flight.
  BootstrappingGds,  ///< Opening the GDS Connection.
  RefreshingTrustList,  ///< `GetTrustList` + conditional `Open(Read)` + drain + commit-scratch.
  RequestingCert,  ///< Per-group `StartSigningRequest` / `StartNewKeyPairRequest` in flight.
  Polling,  ///< `FinishRequest` poll loop with bounded burst.
  Persisting,  ///< Atomic write of the cert + key + trust list.
  Revalidating,  ///< Broadcasting revalidation to every open Connection.
  Failed,  ///< Last cycle errored; retry armed on the update-frequency timer.
  Closed  ///< Terminal.
};

/// @ingroup client
/// Lifecycle event fired to the observer (section 8.1A.1). Delivered off-strand by the host.
enum class PullCertLifecycleEvent
{
  Started,
  CycleStarted,
  CycleSucceeded,
  CycleFailed,
  TrustListCommitted,
  CertificateCommitted,
  RevalidationCompleted,
  Stopped
};

/// One in-flight Start  to  Finish request, surfaced for diagnostics (section 8.1A.1).
/// @ingroup client
struct PendingRequestInfo
{
  /// The certificate group id.
  ua::NodeId certificateGroupId;
  /// The certificate type id.
  ua::NodeId certificateTypeId;
  /// The request id.
  ua::NodeId requestId;
  /// The persisted at.
  ua::DateTime persistedAt;
};

/// The cross-strand pull-cert diagnostics snapshot (section 8.1A.1). Replaced atomically after every
/// state-affecting mutation; read lock-free via @ref PullCertificateManager::pull_cert_info.
/// @ingroup client
struct PullCertManagementInfo
{
  /// The state.
  PullCertManagementState state = PullCertManagementState::Idle;
  /// The last successful cycle at.
  std::optional<ua::DateTime> lastSuccessfulCycleAt;
  /// The last trust list commit at.
  std::optional<ua::DateTime> lastTrustListCommitAt;
  /// The last cert commit at.
  std::optional<ua::DateTime> lastCertCommitAt;
  /// The failure count.
  std::uint32_t failureCount = 0;
  /// section 8.1A.5 error chain from the most recent terminal cycle failure (null on no error).
  std::shared_ptr<const ua::ErrorDetail> lastError;
  /// The pending requests.
  std::vector<PendingRequestInfo> pendingRequests;
};

/// The public tier-2 Pull-Model certificate-management handle (section 8.1A.1). Held by the user via
/// `shared_ptr` (returned from `Client::start_pull_cert_management_sync`); dropping it stops the manager. It
/// is a thin forwarder over the strand-bearing `detail::PullCertificateManagerImpl` (own strand).
///
/// **Status codes.** The manager acts on the GDS's answers itself (it installs what they return), so it uses
/// an answer only when it is Good; a Good subcode is accepted. A Bad answer fails the cycle with its code
/// (FinishRequest's Bad_NothingToDo keeps the request pending instead), and an Uncertain one (the GDS
/// Connection, a browse path, the LastUpdateTime Read, a CertificateDirectory Method or the TrustList
/// download) fails it with Bad_InternalError whose ErrorDetail
/// (`ServiceAnswerUncertain`, `ReferencesAnswerUncertain` or `ReadAnswerUncertain`) has the Uncertain code as
/// its cause. The failure is reported in `pull_cert_info().lastError`.
/// @ingroup client
class PullCertificateManager : public std::enable_shared_from_this<PullCertificateManager>
{
public:
  PullCertificateManager(const PullCertificateManager&) = delete;
  PullCertificateManager& operator=(const PullCertificateManager&) = delete;
  PullCertificateManager(PullCertificateManager&&) = delete;
  PullCertificateManager& operator=(PullCertificateManager&&) = delete;
  ~PullCertificateManager();

  /// @return An immutable snapshot of the current state.
  /// Diagnostics  -  the cross-strand snapshot (lock-free; Rule 4). Never null.
  [[nodiscard]] std::shared_ptr<const PullCertManagementInfo> pull_cert_info() const noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Forces a cycle out-of-band (admin tool / smoke test). Resolves `Good` when the cycle completes
  /// (success or failure both `Good`  -  the result is in `pull_cert_info().lastError`). Coalesces if a cycle
  /// is already running. Never throws.
  void force_cycle_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Idempotent stop. Cancels timers, drains in-flight RPCs (by generation), closes the GDS Connection. Any
  /// pending @ref force_cycle_async callbacks complete `Cancelled`. Never throws.
  void stop_async(std::function<void(ua::VoidResult)> callback) noexcept;

private:
  friend struct detail::PullCertificateManagerFactory;
  friend struct detail::PullCertificateManagerTestAccess;

  explicit PullCertificateManager(std::shared_ptr<detail::PullCertificateManagerImpl> impl) noexcept;

  std::shared_ptr<detail::PullCertificateManagerImpl> mImpl;
};

}  // namespace ua::client

#endif  // UA_PULL_CERTIFICATE_MANAGER_H
