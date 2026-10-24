// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The narrow, mockable host interface the own-strand @ref
/// ua::client::detail::PullCertificateManagerImpl
///        (client design section 8.1A) consumes for ALL external I/O. The manager NEVER reaches into `Client`
///        / `ConnectionImpl` / a raw GDS `Connection` directly  -  it holds an abstract @ref
///        ua::client::detail::PullCertificateManagerHost (the concrete shim on `CoreClientImpl` + a real GDS
///        transport is deferred, cf. section 8.1A.3). The interface keeps the manager unit-testable against
///        `FakePullCertificateManagerHost` with no GDS, cert store, or wire stack: the GDS bootstrap, the
///        Part-12 section 7.6 cert-request / TrustList RPCs, the atomic persist, the persisted-request IO,
///        the revalidation broadcast, the observer fan-out, and the Rule-4 cross-strand snapshot all live
///        here.
///
///        section 8.1A shows the manager calling `mGdsConnection->call_method_async(...)` directly; folding
///        those GDS RPCs into this interface (mirroring `RedundancyManagerHost::read_attributes_async`) is
///        what makes the strand-core mockable per the design specification's testable-interface mandate. The
///        concrete shim rehydrates each primitive against the real GDS `Connection` (section 8.10
///        `FileTransferClient` for the TrustList Open/Read)  -  that wiring is the deferred Slice 11b-wire.
/// @ingroup client

#ifndef UA_PULL_CERTIFICATE_MANAGER_HOST_H
#define UA_PULL_CERTIFICATE_MANAGER_HOST_H

#include "ua_byte_string.h"
#include "ua_crypto_types.h"  // ua::SecurityPolicyId (the GDS channel policy)
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_pull_certificate_manager.h"  // PullCertLifecycleEvent, PullCertManagementInfo
#include "ua_result.h"
#include "ua_trust_list_data_type.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua
{
class CertificateStore;
class X509Certificate;
}  // namespace ua

namespace ua::client::detail
{

/// A Start  to  Finish request that survives SDK restarts (section 8.1A host interface; CL-PULLCRT-003 /
/// CL-PULLCRT-004).
struct PersistedRequest
{
  ua::NodeId certificateGroupId;  ///< e.g. `DefaultApplicationGroup`.
  ua::NodeId certificateTypeId;  ///< RSA-SHA256, ECDSA-NIST256, ...
  ua::NodeId requestId;  ///< server-issued by StartSigningRequest / StartNewKeyPairRequest.
  std::string certThumbprintSha1;  ///< on-channel own-cert thumbprint at issuance (CL-PULLCRT-004).
  ua::DateTime persistedAt;
};

/// The abstract host interface for @ref PullCertificateManagerImpl (section 8.1A).
///
/// Every I/O primitive is async: the host posts internally to its own executor / GDS-connection strand and
/// delivers on the executor; the manager's own strand picks up the reply via a post-borrowing wrapper.
/// Observer fan-out (`fire_observer_*`) is posted to the executor by the host (the design specification  -
/// never the manager's strand). The thumbprint read is synchronous (a cross-strand snapshot of the on-channel
/// own-cert).
///
/// deferred (Slice 11b-wire): each host RPC below is expected to enforce its OWN per-step watchdog timeout
/// and bound the decoded response size (the TrustList blob / issuer-chain / GDS response caps)  -  the
/// concrete shim owns those limits because it holds the wire stack. The strand-core relies on every primitive
/// completing (a hung RPC would otherwise strand the FSM); the manager adds no timer of its own around a host
/// call in this slice.
class PullCertificateManagerHost
{
public:
  /// The hard-coded overlay the manager applies to the GDS Connection (CL-PULLCRT-001 / CL-PULLCRT-002).
  struct GdsConnectionRequest
  {
    std::string endpointUrl;
    ua::MessageSecurityMode securityMode = ua::MessageSecurityMode::SignAndEncrypt;  ///< manager forces this.
    ua::SecurityPolicyId securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;  ///< GDS channel policy.
    std::shared_ptr<const ua::X509Certificate> serverCertificate;  ///< GDS cert (SignAndEncrypt OPN target).
    bool anonymousIdentity = true;  ///< manager forces Anonymous (CL-PULLCRT-002).
    std::shared_ptr<ua::CertificateStore> bootstrapTrustStore;  ///< OPN validation store (CL-PULLCRT-001).
  };

  /// The parameters of a `StartSigningRequest` / `StartNewKeyPairRequest` (CL-PULLCRT-002 / CL-PULLCRT-004).
  struct CertRequestParams
  {
    ua::NodeId applicationId;
    ua::NodeId certificateGroupId;
    ua::NodeId certificateTypeId;
    bool newKeyPair = false;  ///< false = `StartSigningRequest`, true = `StartNewKeyPairRequest`.
    ua::ByteString certificateRequest;  ///< DER PKCS #10 request for StartSigningRequest.
    std::string subjectName;  ///< StartNewKeyPairRequest subject; empty requests a server default.
    std::vector<std::string> domainNames;  ///< StartNewKeyPairRequest DNS names.
    std::string privateKeyFormat{"PEM"};  ///< StartNewKeyPairRequest key encoding.
  };

  /// The result of a successful `FinishRequest` (section 8.1A.7). A `Bad_NothingToDo` status is delivered as
  /// the Result's status, NOT via this payload (the manager treats it as "still in approval queue").
  struct FinishCertificateResult
  {
    std::shared_ptr<const ua::X509Certificate> certificate;  ///< the renewed own cert.
    std::optional<ua::ByteString> privateKey;  ///< present only for a `StartNewKeyPairRequest`.
    std::vector<std::shared_ptr<const ua::X509Certificate>> issuerChain;
  };

  /// Atomic persistence payload (CL-PULLCRT-005). The host writes both artefacts to staging, fsyncs, then
  /// renames so both updates are observed atomically; on failure the staging is discarded and the runtime
  /// store is untouched.
  struct CertUpdate
  {
    std::shared_ptr<const ua::X509Certificate> newOwnCert;  ///< null = no cert change this commit.
    std::optional<ua::ByteString> newPrivateKey;  ///< encrypted at rest by the host.
    std::optional<ua::TrustListDataType> newTrustList;  ///< nullopt = no trust-list change this commit.
    std::optional<ua::DateTime> trustListLastUpdate;  ///< section 7.8.2.1 `LastUpdateTime`.
    /// M9: the issuer chain delivered alongside @ref newOwnCert. Empty when no cert changed this commit. The
    /// store persists it so the renewed leaf validates to a trusted anchor.
    std::vector<std::shared_ptr<const ua::X509Certificate>> newIssuerChain;
  };

  PullCertificateManagerHost() = default;
  PullCertificateManagerHost(const PullCertificateManagerHost&) = delete;
  PullCertificateManagerHost& operator=(const PullCertificateManagerHost&) = delete;
  PullCertificateManagerHost(PullCertificateManagerHost&&) = delete;
  PullCertificateManagerHost& operator=(PullCertificateManagerHost&&) = delete;
  virtual ~PullCertificateManagerHost() = default;

  // -------- Runtime --------

  /// The executor the manager makes its private strand from (the host owns the runtime). The concrete shim
  /// returns the `Client` executor; tests return an `io_context` executor.
  [[nodiscard]] virtual boost::asio::any_io_executor executor() = 0;

  /// The on-channel own-cert SHA-1 thumbprint (CL-PULLCRT-004; synchronous cross-strand snapshot read).
  [[nodiscard]] virtual std::string current_own_cert_thumbprint_sha1() const = 0;

  // -------- GDS bootstrap (CL-PULLCRT-001 / CL-PULLCRT-002) --------

  /// Opens the manager's own GDS Connection with the hard-coded SignAndEncrypt + Anonymous overlay, using the
  /// bootstrap trust store for the OPN handshake. `Good` once the connection is up.
  virtual void open_gds_connection_async(
    GdsConnectionRequest request, std::function<void(ua::VoidResult)> callback) = 0;

  /// Closes the manager's GDS Connection (on `stop_async`).
  virtual void close_gds_connection_async(std::function<void(ua::VoidResult)> callback) = 0;

  // -------- TrustList (CL-PULLCRT-005) --------

  /// Reads `TrustListType.LastUpdateTime` for @p certificateGroupId. `nullopt` value = the server published
  /// no `LastUpdateTime`.
  virtual void read_trust_list_last_update_time_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<std::optional<ua::DateTime>>)> callback) = 0;

  /// `GetTrustList` + `Open(Read)` + Read drain, decoding to a `TrustListDataType` (rides section 8.10
  /// `FileTransferClient` in the concrete shim).
  virtual void read_trust_list_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<ua::TrustListDataType>)> callback) = 0;

  // -------- Cert renewal (CL-PULLCRT-003 / CL-PULLCRT-004) --------

  /// `GetCertificateStatus` (OPC 10000-12 7.9.10): whether the GDS requires a new certificate of
  /// @p certificateTypeId in @p certificateGroupId (null: the GDS's default) for @p applicationId.
  virtual void get_certificate_status_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    ua::NodeId certificateTypeId, std::function<void(ua::Result<bool>)> callback) = 0;

  /// `StartSigningRequest` / `StartNewKeyPairRequest`; delivers the server-issued `requestId`.
  virtual void start_certificate_request_async(
    CertRequestParams params, std::function<void(ua::Result<ua::NodeId>)> callback) = 0;

  /// `FinishRequest` poll. A `Bad_NothingToDo` Result is the "still in approval queue" signal.
  virtual void finish_certificate_request_async(ua::NodeId applicationId, ua::NodeId requestId,
    std::function<void(ua::Result<FinishCertificateResult>)> callback) = 0;

  // -------- Atomic persistence (CL-PULLCRT-005) --------

  /// Atomically commits @p update to the runtime store (staging  to  fsync  to  rename).
  ///
  /// H4(b) interface contract  -  the strand-core treats the pulled cert/key/chain as OPAQUE ByteStrings
  /// (real crypto is deferred to the concrete shim), so the manager CANNOT itself verify the cert<=>request
  /// binding. The implementing host is therefore REQUIRED, before it promotes staging, to validate:
  ///  - the new certificate's public key matches the key pair the request was issued with (the CSR public key
  ///    for a `StartSigningRequest`, or the server-returned key pair for a `StartNewKeyPairRequest`); and
  ///  - `newIssuerChain` (with `newOwnCert`) chains to a trusted anchor.
  /// On a binding/chain-validation failure the host MUST return `Bad` (staging discarded, runtime store
  /// untouched)  -  it MUST NOT silently accept a cert whose key/issuer it could not bind. The manager can
  /// only pre-screen for a structurally-absent certificate (see `on_finish_request`); the cryptographic
  /// binding is this interface's obligation.
  virtual void apply_cert_update_async(CertUpdate update, std::function<void(ua::VoidResult)> callback) = 0;

  // -------- PersistedRequest IO (CL-PULLCRT-003 / CL-PULLCRT-004) --------

  virtual void read_persisted_requests_async(
    std::function<void(ua::Result<std::vector<PersistedRequest>>)> callback) = 0;
  virtual void write_persisted_requests_async(
    std::vector<PersistedRequest> requests, std::function<void(ua::VoidResult)> callback) = 0;

  // -------- Revalidation broadcast (CL-PULLCRT-006) --------

  /// Walks `CoreClient::mConnections` (weak refs); @p ownCertificateChanged forces the Part 4 section 6.7
  /// new-Session path on every live Connection. @p revalidateServerCertificate independently controls whether
  /// each current server certificate is checked against the updated trust store.
  virtual void revalidate_connections_async(bool ownCertificateChanged, bool revalidateServerCertificate,
    std::function<void(ua::VoidResult)> callback) = 0;

  // -------- Observer fan-out (host posts to the executor  -  never the manager's strand) --------

  /// CL-RECONN-006 pre-FSM hook  -  fired when the manager commits a new own-cert.
  virtual void fire_observer_certificate_rotated(std::shared_ptr<const ua::X509Certificate> newCert) = 0;
  virtual void fire_observer_pull_cert_lifecycle(
    ua::client::PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail) = 0;

  // -------- Rule 4 cross-strand snapshot (host owns the atomic backing store) --------

  virtual void publish_info_snapshot(std::shared_ptr<const ua::client::PullCertManagementInfo> info) = 0;
};

}  // namespace ua::client::detail

#endif  // UA_PULL_CERTIFICATE_MANAGER_HOST_H
