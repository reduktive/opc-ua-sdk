// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_PUSH_SERVICE_H
#define UA_CERTIFICATE_PUSH_SERVICE_H

#include "ua_byte_string.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_date_time.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_method_response_correlation.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_string.h"
#include "ua_transaction_error_type.h"
#include "ua_trust_list_manager.h"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ua
{

namespace server
{
class ServerObserver;
}

/// Snapshot of a completed push-certificate transaction, surfaced to the wiring
/// layer so it can populate the NS0 `TransactionDiagnosticsType` Object
/// (Part 12 7.10.11 - renumbered 7.10.17 in UA-1.05.06). Assembled on the
/// CertificatePushService strand at each transaction terminal point (ApplyChanges
/// success/failure, CancelChanges) and delivered via
/// `Dependencies::publishTransactionDiagnostics`.
struct TransactionDiagnosticsRecord
{
  DateTime startTime;  ///< When the transaction started.
  DateTime endTime;  ///< When the transaction completed.
  StatusCode result;  ///< Overall transaction result (ApplyChanges status,
                      ///< or Bad_RequestCancelledByClient on CancelChanges).
  std::vector<NodeId> affectedTrustLists;  ///< TrustListManager NodeIds in the transaction.
  std::vector<NodeId> affectedCertificateGroups;  ///< CertificateGroup NodeIds in the transaction.
  std::vector<TransactionErrorType> errors;  ///< Per-target errors (empty on success).
};

/// Central coordinator for ServerConfigurationType push management methods.
/// Owns transaction lifecycle, pending CSR key pairs, and certificate update state.
/// boost::asio::strand<boost::asio::any_io_executor>-serialized component - all mutable state is accessed
/// exclusively through the strand.
class CertificatePushService : public std::enable_shared_from_this<CertificatePushService>
{
public:
  struct Dependencies
  {
    using DependencyFailureDetailBuilder =
      std::function<std::shared_ptr<const ErrorDetail>(StatusCode cause)>;
    using ApplyWriteStateCheck = std::function<void(std::function<void(Result<bool>)>)>;
    using CertificateDerEncoder =
      std::function<ByteString(const std::shared_ptr<const X509Certificate>& certificate)>;

    boost::asio::strand<boost::asio::any_io_executor> strand;
    std::shared_ptr<const Crypto> crypto;
    std::shared_ptr<CertificateStore> certificateStore;
    std::shared_ptr<TrustListManager> trustList;
    // TrustListManager for the DefaultUserTokenGroup (Part 12 7.8.3.3). Null when the deployment
    // configured no user-token certificate store, in which case that group is not published.
    std::shared_ptr<TrustListManager> userTokenTrustList;
    boost::asio::any_io_executor executor;
    Logger logger;

    // Server identity for building CSR SubjectAlternateName
    std::string applicationUri;
    std::vector<std::string> hostnames;

    // Channel close trigger - acts immediately except for the exactly correlated origin channel.
    std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
      closeAllChannels;

    // Certificate re-evaluation trigger (Part 12 7.8.2.3, 7.10.6) - called after ApplyChanges wrote a
    // changed TrustList: every open SecureChannel and Session re-checks the certificates it holds against
    // the current lists and closes itself when one is no longer valid; the ApplyChanges caller's after its
    // response. Optional: a null hook disables the re-evaluation.
    std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
      reevaluateCertificates;

    // Shutdown trigger - called by ResetToServerDefaults (Part 12 7.10.10) after
    // clearing state, to transition the server to SHUTDOWN with a credential-warning
    // ShutdownReason. Optional: a null hook disables the shutdown side-effect.
    std::function<void()> requestShutdown;

    // Transaction-diagnostics sink - invoked on the service strand at each
    // transaction terminal point with a snapshot of the completed transaction,
    // so the wiring layer can populate the NS0 TransactionDiagnostics Object.
    // Optional: a null callback disables diagnostics population.
    std::function<void(TransactionDiagnosticsRecord)> publishTransactionDiagnostics;

    // Optional builder for mapped dependency-failure diagnostics; an empty builder selects the
    // component default.
    DependencyFailureDetailBuilder dependencyFailureDetailBuilder;

    // Private deterministic interfaces for component tests. Empty callbacks select the production
    // collaborators and certificate encoder.
    ApplyWriteStateCheck applyWriteStateCheck;
    CertificateDerEncoder certificateDerEncoder;

    // Whether a Session still exists. A modification that lands after its Session was closed opens
    // no transaction and takes no claim (nobody could ever apply or cancel it). Optional: a null
    // hook treats every Session as existing.
    std::function<bool(const NodeId&)> sessionExists;

    // The SecurityPolicy of every endpoint the server serves, with a name for messages. UpdateCertificate
    // refuses a certificate that violates any of them (check_own_certificate_against_endpoints, the
    // runtime counterpart of the startup refusal). Read at each UpdateCertificate, so endpoints added after
    // the service was created count. Null: no policy check.
    std::function<std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>()>
      servedEndpointPolicies;

    // The longest ResetToServerDefaults waits for its TrustLists to be cleared before it requests the
    // shutdown anyway and answers Bad_Timeout (Part 12 7.10.10: the shutdown is not optional). The default
    // covers a TrustListManager's wait for another list write (its resetWaitLimit, 5 s) and the clear.
    std::chrono::milliseconds resetDeadline{15000};
  };

  // Transaction state (declared public so per-flow state types can carry
  // PendingCertUpdate snapshots; the data has no privacy semantics - public
  // friends already see it via CertificatePushService-private members).
  struct Transaction
  {
    enum class Phase
    {
      Open,
      Applying,
    };

    NodeId owningSessionId;
    DateTime startTime;  ///< When this transaction was created (Part 12 7.10.11 StartTime).
    uint64_t generation{0};
    Phase phase{Phase::Open};
    /// Opened or joined by a TrustList Open for write or a TrustList change: kept when empty, since only
    /// ApplyChanges, CancelChanges or the Session closing end it (Part 12 Figure 22).
    bool keptWhenEmpty{false};
    std::set<uint64_t> inFlightUpdateReservations;

    struct PendingCertUpdate
    {
      std::shared_ptr<const X509Certificate> certificate;
      std::vector<std::shared_ptr<const X509Certificate>> issuerChain;
      std::shared_ptr<const AsymmetricKeyPair> keyPair;
    };

    std::vector<std::pair<std::pair<NodeId, NodeId>, PendingCertUpdate>> pendingCertificates;
    /// TrustList NodeIds modified within this transaction, in first-modified order. A list rather
    /// than a flag because a transaction can touch more than one certificate group, and Part 12
    /// 7.10.11 AffectedTrustLists reports which.
    std::vector<NodeId> modifiedTrustLists;
  };

  static std::shared_ptr<CertificatePushService> create(Dependencies deps);

  // --- ServerConfigurationType methods (public async API) ---

  void create_signing_request_async(NodeId sessionId, NodeId certificateGroupId, NodeId certificateTypeId,
    String subjectName, bool regeneratePrivateKey, ByteString nonce,
    std::function<void(Result<ByteString>)> callback);

  void update_certificate_async(NodeId sessionId, NodeId certificateGroupId, NodeId certificateTypeId,
    ByteString certificate, std::vector<ByteString> issuerCertificates, String privateKeyFormat,
    ByteString privateKey, std::function<void(Result<bool>)> callback);

  void apply_changes_async(NodeId sessionId, server::MethodResponseCorrelation correlation,
    std::function<void(VoidResult)> callback);

  void cancel_changes_async(NodeId sessionId, std::function<void(VoidResult)> callback);

  void get_rejected_list_async(std::function<void(Result<std::vector<ByteString>>)> callback);

  void get_certificates_async(NodeId certificateGroupId,
    std::function<void(Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>)> callback);

  // ResetToServerDefaults (Part 12 7.10.10): clears every TrustList and triggers a server shutdown (via
  // the requestShutdown hook) so the server restarts at its default configuration. The shutdown is
  // requested once the clears end or Dependencies::resetDeadline passes, whichever is first; the answer is
  // Good only when every TrustList was cleared, otherwise the failure (Bad_Timeout at the deadline).
  // Authorization (SecurityAdmin + authenticated channel) is enforced at the wiring layer.
  void reset_to_server_defaults_async(NodeId sessionId, std::function<void(VoidResult)> callback);

  // Session lifecycle - posted from ServerObserver
  void on_session_closed_async(NodeId sessionId);

  // TrustListManager notification - called from the modified TrustListManager's strand.
  // trustListId identifies which certificate group's list changed. @p claim is the claim the
  // modification held: released once the transaction it opens carries the ownership. A change whose
  // transaction ended while it ran (the claim's generation) opens none: its staged lists are dropped.
  void on_trust_list_modified(
    NodeId sessionId, NodeId trustListId, std::shared_ptr<TrustListModificationClaim> claim = nullptr);

  /// TrustListManager notification - a TrustList was opened with write access (Part 12 Figure 22: the Open
  /// creates the transaction or continues the Session's own). Called from that manager's strand with the
  /// claim the Open took; the transaction is opened or joined on this service's strand, then the claim is
  /// released. Nothing is opened when the claim's transaction ended meanwhile or the Session is gone.
  void on_trust_list_opened_for_write(NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim);

  /// Whether @p sessionId may modify a trust list now: Good when no transaction is open or the
  /// session owns it, Bad_TransactionPending while another session does. Read from any thread (a
  /// mutex-guarded snapshot of the owner, kept beside the transaction), so the TrustListManager can
  /// refuse a change BEFORE applying it instead of applying it and skipping the re-evaluation
  /// (Part 12 7.8.2.3; security review B3-3).
  StatusCode trust_list_modification_allowed(const NodeId& sessionId) const;

  /// Claims the transaction for @p sessionId before a trust-list modification is applied: the claim
  /// (recorded, counted per session) when no session owns or claims it or this one does,
  /// Bad_TransactionPending otherwise, Bad_SessionIdInvalid for a Session the server no longer holds.
  /// The claim records the transaction it belongs to: the one held, or the one the change would open
  /// (TrustListModificationClaim::transaction_generation).
  /// Dropping the returned claim withdraws it; the modified callback that follows a successful
  /// modification hands it to on_trust_list_modified, which turns it into the transaction
  /// (ensure_transaction honours it) before dropping it. Read and written from any thread under one
  /// mutex.
  Result<std::shared_ptr<TrustListModificationClaim>> claim_trust_list_modification(
    const NodeId& sessionId, bool refuseWhileTransactionHeld = false);

  /// The claim AddCertificate and RemoveCertificate take: as claim_trust_list_modification, but
  /// Bad_TransactionPending while any transaction is held, the caller's own included. These Methods
  /// are not part of a transaction and "return Bad_TransactionPending if a transaction is in
  /// progress" (Part 12 7.8.2.4, 7.8.2.5).
  Result<std::shared_ptr<TrustListModificationClaim>> claim_immediate_trust_list_modification(
    const NodeId& sessionId);

  /// Runs the certificate re-evaluation hook after a TrustList change applied outside a transaction
  /// (AddCertificate, RemoveCertificate; Part 12 7.8.2.3: "When the TrustList changes the Server shall
  /// re-evaluate the Certificate associated with any open Sessions"). With @p correlation the calling
  /// Session and its SecureChannel are re-evaluated after their response is written. Completes Good at
  /// once without a hook. Callable from any thread.
  void reevaluate_certificates_async(NodeId sessionId,
    std::optional<server::MethodResponseCorrelation> correlation, std::function<void(VoidResult)> callback);

  // Shutdown: clears the active transaction and pending key pairs on the strand, and blocks until that
  // has run. Refused with Bad_WouldBlock on a thread of the strand's executor.
  VoidResult shutdown();

private:
  explicit CertificatePushService(Dependencies deps);

  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<CertificateStore> mCertificateStore;
  std::shared_ptr<TrustListManager> mTrustList;
  std::shared_ptr<TrustListManager> mUserTokenTrustList;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;

  // Server identity
  std::string mApplicationUri;
  std::function<std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>()>
    mServedEndpointPolicies;
  std::vector<std::string> mHostnames;
  std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
    mCloseAllChannels;
  std::function<void(const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)>)>
    mReevaluateCertificates;
  std::function<void()> mRequestShutdown;
  std::function<void(TransactionDiagnosticsRecord)> mPublishTransactionDiagnostics;
  Dependencies::DependencyFailureDetailBuilder mDependencyFailureDetailBuilder;
  Dependencies::ApplyWriteStateCheck mApplyWriteStateCheck;
  Dependencies::CertificateDerEncoder mCertificateDerEncoder;
  std::function<bool(const NodeId&)> mSessionExists;
  std::chrono::milliseconds mResetDeadline;  // see Dependencies::resetDeadline

  std::optional<Transaction> mActiveTransaction;
  uint64_t mNextTransactionGeneration{1};  // guarded by mTransactionOwnerMutex
  // The owner of mActiveTransaction, readable off the strand (see trust_list_modification_allowed).
  // Who may modify now, readable and writable from any strand under one mutex: the owner of
  // mActiveTransaction, or a session whose trust-list modifications are in flight (claims, counted:
  // a claim is taken before a modification is applied and released after it opened the transaction
  // or failed). Every change of mActiveTransaction happens under this mutex too, so a claim and a
  // transaction can never be granted to two sessions at once.
  mutable std::mutex mTransactionOwnerMutex;
  std::optional<NodeId> mModificationOwner;  // guarded by mTransactionOwnerMutex
  bool mOwnerHoldsTransaction{false};  // guarded by mTransactionOwnerMutex
  // An ApplyChanges is writing (or about to discard) the TrustLists its transaction staged: every
  // TrustList modification is refused until it ends. Guarded by mTransactionOwnerMutex.
  bool mApplyingTrustLists{false};
  uint32_t mOwnerClaimCount{0};  // guarded by mTransactionOwnerMutex
  // Of those, the claims whose change lands in a transaction (CloseAndUpdate, Open for write). Guarded by
  // mTransactionOwnerMutex.
  uint32_t mOwnerTransactionClaimCount{0};
  uint64_t mHeldGeneration{
    0};  // mActiveTransaction's generation, 0 when none; guarded by mTransactionOwnerMutex
  /// CancelChanges / the owner's Session closing / an ApplyChanges that verified errors: the TrustLists
  /// transaction @p generation staged are dropped (Part 12 7.10.1, 7.10.11); a later transaction's are kept.
  void discard_staged_trust_lists(uint64_t generation);
  /// Validates a pushed Server Certificate against the TrustList the open transaction installs: the
  /// application group's staged lists when it has any, otherwise the store (Part 12 7.8.2.3, 7.10.1).
  /// @p useStaged is false unless the caller's own transaction holds the staged lists.
  void validate_against_transaction_trust_list_async(
    CertificateValidationRequest request, bool useStaged, std::function<void(VoidResult)> callback);
  /// Starts ApplyChanges' TrustList phase: false (nothing changed) while a TrustList modification claim is in
  /// flight - a CloseAndUpdate begun after the write-state preflight, whose lists the apply would not verify.
  /// Otherwise closes the TrustList gate when @p closeGate (the transaction changed a TrustList).
  bool begin_trust_list_apply(bool closeGate);
  void end_trust_list_apply();
  void clear_active_transaction();
  void clear_active_transaction_locked();
  /// A failed UpdateCertificate's rollback: ends the transaction only when it holds nothing, no TrustList
  /// Open or change opened it, and no CloseAndUpdate or Open for write of its owner is in flight (one would
  /// land in it; an AddCertificate or RemoveCertificate in flight does not keep it).
  void drop_transaction_if_empty();
  void release_owner_locked();
  // Releases one of @p sessionId's claims; called only by a TrustListModificationClaim's destruction.
  // @p joinsTransaction: the claim was counted in mOwnerTransactionClaimCount too.
  void withdraw_trust_list_claim(const NodeId& sessionId, bool joinsTransaction);
  uint64_t mNextUpdateReservationId{1};

  // Pending CSR key pairs: (groupId, typeId) -> new key pair
  // NOT session-scoped - spec scopes by (groupId, typeId) and overwrites on repeat calls.
  std::map<std::pair<NodeId, NodeId>, std::shared_ptr<const AsymmetricKeyPair>> mPendingKeyPairs;

  // Per-flow orchestrators are friends so the .cpp owns the post-flip
  // continuation logic without exposing per-flow state on the header.
  friend class CreateSigningRequestOperation;
  friend class UpdateCertificateOperation;
  friend class ApplyChangesOperation;

  // Helpers (must run on strand)
  NodeId resolve_group_id(const NodeId& groupId) const;
  void validate_certificate_type_id_async(NodeId typeId, std::function<void(StatusCode)> callback);
  CertificateType node_id_to_certificate_type(const NodeId& typeId) const;
  CertificateKeyAlgorithm certificate_type_to_key_algorithm(CertificateType type) const;
  CertificateSignatureAlgorithm certificate_type_to_signature_algorithm(CertificateType type) const;

  // SVR-PULLCRT-026 (Part 12 7.8.4.4-7.8.4.12): the supplied certificate's key
  // shape (RSA bit size / ECC named curve) must match the constraint defined by
  // the certificateTypeId subtype. Validates key algorithm/size/curve ONLY - the
  // signature algorithm is a SecurityPolicy (Part 6/7) concern, not a Part 12 one.
  // Returns Good when the shape matches (or when the type carries no key-shape
  // constraint), Bad_InvalidArgument on mismatch.
  StatusCode validate_key_shape_for_type(CertificateType type, const X509Certificate& certificate) const;

  /// Opens or joins @p sessionId's transaction. With @p generation (a claim's), only that transaction: the
  /// one held, or the next when none is (Bad_InvalidState when it has ended).
  StatusCode ensure_transaction(const NodeId& sessionId, std::optional<uint64_t> generation = std::nullopt);
};

/// Create a ServerObserver that forwards session-close events to CertificatePushService
/// and TrustListManager. Registered via ServerImpl::add_internal_observer at server startup.
std::shared_ptr<server::ServerObserver> make_push_certificate_observer(
  std::weak_ptr<CertificatePushService> pushService, std::weak_ptr<TrustListManager> trustList,
  std::weak_ptr<TrustListManager> userTokenTrustList = {});

}  // namespace ua

#endif  // UA_CERTIFICATE_PUSH_SERVICE_H
