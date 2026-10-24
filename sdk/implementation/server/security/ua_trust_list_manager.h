// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TRUST_LIST_MANAGER_H
#define UA_TRUST_LIST_MANAGER_H

#include "ua_callback_safety.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_open_file_mode_bits.h"
#include "ua_result.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_timer.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace ua
{

/// Cross-strand observable state for TrustListManager (Rule 4).
/// Owns its own synchronization via atomics. Separate from the strand-serialized component.
struct TrustListInfo
{
  std::atomic<int64_t> lastUpdateTime{0};
  std::atomic<uint16_t> openCount{0};

  UtcTime last_update_time() const;
  uint16_t open_count() const;
};

namespace detail
{
/// The four lists of one TrustList: what the store holds, or what a push transaction has staged.
struct TrustListContent
{
  CertificateList trustedCerts;
  CrlList trustedCrls;
  CertificateList issuerCerts;
  CrlList issuerCrls;
};
}  // namespace detail

/// A session's claim on the push transaction, taken before a trust-list modification is applied
/// (Part 12 7.8.2.3; security review B3-3). The claim is withdrawn when the last holder drops it, so
/// it cannot be taken without being released: a refused, failed, thrown or lost modification drops
/// it where it stops, and an applied one hands it to the modified callback, whose transaction step
/// drops it once the transaction carries the ownership. Not copyable or movable: share the pointer.
class TrustListModificationClaim
{
public:
  /// @p withdraw releases the claim; empty for a claim that holds nothing (no gate is wired).
  /// @p transactionGeneration names the push transaction the claim was taken in: the one in progress, or the
  /// one the change would start. The push service drops a change whose transaction ended (CancelChanges,
  /// ApplyChanges, its Session closing) while it ran, and a list staged in another one is stale.
  explicit TrustListModificationClaim(std::function<void()> withdraw, uint64_t transactionGeneration = 0)
    : mWithdraw(std::move(withdraw)), mTransactionGeneration(transactionGeneration)
  {}

  TrustListModificationClaim(const TrustListModificationClaim&) = delete;
  TrustListModificationClaim& operator=(const TrustListModificationClaim&) = delete;
  TrustListModificationClaim(TrustListModificationClaim&&) = delete;
  TrustListModificationClaim& operator=(TrustListModificationClaim&&) = delete;

  ~TrustListModificationClaim()
  {
    if (mWithdraw)
    {
      try
      {
        mWithdraw();
      }
      catch (...)
      {
        // A destructor never throws; the withdrawal has no caller to report to.
        ::ua::detail::ignore_expected_exception();
      }
    }
  }

  /// See the constructor; 0 when no push transaction gates the TrustList.
  uint64_t transaction_generation() const
  {
    return mTransactionGeneration;
  }

private:
  std::function<void()> mWithdraw;
  uint64_t mTransactionGeneration{0};
};

/// boost::asio::strand<boost::asio::any_io_executor>-serialized component managing a single TrustListType
/// node's FileType protocol and TrustListManager-specific methods (OpenWithMasks, CloseAndUpdate,
/// AddCertificate, RemoveCertificate). One instance per certificate group.
class TrustListManager : public std::enable_shared_from_this<TrustListManager>
{
public:
  struct Dependencies
  {
    boost::asio::strand<boost::asio::any_io_executor> strand;
    std::shared_ptr<CertificateStore> certificateStore;
    std::shared_ptr<const Crypto> crypto;
    boost::asio::any_io_executor executor;
    uint32_t maxTrustListSize{65535};
    std::chrono::milliseconds activityTimeout{60000};
    Logger logger;
    /// Asked before any modification (CloseAndUpdate, AddCertificate, RemoveCertificate) is applied:
    /// a bad status refuses it, a good one CLAIMS the push transaction for the session until the
    /// returned claim is dropped (see TrustListModificationClaim; a null claim holds nothing). The
    /// push service answers Bad_TransactionPending while another session owns or claims the
    /// transaction, so a change is never applied and then silently left out of the re-evaluation
    /// (Part 12 7.8.2.3). Null allows every modification.
    std::function<Result<std::shared_ptr<TrustListModificationClaim>>(const NodeId& sessionId)>
      modificationClaim;
    /// Asked before AddCertificate and RemoveCertificate instead of modificationClaim. These Methods are
    /// not part of a transaction: they change the TrustList at once and "return Bad_TransactionPending if
    /// a transaction is in progress" (Part 12 7.8.2.4, 7.8.2.5) - any transaction, the caller's own
    /// included. A good answer claims as modificationClaim does, so no transaction starts while the
    /// change is written. Null: modificationClaim is asked.
    std::function<Result<std::shared_ptr<TrustListModificationClaim>>(const NodeId& sessionId)>
      immediateModificationClaim;
    /// Called on the strand when the TrustList is opened with write access, before the Open is answered,
    /// with the claim the Open took through modificationClaim (which refuses the Open: Bad_TransactionPending
    /// while another Session owns or claims the transaction). Part 12 Figure 22: TrustList.Open() creates the
    /// transaction when none exists and continues the Session's own; the push service opens or joins it,
    /// then drops the claim. Null: the claim is dropped.
    std::function<void(NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)> openedForWrite;
    /// True when a push transaction applies the changes (the server's wiring). Part 12 7.8.2.3: "If a
    /// transaction exists, the Server does not update the TrustList until ApplyChanges". A
    /// modification then validates against, and changes, the lists staged in this manager; the store
    /// is written only by apply_staged_async, and discard_staged_async drops them. False writes the
    /// store at once.
    bool stageUntilApply{false};
    /// The longest a reset waits for a list write in progress before it clears anyway (a write that never
    /// completes must not hold back the shutdown Part 12 7.10.10 requires); it clears again when that write
    /// ends, and the reset is answered Bad_Timeout (the cleared lists may yet be written over).
    std::chrono::milliseconds resetWaitLimit{5000};
  };

  /// Callback to notify CertificatePushService that a trust list modification occurred, handed the
  /// claim the modification held (the transaction takes the ownership over; dropping it releases it).
  /// Called from the TrustListManager's strand after CloseAndUpdate. AddCertificate and RemoveCertificate
  /// are not part of a transaction (Part 12 7.8.2.4, 7.8.2.5) and do not call it.
  using TrustListModifiedCallback =
    std::function<void(NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)>;

  static std::shared_ptr<TrustListManager> create(Dependencies deps, TrustListModifiedCallback onModified);

  // --- Public async API (strand rule 2: posts to internal strand) ---

  // Inherited FileType methods
  void open_async(NodeId sessionId, uint8_t mode, std::function<void(Result<uint32_t>)> callback);
  void close_async(NodeId sessionId, uint32_t fileHandle, std::function<void(VoidResult)> callback);
  void read_async(
    NodeId sessionId, uint32_t fileHandle, int32_t length, std::function<void(Result<ByteString>)> callback);
  void write_async(
    NodeId sessionId, uint32_t fileHandle, ByteString data, std::function<void(VoidResult)> callback);
  void get_position_async(
    NodeId sessionId, uint32_t fileHandle, std::function<void(Result<uint64_t>)> callback);
  void set_position_async(
    NodeId sessionId, uint32_t fileHandle, uint64_t position, std::function<void(VoidResult)> callback);

  // TrustListManager-specific methods
  void open_with_masks_async(
    NodeId sessionId, uint32_t masks, std::function<void(Result<uint32_t>)> callback);
  void close_and_update_async(
    NodeId sessionId, uint32_t fileHandle, std::function<void(Result<bool>)> callback);
  void add_certificate_async(NodeId sessionId, ByteString certificate, bool isTrustedCertificate,
    std::function<void(VoidResult)> callback);
  void remove_certificate_async(NodeId sessionId, std::string thumbprint, bool isTrustedCertificate,
    std::function<void(VoidResult)> callback);

  /// ApplyChanges (Part 12 7.10.6): writes the staged lists to the store (trusted, then issuer) and
  /// forgets them. Completes Good at once when nothing is staged.
  void apply_staged_async(std::function<void(VoidResult)> callback);

  /// CancelChanges, or the transaction owner's Session closing (Part 12 7.10.11): drops the staged
  /// lists, so the store keeps the lists it had.
  /// With @p stagedBy, only lists that Session staged are dropped (a change no transaction took over); with
  /// @p generation, only lists staged in that transaction (a later one's are kept; lists staged without a
  /// push gate name none and are dropped).
  void discard_staged_async(
    std::optional<NodeId> stagedBy = std::nullopt, std::optional<uint64_t> generation = std::nullopt);

  /// ResetToServerDefaults (Part 12 7.10.10: "All TrustLists are cleared"): closes a handle open for write,
  /// drops the staged lists and writes empty trusted and issuer lists (certificates and CRLs). A list write
  /// in progress is waited for, never refused (no new one starts meanwhile), for at most resetWaitLimit; a
  /// write that ends later is cleared again, and a clear made beside it answers Bad_Timeout
  /// (TrustListWriteOutlastedTheReset). Otherwise the answer is the store's.
  void clear_lists_async(std::function<void(VoidResult)> callback);

  /// The staged lists (a copy), or none when nothing is staged. ApplyChanges verifies a pushed
  /// Certificate against the TrustList the transaction installs, before anything is written.
  void staged_lists_async(std::function<void(std::optional<detail::TrustListContent>)> callback);

  // Query: is a write-mode handle currently open, or a list write in progress or waited for? (called by
  // CertificatePushService for REQ-AC-1: ApplyChanges is refused, the transaction kept, until it is not)
  void is_write_open_async(std::function<void(Result<bool>)> callback);

  // Session cleanup (called from ServerObserver::on_session_closed, posted to strand)
  void on_session_closed_async(NodeId sessionId);

  // Shutdown: clears the open handle, the activity timer and any waiting reset on the strand, and blocks
  // until that has run. Refused with Bad_WouldBlock on a thread of the strand's executor.
  VoidResult shutdown();

  // Properties (thread-safe reads via separately-synchronized info object)
  UtcTime last_update_time() const;
  uint16_t open_count() const;

  /// Thread-safe accessor to the separately-synchronized info object (Rule 4).
  std::shared_ptr<const TrustListInfo> info() const
  {
    return mInfo;
  }

private:
  friend class TrustListManagerTestAccess;

  explicit TrustListManager(Dependencies deps, TrustListModifiedCallback onModified);

  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::shared_ptr<CertificateStore> mCertificateStore;
  std::shared_ptr<const Crypto> mCrypto;
  boost::asio::any_io_executor mExecutor;
  TrustListModifiedCallback mOnModified;
  std::function<Result<std::shared_ptr<TrustListModificationClaim>>(const NodeId& sessionId)>
    mModificationClaim;
  std::function<Result<std::shared_ptr<TrustListModificationClaim>>(const NodeId& sessionId)>
    mImmediateModificationClaim;
  std::function<void(NodeId, std::shared_ptr<TrustListModificationClaim>)> mOnOpenedForWrite;
  std::chrono::milliseconds mResetWaitLimit;  // see Dependencies::resetWaitLimit
  Logger mLogger;
  /// Bumped on the strand by every change this manager applies to the store (CloseAndUpdate's
  /// replacement, AddCertificate, RemoveCertificate). AddCertificate captures it before it fetches the
  /// lists it validates against and refuses at commit if it moved (the lists it validated against are
  /// no longer the store's).
  uint64_t mModificationCount{0};
  /// See Dependencies::stageUntilApply.
  bool mStageUntilApply{false};
  /// The lists the push transaction has staged (complete: all four), or none when nothing is staged.
  /// Every staged modification reads and replaces them; the store is untouched until ApplyChanges.
  std::optional<detail::TrustListContent> mStaged;
  NodeId mStagedSessionId;  // the Session whose transaction staged mStaged
  uint64_t mStagedGeneration{0};  // that transaction (TrustListModificationClaim::transaction_generation)

  // File handle state - at most one open handle at a time
  struct OpenHandle
  {
    uint32_t fileHandle;
    NodeId sessionId;
    bool isWriteMode;
    uint32_t masks;  // Relevant for read via OpenWithMasks
    uint64_t transactionGeneration{0};  // write mode: the push transaction the Open's claim named

    // MemoryStream-backed buffer
    memory_stream_device::Dynamic device;
    MemoryStream<memory_stream_device::Dynamic> stream;

    OpenHandle(uint32_t handle, NodeId session, bool writeMode, uint32_t openMasks, size_t capacity)
      : fileHandle(handle), sessionId(std::move(session)), isWriteMode(writeMode), masks(openMasks),
        device(capacity, /*reserve=*/true), stream(device)
    {}
  };

  std::optional<OpenHandle> mOpenHandle;
  uint32_t mNextFileHandle{1};

  // Activity timeout
  std::optional<Timer> mActivityTimer;
  std::chrono::milliseconds mActivityTimeout;
  void reset_activity_timer();
  void on_activity_timeout();

  // Cross-strand observable state (Rule 4 - separate info object with its own synchronization)
  std::shared_ptr<TrustListInfo> mInfo{std::make_shared<TrustListInfo>()};
  uint32_t mMaxTrustListSize;

  // The Open modes a TrustList accepts (Part 12 7.8.2.1): Read, or Write with EraseExisting.
  static constexpr uint8_t sOpenRead = detail::file_mode_bits(OpenFileMode::Read);
  static constexpr uint8_t sOpenWriteEraseExisting =
    detail::file_mode_bits(OpenFileMode::Write, OpenFileMode::EraseExisting);

  // TrustListMasks constants
  static constexpr uint32_t sMaskTrustedCertificates = 0x01;
  static constexpr uint32_t sMaskTrustedCrls = 0x02;
  static constexpr uint32_t sMaskIssuerCertificates = 0x04;
  static constexpr uint32_t sMaskIssuerCrls = 0x08;
  static constexpr uint32_t sMaskAll = 0x0F;

  // Helpers running on strand
  StatusCode validate_handle(const OpenHandle& handle, const NodeId& sessionId, uint32_t fileHandle) const;
  void close_handle();

  /// The lists CloseAndUpdate will install: the upload for the masked halves, the store's current
  /// content for the rest, collected before anything is validated or written.
  struct PendingUpdate
  {
    NodeId sessionId;
    uint32_t specifiedLists{0};
    CertificateList trustedCerts;
    CrlList trustedCrls;
    CertificateList issuerCerts;
    CrlList issuerCrls;
    std::function<void(Result<bool>)> callback;
    uint32_t fileHandle{0};
    std::shared_ptr<void> writeToken;  // the list write this update holds until it ends
  };

  /// Closes the session's own handle, releases the update's claim and completes it with @p status.
  void abandon_pending_update(PendingUpdate& pending, StatusCode status);

  /// Asks the gate for @p sessionId: a claim when granted (never null: one holding nothing when no
  /// gate is wired), null (and @p refusal set) otherwise. Dropping the claim releases it, which
  /// covers every failure, throw and lost-strand path at once; an applied modification hands it to
  /// the modified callback instead.
  std::shared_ptr<TrustListModificationClaim> take_claim(
    const NodeId& sessionId, StatusCode& refusal, bool immediate = false);

  /// Closes the open handle only when it is the one the update in flight was started on (the session
  /// may have closed it and opened another while the update ran its store round-trips).
  void close_update_handle();

  // The claim of the CloseAndUpdate in progress (one at a time: it runs on the single open handle).
  std::shared_ptr<TrustListModificationClaim> mUpdateClaim;

  // A list write in progress. The manager is the only writer of its lists, one write at a time, so it never
  // depends on the order in which a store applies requests: AddCertificate's store write, RemoveCertificate,
  // CloseAndUpdate, ApplyChanges and the reset each hold a token until the store has answered, and new
  // changes are refused (Bad_InvalidState) while one is held. The one exception is a reset's forced clear
  // after its wait limit, which runs beside the stalled write (two tokens) and is followed by a clear once
  // that write ends. The token lives in the write's own continuation, so a dropped callback cannot leave it
  // held; releasing it runs the work queued behind it (the reset). A write that never ends keeps the
  // TrustList refusing changes until the restart the reset requests.
  struct ListWriteToken
  {
    ListWriteToken() = default;
    ListWriteToken(const ListWriteToken&) = delete;
    ListWriteToken& operator=(const ListWriteToken&) = delete;
    ListWriteToken(ListWriteToken&&) = delete;
    ListWriteToken& operator=(ListWriteToken&&) = delete;
    std::weak_ptr<TrustListManager> manager;
    Logger logger;
    ~ListWriteToken();
  };

  std::vector<std::weak_ptr<ListWriteToken>>
    mWritesInFlight;  // every live token (a forced clear adds a second)
  std::vector<std::function<void(TrustListManager&)>>
    mAfterListWrite;  // run, on the strand, when no write is held

  /// On the strand: a new token, recorded among the writes in progress (only a forced clear starts one while
  /// another is held).
  std::shared_ptr<ListWriteToken> begin_list_write();
  /// On the strand: a write is in progress (a token is held).
  bool list_write_in_flight() const;
  /// On the strand: a new AddCertificate, RemoveCertificate or CloseAndUpdate must not start - a write is in
  /// progress, or a reset waits for one (it goes first, so a stream of changes cannot starve it).
  bool list_writes_blocked() const;
  /// On the strand: runs the queued work while no write is held.
  void run_after_list_write();
  /// On the strand: ApplyChanges' write of the staged lists; refused while a list write is in progress.
  void apply_staged_on_strand(std::function<void(VoidResult)> finish);

  /// One reset's clear. Answered once: by the clear, or with Bad_InternalError if the request is dropped
  /// unanswered (the manager gone while it waited), so the reset still reaches its shutdown.
  struct ClearRequest
  {
    ClearRequest() = default;
    ClearRequest(const ClearRequest&) = delete;
    ClearRequest& operator=(const ClearRequest&) = delete;
    ClearRequest(ClearRequest&&) = delete;
    ClearRequest& operator=(ClearRequest&&) = delete;
    std::function<void(VoidResult)> finish;  // fire-once
    bool started{false};
    bool followUp{
      false};  // the clear after a forced one: waits for the late write, unbounded, answers no one
    std::optional<Timer> waitTimer;  // the wait limit; cancelled when the clear starts
    bool forced{false};  // cleared at the wait limit, beside a write that has not ended
    ~ClearRequest();
  };

  /// On the strand: the reset's clear, after any write in progress (at most mResetWaitLimit).
  void clear_lists_on_strand(std::shared_ptr<ClearRequest> request);
  /// On the strand: clears now - closes a write handle, drops the staged lists, writes empty lists.
  void clear_lists_now(std::shared_ptr<ClearRequest> request);

  /// RemoveCertificate's store work: reads the list and its CRLs, finds @p wanted, and removes it - with
  /// every CRL it issued when it is a CA, in one replace - then calls @p onComplete with the outcome.
  void read_list_for_removal(bool isTrustedCertificate, std::vector<uint8_t> wanted, std::string thumbprint,
    std::function<void(VoidResult)> onComplete);
  uint32_t mUpdateFileHandle{0};  // the handle the update in flight was started on

  /// Step @p step of the merge (0..3: trusted certs, trusted CRLs, issuer certs, issuer CRLs), each
  /// fetching the store's list when its mask bit is clear; then validation, then the replacement.
  void merge_pending_update_on_strand(std::shared_ptr<PendingUpdate> pending, unsigned step);

  /// Part 12 7.8.2.3: every certificate of the new trust list must pass Part 4 validation, with the
  /// new list as its anchors, before anything is replaced; then the handle is re-checked (validation
  /// is asynchronous) and the lists are replaced. Runs on the strand; completes on it.
  void validate_and_replace_on_strand(std::shared_ptr<PendingUpdate> pending);

  /// The store replacement chain (trusted, then issuer), followed by the update time, the close of
  /// the write handle and the modified notification. Runs on the strand.
  void replace_lists_on_strand(std::shared_ptr<PendingUpdate> pending);

  // Internal open-for-read implementation - must already be on strand
  void open_for_read_on_strand(
    NodeId sessionId, uint32_t masks, std::function<void(Result<uint32_t>)> callback);
};

}  // namespace ua

#endif  // UA_TRUST_LIST_MANAGER_H
