// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_certificate_validation_paths.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_certificate_push_service.h"

#include "ua_secure_memory.h"
#include "ua_security_policy.h"
#include "ua_security_policy_internal.h"

#include "ua_self_owning_operation.h"
#include "ua_server_observer.h"
#include "ua_fmt.h"
#include "ua_callback_safety.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_on_strand.h"
#include "ua_to_result.h"

#include <algorithm>
#include <atomic>
#include <future>
#include <initializer_list>

namespace ua
{

namespace
{

// Well-known NodeId for the DefaultApplicationGroup instance in the server's address space.
const NodeId defaultApplicationGroupId{
  0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup)};

// Well-known NodeId for the DefaultApplicationGroup's TrustListManager Object.
const NodeId defaultApplicationGroupTrustListId{
  0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList)};

// Well-known NodeIds for the DefaultUserTokenGroup (Part 12 7.8.3.3) and its TrustListManager.
const NodeId defaultUserTokenGroupId{
  0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup)};
const NodeId defaultUserTokenGroupTrustListId{
  0, utils::to_underlying(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList)};

bool contains(const std::vector<NodeId>& ids, const NodeId& id)
{
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

template<typename ResultType>
class SharedUserCompletion
{
public:
  SharedUserCompletion(Logger logger, std::function<void(ResultType)> callback)
    : mLogger(std::move(logger)), mCallback(std::move(callback))
  {}

  void complete(ResultType result) noexcept
  {
    if (mFired.exchange(true))
      return;
    detail::invoke_user_callback(mLogger, mCallback, std::move(result));
  }

private:
  Logger mLogger;
  std::function<void(ResultType)> mCallback;
  std::atomic_bool mFired{false};
};

template<typename ResultType>
std::function<void(ResultType)> make_shared_user_completion(
  Logger logger, std::function<void(ResultType)> callback)
{
  auto completion =
    std::make_shared<SharedUserCompletion<ResultType>>(std::move(logger), std::move(callback));
  return [completion = std::move(completion)](ResultType result) mutable
  {
    completion->complete(std::move(result));
  };
}

template<typename Callback>
auto make_fire_once_callback(Callback callback)
{
  auto fired = std::make_shared<std::atomic_bool>(false);
  return [fired = std::move(fired), callback = std::move(callback)](auto&&... args) mutable
  {
    if (fired->exchange(true))
      return;
    callback(std::forward<decltype(args)>(args)...);
  };
}

using PendingCertList =
  std::vector<std::pair<std::pair<NodeId, NodeId>, CertificatePushService::Transaction::PendingCertUpdate>>;

// Build a TransactionDiagnostics snapshot (Part 12 7.10.11) from the committed
// transaction state. AffectedCertificateGroups is the unique set of resolved
// group NodeIds touched by certificate updates; AffectedTrustLists holds the
// TrustListManager NodeId of each certificate group whose trust list was modified
// within the transaction.
TransactionDiagnosticsRecord build_diagnostics_record(DateTime startTime, DateTime endTime, StatusCode result,
  const PendingCertList& pending, std::vector<NodeId> modifiedTrustLists,
  std::vector<TransactionErrorType> errors)
{
  TransactionDiagnosticsRecord record;
  record.startTime = startTime;
  record.endTime = endTime;
  record.result = result;
  record.errors = std::move(errors);

  for (const auto& entry : pending)
  {
    const NodeId& groupId = entry.first.first;
    if (std::find(record.affectedCertificateGroups.begin(),
          record.affectedCertificateGroups.end(),
          groupId) == record.affectedCertificateGroups.end())
    {
      record.affectedCertificateGroups.push_back(groupId);
    }
  }

  // Part 12 7.10.11: a CertificateGroup joins the transaction as soon as one of its lists does,
  // so a trust-list modification contributes its owning group as well as the list itself.
  for (const auto& trustListId : modifiedTrustLists)
  {
    const NodeId& groupId =
      trustListId == defaultUserTokenGroupTrustListId ? defaultUserTokenGroupId : defaultApplicationGroupId;
    if (std::find(record.affectedCertificateGroups.begin(),
          record.affectedCertificateGroups.end(),
          groupId) == record.affectedCertificateGroups.end())
    {
      record.affectedCertificateGroups.push_back(groupId);
    }
  }

  record.affectedTrustLists = std::move(modifiedTrustLists);

  return record;
}

}  // namespace

// ---------------------------------------------------------------------------
// Factory + constructor
// ---------------------------------------------------------------------------

std::shared_ptr<CertificatePushService> CertificatePushService::create(Dependencies deps)
{
  return std::shared_ptr<CertificatePushService>(new CertificatePushService(std::move(deps)));
}

CertificatePushService::CertificatePushService(Dependencies deps)
  : mStrand(std::move(deps.strand)), mCrypto(std::move(deps.crypto)),
    mCertificateStore(std::move(deps.certificateStore)), mTrustList(std::move(deps.trustList)),
    mUserTokenTrustList(std::move(deps.userTokenTrustList)), mExecutor(deps.executor),
    mLogger(std::move(deps.logger)), mApplicationUri(std::move(deps.applicationUri)),
    mServedEndpointPolicies(std::move(deps.servedEndpointPolicies)), mHostnames(std::move(deps.hostnames)),
    mCloseAllChannels(std::move(deps.closeAllChannels)),
    mReevaluateCertificates(std::move(deps.reevaluateCertificates)),
    mRequestShutdown(std::move(deps.requestShutdown)),
    mPublishTransactionDiagnostics(std::move(deps.publishTransactionDiagnostics)),
    mDependencyFailureDetailBuilder(std::move(deps.dependencyFailureDetailBuilder)),
    mApplyWriteStateCheck(std::move(deps.applyWriteStateCheck)),
    mCertificateDerEncoder(std::move(deps.certificateDerEncoder)),
    mSessionExists(std::move(deps.sessionExists)), mResetDeadline(deps.resetDeadline)
{}

// ---------------------------------------------------------------------------
// Helpers (must run on strand)
// ---------------------------------------------------------------------------

NodeId CertificatePushService::resolve_group_id(const NodeId& groupId) const
{
  if (groupId.is_null())
  {
    return defaultApplicationGroupId;
  }
  return groupId;
}

// Callback-canonical helper. Result delivered on whichever executor / strand the certificate-store
// callback fires from - callers post back to mStrand if continuation work is needed.
void CertificatePushService::validate_certificate_type_id_async(
  NodeId typeId, std::function<void(StatusCode)> callback)
{
  auto certType = node_id_to_certificate_type(typeId);
  if (certType == CertificateType::Invalid)
  {
    callback(StatusCode{Status::BadInvalidArgument});
    return;
  }

  mCertificateStore->get_application_certificates_async(

    [certType, callback = std::move(callback)](
      CertificateStore::ApplicationCertificateListResult result) mutable
    {
      if (!result.is_good())
      {
        // The type is checked only against a list the store answered Good: an Uncertain answer is refused,
        // so no caller takes it for a supported type.
        callback(ua::security_internal::not_good_store_answer(
          result.status_code(), Status::BadInternalError, "CertificatePushService"));
        return;
      }
      for (const auto& appCert : result.value())
      {
        if (appCert.certificateType == certType)
        {
          callback(StatusCode{Status::Good});
          return;
        }
      }
      callback(StatusCode{Status::BadInvalidArgument});
    });
}

CertificateType CertificatePushService::node_id_to_certificate_type(const NodeId& typeId) const
{
  if (typeId.namespace_index() != 0 || !typeId.identifier().is_numeric())
  {
    return CertificateType::Invalid;
  }

  switch (static_cast<ObjectTypeId>(typeId.identifier().get_numeric()))
  {
  case ObjectTypeId::RsaMinApplicationCertificateType:
    return CertificateType::RsaMinApplication;
  case ObjectTypeId::RsaSha256ApplicationCertificateType:
    return CertificateType::RsaSha256Application;
  case ObjectTypeId::EccApplicationCertificateType:
    return CertificateType::EccApplication;
  case ObjectTypeId::EccNistP256ApplicationCertificateType:
    return CertificateType::EccNistP256Application;
  case ObjectTypeId::EccNistP384ApplicationCertificateType:
    return CertificateType::EccNistP384Application;
  case ObjectTypeId::EccBrainpoolP256r1ApplicationCertificateType:
    return CertificateType::EccBrainpoolP256r1Application;
  case ObjectTypeId::EccBrainpoolP384r1ApplicationCertificateType:
    return CertificateType::EccBrainpoolP384r1Application;
  case ObjectTypeId::EccCurve25519ApplicationCertificateType:
    return CertificateType::EccCurve25519Application;
  case ObjectTypeId::EccCurve448ApplicationCertificateType:
    return CertificateType::EccCurve448Application;
  case ObjectTypeId::ApplicationCertificateType:
    return CertificateType::Application;
  default:
    return CertificateType::Invalid;
  }
}

CertificateKeyAlgorithm CertificatePushService::certificate_type_to_key_algorithm(CertificateType type) const
{
  switch (type)
  {
  case CertificateType::RsaMinApplication:
  case CertificateType::RsaSha256Application:
  case CertificateType::Application:
    return CertificateKeyAlgorithm::Rsa;
  case CertificateType::EccApplication:
  case CertificateType::EccNistP256Application:
    return CertificateKeyAlgorithm::EccNistP256;
  case CertificateType::EccNistP384Application:
    return CertificateKeyAlgorithm::EccNistP384;
  case CertificateType::EccBrainpoolP256r1Application:
    return CertificateKeyAlgorithm::EccBrainpoolP256r1;
  case CertificateType::EccBrainpoolP384r1Application:
    return CertificateKeyAlgorithm::EccBrainpoolP384r1;
  case CertificateType::EccCurve25519Application:
    return CertificateKeyAlgorithm::EccCurve25519;
  case CertificateType::EccCurve448Application:
    return CertificateKeyAlgorithm::EccCurve448;
  default:
    return CertificateKeyAlgorithm::Rsa;
  }
}

CertificateSignatureAlgorithm CertificatePushService::certificate_type_to_signature_algorithm(
  CertificateType type) const
{
  switch (type)
  {
  case CertificateType::RsaMinApplication:
  case CertificateType::Application:
  case CertificateType::RsaSha256Application:
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  case CertificateType::EccNistP256Application:
  case CertificateType::EccApplication:
  case CertificateType::EccBrainpoolP256r1Application:
    return CertificateSignatureAlgorithm::EcDsaSha2256;
  case CertificateType::EccNistP384Application:
  case CertificateType::EccBrainpoolP384r1Application:
    return CertificateSignatureAlgorithm::EcDsaSha2384;
  case CertificateType::EccCurve25519Application:
    return CertificateSignatureAlgorithm::PureEdDsa25519;
  case CertificateType::EccCurve448Application:
    return CertificateSignatureAlgorithm::PureEdDsa448;
  default:
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
}

StatusCode CertificatePushService::validate_key_shape_for_type(
  CertificateType type, const X509Certificate& certificate) const
{
  const CertificateKeyAlgorithm keyAlgorithm = certificate.key_algorithm();
  const size_t keyBits = certificate.public_key_bit_length();

  // Helpers keep the per-subtype branches single-statement.
  const auto rsaSizeIn = [&](std::initializer_list<size_t> allowed) -> StatusCode
  {
    if (keyAlgorithm != CertificateKeyAlgorithm::Rsa)
      return StatusCode{Status::BadInvalidArgument};
    if (std::find(allowed.begin(), allowed.end(), keyBits) == allowed.end())
      return StatusCode{Status::BadInvalidArgument};
    return StatusCode{Status::Good};
  };
  const auto curveIs = [&](CertificateKeyAlgorithm curve) -> StatusCode
  {
    return keyAlgorithm == curve ? StatusCode{Status::Good} : StatusCode{Status::BadInvalidArgument};
  };
  const auto isEccFamily = [&]() -> StatusCode
  {
    switch (keyAlgorithm)
    {
    case CertificateKeyAlgorithm::EccNistP256:
    case CertificateKeyAlgorithm::EccNistP384:
    case CertificateKeyAlgorithm::EccNistP521:
    case CertificateKeyAlgorithm::EccBrainpoolP256r1:
    case CertificateKeyAlgorithm::EccBrainpoolP384r1:
    case CertificateKeyAlgorithm::EccBrainpoolP512r1:
    case CertificateKeyAlgorithm::EccCurve25519:
    case CertificateKeyAlgorithm::EccCurve448:
      return StatusCode{Status::Good};
    default:
      return StatusCode{Status::BadInvalidArgument};
    }
  };

  switch (type)
  {
  // Part 12 7.8.4.4: RSA key size of 1024 or 2048 bits.
  case CertificateType::RsaMinApplication:
    return rsaSizeIn({1024, 2048});
  // Part 12 7.8.4.5: RSA key size of 2048, 3072 or 4096 bits.
  case CertificateType::RsaSha256Application:
    return rsaSizeIn({2048, 3072, 4096});
  // Part 12 7.8.4.6: ECC public key (curve constrained only by the concrete subtypes below).
  case CertificateType::EccApplication:
    return isEccFamily();
  case CertificateType::EccNistP256Application:  // 7.8.4.7
    return curveIs(CertificateKeyAlgorithm::EccNistP256);
  case CertificateType::EccNistP384Application:  // 7.8.4.8
    return curveIs(CertificateKeyAlgorithm::EccNistP384);
  case CertificateType::EccBrainpoolP256r1Application:  // 7.8.4.9
    return curveIs(CertificateKeyAlgorithm::EccBrainpoolP256r1);
  case CertificateType::EccBrainpoolP384r1Application:  // 7.8.4.10
    return curveIs(CertificateKeyAlgorithm::EccBrainpoolP384r1);
  case CertificateType::EccCurve25519Application:  // 7.8.4.11
    return curveIs(CertificateKeyAlgorithm::EccCurve25519);
  case CertificateType::EccCurve448Application:  // 7.8.4.12
    return curveIs(CertificateKeyAlgorithm::EccCurve448);
  // ApplicationCertificateType is the abstract root (7.8.4.2) - no key-shape
  // constraint of its own. Https / Invalid never reach here (type validation
  // rejects them first). No constraint -> accept.
  case CertificateType::Application:
  case CertificateType::Https:
  case CertificateType::Invalid:
  default:
    return StatusCode{Status::Good};
  }
}

StatusCode CertificatePushService::ensure_transaction(
  const NodeId& sessionId, std::optional<uint64_t> generation)
{
  // A modification that lands after its Session was closed opens no transaction: nobody could ever
  // apply or cancel it. Asked before the ownership lock, which the Session lookup must not nest in.
  if (mSessionExists && !mSessionExists(sessionId))
  {
    return StatusCode{Status::BadSessionIdInvalid};
  }
  // The check and the ownership change are one critical section, shared with the claims taken on the
  // trust-list strands (security review B3-3, round-2 panel).
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  // A change claimed in a transaction that has ended since (CancelChanges, ApplyChanges, the Session closing)
  // must not be carried into a new one: CancelChanges discarded it (Part 12 7.10.8), and ApplyChanges did not
  // verify it (7.10.6).
  if (generation &&
      *generation != (mActiveTransaction ? mActiveTransaction->generation : mNextTransactionGeneration))
  {
    return StatusCode{Status::BadInvalidState,
      make_error_detail("TrustListTransactionEnded",
        "the transaction this TrustList change was made in ended while it ran",
        "CertificatePushService")};
  }
  if (mActiveTransaction.has_value())
  {
    return mActiveTransaction->owningSessionId == sessionId ? StatusCode{Status::Good}
                                                            : StatusCode{Status::BadTransactionPending};
  }
  if (mModificationOwner.has_value() && *mModificationOwner != sessionId)
  {
    return StatusCode{Status::BadTransactionPending};
  }

  Transaction txn;
  txn.owningSessionId = sessionId;
  txn.startTime = DateTime::now();
  txn.generation = mNextTransactionGeneration++;
  mHeldGeneration = txn.generation;
  mActiveTransaction.emplace(std::move(txn));
  mModificationOwner = sessionId;
  mOwnerHoldsTransaction = true;
  return StatusCode{Status::Good};
}

void CertificatePushService::release_owner_locked()
{
  // The transaction claims are a subset of the claims: a withdrawal counted before a Session close zeroed the
  // counts must not leave one behind (it would keep every later empty transaction alive).
  mOwnerTransactionClaimCount = std::min(mOwnerTransactionClaimCount, mOwnerClaimCount);
  if (!mOwnerHoldsTransaction && mOwnerClaimCount == 0)
  {
    mModificationOwner.reset();
  }
}

Result<std::shared_ptr<TrustListModificationClaim>>
  CertificatePushService::claim_immediate_trust_list_modification(const NodeId& sessionId)
{
  return claim_trust_list_modification(sessionId, /*refuseWhileTransactionHeld=*/true);
}

void CertificatePushService::reevaluate_certificates_async(NodeId sessionId,
  std::optional<server::MethodResponseCorrelation> correlation, std::function<void(VoidResult)> callback)
{
  auto once = make_fire_once_callback(std::move(callback));
  if (!mReevaluateCertificates)
  {
    once(VoidResult{});
    return;
  }
  try
  {
    // Without a correlation there is no response to wait for: no origin is named, and every Session and
    // channel is re-evaluated at once.
    if (correlation)
      mReevaluateCertificates(sessionId, *correlation, once);
    else
      mReevaluateCertificates(NodeId{}, server::MethodResponseCorrelation{}, once);
  }
  catch (...)
  {
    once(VoidResult{Status::BadInternalError,
      ErrorDetail::build(
        "CertificateReevaluationHookFailed", "Certificate re-evaluation hook threw", "CertificatePushService")
        .cause(ua::exception_to_status_code(std::current_exception()))});
  }
}

Result<std::shared_ptr<TrustListModificationClaim>> CertificatePushService::claim_trust_list_modification(
  const NodeId& sessionId, bool refuseWhileTransactionHeld)
{
  uint64_t generation = 0;
  {
    const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
    if (mApplyingTrustLists)
    {
      return StatusCode{Status::BadTransactionPending,
        make_error_detail("TrustListApplyInProgress",
          "an ApplyChanges is writing the TrustLists of its transaction",
          "CertificatePushService")};
    }
    if (refuseWhileTransactionHeld && mOwnerHoldsTransaction)
    {
      return StatusCode{Status::BadTransactionPending,
        make_error_detail("TrustListTransactionInProgress",
          "AddCertificate and RemoveCertificate are refused while a transaction is in progress (ApplyChanges "
          "or "
          "CancelChanges ends it)",
          "CertificatePushService")};
    }
    if (mModificationOwner.has_value() && *mModificationOwner != sessionId)
    {
      return StatusCode{Status::BadTransactionPending};
    }
    mModificationOwner = sessionId;
    ++mOwnerClaimCount;
    if (!refuseWhileTransactionHeld)
      ++mOwnerTransactionClaimCount;
    // The transaction the change belongs to: the one this Session holds, or the one it would open (no other
    // Session can open one while the claim is counted).
    generation = mOwnerHoldsTransaction ? mHeldGeneration : mNextTransactionGeneration;
  }
  // From here the claim is counted, so it is owned by the token that withdraws it on destruction.
  auto claim = std::make_shared<TrustListModificationClaim>(
    [weakSelf = weak_from_this(), sessionId, joinsTransaction = !refuseWhileTransactionHeld]()
    {
      if (auto self = weakSelf.lock())
        self->withdraw_trust_list_claim(sessionId, joinsTransaction);
    },
    generation);
  // A closed Session keeps no claim. The Session is looked up AFTER the claim is taken, outside the
  // ownership lock (which the lookup must not nest in): the server removes a Session before it posts
  // the close event, so either this lookup sees the Session gone and the dropped claim is withdrawn,
  // or on_session_closed_async runs after the claim and resets it.
  if (mSessionExists && !mSessionExists(sessionId))
  {
    return StatusCode{Status::BadSessionIdInvalid};
  }
  return claim;
}

void CertificatePushService::withdraw_trust_list_claim(const NodeId& sessionId, bool joinsTransaction)
{
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  if (mModificationOwner.has_value() && *mModificationOwner == sessionId && mOwnerClaimCount > 0)
  {
    --mOwnerClaimCount;
    if (joinsTransaction && mOwnerTransactionClaimCount > 0)
      --mOwnerTransactionClaimCount;
    release_owner_locked();
  }
}

void CertificatePushService::validate_against_transaction_trust_list_async(
  CertificateValidationRequest request, bool useStaged, std::function<void(VoidResult)> callback)
{
  if (!useStaged || !mTrustList || !mCrypto)
  {
    mCertificateStore->validate_certificate_async(std::move(request), std::move(callback));
    return;
  }
  // Part 12 7.8.2.3: a TrustList changed in the open transaction is staged, not in the store, until
  // ApplyChanges; 7.10.1: ApplyChanges "verifies that all the changes are consistent". A pushed Server
  // Certificate is therefore validated against the TrustList the transaction installs, so it may chain to a
  // CA added in the same transaction (the order is not specified; owner report 2026-10-03, BR-13). Cost: one
  // strand round trip to the TrustListManager per validation, at UpdateCertificate and ApplyChanges only.
  auto once = make_fire_once_callback(std::move(callback));
  mTrustList->staged_lists_async(
    [weakSelf = weak_from_this(), request = std::move(request), once](
      std::optional<detail::TrustListContent> staged) mutable
    {
      auto self = weakSelf.lock();
      if (!self)
      {
        once(VoidResult{StatusCode{Status::BadInternalError}});
        return;
      }
      try
      {
        if (!staged)
        {
          self->mCertificateStore->validate_certificate_async(std::move(request), once);
          return;
        }
        // What the store would supply, taken from the staged lists: its options and its use.
        CertificateValidationMaterial material;
        material.trusted = std::move(staged->trustedCerts);
        material.issuers = std::move(staged->issuerCerts);
        material.trustedCrls = std::move(staged->trustedCrls);
        material.issuerCrls = std::move(staged->issuerCrls);
        material.options = request.options.value_or(self->mCertificateStore->validation_options());
        request.options = material.options;
        if (!request.use)
          request.use = CertificateUse::ApplicationInstance;
        self->mCrypto->validate_certificate_async(request, std::move(material), once);
      }
      catch (...)
      {
        once(VoidResult{ua::exception_to_status_code(std::current_exception())});
      }
    });
}

bool CertificatePushService::begin_trust_list_apply(bool closeGate)
{
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  if (mOwnerClaimCount > 0)
    return false;
  if (closeGate)
    mApplyingTrustLists = true;
  return true;
}

void CertificatePushService::end_trust_list_apply()
{
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  mApplyingTrustLists = false;
}

void CertificatePushService::discard_staged_trust_lists(uint64_t generation)
{
  // Each manager forgets the lists this transaction staged on its own strand, after any modification
  // already posted to it; a later transaction's lists (it may already have staged some) are kept.
  if (mTrustList)
    mTrustList->discard_staged_async(std::nullopt, generation);
  if (mUserTokenTrustList)
    mUserTokenTrustList->discard_staged_async(std::nullopt, generation);
}

void CertificatePushService::clear_active_transaction()
{
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  clear_active_transaction_locked();
}

void CertificatePushService::drop_transaction_if_empty()
{
  const auto& transaction = mActiveTransaction;
  if (!transaction || transaction->keptWhenEmpty || !transaction->inFlightUpdateReservations.empty() ||
      !transaction->pendingCertificates.empty() || !transaction->modifiedTrustLists.empty())
    return;
  // One critical section with the claims, so no claim can name this transaction after the check. Only a
  // claim whose change lands in a transaction counts (AddCertificate's and RemoveCertificate's do not).
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  if (mOwnerTransactionClaimCount > 0)
    return;
  clear_active_transaction_locked();
}

void CertificatePushService::clear_active_transaction_locked()
{
  mActiveTransaction.reset();
  mOwnerHoldsTransaction = false;
  mHeldGeneration = 0;
  release_owner_locked();
}

StatusCode CertificatePushService::trust_list_modification_allowed(const NodeId& sessionId) const
{
  const std::lock_guard<std::mutex> lock(mTransactionOwnerMutex);
  if (mModificationOwner.has_value() && *mModificationOwner != sessionId)
    return StatusCode{Status::BadTransactionPending};
  return StatusCode{Status::Good};
}

// ---------------------------------------------------------------------------
// CreateSigningRequest
// ---------------------------------------------------------------------------

namespace
{

namespace
{
/// The CSR flow abandoned at @p site because its manager was gone or a strand post did not run.
///
/// Every step of this flow answered a bare `Bad_InternalError` with no detail, so all fourteen abandon
/// sites were indistinguishable and a failure said only that something went wrong. ErrorDetail
/// propagation is this repository's first rule; naming the site is what turns "CreateSigningRequest
/// failed" into a defect that can be read straight off the status.
ua::StatusCode csr_abandoned(const char* site)
{
  // The site goes in the SOURCE tag, matching the convention the rest of the SDK uses for a
  // component-and-reason pair (`client.tier0.token_builder.missing_policy_id`), so it needs no
  // addition to the curated ContextKeys vocabulary.
  return ua::StatusCode{ua::Status::BadInternalError,
    ua::make_error_detail("CreateSigningRequestAbandoned",
      "the CreateSigningRequest flow was abandoned before it could produce a CSR",
      std::string{"server.push.create_signing_request."} + site)};
}

}  // namespace

}  // namespace

/// Builds a Certificate Signing Request: validate the type, obtain keys, settle the subject, sign.
///
/// Five awaits in a row. The chain this replaces was eight static functions, a seven-value Step enum
/// and an `enter_step` guard called at every re-entry, all of which existed so that "which step is
/// this answer for" could survive a callback boundary.
///
/// Runs on the service's OWN strand. Every step of the chain re-locked the manager and re-posted to
/// that strand, because its collaborators answer on the certificate store's executor and on the
/// crypto provider's; `await_step` does exactly that, once, for every step.
/// @see ua::async::SelfOwningOperation
class CreateSigningRequestOperation final
  : public ua::async::SelfOwningOperation<CreateSigningRequestOperation>
{
public:
  CreateSigningRequestOperation(CertificatePushService& manager, NodeId resolvedGroupId, NodeId typeId,
    String subjectName, bool regeneratePrivateKey, ByteString nonce, CertificateType certType,
    CertificateKeyAlgorithm keyAlgorithm, std::function<void(Result<ByteString>)> onComplete)
    : ua::async::SelfOwningOperation<CreateSigningRequestOperation>(manager.mStrand, manager.mLogger),
      mManager(manager.weak_from_this()), mResolvedGroupId(std::move(resolvedGroupId)),
      mTypeId(std::move(typeId)), mSubjectName(std::move(subjectName)),
      mRegeneratePrivateKey(regeneratePrivateKey), mNonce(std::move(nonce)), mCertType(certType),
      mKeyAlgorithm(keyAlgorithm), mOnComplete(std::move(onComplete))
  {}

  static void start(CertificatePushService& manager, NodeId resolvedGroupId, NodeId typeId,
    String subjectName, bool regeneratePrivateKey, ByteString nonce, CertificateType certType,
    CertificateKeyAlgorithm keyAlgorithm, std::function<void(Result<ByteString>)> onComplete)
  {
    launch(std::make_shared<CreateSigningRequestOperation>(manager,
      std::move(resolvedGroupId),
      std::move(typeId),
      std::move(subjectName),
      regeneratePrivateKey,
      std::move(nonce),
      certType,
      keyAlgorithm,
      std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<CreateSigningRequestOperation>;

  /// The manager, or nothing. Every named abandon site below is a distinct answer, and they are kept
  /// distinct on purpose: before they existed every step answered a bare `BadInternalError` and a
  /// failure said only that something had gone wrong.
  std::shared_ptr<CertificatePushService> manager_or_abandon(const char* site)
  {
    auto manager = mManager.lock();
    if (!manager)
    {
      complete(csr_abandoned(site));
    }
    return manager;
  }

  /// Every completion handed to a collaborator is FIRE-ONCE, as the chain's were.
  ///
  /// Not defensive tidiness: `CreateSigningRequest_DuplicateTypeListAfterSuccessIsIgnored` exists
  /// because a collaborator here really does answer twice, and a second answer resuming a body whose
  /// operation has already completed and been released dereferences a null owner. The chain wrapped
  /// every one of these; so does this.
  ua::async::Task<> run()
  {
    try
    {
      {
        auto manager = manager_or_abandon("start.manager_gone");
        if (!manager)
        {
          co_return;
        }
      }

      auto typeStatus = co_await await_step<StatusCode>(
        [this](auto completion)
        {
          if (auto manager = mManager.lock())
          {
            manager->validate_certificate_type_id_async(
              mTypeId, make_fire_once_callback(std::move(completion)));
          }
          else
          {
            completion(csr_abandoned("on_type_validated.manager_gone"));
          }
        });

      if (typeStatus.is_bad())
      {
        complete(typeStatus);
        co_return;
      }

      if (mRegeneratePrivateKey)
      {
        // REQ-CSR-4: nonce must be at least 32 bytes.
        if (mNonce.size() < 32)
        {
          complete(StatusCode{Status::BadInvalidArgument});
          co_return;
        }

        // RSA requires an explicit key size; ECC derives one from its curve.
        std::optional<size_t> keySize;
        if (mKeyAlgorithm == CertificateKeyAlgorithm::Rsa)
        {
          keySize = 2048;
        }

        auto keyPair = co_await await_step<KeyPairResult>(
          [this, keySize](auto completion)
          {
            if (auto manager = mManager.lock())
            {
              manager->mCrypto->create_asymmetric_key_pair_async(
                mKeyAlgorithm, keySize, make_fire_once_callback(std::move(completion)));
            }
            else
            {
              completion(KeyPairResult{csr_abandoned("on_key_pair_generated.manager_gone")});
            }
          });

        if (!keyPair.is_good())
        {
          complete(Result<ByteString>{ua::security_internal::not_good_answer(
            keyPair.status_code(), Status::BadInternalError, "CertificatePushService")});
          co_return;
        }
        mKeys = std::move(keyPair).value();
      }
      else
      {
        auto existing = co_await await_step<CertificateStore::ApplicationCertificateResult>(
          [this](auto completion)
          {
            if (auto manager = mManager.lock())
            {
              manager->mCertificateStore->get_application_certificate_async(
                mCertType, make_fire_once_callback(std::move(completion)));
            }
            else
            {
              completion(CertificateStore::ApplicationCertificateResult{
                csr_abandoned("on_existing_keys_loaded.manager_gone")});
            }
          });

        if (!existing.is_good())
        {
          complete(Result<ByteString>{ua::security_internal::not_good_store_answer(
            existing.status_code(), Status::BadInternalError, "CertificatePushService")});
          co_return;
        }
        mKeys = existing.value().keys;
      }

      // The subject: the caller's common name when it gave one, otherwise the distinguished name of
      // the application certificate already in the store.
      Crypto::CreateCsrConfig csrParams;
      if (mSubjectName.empty())
      {
        auto subject = co_await await_step<CertificateStore::ApplicationCertificateResult>(
          [this](auto completion)
          {
            if (auto manager = mManager.lock())
            {
              manager->mCertificateStore->get_application_certificate_async(
                mCertType, make_fire_once_callback(std::move(completion)));
            }
            else
            {
              completion(CertificateStore::ApplicationCertificateResult{
                csr_abandoned("on_subject_loaded.manager_gone")});
            }
          });

        if (!subject.is_good())
        {
          complete(Result<ByteString>{ua::security_internal::not_good_store_answer(
            subject.status_code(), Status::BadInternalError, "CertificatePushService")});
          co_return;
        }
        if (const auto& current = subject.value().certificate)
        {
          // The CSR subject is the current certificate's name, component by component. subject()
          // is the raw DER of the whole Name, not a distinguished-name string: handing it over as
          // distinguishedName produced a CSR whose subject was one dnQualifier holding DER bytes
          // (review B3-11).
          csrParams.subject.commonName = current->subject_common_name();
          csrParams.subject.organization = current->subject_organization();
          csrParams.subject.organizationUnit = current->subject_organizational_unit();
          csrParams.subject.locality = current->subject_locality();
          csrParams.subject.state = current->subject_state();
          csrParams.subject.country = current->subject_country();
        }
      }
      else
      {
        csrParams.subject.commonName = std::string(static_cast<string_view>(mSubjectName));
      }

      {
        auto manager = manager_or_abandon("sign_csr.manager_gone");
        if (!manager)
        {
          co_return;
        }
        csrParams.subjectKeys = mKeys;
        csrParams.certificateSignatureAlgorithm = manager->certificate_type_to_signature_algorithm(mCertType);
        csrParams.keyUsage.digitalSignature = true;
        csrParams.keyUsage.nonRepudiation = true;
        csrParams.keyUsage.keyEncipherment = true;
        csrParams.keyUsage.dataEncipherment = true;
        csrParams.subjectAlternateName.uris = {manager->mApplicationUri};
        csrParams.subjectAlternateName.hostnames = manager->mHostnames;
      }

      auto csr = co_await await_step<ByteStringResult>(
        [this, &csrParams](auto completion)
        {
          if (auto manager = mManager.lock())
          {
            manager->mCrypto->create_certificate_signing_request_async(
              csrParams, make_fire_once_callback(std::move(completion)));
          }
          else
          {
            completion(ByteStringResult{csr_abandoned("on_csr_built.manager_gone")});
          }
        });

      if (!csr.is_good())
      {
        // A CSR is returned, and its regenerated key kept, only on a Good answer; an Uncertain one, with or
        // without a CSR, is refused.
        complete(Result<ByteString>{ua::security_internal::not_good_answer(
          csr.status_code(), Status::BadInternalError, "CertificatePushService")});
        co_return;
      }

      if (mRegeneratePrivateKey)
      {
        // REQ-CSR-1: store the pending key pair, overwriting any prior one for the same
        // (group, type).
        auto manager = manager_or_abandon("on_csr_built.manager_gone");
        if (!manager)
        {
          co_return;
        }
        manager->mPendingKeyPairs[std::make_pair(mResolvedGroupId, mTypeId)] = mKeys;
      }

      complete(std::move(csr).value());
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      complete(ua::exception_to_status_code(std::current_exception()));
    }
  }

  void fail_to_start(StatusCode status)
  {
    complete(status);
  }

  /// Answers the caller exactly once: the handler is moved out, so a second call does nothing. That
  /// is what the chain's static `complete` choke did.
  void complete(Result<ByteString> result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  std::weak_ptr<CertificatePushService> mManager;
  NodeId mResolvedGroupId;
  NodeId mTypeId;
  String mSubjectName;
  bool mRegeneratePrivateKey{false};
  ByteString mNonce;
  CertificateType mCertType{CertificateType::Invalid};
  CertificateKeyAlgorithm mKeyAlgorithm{CertificateKeyAlgorithm::Rsa};
  std::shared_ptr<const AsymmetricKeyPair> mKeys;
  std::function<void(Result<ByteString>)> mOnComplete;
};

void CertificatePushService::create_signing_request_async(NodeId sessionId, NodeId certificateGroupId,
  NodeId certificateTypeId, String subjectName, bool regeneratePrivateKey, ByteString nonce,
  std::function<void(Result<ByteString>)> completionHandler)
{
  (void)sessionId;  // sessionId is used only for transaction-bound flows; CSR is multi-instance.
  auto sharedCompletion =
    make_shared_user_completion<Result<ByteString>>(mLogger, std::move(completionHandler));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(sharedCompletion),
    csr_abandoned("create_signing_request_async.post_gone"),
    [certificateGroupId = std::move(certificateGroupId),
      certificateTypeId = std::move(certificateTypeId),
      subjectName = std::move(subjectName),
      regeneratePrivateKey,
      nonce = std::move(nonce)](
      CertificatePushService& self, std::function<void(Result<ByteString>)> callback) mutable
    {
      try
      {
        // The PROLOGUE stays here, synchronous, exactly where the chain had it: an invalid
        // certificate group is rejected without ever starting a body, which is the 5.3
        // synchronous-completion path. Only what actually suspends becomes a coroutine.
        const NodeId resolvedGroupId = self.resolve_group_id(certificateGroupId);
        if (resolvedGroupId != defaultApplicationGroupId)
        {
          callback(StatusCode{Status::BadInvalidArgument});
          return;
        }

        const CertificateType certType = self.node_id_to_certificate_type(certificateTypeId);
        const CertificateKeyAlgorithm keyAlgorithm = self.certificate_type_to_key_algorithm(certType);

        // Copied (not moved): if `start` throws after ownership transfer, the catch below must still
        // hold a valid callback to report through. The operation then owns the only live copy.
        CreateSigningRequestOperation::start(self,
          resolvedGroupId,
          std::move(certificateTypeId),
          std::move(subjectName),
          regeneratePrivateKey,
          std::move(nonce),
          certType,
          keyAlgorithm,
          callback);
      }
      catch (...)
      {
        callback(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// UpdateCertificate
// ---------------------------------------------------------------------------

/// Validates a pushed certificate and stages it on the session's open transaction.
///
/// Three awaits, and two invariants that the chain spent most of its size expressing.
///
/// The TRANSACTION may be invalidated while this is suspended - a different session may close it, or
/// ApplyChanges may take it - so `reservation_is_live` is re-asked after every suspension, exactly
/// where the chain re-asked it. A straggler answering into a transaction that has moved on must not
/// mutate it.
///
/// The RESERVATION must be released on every exit but one. `fail()` releases it; the success path in
/// `finalise` erases it after staging; and an abandoned path releases nothing because the
/// transaction it belonged to is already gone. Missing a release leaves
/// `inFlightUpdateReservations` non-empty forever, which makes every later ApplyChanges answer
/// BadInvalidState - and three tests say so.
/// @see ua::async::SelfOwningOperation
class UpdateCertificateOperation final : public ua::async::SelfOwningOperation<UpdateCertificateOperation>
{
public:
  UpdateCertificateOperation(const UpdateCertificateOperation&) = delete;
  UpdateCertificateOperation& operator=(const UpdateCertificateOperation&) = delete;
  UpdateCertificateOperation(UpdateCertificateOperation&&) = delete;
  UpdateCertificateOperation& operator=(UpdateCertificateOperation&&) = delete;

  // The PEM private key is a secret on every exit, not only where it is parsed (review B3-11).
  ~UpdateCertificateOperation()
  {
    security::secure_clear(mPrivateKey);
  }

  UpdateCertificateOperation(CertificatePushService& manager, NodeId sessionId, NodeId resolvedGroupId,
    NodeId typeId, ByteString certificate, std::vector<ByteString> issuerCertificates,
    String privateKeyFormat, ByteString privateKey, uint64_t transactionGeneration, uint64_t reservationId,
    std::function<void(Result<bool>)> onComplete)
    : ua::async::SelfOwningOperation<UpdateCertificateOperation>(manager.mStrand, manager.mLogger),
      mManager(manager.weak_from_this()), mSessionId(std::move(sessionId)),
      mResolvedGroupId(std::move(resolvedGroupId)), mTypeId(std::move(typeId)),
      mCertificate(std::move(certificate)), mIssuerCertificates(std::move(issuerCertificates)),
      mPrivateKeyFormat(std::move(privateKeyFormat)), mPrivateKey(std::move(privateKey)),
      mTransactionGeneration(transactionGeneration), mReservationId(reservationId),
      mOnComplete(std::move(onComplete))
  {}

  static void start(CertificatePushService& manager, NodeId sessionId, NodeId resolvedGroupId, NodeId typeId,
    ByteString certificate, std::vector<ByteString> issuerCertificates, String privateKeyFormat,
    ByteString privateKey, uint64_t transactionGeneration, uint64_t reservationId,
    std::function<void(Result<bool>)> onComplete)
  {
    launch(std::make_shared<UpdateCertificateOperation>(manager,
      std::move(sessionId),
      std::move(resolvedGroupId),
      std::move(typeId),
      std::move(certificate),
      std::move(issuerCertificates),
      std::move(privateKeyFormat),
      std::move(privateKey),
      transactionGeneration,
      reservationId,
      std::move(onComplete)));
  }

  bool reservation_is_live(const CertificatePushService& manager) const
  {
    const auto& transaction = manager.mActiveTransaction;
    return transaction && transaction->owningSessionId == mSessionId &&
           transaction->generation == mTransactionGeneration &&
           transaction->inFlightUpdateReservations.contains(mReservationId);
  }

  void release_reservation(CertificatePushService& manager) const
  {
    if (!manager.mActiveTransaction)
    {
      return;
    }
    auto& transaction = *manager.mActiveTransaction;
    if (transaction.owningSessionId != mSessionId || transaction.generation != mTransactionGeneration)
    {
      return;
    }
    transaction.inFlightUpdateReservations.erase(mReservationId);
    manager.drop_transaction_if_empty();
  }

  /// The synchronous prologue in `update_certificate_async` rejects with this before the operation
  /// exists, so it is public rather than an implementation detail of the body.
  static StatusCode update_rejected_while_applying_status()
  {
    try
    {
      return StatusCode{Status::BadInvalidState,
        ErrorDetail::build("UpdateRejectedWhileApplying",
          "UpdateCertificate cannot start while ApplyChanges is in progress",
          "CertificatePushService")};
    }
    catch (...)
    {
      return ua::exception_to_status_code(std::current_exception());
    }
  }

private:
  friend class ua::async::SelfOwningOperation<UpdateCertificateOperation>;

  void fail(CertificatePushService& manager, Result<bool> result)
  {
    release_reservation(manager);
    complete(std::move(result));
  }

  ua::async::Task<> run()
  {
    try
    {
      auto typeStatus = co_await await_step<StatusCode>(
        [this](auto completion)
        {
          if (auto manager = mManager.lock())
          {
            manager->validate_certificate_type_id_async(
              mTypeId, make_fire_once_callback(std::move(completion)));
          }
          else
          {
            completion(StatusCode{Status::BadInternalError});
          }
        });

      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (!reservation_is_live(*manager))
        {
          complete(transaction_invalidated_status());
          co_return;
        }
        if (typeStatus.is_bad())
        {
          fail(*manager, typeStatus);
          co_return;
        }

        // A new certificate that will not parse is BadCertificateInvalid (7.10.4), not an internal error:
        // the client sent it. An issuer that will not parse is Bad_SecurityChecksFailed (below).
        try
        {
          const auto certData =
            span<const byte>{reinterpret_cast<const byte*>(mCertificate.data()), mCertificate.size()};
          // The one chain parser: a certificate field that carries its issuers after the leaf adds
          // them to the issuerCertificates argument (decision 24).
          auto parsed = ::ua::detail::parse_certificate_field(*manager->mCrypto, certData);
          if (!parsed.is_good())
          {
            throw UaException{parsed.status_code()};
          }
          auto certificates = std::move(parsed).value();
          mCert = certificates.front();
          mIssuerChain.assign(certificates.begin() + 1, certificates.end());
        }
        catch (...)
        {
          fail(*manager, StatusCode{Status::BadCertificateInvalid});
          co_return;
        }
        try
        {
          for (const auto& issuerDer : mIssuerCertificates)
          {
            const auto issuerData =
              span<const byte>{reinterpret_cast<const byte*>(issuerDer.data()), issuerDer.size()};
            auto parsed = ::ua::detail::parse_certificate_field(*manager->mCrypto, issuerData);
            if (!parsed.is_good())
            {
              throw UaException{parsed.status_code()};
            }
            for (auto& issuer : std::move(parsed).value())
            {
              mIssuerChain.push_back(std::move(issuer));
            }
          }
        }
        catch (...)
        {
          // OPC 10000-12 7.10.4: "The Server shall do all normal integrity checks on the Certificate and all
          // of the issuer Certificates. If errors occur the Bad_SecurityChecksFailed error is returned."
          // Bad_CertificateInvalid is for the new Certificate itself (handled above).
          fail(*manager,
            StatusCode{Status::BadSecurityChecksFailed,
              make_error_detail("IssuerCertificateInvalid",
                "An issuer certificate could not be parsed",
                "CertificatePushService")});
          co_return;
        }

        const auto certType = manager->node_id_to_certificate_type(mTypeId);
        const auto shapeStatus = manager->validate_key_shape_for_type(certType, *mCert);
        if (shapeStatus.is_bad())
        {
          fail(*manager, shapeStatus);
          co_return;
        }

        // G: the certificate must comply with the SecurityPolicy of every served endpoint that presents a
        // certificate of this type (the runtime counterpart of the startup refusal, which checks each
        // endpoint's own certificate): an ECC certificate is not held to an RSA endpoint's policy. A
        // violation is Bad_SecurityChecksFailed with the endpoint and rule as its cause.
        const X509Certificate& signer = mIssuerChain.empty() ? *mCert : *mIssuerChain.front();
        auto servedEndpoints =
          manager->mServedEndpointPolicies
            ? manager->mServedEndpointPolicies()
            : std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>{};
        std::erase_if(servedEndpoints,
          [certType](const auto& endpoint)
          { return !endpoint.second || endpoint.second->certificate_type() != certType; });
        const auto compliance =
          server::detail::check_own_certificate_against_endpoints(*mCert, signer, servedEndpoints);
        if (compliance.is_bad())
        {
          fail(*manager,
            StatusCode{Status::BadSecurityChecksFailed,
              make_error_detail("CertificateViolatesEndpointPolicy",
                "The certificate does not comply with the SecurityPolicy of a served endpoint",
                "CertificatePushService",
                compliance.status_code())});
          co_return;
        }
      }

      auto validation = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          if (auto manager = mManager.lock())
          {
            // The candidate must name THIS server (Part 12 7.10.4 "all normal integrity checks"): a
            // certificate whose SAN URI is another application's would be installed and then refused
            // by every client (review B3-11).
            CertificateValidationRequest request;
            request.certificate = mCert;
            request.presentedIssuers = mIssuerChain;
            request.applicationUri = manager->mApplicationUri;
            // The staged TrustList is this Session's only while its own transaction holds it.
            const bool ownTransaction = manager->mActiveTransaction.has_value() &&
                                        manager->mActiveTransaction->owningSessionId == mSessionId;
            manager->validate_against_transaction_trust_list_async(
              std::move(request), ownTransaction, make_fire_once_callback(std::move(completion)));
          }
          else
          {
            completion(VoidResult{StatusCode{Status::BadInternalError}});
          }
        });

      std::shared_ptr<const AsymmetricKeyPair> resolvedKeys;
      bool needExistingKeys = false;
      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (!reservation_is_live(*manager))
        {
          complete(transaction_invalidated_status());
          co_return;
        }
        if (validation.is_bad())
        {
          StatusCode failure{Status::BadSecurityChecksFailed};
          try
          {
            failure = map_certificate_integrity_validation_failure(*manager, validation.status_code());
          }
          catch (...)
          {
            failure = ua::exception_to_status_code(std::current_exception());
          }
          fail(*manager, std::move(failure));
          co_return;
        }

        // Three ways to obtain the key pair the certificate must match, in the order the chain tried
        // them: the PEM the client supplied, a key pair this service generated for an earlier CSR,
        // or the one already in the store.
        if (!mPrivateKey.empty())
        {
          if (mPrivateKeyFormat.empty() || static_cast<string_view>(mPrivateKeyFormat) != "PEM")
          {
            security::secure_clear(mPrivateKey);
            fail(*manager, StatusCode{Status::BadNotSupported});
            co_return;
          }
          try
          {
            const auto certType = manager->node_id_to_certificate_type(mTypeId);
            const auto keyAlgo = manager->certificate_type_to_key_algorithm(certType);
            std::vector<byte> pemCopy(mPrivateKey.size());

            // The PEM is a secret: both copies are wiped on every exit of this scope, once the key
            // object exists or the parse failed (review B3-11).
            // Declared original first so the copy is zeroed before the original is cleared.
            const security::ScrubOnExit wipeOriginal{mPrivateKey};
            const security::ScrubOnExit wipeCopy{pemCopy.data(), pemCopy.size()};

            std::memcpy(pemCopy.data(), mPrivateKey.data(), mPrivateKey.size());
            resolvedKeys = manager->mCrypto->get_private_key_from_pem(keyAlgo, span<byte>{pemCopy});
          }
          catch (...)
          {
            fail(*manager, StatusCode{Status::BadSecurityChecksFailed});
            co_return;
          }
        }
        else if (auto pending = manager->mPendingKeyPairs.find(std::make_pair(mResolvedGroupId, mTypeId));
                 pending != manager->mPendingKeyPairs.end())
        {
          resolvedKeys = pending->second;
        }
        else
        {
          needExistingKeys = true;
        }
      }

      if (needExistingKeys)
      {
        auto existing = co_await await_step<CertificateStore::ApplicationCertificateResult>(
          [this](auto completion)
          {
            if (auto manager = mManager.lock())
            {
              const auto certType = manager->node_id_to_certificate_type(mTypeId);
              manager->mCertificateStore->get_application_certificate_async(
                certType, make_fire_once_callback(std::move(completion)));
            }
            else
            {
              completion(
                CertificateStore::ApplicationCertificateResult{StatusCode{Status::BadInternalError}});
            }
          });

        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (!reservation_is_live(*manager))
        {
          complete(transaction_invalidated_status());
          co_return;
        }
        if (!existing.is_good())
        {
          StatusCode failure{Status::BadSecurityChecksFailed};
          try
          {
            failure = map_existing_certificate_resolution_failure(*manager, existing.status_code());
          }
          catch (...)
          {
            failure = ua::exception_to_status_code(std::current_exception());
          }
          fail(*manager, std::move(failure));
          co_return;
        }
        resolvedKeys = existing.value().keys;
      }

      // Whichever way the keys were obtained, they must match the certificate being pushed.
      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (!reservation_is_live(*manager))
        {
          complete(transaction_invalidated_status());
          co_return;
        }
        if (resolvedKeys->public_key_der() != mCert->public_key())
        {
          fail(*manager, StatusCode{Status::BadSecurityChecksFailed});
          co_return;
        }

        CertificatePushService::Transaction::PendingCertUpdate update;
        update.certificate = std::move(mCert);
        update.issuerChain = std::move(mIssuerChain);
        update.keyPair = std::move(resolvedKeys);
        try
        {
          manager->mActiveTransaction->pendingCertificates.emplace_back(
            std::make_pair(mResolvedGroupId, mTypeId), std::move(update));
        }
        catch (...)
        {
          fail(*manager, ua::exception_to_status_code(std::current_exception()));
          co_return;
        }

        // The reservation is ERASED rather than released: the staged certificate is now what keeps
        // the transaction alive, so the empty-transaction rollback in `release_reservation` must not
        // run here.
        manager->mActiveTransaction->inFlightUpdateReservations.erase(mReservationId);
        complete(true);
      }
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      if (auto manager = mManager.lock())
      {
        fail(*manager, failure);
      }
      else
      {
        complete(failure);
      }
    }
  }

  void fail_to_start(StatusCode status)
  {
    if (auto manager = mManager.lock())
    {
      fail(*manager, status);
      return;
    }
    complete(status);
  }

  void complete(Result<bool> result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  static StatusCode transaction_invalidated_status()
  {
    try
    {
      return StatusCode{Status::BadInvalidState,
        ErrorDetail::build("UpdateTransactionInvalidated",
          "UpdateCertificate transaction was invalidated before completion",
          "CertificatePushService")};
    }
    catch (...)
    {
      return ua::exception_to_status_code(std::current_exception());
    }
  }

  static StatusCode map_certificate_integrity_validation_failure(
    CertificatePushService& manager, StatusCode cause)
  {
    std::shared_ptr<const ErrorDetail> mappedDetail;
    if (manager.mDependencyFailureDetailBuilder)
      mappedDetail = manager.mDependencyFailureDetailBuilder(std::move(cause));
    else
      mappedDetail = ErrorDetail::build("CertificateIntegrityValidationFailed",
        "Certificate integrity validation failed",
        "CertificatePushService")
                       .cause(std::move(cause));
    return StatusCode{Status::BadSecurityChecksFailed, std::move(mappedDetail)};
  }

  static StatusCode map_existing_certificate_resolution_failure(
    CertificatePushService& manager, StatusCode cause)
  {
    std::shared_ptr<const ErrorDetail> mappedDetail;
    if (manager.mDependencyFailureDetailBuilder)
      mappedDetail = manager.mDependencyFailureDetailBuilder(std::move(cause));
    else
      mappedDetail = ErrorDetail::build("ExistingCertificateResolutionFailed",
        "Existing application certificate could not be resolved",
        "CertificatePushService")
                       .cause(std::move(cause));
    return StatusCode{Status::BadSecurityChecksFailed, std::move(mappedDetail)};
  }

  std::weak_ptr<CertificatePushService> mManager;
  NodeId mSessionId;
  NodeId mResolvedGroupId;
  NodeId mTypeId;
  ByteString mCertificate;
  std::vector<ByteString> mIssuerCertificates;
  String mPrivateKeyFormat;
  ByteString mPrivateKey;
  uint64_t mTransactionGeneration{0};
  uint64_t mReservationId{0};
  std::shared_ptr<const X509Certificate> mCert;
  std::vector<std::shared_ptr<const X509Certificate>> mIssuerChain;
  std::function<void(Result<bool>)> mOnComplete;
};

void CertificatePushService::update_certificate_async(NodeId sessionId, NodeId certificateGroupId,
  NodeId certificateTypeId, ByteString certificate, std::vector<ByteString> issuerCertificates,
  String privateKeyFormat, ByteString privateKey, std::function<void(Result<bool>)> completionHandler)
{
  auto sharedCompletion = make_shared_user_completion<Result<bool>>(mLogger, std::move(completionHandler));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(sharedCompletion),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId),
      certificateGroupId = std::move(certificateGroupId),
      certificateTypeId = std::move(certificateTypeId),
      certificate = std::move(certificate),
      issuerCertificates = std::move(issuerCertificates),
      privateKeyFormat = std::move(privateKeyFormat),
      privateKey = std::move(privateKey)](
      CertificatePushService& self, std::function<void(Result<bool>)> callback) mutable
    {
      try
      {
        // The PROLOGUE stays here, synchronous, as the chain had it: resolving the group, opening or
        // joining the transaction, refusing while ApplyChanges holds it, and TAKING the reservation
        // all happen before anything suspends. Only what suspends became a body.
        const NodeId resolvedGroupId = self.resolve_group_id(certificateGroupId);
        if (resolvedGroupId != defaultApplicationGroupId)
        {
          callback(StatusCode{Status::BadInvalidArgument});
          return;
        }

        const auto transactionStatus = self.ensure_transaction(sessionId);
        if (transactionStatus.is_bad())
        {
          callback(transactionStatus);
          return;
        }

        auto& transaction = *self.mActiveTransaction;
        if (transaction.phase != CertificatePushService::Transaction::Phase::Open)
        {
          callback(UpdateCertificateOperation::update_rejected_while_applying_status());
          return;
        }

        const uint64_t transactionGeneration = transaction.generation;
        const uint64_t reservationId = self.mNextUpdateReservationId++;
        try
        {
          transaction.inFlightUpdateReservations.insert(reservationId);
        }
        catch (...)
        {
          // The chain rolled back here through `fail`, which drops a transaction that holds nothing:
          // `ensure_transaction` may have just created this one for us, and if the reservation never
          // landed there is no other reason for it to exist.
          self.drop_transaction_if_empty();
          callback(ua::exception_to_status_code(std::current_exception()));
          return;
        }

        UpdateCertificateOperation::start(self,
          std::move(sessionId),
          resolvedGroupId,
          std::move(certificateTypeId),
          std::move(certificate),
          std::move(issuerCertificates),
          std::move(privateKeyFormat),
          std::move(privateKey),
          transactionGeneration,
          reservationId,
          callback);
      }
      catch (...)
      {
        callback(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// ApplyChanges
// ---------------------------------------------------------------------------

/// Applies every change staged on the session's transaction, all or nothing.
///
/// Part 12 7.10.1: "When ApplyChanges is called the Server verifies that all the changes are
/// consistent and can be applied without errors. If any errors are found then all changes are
/// discarded. If no errors are found, the Server applies all changes." That is why the verify pass
/// is a separate loop that finishes before the commit loop starts, and why it keeps verifying after
/// the first failure - the Errors list in TransactionDiagnostics (7.10.11) is meant to be complete.
///
/// Residual: a non-transactional CertificateStore offers no rollback, so a raw store-write failure
/// during the commit loop, after a clean verify, can still leave a partial commit. That is an
/// exceptional I/O condition rather than an inconsistency, and it is surfaced the same way.
///
/// The transaction is MOVED onto this operation once the write-state preflight passes, and
/// `mActiveTransaction` is reset there. Everything after that point works from the frame, which is
/// why `transaction_is_live` is asked during the preflight and never again.
/// @see ua::async::SelfOwningOperation
class ApplyChangesOperation final : public ua::async::SelfOwningOperation<ApplyChangesOperation>
{
public:
  ApplyChangesOperation(CertificatePushService& manager, NodeId sessionId,
    server::MethodResponseCorrelation correlation, uint64_t transactionGeneration,
    std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<ApplyChangesOperation>(manager.mStrand, manager.mLogger),
      mManager(manager.weak_from_this()), mSessionId(std::move(sessionId)),
      mResponseCorrelation(std::move(correlation)), mTransactionGeneration(transactionGeneration),
      mOnComplete(std::move(onComplete))
  {}

  ApplyChangesOperation(const ApplyChangesOperation&) = delete;
  ApplyChangesOperation& operator=(const ApplyChangesOperation&) = delete;
  ApplyChangesOperation(ApplyChangesOperation&&) = delete;
  ApplyChangesOperation& operator=(ApplyChangesOperation&&) = delete;

  ~ApplyChangesOperation()
  {
    // A frame abandoned before it completed (its collaborator never answered) still drops the lists its
    // transaction staged and opens the gate it closed; posts and a mutex-guarded flag, never a wait.
    if (auto manager = mManager.lock())
    {
      release_taken_lists(*manager);
      if (mHoldsTrustListGate)
        manager->end_trust_list_apply();
    }
  }

  /// Once the frame has taken the transaction, nothing else drops what it staged: whatever the outcome, the
  /// lists still staged under its generation go (none are left after a successful write; a later
  /// transaction's are kept).
  void release_taken_lists(CertificatePushService& manager)
  {
    if (!mTookTransaction)
      return;
    mTookTransaction = false;
    manager.discard_staged_trust_lists(mTransactionGeneration);
  }

  static void start(CertificatePushService& manager, NodeId sessionId,
    server::MethodResponseCorrelation correlation, uint64_t transactionGeneration,
    std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<ApplyChangesOperation>(
      manager, std::move(sessionId), std::move(correlation), transactionGeneration, std::move(onComplete)));
  }

  /// The synchronous prologue in `apply_changes_async` rejects with this before the operation
  /// exists, so it is public rather than an implementation detail of the body.
  static StatusCode apply_update_prerequisite_pending_status()
  {
    try
    {
      return StatusCode{Status::BadInvalidState,
        ErrorDetail::build("ApplyUpdatePrerequisitePending",
          "ApplyChanges cannot start while UpdateCertificate prerequisites are pending",
          "CertificatePushService")};
    }
    catch (...)
    {
      return ua::exception_to_status_code(std::current_exception());
    }
  }

private:
  friend class ua::async::SelfOwningOperation<ApplyChangesOperation>;

  /// Which of the three write-state queries a preflight round is running. An injected check replaces
  /// both trust-list queries; the user-token list is only queried after the application one.
  enum class WriteStateSource
  {
    Injected,
    Application,
    UserToken,
  };

  enum class Preflight
  {
    Proceed,
    Stopped,
  };

  ua::async::Task<> run()
  {
    try
    {
      // --- write-state preflight -------------------------------------------------------------
      bool injected = false;
      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        injected = static_cast<bool>(manager->mApplyWriteStateCheck);
      }

      {
        auto answer = co_await await_step<Result<bool>>(
          [this, injected](auto completion)
          {
            start_write_state_query(
              injected ? WriteStateSource::Injected : WriteStateSource::Application, std::move(completion));
          });
        if (after_write_state(answer) == Preflight::Stopped)
          co_return;
      }

      if (!injected)
      {
        bool haveUserTokenList = false;
        {
          auto manager = mManager.lock();
          if (!manager)
          {
            complete(StatusCode{Status::BadInternalError});
            co_return;
          }
          haveUserTokenList = manager->mUserTokenTrustList != nullptr;
        }
        if (haveUserTokenList)
        {
          auto answer = co_await await_step<Result<bool>>([this](auto completion)
            { start_write_state_query(WriteStateSource::UserToken, std::move(completion)); });
          if (after_write_state(answer) == Preflight::Stopped)
            co_return;
        }
      }

      // --- take the transaction --------------------------------------------------------------
      // Past this point the transaction belongs to the frame, not to the manager: a concurrent
      // UpdateCertificate sees no active transaction and opens its own.
      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        // The staged TrustLists stay this frame's until they are written or discarded: no TrustList
        // modification may stage over them or write the store under them meanwhile (review BR-13). One still
        // in flight (begun after the write-state preflight) would stage lists this frame does not verify: the
        // apply is refused before anything is committed, the transaction kept, as for a TrustList open for
        // write.
        const bool changesTrustLists = !manager->mActiveTransaction->modifiedTrustLists.empty();
        if (!manager->begin_trust_list_apply(changesTrustLists))
        {
          restore_open_phase(*manager);  // kept, and open: a later ApplyChanges or CancelChanges may end it
          complete(StatusCode{Status::BadInvalidState,
            make_error_detail("TrustListModificationInProgress",
              "a TrustList modification of the transaction is still in progress; nothing was applied",
              "CertificatePushService")});
          co_return;
        }
        mHoldsTrustListGate = changesTrustLists;
        mTookTransaction = true;
        mPending = std::move(manager->mActiveTransaction->pendingCertificates);
        mModifiedTrustLists = std::move(manager->mActiveTransaction->modifiedTrustLists);
        mStartTime = manager->mActiveTransaction->startTime;
        manager->clear_active_transaction();
      }

      // --- verify every staged certificate before committing any of them ---------------------
      std::vector<TransactionErrorType> verifyErrors;
      for (size_t index = 0; index < mPending.size(); ++index)
      {
        {
          auto manager = mManager.lock();
          if (!manager)
          {
            complete(StatusCode{Status::BadInternalError});
            co_return;
          }
        }

        auto result = co_await await_step<VoidResult>(
          [this, index](auto completion)
          {
            auto once = make_fire_once_callback(std::move(completion));
            auto manager = mManager.lock();
            if (!manager)
            {
              once(VoidResult{StatusCode{Status::BadInternalError}});
              return;
            }
            CertificateValidationRequest request;
            request.certificate = mPending[index].second.certificate;
            request.presentedIssuers = mPending[index].second.issuerChain;
            manager->validate_against_transaction_trust_list_async(
              std::move(request), /*useStaged=*/true, once);
          });

        {
          auto manager = mManager.lock();
          if (!manager)
          {
            complete(StatusCode{Status::BadInternalError});
            co_return;
          }
        }

        if (result.is_bad())
        {
          // Record a per-target error against the certificate group and keep verifying the rest so
          // the TransactionDiagnostics Errors list is complete (7.10.11 / 7.10.12).
          TransactionErrorType txnError;
          txnError.target_id() = mPending[index].first.first;
          txnError.error() = StatusCode{Status::BadSecurityChecksFailed,
            ErrorDetail::build(
              "ApplyValidationFailed", "Certificate failed apply-time validation", "CertificatePushService")
              .cause(result.status_code())};
          txnError.message() = LocalizedText{"", "Certificate failed apply-time validation"};
          verifyErrors.push_back(std::move(txnError));
        }
      }

      if (!verifyErrors.empty())
      {
        // 7.10.1: errors found -> discard ALL changes (commit nothing). The pending key pairs are
        // NOT consumed; the transaction was already reset.
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        const auto firstStatus = verifyErrors.front().error();
        manager->discard_staged_trust_lists(mTransactionGeneration);
        publish_diagnostics(*manager, firstStatus, std::move(verifyErrors));
        complete(VoidResult{firstStatus});
        co_return;
      }

      // --- the whole batch verified consistent, so apply it ----------------------------------
      for (size_t index = 0; index < mPending.size(); ++index)
      {
        CertificateStore::ApplicationCertificate appCert;
        {
          auto manager = mManager.lock();
          if (!manager)
          {
            complete(StatusCode{Status::BadInternalError});
            co_return;
          }
          auto& entry = mPending[index];
          appCert.certificateType = manager->node_id_to_certificate_type(entry.first.second);
          appCert.certificate = std::move(entry.second.certificate);
          appCert.keys = std::move(entry.second.keyPair);
          // Decision 24: the issuerCertificates argument is kept as the own issuer chain and sent after
          // the leaf on every outgoing certificate field.
          appCert.issuerCertificates = entry.second.issuerChain;
        }

        auto commitResult = co_await await_step<VoidResult>(
          [this, cert = std::move(appCert)](auto completion) mutable
          {
            auto once = make_fire_once_callback(std::move(completion));
            auto manager = mManager.lock();
            if (!manager)
            {
              once(VoidResult{StatusCode{Status::BadInternalError}});
              return;
            }
            manager->mCertificateStore->add_to_application_certificates_async(std::move(cert), once);
          });

        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (commitResult.is_bad())
        {
          // Record the failing operation against its certificate group target (7.10.11 / 7.10.12).
          std::vector<TransactionErrorType> errors;
          TransactionErrorType txnError;
          txnError.target_id() = mPending[index].first.first;
          txnError.error() = commitResult.status_code();
          txnError.message() = LocalizedText{"", "Failed to apply certificate update"};
          errors.push_back(std::move(txnError));
          // The transaction is over: its TrustLists must not ride along with the next one.
          manager->discard_staged_trust_lists(mTransactionGeneration);
          publish_diagnostics(*manager, commitResult.status_code(), std::move(errors));
          complete(std::move(commitResult));
          co_return;
        }
      }

      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        // Remove consumed pending key pairs (matches pre-flip behaviour).
        for (const auto& entry : mPending)
        {
          manager->mPendingKeyPairs.erase(entry.first);
        }

        const bool hadChanges = !mPending.empty() || !mModifiedTrustLists.empty();
        if (!hadChanges)
        {
          // Degenerate (empty) transaction applied successfully.
          publish_diagnostics(*manager, StatusCode{Status::Good}, {});
          complete(VoidResult{});
          co_return;
        }
      }

      // --- write the staged TrustLists (Part 12 7.8.2.3: "does not update the TrustList until
      // ApplyChanges") -------------------------------------------------------------------------
      for (const bool userTokenGroup : {false, true})
      {
        std::shared_ptr<TrustListManager> trustList;
        const NodeId& trustListId =
          userTokenGroup ? defaultUserTokenGroupTrustListId : defaultApplicationGroupTrustListId;
        {
          auto manager = mManager.lock();
          if (!manager)
          {
            complete(StatusCode{Status::BadInternalError});
            co_return;
          }
          trustList = userTokenGroup ? manager->mUserTokenTrustList : manager->mTrustList;
        }
        if (!trustList)
        {
          continue;
        }
        if (!contains(mModifiedTrustLists, trustListId))
          continue;

        auto applied = co_await await_step<VoidResult>(
          [trustList](auto completion)
          {
            auto once = make_fire_once_callback(std::move(completion));
            trustList->apply_staged_async(once);
          });

        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (applied.is_bad())
        {
          // What reached the store before the failure is in force, so the cache is still refreshed and the
          // open channels and Sessions still re-evaluated below; the TrustLists not yet written are
          // discarded with the transaction, and ApplyChanges reports the failure (review BR-13).
          TransactionErrorType txnError;
          txnError.target_id() = trustListId;
          txnError.error() = applied.status_code();
          txnError.message() = LocalizedText{"", "Failed to apply TrustList update"};
          mWriteErrors.push_back(std::move(txnError));
          mWriteFailure = std::move(applied);
          manager->discard_staged_trust_lists(mTransactionGeneration);
          break;
        }
      }

      // --- refresh the store cache, then close channels and re-evaluate certificates ---------
      auto refreshResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          auto once = make_fire_once_callback(std::move(completion));
          auto manager = mManager.lock();
          if (!manager)
          {
            once(VoidResult{StatusCode{Status::BadInternalError}});
            return;
          }
          try
          {
            manager->mCertificateStore->refresh_cache(once);
          }
          catch (...)
          {
            once(VoidResult{::ua::exception_to_status_code(std::current_exception())});
          }
        });

      bool channelsAffected = false;
      bool certificatesAffected = false;
      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (refreshResult.is_bad())
        {
          publish_diagnostics(*manager, refreshResult.status_code(), {});
          complete(std::move(refreshResult));
          co_return;
        }
        // A new Server Certificate: every SecureChannel renegotiates (Part 12 7.10.6). A changed TrustList:
        // every open SecureChannel and Session re-evaluates its Certificates and only those no longer
        // valid close (7.8.2.3: "Sessions with an untrusted or revoked Certificate shall be closed").
        channelsAffected = !mPending.empty() && manager->mCloseAllChannels != nullptr;
        certificatesAffected = !mModifiedTrustLists.empty();
      }

      if (channelsAffected)
      {
        auto result = co_await await_step<VoidResult>(
          [this](auto completion)
          {
            auto once = make_fire_once_callback(std::move(completion));
            auto manager = mManager.lock();
            if (!manager)
            {
              once(VoidResult{StatusCode{Status::BadInternalError}});
              return;
            }
            try
            {
              manager->mCloseAllChannels(mSessionId, mResponseCorrelation, once);
            }
            catch (...)
            {
              once(channel_close_hook_exception_result());
            }
          });

        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (result.is_bad())
        {
          finish_effects(*manager, std::move(result));
          co_return;
        }
      }

      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        if (!certificatesAffected || !manager->mReevaluateCertificates)
        {
          finish_effects(*manager, VoidResult{});
          co_return;
        }
      }

      auto identityResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          auto once = make_fire_once_callback(std::move(completion));
          auto manager = mManager.lock();
          if (!manager)
          {
            once(VoidResult{StatusCode{Status::BadInternalError}});
            return;
          }
          try
          {
            manager->mReevaluateCertificates(mSessionId, mResponseCorrelation, once);
          }
          catch (...)
          {
            once(certificate_reevaluation_hook_exception_result());
          }
        });

      {
        auto manager = mManager.lock();
        if (!manager)
        {
          complete(StatusCode{Status::BadInternalError});
          co_return;
        }
        finish_effects(*manager, std::move(identityResult));
      }
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      if (auto manager = mManager.lock())
      {
        restore_open_phase(*manager);
      }
      complete(failure);
    }
  }

  void fail_to_start(StatusCode status)
  {
    if (auto manager = mManager.lock())
    {
      restore_open_phase(*manager);
    }
    complete(status);
  }

  template<typename Completion>
  void start_write_state_query(WriteStateSource source, Completion completion)
  {
    // The chain wrapped each of these in a catch that fed the exception status back through the
    // SAME answer path, so a throwing query and a bad answer are handled identically. `once` is what
    // makes that safe: a query that throws after it has already answered cannot answer twice.
    auto once = make_fire_once_callback(std::move(completion));
    auto manager = mManager.lock();
    if (!manager)
    {
      once(Result<bool>{StatusCode{Status::BadInternalError}});
      return;
    }
    try
    {
      switch (source)
      {
      case WriteStateSource::Injected:
        manager->mApplyWriteStateCheck(once);
        break;
      case WriteStateSource::Application:
        manager->mTrustList->is_write_open_async(once);
        break;
      case WriteStateSource::UserToken:
        manager->mUserTokenTrustList->is_write_open_async(once);
        break;
      }
    }
    catch (...)
    {
      once(Result<bool>{ua::exception_to_status_code(std::current_exception())});
    }
  }

  /// The three questions the chain asked after every write-state answer. A trust list that is open
  /// for writing means someone is still editing it, so the transaction goes back to Open rather than
  /// being applied half-edited.
  Preflight after_write_state(const Result<bool>& answer)
  {
    auto manager = mManager.lock();
    if (!manager)
    {
      complete(StatusCode{Status::BadInternalError});
      return Preflight::Stopped;
    }
    if (!transaction_is_live(*manager))
    {
      complete(apply_transaction_invalidated_status());
      return Preflight::Stopped;
    }
    if (!answer.is_good())
    {
      restore_open_phase(*manager);
      complete(VoidResult{answer.status_code(), answer.shared_detail()});
      return Preflight::Stopped;
    }
    if (answer.value())
    {
      restore_open_phase(*manager);
      complete(StatusCode{Status::BadInvalidState});
      return Preflight::Stopped;
    }
    return Preflight::Proceed;
  }

  bool transaction_is_live(const CertificatePushService& manager) const
  {
    const auto& transaction = manager.mActiveTransaction;
    return transaction && transaction->owningSessionId == mSessionId &&
           transaction->generation == mTransactionGeneration &&
           transaction->phase == CertificatePushService::Transaction::Phase::Applying;
  }

  void restore_open_phase(CertificatePushService& manager) const
  {
    if (transaction_is_live(manager))
      manager.mActiveTransaction->phase = CertificatePushService::Transaction::Phase::Open;
  }

  void finish_effects(CertificatePushService& manager, VoidResult effectResult)
  {
    if (effectResult.is_good() && mWriteFailure.is_bad())
    {
      const auto failure = mWriteFailure.status_code();
      publish_diagnostics(manager, failure, std::move(mWriteErrors));
      complete(std::move(mWriteFailure));
      return;
    }
    if (effectResult.is_bad())
    {
      publish_diagnostics(manager, effectResult.status_code(), {});
      complete(std::move(effectResult));
      return;
    }
    publish_diagnostics(manager, StatusCode{Status::Good}, {});
    complete(VoidResult{});
  }

  /// Publish a TransactionDiagnostics snapshot for this (consumed) transaction. Runs on the
  /// manager's strand; a no-op when no sink is configured. Only called after the transaction has
  /// been moved onto the frame, i.e. at a genuine terminal point of an applied transaction.
  void publish_diagnostics(
    CertificatePushService& manager, StatusCode result, std::vector<TransactionErrorType> errors)
  {
    if (!manager.mPublishTransactionDiagnostics)
      return;
    try
    {
      auto record = build_diagnostics_record(
        mStartTime, DateTime::now(), result, mPending, mModifiedTrustLists, std::move(errors));
      manager.mPublishTransactionDiagnostics(std::move(record));
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      manager.mLogger.with_category("security")
        .error({{"error", to_string(failure)}},
          "TransactionDiagnostics sink threw; ApplyChanges result preserved");
    }
  }

  void complete(VoidResult result)
  {
    if (auto manager = mManager.lock())
      release_taken_lists(*manager);
    if (mHoldsTrustListGate)
    {
      mHoldsTrustListGate = false;
      if (auto manager = mManager.lock())
        manager->end_trust_list_apply();
    }
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  static StatusCode apply_transaction_invalidated_status()
  {
    try
    {
      return StatusCode{Status::BadInvalidState,
        ErrorDetail::build("ApplyTransactionInvalidated",
          "ApplyChanges transaction was invalidated before preflight completed",
          "CertificatePushService")};
    }
    catch (...)
    {
      return ua::exception_to_status_code(std::current_exception());
    }
  }

  static VoidResult channel_close_hook_exception_result()
  {
    return VoidResult{Status::BadInternalError,
      ErrorDetail::build(
        "ChannelCloseHookFailed", "ApplyChanges channel-close hook threw", "CertificatePushService")
        .cause(ua::exception_to_status_code(std::current_exception()))};
  }

  static VoidResult certificate_reevaluation_hook_exception_result()
  {
    return VoidResult{Status::BadInternalError,
      ErrorDetail::build("CertificateReevaluationHookFailed",
        "ApplyChanges certificate re-evaluation hook threw",
        "CertificatePushService")
        .cause(ua::exception_to_status_code(std::current_exception()))};
  }

  std::weak_ptr<CertificatePushService> mManager;
  NodeId mSessionId;
  server::MethodResponseCorrelation mResponseCorrelation;
  uint64_t mTransactionGeneration{0};
  std::function<void(VoidResult)> mOnComplete;
  bool mHoldsTrustListGate{false};  // begin_trust_list_apply was called; complete() ends it
  bool mTookTransaction{false};  // the transaction is the frame's; complete() drops its staged lists
  VoidResult mWriteFailure;  // a staged TrustList the store refused; reported after the effects run
  std::vector<TransactionErrorType> mWriteErrors;

  /// The transaction, moved off the manager once the preflight passes.
  PendingCertList mPending;
  std::vector<NodeId> mModifiedTrustLists;
  DateTime mStartTime;  ///< Snapshotted transaction start time (Part 12 7.10.11).
};

void CertificatePushService::apply_changes_async(NodeId sessionId,
  server::MethodResponseCorrelation correlation, std::function<void(VoidResult)> completionHandler)
{
  auto sharedCompletion = make_shared_user_completion<VoidResult>(mLogger, std::move(completionHandler));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(sharedCompletion),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId), correlation](
      CertificatePushService& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        // The PROLOGUE stays here, synchronous, as the chain had it. Flipping the transaction to
        // Applying is what makes a concurrent UpdateCertificate reject, and `launch()` posts the
        // body - so a prologue moved into the body would leave a window in which the transaction
        // still looked Open.
        if (!self.mActiveTransaction)
        {
          callback(StatusCode{Status::BadNothingToDo});
          return;
        }
        auto& activeTransaction = *self.mActiveTransaction;
        if (activeTransaction.owningSessionId != sessionId)
        {
          callback(StatusCode{Status::BadUserAccessDenied});
          return;
        }
        if (!activeTransaction.inFlightUpdateReservations.empty())
        {
          callback(ApplyChangesOperation::apply_update_prerequisite_pending_status());
          return;
        }
        if (activeTransaction.phase != CertificatePushService::Transaction::Phase::Open)
        {
          callback(StatusCode{Status::BadInvalidState});
          return;
        }

        const uint64_t transactionGeneration = activeTransaction.generation;
        activeTransaction.phase = CertificatePushService::Transaction::Phase::Applying;

        // Copy (not move) the callback into the operation: if start() throws after ownership
        // transfer, the catch below must still hold a valid callback to report the error through.
        ApplyChangesOperation::start(
          self, std::move(sessionId), correlation, transactionGeneration, callback);
      }
      catch (...)
      {
        callback(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

// ---------------------------------------------------------------------------
// CancelChanges
// ---------------------------------------------------------------------------

void CertificatePushService::cancel_changes_async(
  NodeId sessionId, std::function<void(VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [sessionId = std::move(sessionId)](
      CertificatePushService& self, std::function<void(VoidResult)> callback) mutable
    {
      try
      {
        if (!self.mActiveTransaction.has_value())
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadNothingToDo});
          return;
        }

        if (self.mActiveTransaction->owningSessionId != sessionId)
        {
          detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadUserAccessDenied});
          return;
        }

        // Snapshot the transaction for diagnostics before discarding it. Part 12
        // 7.10.11: on CancelChanges the TransactionDiagnostics Result value is
        // Bad_RequestCancelledByClient.
        auto startTime = self.mActiveTransaction->startTime;
        auto pending = std::move(self.mActiveTransaction->pendingCertificates);
        auto modifiedTrustLists = std::move(self.mActiveTransaction->modifiedTrustLists);
        const auto generation = self.mActiveTransaction->generation;
        self.clear_active_transaction();
        self.discard_staged_trust_lists(generation);

        if (self.mPublishTransactionDiagnostics)
        {
          auto record = build_diagnostics_record(startTime,
            DateTime::now(),
            StatusCode{Status::BadRequestCancelledByClient},
            pending,
            std::move(modifiedTrustLists),
            {});
          self.mPublishTransactionDiagnostics(std::move(record));
        }

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
// GetRejectedList
// ---------------------------------------------------------------------------

void CertificatePushService::get_rejected_list_async(
  std::function<void(Result<std::vector<ByteString>>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [](CertificatePushService& self, std::function<void(Result<std::vector<ByteString>>)> callback) mutable
    {
      auto me = self.weak_from_this();
      self.mCertificateStore->get_rejected_certificates_async(
        [me, callback = std::move(callback)](CertificateListResult result) mutable
        {
          auto lockedSelf = me.lock();
          if (!lockedSelf)
          {
            detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
            return;
          }
          ua::async::post_borrowing(lockedSelf.get(),
            lockedSelf->mStrand,
            lockedSelf->mLogger,
            std::move(callback),
            StatusCode{Status::BadInternalError},
            [result = std::move(result)](CertificatePushService& postSelf,
              std::function<void(Result<std::vector<ByteString>>)>
                postCallback) mutable
            {
              if (!result.has_value())
              {
                detail::invoke_user_callback(postSelf.mLogger, postCallback, result.status_code());
                return;
              }

              auto materialized = [&postSelf, &result]() -> Result<std::vector<ByteString>>
              {
                try
                {
                  std::vector<ByteString> derCerts;
                  for (const auto& cert : result.value())
                  {
                    derCerts.push_back(postSelf.mCertificateDerEncoder ? postSelf.mCertificateDerEncoder(cert)
                                                                       : cert->der_encoding());
                  }
                  return derCerts;
                }
                catch (...)
                {
                  return ua::exception_to_status_code(std::current_exception());
                }
              }();

              // The list keeps the code the store answered it with: a Good subcode or an Uncertain code.
              detail::invoke_user_callback(postSelf.mLogger,
                postCallback,
                ua::detail::carried(std::move(materialized), result.status_code()));
            })();
        });
    })();
}

// ---------------------------------------------------------------------------
// GetCertificates
// ---------------------------------------------------------------------------

void CertificatePushService::get_certificates_async(NodeId certificateGroupId,
  std::function<void(Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [groupId = std::move(certificateGroupId)](CertificatePushService& self,
      std::function<void(Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>)>
        callback) mutable
    {
      auto resolvedGroupId = self.resolve_group_id(groupId);
      if (self.mUserTokenTrustList && resolvedGroupId == defaultUserTokenGroupId)
      {
        // Part 12 7.10.5: certificateTypeIds is "an empty list if the CertificateGroup does not
        // have any CertificateTypes", which is exactly the DefaultUserTokenGroup (7.8.3.3). The
        // group is valid, so this is Good with nothing assigned - not Bad_InvalidArgument, which
        // 7.10.5 reserves for a NodeId that is not a CertificateGroup of this Server.
        detail::invoke_user_callback(
          self.mLogger, callback, std::pair<std::vector<NodeId>, std::vector<ByteString>>{});
        return;
      }
      if (resolvedGroupId != defaultApplicationGroupId)
      {
        detail::invoke_user_callback(self.mLogger, callback, StatusCode{Status::BadInvalidArgument});
        return;
      }

      auto me = self.weak_from_this();
      self.mCertificateStore->get_application_certificates_async(
        [me, callback = std::move(callback)](
          CertificateStore::ApplicationCertificateListResult result) mutable
        {
          auto lockedSelf = me.lock();
          if (!lockedSelf)
          {
            detail::invoke_user_callback(callback, StatusCode{Status::BadInternalError});
            return;
          }
          ua::async::post_borrowing(lockedSelf.get(),
            lockedSelf->mStrand,
            lockedSelf->mLogger,
            std::move(callback),
            StatusCode{Status::BadInternalError},
            [result = std::move(result)](CertificatePushService& postSelf,
              std::function<void(Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>)>
                postCallback) mutable
            {
              if (!result.has_value())
              {
                detail::invoke_user_callback(postSelf.mLogger, postCallback, result.status_code());
                return;
              }

              auto materialized =
                [&postSelf, &result]() -> Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>>
              {
                try
                {
                  std::vector<NodeId> typeIds;
                  std::vector<ByteString> certs;
                  for (const auto& appCert : result.value())
                  {
                    NodeId typeNodeId;
                    switch (appCert.certificateType)
                    {
                    case CertificateType::RsaMinApplication:
                      typeNodeId =
                        NodeId{0, utils::to_underlying(ObjectTypeId::RsaMinApplicationCertificateType)};
                      break;
                    case CertificateType::RsaSha256Application:
                      typeNodeId =
                        NodeId{0, utils::to_underlying(ObjectTypeId::RsaSha256ApplicationCertificateType)};
                      break;
                    case CertificateType::EccNistP256Application:
                      typeNodeId =
                        NodeId{0, utils::to_underlying(ObjectTypeId::EccNistP256ApplicationCertificateType)};
                      break;
                    case CertificateType::EccNistP384Application:
                      typeNodeId =
                        NodeId{0, utils::to_underlying(ObjectTypeId::EccNistP384ApplicationCertificateType)};
                      break;
                    case CertificateType::EccBrainpoolP256r1Application:
                      typeNodeId = NodeId{
                        0, utils::to_underlying(ObjectTypeId::EccBrainpoolP256r1ApplicationCertificateType)};
                      break;
                    case CertificateType::EccBrainpoolP384r1Application:
                      typeNodeId = NodeId{
                        0, utils::to_underlying(ObjectTypeId::EccBrainpoolP384r1ApplicationCertificateType)};
                      break;
                    case CertificateType::EccCurve25519Application:
                      typeNodeId = NodeId{
                        0, utils::to_underlying(ObjectTypeId::EccCurve25519ApplicationCertificateType)};
                      break;
                    case CertificateType::EccCurve448Application:
                      typeNodeId =
                        NodeId{0, utils::to_underlying(ObjectTypeId::EccCurve448ApplicationCertificateType)};
                      break;
                    default:
                      typeNodeId = NodeId{0, utils::to_underlying(ObjectTypeId::ApplicationCertificateType)};
                      break;
                    }

                    typeIds.push_back(std::move(typeNodeId));
                    if (appCert.certificate)
                    {
                      certs.push_back(postSelf.mCertificateDerEncoder
                                        ? postSelf.mCertificateDerEncoder(appCert.certificate)
                                        : appCert.certificate->der_encoding());
                    }
                    else
                    {
                      certs.push_back(ByteString{});
                    }
                  }
                  return std::make_pair(std::move(typeIds), std::move(certs));
                }
                catch (...)
                {
                  return ua::exception_to_status_code(std::current_exception());
                }
              }();

              // The list keeps the code the store answered it with: a Good subcode or an Uncertain code.
              detail::invoke_user_callback(postSelf.mLogger,
                postCallback,
                ua::detail::carried(std::move(materialized), result.status_code()));
            })();
        });
    })();
}

// ---------------------------------------------------------------------------
// ResetToServerDefaults (Part 12 7.10.10)
// ---------------------------------------------------------------------------

namespace
{
/// One ResetToServerDefaults: answered, and the shutdown requested, once - by the clears or by the deadline.
/// Owned by the clears' continuations; the deadline timer holds it weakly. Dropped unfinished (a store that
/// dropped a continuation), it still requests the shutdown and answers Bad_InternalError.
struct ResetRun
{
  std::function<void(VoidResult)> answer;  // fire-once
  std::function<void()> requestShutdown;  // the service's hook, for the dropped case
  bool finished{false};  // on the service strand
  std::optional<Timer> deadline;  // on the service strand

  ResetRun() = default;
  ResetRun(const ResetRun&) = delete;
  ResetRun& operator=(const ResetRun&) = delete;
  ResetRun(ResetRun&&) = delete;
  ResetRun& operator=(ResetRun&&) = delete;

  ~ResetRun()
  {
    if (finished)
      return;
    try
    {
      if (requestShutdown)
        requestShutdown();
      if (answer)
      {
        answer(VoidResult{Status::BadInternalError,
          ErrorDetail::build("ResetToServerDefaultsAbandoned",
            "a TrustList clear was dropped unanswered; the server shuts down anyway",
            "CertificatePushService")});
      }
    }
    catch (...)
    {
      // A destructor has no caller to report to, and an exception must not escape it.
      ua::detail::ignore_expected_exception();
    }
  }
};
}  // namespace

void CertificatePushService::reset_to_server_defaults_async(
  NodeId sessionId, std::function<void(VoidResult)> completionHandler)
{
  UA_UNUSED(sessionId);  // Authorization is enforced at the wiring layer.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    StatusCode{Status::BadInternalError},
    [](CertificatePushService& self, std::function<void(VoidResult)> callback) mutable
    {
      // Part 12 7.10.10: clear every TrustList (trusted + issuer certificates and CRLs) as part of the
      // factory reset, then trigger a server shutdown so the server restarts at its default configuration
      // (re-running Application Setup). Application-certificate deletion is not exposed by the
      // CertificateStore and is left to the host's restart path. A clear that fails or does not end must not
      // prevent the mandatory SHUTDOWN transition: the shutdown is requested when the clears end or the
      // deadline passes, whichever is first, and the answer says whether every TrustList was cleared. Each
      // TrustListManager is the only writer of its lists, so it clears them: after any list write in
      // progress, never interleaved with one.
      // The reset ends the push transaction: nothing staged before it may be applied after it (an
      // ApplyChanges in the shutdown window would otherwise commit pending certificates). Its TrustList lists
      // are dropped by the clears below.
      // Also in the Applying phase before the frame takes it: the frame then answers
      // ApplyTransactionInvalidated instead of restoring it after its preflight.
      if (self.mActiveTransaction)
        self.clear_active_transaction();
      auto run = std::make_shared<ResetRun>();
      run->answer = make_fire_once_callback(std::move(callback));
      run->requestShutdown = self.mRequestShutdown;
      // Stateless, so the deadline timer can hold it without holding the run.
      const auto finishReset = [](const std::weak_ptr<CertificatePushService>& me,
                                 std::shared_ptr<ResetRun>
                                   resetRun,
                                 VoidResult cleared)
      {
        auto lockedSelf = me.lock();
        if (!lockedSelf)
        {
          resetRun->answer(
            StatusCode{Status::BadInternalError});  // the service is gone: no shutdown to request
          return;
        }
        ua::async::post_borrowing(lockedSelf.get(),
          lockedSelf->mStrand,
          lockedSelf->mLogger,
          resetRun->answer,
          StatusCode{Status::BadInternalError},
          [resetRun, cleared = std::move(cleared)](
            CertificatePushService& postSelf, std::function<void(VoidResult)> answer) mutable
          {
            if (resetRun->finished)
              return;  // the deadline or the clears finished it first
            resetRun->finished = true;
            resetRun->deadline.reset();
            // Trigger the SHUTDOWN transition (sets ServerState=SHUTDOWN + ShutdownReason +
            // SecondsTillShutdown via the supplied hook).
            if (postSelf.mRequestShutdown)
            {
              postSelf.mRequestShutdown();
            }
            if (cleared.is_bad())
            {
              const std::string reason = ua::describe(cleared.status_code());
              postSelf.mLogger.warning({{"error", std::string_view{reason}}},
                "ResetToServerDefaults: the TrustLists were not all cleared; the server shuts down anyway");
            }
            detail::invoke_user_callback(postSelf.mLogger, answer, std::move(cleared));
          })();
      };
      auto finish = [me = self.weak_from_this(), run, finishReset](VoidResult cleared)
      {
        finishReset(me, run, std::move(cleared));
      };
      run->deadline.emplace(Timer::schedule_after(self.mStrand,
        self.mResetDeadline,
        [me = self.weak_from_this(),
          weakRun = std::weak_ptr<ResetRun>(run),
          finishReset,
          deadline = self.mResetDeadline](boost::system::error_code ec)
        {
          auto timedOut = weakRun.lock();
          if (ec || !timedOut)
            return;
          finishReset(me,
            std::move(timedOut),
            VoidResult{Status::BadTimeout,
              ErrorDetail::build("ResetToServerDefaultsTimedOut",
                "the TrustLists were not cleared before the reset deadline; the server shuts down anyway",
                "CertificatePushService")
                .context(ua::ContextKeys::limit, std::to_string(deadline.count()) + " ms")});
        }));
      // "All TrustLists are cleared": the DefaultApplicationGroup's, then the DefaultUserTokenGroup's, which
      // is cleared even when the first failed. The answer is the first failure.
      auto clearUserToken = [userToken = self.mUserTokenTrustList, finish](
                              VoidResult applicationCleared) mutable
      {
        auto answer = [finish, applicationCleared](VoidResult userTokenCleared) mutable
        {
          finish(applicationCleared.is_bad() ? std::move(applicationCleared) : std::move(userTokenCleared));
        };
        if (userToken)
          userToken->clear_lists_async(std::move(answer));
        else
          answer(VoidResult{});
      };
      if (self.mTrustList)
      {
        self.mTrustList->clear_lists_async(std::move(clearUserToken));
        return;
      }
      // No TrustListManager (a push service without a TrustList): the store is cleared directly.
      auto store = self.mCertificateStore;
      store->replace_trusted_certificates_async({},
        {},
        [store, clearUserToken = std::move(clearUserToken)](VoidResult trustedCleared) mutable
        {
          store->replace_issuer_certificates_async({},
            {},
            [clearUserToken = std::move(clearUserToken), trustedCleared](VoidResult issuerCleared) mutable {
              clearUserToken(trustedCleared.is_bad() ? std::move(trustedCleared) : std::move(issuerCleared));
            });
        });
    })();
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

void CertificatePushService::on_session_closed_async(NodeId sessionId)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [sessionId = std::move(sessionId)](CertificatePushService& self) mutable
    {
      {
        // A closed session keeps no claim; its late modifications are refused by the Session lookup.
        const std::lock_guard<std::mutex> lock(self.mTransactionOwnerMutex);
        if (self.mModificationOwner.has_value() && *self.mModificationOwner == sessionId)
        {
          self.mOwnerClaimCount = 0;
          self.mOwnerTransactionClaimCount = 0;
          self.release_owner_locked();
        }
      }
      // REQ-TXN-4: auto-cancel transaction when owning session closes
      if (self.mActiveTransaction.has_value() && self.mActiveTransaction->owningSessionId == sessionId)
      {
        self.mLogger.info("Push management: cancelling transaction for disconnected session");
        const auto generation = self.mActiveTransaction->generation;
        self.clear_active_transaction();
        self.discard_staged_trust_lists(generation);
      }
    })();
}

// ---------------------------------------------------------------------------
// TrustListManager notification
// ---------------------------------------------------------------------------

void CertificatePushService::on_trust_list_modified(
  NodeId sessionId, NodeId trustListId, std::shared_ptr<TrustListModificationClaim> claim)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [sessionId = std::move(sessionId), trustListId = std::move(trustListId), claim = std::move(claim)](
      CertificatePushService& self) mutable
    {
      // Ensure the transaction the change was made in exists for this session (Part 12 7.8.2.3:
      // CloseAndUpdate "creates a new transaction or continues an existing transaction"); the claim its
      // modification held is then released, the transaction now carrying the ownership. A turn that never
      // runs drops the claim with it.
      std::optional<uint64_t> generation;  // 0: a claim no push gate issued, so no transaction is named
      if (claim && claim->transaction_generation() != 0)
        generation = claim->transaction_generation();
      auto status = self.ensure_transaction(sessionId, generation);
      if (status.is_bad())
      {
        // No transaction owns the change the manager staged, so nothing would ever apply or cancel it: drop
        // it now (review BR-13), and only it - a later transaction of the Session may have staged since. The
        // drop is posted before the claim is released, so it lands before any ApplyChanges that waited for
        // the claim.
        if (trustListId == defaultApplicationGroupTrustListId && self.mTrustList)
          self.mTrustList->discard_staged_async(sessionId, generation);
        else if (trustListId == defaultUserTokenGroupTrustListId && self.mUserTokenTrustList)
          self.mUserTokenTrustList->discard_staged_async(sessionId, generation);
        claim.reset();
        const std::string reason = ua::describe(status);
        self.mLogger.warning({{"error", std::string_view{reason}}},
          "Push management: TrustList change dropped, no transaction takes it (session {})",
          sessionId);
        return;
      }
      claim.reset();
      self.mActiveTransaction->keptWhenEmpty = true;

      auto& modified = self.mActiveTransaction->modifiedTrustLists;
      if (std::find(modified.begin(), modified.end(), trustListId) == modified.end())
      {
        modified.push_back(std::move(trustListId));
      }
    })();
}

void CertificatePushService::on_trust_list_opened_for_write(
  NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [sessionId = std::move(sessionId), claim = std::move(claim)](CertificatePushService& self) mutable
    {
      // Part 12 Figure 22: the Open creates the transaction, or continues the Session's own. Nothing is
      // opened when that transaction ended meanwhile or the Session is gone; a later CloseAndUpdate opens
      // one.
      std::optional<uint64_t> generation;  // 0: a claim no push gate issued, so no transaction is named
      if (claim && claim->transaction_generation() != 0)
        generation = claim->transaction_generation();
      auto status = self.ensure_transaction(sessionId, generation);
      claim.reset();
      if (status.is_bad())
      {
        const std::string reason = ua::describe(status);
        self.mLogger.info({{"error", std::string_view{reason}}},
          "Push management: TrustList opened for write, no transaction opened (session {})",
          sessionId);
        return;
      }
      self.mActiveTransaction->keptWhenEmpty = true;
    })();
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

VoidResult CertificatePushService::shutdown()
{
  // Synchronous teardown barrier: post the state-clear onto the strand and block the caller until it
  // runs. `this` is guaranteed alive (the caller blocks), so a raw `this` capture is correct. A throw
  // from the body is answered as the result, so the caller is never left waiting; guarded stays as
  // the post-discipline backstop.
  return ua::async::detail::blocking_call<VoidResult>(boost::asio::any_io_executor{mStrand},
    [this](std::function<void(VoidResult)> complete)
    {
      boost::asio::post(mStrand,
        ua::async::guarded(mLogger,
          [this, complete = std::move(complete)]()
          {
            try
            {
              clear_active_transaction();
              mPendingKeyPairs.clear();
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
// PushCertificateObserver factory
// ---------------------------------------------------------------------------

namespace
{

class PushCertificateObserver final : public server::ServerObserver
{
public:
  PushCertificateObserver(std::weak_ptr<CertificatePushService> pushService,
    std::weak_ptr<TrustListManager> trustList, std::weak_ptr<TrustListManager> userTokenTrustList)
    : mPushService(std::move(pushService)), mTrustList(std::move(trustList)),
      mUserTokenTrustList(std::move(userTokenTrustList))
  {}

  void on_session_closed(const server::SessionEventInfo& info, StatusCode /*reason*/) override
  {
    if (auto mgr = mPushService.lock())
      mgr->on_session_closed_async(info.sessionId);
    if (auto tlm = mTrustList.lock())
      tlm->on_session_closed_async(info.sessionId);
    // A session that left a file handle open on the user-token trust list must release it too,
    // otherwise that group stays write-locked until the activity timeout expires.
    if (auto tlm = mUserTokenTrustList.lock())
      tlm->on_session_closed_async(info.sessionId);
  }

private:
  std::weak_ptr<CertificatePushService> mPushService;
  std::weak_ptr<TrustListManager> mTrustList;
  std::weak_ptr<TrustListManager> mUserTokenTrustList;
};

}  // namespace

std::shared_ptr<server::ServerObserver> make_push_certificate_observer(
  std::weak_ptr<CertificatePushService> pushService, std::weak_ptr<TrustListManager> trustList,
  std::weak_ptr<TrustListManager> userTokenTrustList)
{
  return std::make_shared<PushCertificateObserver>(
    std::move(pushService), std::move(trustList), std::move(userTokenTrustList));
}

}  // namespace ua
