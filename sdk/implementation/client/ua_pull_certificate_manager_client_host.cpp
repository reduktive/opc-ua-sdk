// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_pull_certificate_manager_client_host.h"

#include "ua_pull_cert_trust_list_codec.h"  // interpret_trust_list_last_update_time / decode_trust_list_body (CL-PULLCRT-005)
#include "ua_pull_certificate_request_codec.h"

#include "ua_certificate_store.h"
#include "ua_client_answer_status.h"
#include "ua_core_client_impl.h"
#include "ua_codec_namespace_context.h"  // ua::CodecNamespaceContext (UaBinaryDecoder ctor)
#include "ua_connection.h"  // ua::client::Connection  -  the owned GDS transport
#include "ua_connection_config.h"  // ua::client::ConnectionConfig (the GDS connect config)
#include "ua_crypto.h"
#include "ua_data_value.h"  // ua::DataValue  -  the LastUpdateTime Read result payload
#include "ua_date_time.h"  // ua::DateTime  -  the TrustList LastUpdateTime (UtcTime)
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"  // ua::ObjectId  -  the well-known default-group TrustList Object NodeId
#include "ua_referencetype_id.h"
#include "ua_security_policy.h"
#include "ua_user_identity.h"  // ua::client::AnonymousIdentity (CL-PULLCRT-002)
#include "ua_observer_sink.h"  // detail::ClientObserverSink
#include "ua_pull_certificate_manager.h"  // PullCertManagementInfo / PullCertLifecycleEvent
#include "ua_status.h"
#include "ua_to_result.h"
#include "ua_trust_list_data_type.h"
#include "ua_variable_id.h"  // ua::VariableId  -  the well-known default-group LastUpdateTime NodeId
#include "ua_x509_certificate.h"

#include <boost/asio/post.hpp>

#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client::detail
{

namespace
{

// Source tags for the manufactured `client.tier1.pull_cert.*` boundary failures (the design specification).
constexpr std::string_view openGdsClientGoneSource = "client.tier1.pull_cert.open_gds.client_gone";
constexpr std::string_view openGdsHostGoneSource = "client.tier1.pull_cert.open_gds.host_gone";
constexpr std::string_view openGdsClosedDuringOpenSource =
  "client.tier1.pull_cert.open_gds.closed_during_open";
constexpr std::string_view openGdsOwnCertSource = "client.tier1.pull_cert.open_gds.own_cert";
constexpr std::string_view openGdsConnectSource = "client.tier1.pull_cert.open_gds.connect";
// The `.gds_not_open` tags are the CLOSED-connection (null-guard) production path  -  distinct so a
// test/operator can tell "no GDS" from a live-GDS failure. The TrustList-pull RPCs (LastUpdateTime read +
// download) are now WIRED onto the live GDS Connection (CL-PULLCRT-005): a non-default certificate group is
// refused with a `.group_unresolved` tag (arbitrary-group TranslateBrowsePath resolution is a follow-up),
// and a malformed downloaded TrustList body is a `.decode_failed` tag. The cert-request RPCs
// (start/finish) remain the W6b-deferred `.present_branch_deferred` stubs (blocked on a GDS
// CertificateManager oracle).
constexpr std::string_view trustListLastUpdateGdsClosedSource =
  "client.tier1.pull_cert.trust_list_last_update.gds_not_open";
constexpr std::string_view trustListLastUpdateGroupUnresolvedSource =
  "client.tier1.pull_cert.trust_list_last_update.group_unresolved";
constexpr std::string_view trustListGdsClosedSource = "client.tier1.pull_cert.trust_list.gds_not_open";
constexpr std::string_view trustListGroupUnresolvedSource =
  "client.tier1.pull_cert.trust_list.group_unresolved";
constexpr std::string_view trustListDownloadSource = "client.tier1.pull_cert.trust_list.download";
constexpr std::string_view getCertificateStatusSource = "client.tier1.pull_cert.get_certificate_status";
constexpr std::string_view startRequestGdsClosedSource = "client.tier1.pull_cert.start_request.gds_not_open";
constexpr std::string_view startRequestNamespaceSource =
  "client.tier1.pull_cert.start_request.gds_namespace_missing";
constexpr std::string_view finishRequestGdsClosedSource =
  "client.tier1.pull_cert.finish_request.gds_not_open";
constexpr std::string_view finishRequestNamespaceSource =
  "client.tier1.pull_cert.finish_request.gds_namespace_missing";
constexpr std::string_view finishRequestCertificateSource =
  "client.tier1.pull_cert.finish_request.certificate_decode";
constexpr std::string_view applyClientGoneSource = "client.tier1.pull_cert.apply.client_gone";
constexpr std::string_view applyStoreAbsentSource = "client.tier1.pull_cert.apply.store_absent";
constexpr std::string_view applyCryptoAbsentSource = "client.tier1.pull_cert.apply.crypto_absent";
constexpr std::string_view applyIssuerUnboundSource = "client.tier1.pull_cert.apply.issuer_unbound";
constexpr std::string_view applyTypeUnsupportedSource = "client.tier1.pull_cert.apply.type_unsupported";
constexpr std::string_view applyIssuerUnanchoredSource = "client.tier1.pull_cert.apply.issuer_unanchored";
constexpr std::string_view applyKeyMismatchSource = "client.tier1.pull_cert.apply.key_mismatch";
constexpr std::string_view applyValidationFailedSource = "client.tier1.pull_cert.apply.validation_failed";
constexpr std::string_view applyExistingKeyAbsentSource = "client.tier1.pull_cert.apply.existing_key_absent";
constexpr std::string_view applySigningKeyMismatchSource =
  "client.tier1.pull_cert.apply.signing_key_mismatch";
constexpr std::string_view applyKeyParseFailedSource = "client.tier1.pull_cert.apply.key_parse_failed";
constexpr std::string_view applyTrustDecodeFailedSource = "client.tier1.pull_cert.apply.trust_decode_failed";
constexpr std::string_view revalidateClientGoneSource = "client.tier1.pull_cert.revalidate.client_gone";
constexpr std::string_view gdsNamespaceUri{"http://opcfoundation.org/UA/GDS/"};

/// Completes @p callback on @p executor with @p status carrying a source-tagged ErrorDetail (posts, never
/// fires inline, so the callback runs on the executor  -  the design specification). Mirrors the W4
/// redundancy host.
template<typename Value>
void complete_bad_on_executor(const boost::asio::any_io_executor& executor, ua::Status status,
  std::string code, std::string summary, std::string_view source,
  std::function<void(ua::Result<Value>)> callback)
{
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [status,
        code = std::move(code),
        summary = std::move(summary),
        source = std::string{source},
        callback = std::move(callback)]() mutable
      {
        callback(ua::Result<Value>{ua::StatusCode{status,
          ua::ErrorDetail::build(std::move(code), "Pull certificate operation failed", std::move(source))
            .context(ua::ContextKeys::errorMessage, summary)}});
      }));
}

/// A single async CertificateStore staging step (each posts internally and delivers on the store's worker).
using StoreStep = std::function<void(std::function<void(ua::VoidResult)>)>;

/// Runs @p steps sequentially, short-circuiting to @p callback on the first bad step (its ErrorDetail is
/// propagated unchanged), else completing Good after the last step. Owns the step vector until it drains.
///
/// ATOMICITY LIMITATION (flagged for the maintainer): the @ref ua::CertificateStore exposes no batch /
/// transactional apply API  -  each step commits individually and durably, so a mid-sequence failure leaves a
/// PARTIALLY-applied store, not a clean rollback. This is NOT true cross-set atomicity. Two things bound the
/// scope of change until a `CertificateStore` transactional apply lands (a follow-up):
///  1. The caller orders the steps least-reversible-LAST  -  the own-cert swap (the most visible, hardest to
///     undo change) runs only after the idempotent trust-list / issuer replaces succeed, so a trust-list-step
///     failure leaves the own cert UNCHANGED (see @ref
///     PullCertificateManagerClientHost::apply_cert_update_async).
///  2. The steps are replace-based (idempotent), and the manager does NOT advance `mLastTrustListUpdate` on a
///     Bad apply  -  so the next cycle retries and re-converges.
void run_store_steps(std::shared_ptr<std::vector<StoreStep>> steps, std::size_t index,
  std::function<void(ua::VoidResult)> callback)
{
  if (index >= steps->size())
  {
    callback(ua::VoidResult{});
    return;
  }
  const auto& step = (*steps)[index];
  step(
    [steps, index, callback = std::move(callback)](ua::VoidResult result) mutable
    {
      if (result.is_bad())
      {
        callback(std::move(result));
        return;
      }
      run_store_steps(std::move(steps), index + 1, std::move(callback));
    });
}

/// Closes @p connection best-effort on the server (destroying the handle alone does NOT close it  -
/// ua_connection.h), keeping it alive across the async close via the callback capture, then discards it. Used
/// wherever a GDS Connection cannot be stashed (host gone / a stop raced the open / a displaced Failed-retry
/// double-open) or on the host-destructor teardown backstop  -  so an open-but-unstashable GDS session is not
/// leaked. Best-effort: if the executor is already stopped the posted close never runs (the session then
/// times out server-side, the generic Connection bound).
void gds_close_and_forget(std::shared_ptr<ua::client::Connection> connection)
{
  if (!connection)
  {
    return;
  }
  // Compute the raw pointer into a LOCAL before moving the shared_ptr into the callback capture (the design
  // specification section 5): the moved-from shared_ptr keeps the pointee alive (the callback now owns it),
  // so `raw` stays valid.
  auto* raw = connection.get();
  raw->close_async([connection = std::move(connection)](ua::VoidResult) {});
}

ua::RelativePath make_certificate_directory_path(
  ua::ReferenceTypeId referenceType, std::uint16_t namespaceIndex, std::string_view targetName)
{
  ua::RelativePathElement element;
  element.reference_type_id() = ua::NodeId{referenceType};
  element.include_subtypes() = true;
  element.target_name() = ua::QualifiedName{namespaceIndex, targetName};
  ua::RelativePath path;
  path.elements().push_back(std::move(element));
  return path;
}

/// The GDS node a browse path resolved to, used only from a Good answer (a Good subcode is consumed).
/// Otherwise names which node failed to resolve, keeping the failure as the cause: a Bad answer as it is,
/// an Uncertain one refused with Bad_InternalError (`ReferencesAnswerUncertain`).
ua::Result<ua::NodeId> require_local_certificate_directory_node(
  ua::NodeIdResult resolved, std::string_view code)
{
  constexpr std::string_view source = "client.tier1.pull_cert.certificate_request.resolve";
  if (resolved.is_good())
  {
    return ua::Result<ua::NodeId>{std::move(resolved).value()};
  }
  const ua::StatusCode failure = answer_refused(resolved.status_code(), "ReferencesAnswerUncertain", source);
  return {failure.as_status(),
    ua::ErrorDetail::build(std::string{code},
      "the standard GDS browse path did not resolve to one local node",
      std::string{source})
      .cause(failure)};
}

void call_certificate_directory_method_async(std::shared_ptr<ua::client::Connection> connection,
  std::uint16_t namespaceIndex, std::string methodName, std::vector<ua::Variant> arguments,
  std::function<void(ua::Result<ua::CallResult>)> callback)
{
  connection->typed().resolve_path_async(ua::NodeId{ua::ObjectId::ObjectsFolder},
    make_certificate_directory_path(ua::ReferenceTypeId::Organizes, namespaceIndex, "Directory"),
    [connection,
      namespaceIndex,
      methodName = std::move(methodName),
      arguments = std::move(arguments),
      callback = std::move(callback)](ua::NodeIdResult resolved) mutable
    {
      auto directory =
        require_local_certificate_directory_node(std::move(resolved), "PullCertDirectoryResolutionFailed");
      if (!directory.is_good())
      {
        callback({directory.status_code(), directory.shared_detail()});
        return;
      }
      auto directoryId = std::move(directory).value();
      connection->typed().resolve_path_async(directoryId,
        make_certificate_directory_path(ua::ReferenceTypeId::HasComponent, namespaceIndex, methodName),
        [connection,
          directoryId = std::move(directoryId),
          arguments = std::move(arguments),
          callback = std::move(callback)](ua::NodeIdResult resolvedMethod) mutable
        {
          auto method = require_local_certificate_directory_node(
            std::move(resolvedMethod), "PullCertMethodResolutionFailed");
          if (!method.is_good())
          {
            callback({method.status_code(), method.shared_detail()});
            return;
          }
          connection->typed().call_method_async(
            std::move(directoryId), std::move(method).value(), std::move(arguments), std::move(callback));
        });
    });
}

void get_trust_list_node_async(std::shared_ptr<ua::client::Connection> connection,
  std::uint16_t namespaceIndex, ua::NodeId applicationId, ua::NodeId certificateGroupId,
  std::function<void(ua::Result<ua::NodeId>)> callback)
{
  call_certificate_directory_method_async(connection,
    namespaceIndex,
    "GetTrustList",
    build_get_trust_list_arguments(std::move(applicationId), std::move(certificateGroupId)),
    [connection, callback = std::move(callback)](ua::Result<ua::CallResult> call) mutable
    { callback(decode_get_trust_list_result(std::move(call))); });
}

/// Maps a certificate's key algorithm to the CertificateStore's application @ref ua::CertificateType: the
/// store keeps one certificate per curve, so an ECC certificate is filed under its curve's type (the generic
/// EccApplication has no slot in a store, and a commit under it fails). Invalid for a key the store cannot
/// hold.
[[nodiscard]] ua::CertificateType certificate_type_of(const ua::X509Certificate& certificate)
{
  switch (certificate.key_algorithm())
  {
  case ua::CertificateKeyAlgorithm::Rsa:
    return ua::CertificateType::RsaSha256Application;
  case ua::CertificateKeyAlgorithm::EccNistP256:
    return ua::CertificateType::EccNistP256Application;
  case ua::CertificateKeyAlgorithm::EccNistP384:
    return ua::CertificateType::EccNistP384Application;
  case ua::CertificateKeyAlgorithm::EccBrainpoolP256r1:
    return ua::CertificateType::EccBrainpoolP256r1Application;
  case ua::CertificateKeyAlgorithm::EccBrainpoolP384r1:
    return ua::CertificateType::EccBrainpoolP384r1Application;
  case ua::CertificateKeyAlgorithm::EccCurve25519:
    return ua::CertificateType::EccCurve25519Application;
  case ua::CertificateKeyAlgorithm::EccCurve448:
    return ua::CertificateType::EccCurve448Application;
  default:
    return ua::CertificateType::Invalid;
  }
}

}  // namespace

PullCertificateManagerClientHost::PullCertificateManagerClientHost(std::weak_ptr<CoreClientImpl> client,
  boost::asio::any_io_executor executor, std::shared_ptr<ClientObserverSink> sink,
  std::shared_ptr<const ua::X509Certificate> ownCert, ua::Logger logger)
  : mClient(std::move(client)), mExecutor(std::move(executor)), mSink(std::move(sink)),
    mLogger(std::move(logger)), mOwnCert(std::move(ownCert))
{}

PullCertificateManagerClientHost::~PullCertificateManagerClientHost()
{
  // Best-effort teardown backstop (section 3.1). The RELIABLE GDS close is `stop_async`  to  `do_stop`  to
  // `close_gds_connection_async`. But on the drop-without-explicit-stop path (the user drops the Client
  // without first stopping + draining the manager), the facade dtor's posted `do_stop` no-ops against the
  // already-destroyed impl, so `close_gds_connection_async` never runs and a stashed GDS Connection would be
  // dropped without a server close. Close it here fire-and-forget: if the executor is still live the server
  // session is closed; if it is already stopped the close cannot complete and the session times out
  // server-side  -  the same bound the generic Connection contract carries (destroying a handle does NOT
  // close it, ua_connection.h). This only narrows the leak window on the improper-lifecycle drop.
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = std::move(mGdsConnection);
  }
  gds_close_and_forget(std::move(connection));
}

// -------- Runtime --------

boost::asio::any_io_executor PullCertificateManagerClientHost::executor()
{
  return mExecutor;
}

std::string PullCertificateManagerClientHost::current_own_cert_thumbprint_sha1() const
{
  const auto ownCert = mOwnCert.load(std::memory_order_acquire);
  if (!ownCert)
  {
    return {};
  }
  // Lowercase, no-separator hex of the SHA-1 DER thumbprint (CL-PULLCRT-004). Not `bytes_to_hex_string`,
  // which space-separates: the persisted vs current thumbprint match wants a canonical contiguous digest
  // string.
  const ua::ByteString thumbprint = ownCert->thumbprint();
  return fmt::format("{:02x}", fmt::join(thumbprint, ""));
}

// -------- GDS bootstrap (CL-PULLCRT-001 / CL-PULLCRT-002) --------

void PullCertificateManagerClientHost::open_gds_connection_async(
  GdsConnectionRequest request, std::function<void(ua::VoidResult)> callback)
{
  const auto client = mClient.lock();
  if (!client)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadInvalidState,
      "PullCertClientGone",
      "the Client was destroyed before the GDS connection could be opened",
      openGdsClientGoneSource,
      std::move(callback));
    return;
  }
  // Build a single-shot secured ConnectionConfig for the GDS channel: SignAndEncrypt + Anonymous
  // (CL-PULLCRT-002), OPN validated against the bootstrap trust store (CL-PULLCRT-001). The manager owns the
  // per-cycle re-open, so the GDS Connection is NOT auto-reconnect (reconnect == nullopt). The SDK connect is
  // ExactUrl-only, so the caller-supplied GDS server cert + policy are threaded verbatim (see the config).
  ua::client::ConnectionConfig config;
  config.endpointUrl = request.endpointUrl;
  config.securityMode = request.securityMode;
  config.securityPolicyId = request.securityPolicyId;
  config.serverCertificate = request.serverCertificate;
  config.trustStoreOverride = request.bootstrapTrustStore;
  config.identity = ua::client::AnonymousIdentity{};  // CL-PULLCRT-002 (also the default; explicit here)
  config.reconnect = std::nullopt;  // single-shot; the pull cycle owns any re-open

  ua::CertificateType certificateType;
  try
  {
    certificateType = ua::SecurityPolicy::create(request.securityPolicyId)->certificate_type();
  }
  catch (...)
  {
    const auto status = ua::exception_to_status_code(std::current_exception());
    complete_bad_on_executor<void>(mExecutor,
      status.as_status(),
      "PullCertSecurityPolicyInvalid",
      "the GDS security policy could not select an application certificate type",
      openGdsOwnCertSource,
      std::move(callback));
    return;
  }

  auto weakSelf = weak_from_this();
  client->connect_async(std::move(config),
    [weakSelf, certificateType, callback = std::move(callback)](
      ua::client::Client::ConnectResult result) mutable
    {
      // connect_async delivers on the Client executor, so this interface callback is already
      // executor-delivered (the design specification). A bad connect propagates its status + ErrorDetail
      // verbatim (never re-synthesised).
      if (!result.has_value())
      {
        callback(ua::VoidResult{result.status_code()});
        return;
      }
      // The pull cycle runs over this Connection, so only a Good connect is used: an Uncertain one is
      // refused (ServiceAnswerUncertain) and the Connection closed.
      const ua::StatusCode connected = result.status_code();
      auto connection = std::make_shared<ua::client::Connection>(std::move(result).value());
      if (!connected.is_good())
      {
        gds_close_and_forget(std::move(connection));
        callback(ua::VoidResult{
          uncertain_answer_refused(connected, "ServiceAnswerUncertain", openGdsConnectSource)});
        return;
      }
      const auto self = weakSelf.lock();
      if (!self)
      {
        // The host was torn down mid-connect. The freshly-opened Connection would leak if merely dropped
        // (destroying the handle does NOT close the server session  -  ua_connection.h), so close it
        // best-effort, then fire the owed completion (the manager's FSM must never strand).
        gds_close_and_forget(std::move(connection));
        callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState},
          ua::make_error_detail("PullCertHostGone",
            "the pull-cert host was torn down before the GDS connection open completed",
            std::string{openGdsHostGoneSource})});
        return;
      }
      const auto currentClient = self->mClient.lock();
      const auto store = currentClient ? currentClient->certificate_store() : nullptr;
      if (!store)
      {
        gds_close_and_forget(std::move(connection));
        callback(ua::VoidResult{ua::StatusCode{ua::Status::BadConfigurationError},
          ua::make_error_detail("PullCertOwnCertStoreAbsent",
            "the Client certificate store is unavailable after the secured GDS channel opened",
            std::string{openGdsOwnCertSource})});
        return;
      }
      store->get_application_certificate_async(certificateType,
        [weakSelf, connection = std::move(connection), callback = std::move(callback)](
          ua::CertificateStore::ApplicationCertificateResult certificate) mutable
        {
          if (!certificate.is_good())
          {
            gds_close_and_forget(std::move(connection));
            // A Bad answer is passed on as it is; an Uncertain one is refused, since the certificate is used
            // only from a Good answer.
            const ua::StatusCode failure = certificate.is_uncertain()
                                             ? ua::client::detail::certificate_store_answer_refused(
                                                 certificate.status_code(), openGdsOwnCertSource)
                                             : certificate.status_code();
            callback(ua::VoidResult{failure.as_status(),
              ua::ErrorDetail::build("PullCertOwnCertLookupFailed",
                "the certificate used by the secured GDS channel could not be snapshotted",
                std::string{openGdsOwnCertSource})
                .cause(failure)});
            return;
          }
          const auto currentSelf = weakSelf.lock();
          if (!currentSelf)
          {
            gds_close_and_forget(std::move(connection));
            callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState},
              ua::make_error_detail("PullCertHostGone",
                "the pull-cert host was torn down before its GDS certificate snapshot completed",
                std::string{openGdsHostGoneSource})});
            return;
          }
          currentSelf->complete_gds_open(
            std::move(connection), certificate.value().certificate, std::move(callback));
        });
    });
}

void PullCertificateManagerClientHost::complete_gds_open(std::shared_ptr<ua::client::Connection> connection,
  std::shared_ptr<const ua::X509Certificate> ownCert, std::function<void(ua::VoidResult)> callback)
{
  // Stash the certificate and Connection as one logical open completion. The snapshot is the certificate
  // selected for this just-opened secured channel and is stamped onto every Start request (CL-PULLCRT-004).
  std::shared_ptr<ua::client::Connection> toClose;
  bool stashed = false;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    if (mGdsClosing)
    {
      toClose = std::move(connection);
    }
    else
    {
      toClose = std::move(mGdsConnection);
      mGdsConnection = std::move(connection);
      mOwnCert.store(std::move(ownCert), std::memory_order_release);
      stashed = true;
    }
  }
  if (toClose)
  {
    gds_close_and_forget(std::move(toClose));
  }
  if (stashed)
  {
    callback(ua::VoidResult{});
    return;
  }
  callback(ua::VoidResult{ua::StatusCode{ua::Status::BadInvalidState},
    ua::make_error_detail("PullCertGdsClosedDuringOpen",
      "the GDS connection was closed (stop) while its open was in flight",
      std::string{openGdsClosedDuringOpenSource})});
}

void PullCertificateManagerClientHost::close_gds_connection_async(
  std::function<void(ua::VoidResult)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    mGdsClosing = true;  // latch: a late open-success must now close-instead-of-stash (stop-races-open guard)
    connection = std::move(mGdsConnection);  // detach; the handle is closed + dropped below
  }
  if (!connection)
  {
    // Nothing open (never opened, or already closed): the Good is honest (idempotent).
    boost::asio::post(mExecutor,
      ua::async::guarded(
        ua::Logger{}, [callback = std::move(callback)]() mutable { callback(ua::VoidResult{}); }));
    return;
  }
  // Close the GDS session on the server BEFORE dropping the handle (destroying the handle alone does NOT
  // close the Connection  -  see ua_connection.h). Keep the handle alive across the close via the capture.
  // The close outcome is best-effort: acknowledge Good regardless (the manager's stop path only needs the
  // primitive to complete), and the close status is already logged at the tier-0 boundary.
  auto* raw = connection.get();
  raw->close_async([connection = std::move(connection), callback = std::move(callback)](
                     ua::VoidResult /*closeResult*/) mutable { callback(ua::VoidResult{}); });
}

// -------- TrustList pull (GDS RPC; wired onto the live GDS Connection, CL-PULLCRT-005) --------

void PullCertificateManagerClientHost::read_trust_list_last_update_time_async(ua::NodeId applicationId,
  ua::NodeId certificateGroupId, std::function<void(ua::Result<std::optional<ua::DateTime>>)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = mGdsConnection;
  }
  if (!connection)
  {
    // No GDS Connection open (never opened, or closed/stopped). Fail EXPLICITLY (never a fake "unchanged").
    complete_bad_on_executor<std::optional<ua::DateTime>>(mExecutor,
      ua::Status::BadNotConnected,
      "PullCertGdsNotOpen",
      "no GDS Connection is open; cannot read the TrustList LastUpdateTime",
      trustListLastUpdateGdsClosedSource,
      std::move(callback));
    return;
  }
  const auto namespaceTable = connection->namespace_table();
  const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
  if (!namespaceIndex)
  {
    complete_bad_on_executor<std::optional<ua::DateTime>>(mExecutor,
      ua::Status::BadNodeIdUnknown,
      "PullCertGdsNamespaceMissing",
      "the connected server does not expose the standard GDS namespace",
      trustListLastUpdateGroupUnresolvedSource,
      std::move(callback));
    return;
  }
  get_trust_list_node_async(connection,
    *namespaceIndex,
    std::move(applicationId),
    std::move(certificateGroupId),
    [connection, callback = std::move(callback)](ua::Result<ua::NodeId> trustList) mutable
    {
      if (!trustList.is_good())
      {
        callback({trustList.status_code(), trustList.shared_detail()});
        return;
      }
      connection->typed().resolve_path_async(std::move(trustList).value(),
        make_certificate_directory_path(ua::ReferenceTypeId::HasProperty, 0, "LastUpdateTime"),
        [connection, callback = std::move(callback)](ua::NodeIdResult resolved) mutable
        {
          auto property = require_local_certificate_directory_node(
            std::move(resolved), "PullCertLastUpdateTimeResolutionFailed");
          if (!property.is_good())
          {
            callback({property.status_code(), property.shared_detail()});
            return;
          }
          connection->read_value_async(std::move(property).value(),
            [connection, callback = std::move(callback)](ua::Result<ua::DataValue> result) mutable
            { callback(interpret_trust_list_last_update_time(std::move(result))); });
        });
    });
}

void PullCertificateManagerClientHost::read_trust_list_async(ua::NodeId applicationId,
  ua::NodeId certificateGroupId, std::function<void(ua::Result<ua::TrustListDataType>)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = mGdsConnection;
  }
  if (!connection)
  {
    complete_bad_on_executor<ua::TrustListDataType>(mExecutor,
      ua::Status::BadNotConnected,
      "PullCertGdsNotOpen",
      "no GDS Connection is open; cannot download the TrustList",
      trustListGdsClosedSource,
      std::move(callback));
    return;
  }
  const auto namespaceTable = connection->namespace_table();
  const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
  if (!namespaceIndex)
  {
    complete_bad_on_executor<ua::TrustListDataType>(mExecutor,
      ua::Status::BadNodeIdUnknown,
      "PullCertGdsNamespaceMissing",
      "the connected server does not expose the standard GDS namespace",
      trustListGroupUnresolvedSource,
      std::move(callback));
    return;
  }
  get_trust_list_node_async(connection,
    *namespaceIndex,
    std::move(applicationId),
    std::move(certificateGroupId),
    [connection, callback = std::move(callback)](ua::Result<ua::NodeId> trustList) mutable
    {
      if (!trustList.is_good())
      {
        callback({trustList.status_code(), trustList.shared_detail()});
        return;
      }
      auto fileTransfer = connection->files();
      fileTransfer.read_all_async(std::move(trustList).value(),
        [connection, fileTransfer, callback = std::move(callback)](ua::Result<ua::ByteString> result) mutable
        {
          // The downloaded TrustList is installed, so only a Good read is decoded: a Bad one is passed on and
          // an Uncertain one refused (ServiceAnswerUncertain).
          if (!result.is_good())
          {
            callback(ua::Result<ua::TrustListDataType>{
              answer_refused(result.status_code(), "ServiceAnswerUncertain", trustListDownloadSource)});
            return;
          }
          callback(decode_trust_list_body(result.value()));
        });
    });
}

// -------- Cert renewal (GDS RPC; null-guarded until W6b) --------

void PullCertificateManagerClientHost::get_certificate_status_async(ua::NodeId applicationId,
  ua::NodeId certificateGroupId, ua::NodeId certificateTypeId, std::function<void(ua::Result<bool>)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = mGdsConnection;
  }
  if (!connection)
  {
    complete_bad_on_executor<bool>(mExecutor,
      ua::Status::BadNotConnected,
      "PullCertGdsNotOpen",
      "no GDS Connection is open; cannot ask whether a certificate update is required",
      getCertificateStatusSource,
      std::move(callback));
    return;
  }
  const auto namespaceTable = connection->namespace_table();
  const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
  if (!namespaceIndex)
  {
    complete_bad_on_executor<bool>(mExecutor,
      ua::Status::BadNodeIdUnknown,
      "PullCertGdsNamespaceMissing",
      "the connected server does not expose the standard GDS namespace",
      getCertificateStatusSource,
      std::move(callback));
    return;
  }
  call_certificate_directory_method_async(connection,
    *namespaceIndex,
    "GetCertificateStatus",
    build_get_certificate_status_arguments(
      std::move(applicationId), std::move(certificateGroupId), std::move(certificateTypeId)),
    [connection, callback = std::move(callback)](ua::Result<ua::CallResult> call) mutable
    { callback(decode_get_certificate_status_result(std::move(call))); });
}

void PullCertificateManagerClientHost::start_certificate_request_async(
  CertRequestParams params, std::function<void(ua::Result<ua::NodeId>)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = mGdsConnection;
  }
  if (!connection)
  {
    complete_bad_on_executor<ua::NodeId>(mExecutor,
      ua::Status::BadNotConnected,
      "PullCertGdsNotOpen",
      "no GDS Connection is open; cannot issue a certificate request",
      startRequestGdsClosedSource,
      std::move(callback));
    return;
  }
  const auto namespaceTable = connection->namespace_table();
  const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
  if (!namespaceIndex)
  {
    complete_bad_on_executor<ua::NodeId>(mExecutor,
      ua::Status::BadNodeIdUnknown,
      "PullCertGdsNamespaceMissing",
      "the connected server does not expose the standard GDS namespace",
      startRequestNamespaceSource,
      std::move(callback));
    return;
  }

  StartCertificateRequestWireParams wireParams;
  wireParams.applicationId = std::move(params.applicationId);
  wireParams.certificateGroupId = std::move(params.certificateGroupId);
  wireParams.certificateTypeId = std::move(params.certificateTypeId);
  wireParams.newKeyPair = params.newKeyPair;
  wireParams.certificateRequest = std::move(params.certificateRequest);
  wireParams.subjectName = std::move(params.subjectName);
  wireParams.domainNames = std::move(params.domainNames);
  wireParams.privateKeyFormat = std::move(params.privateKeyFormat);
  auto arguments = build_start_certificate_request_arguments(std::move(wireParams));
  if (!arguments.has_value())
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [result = ua::Result<ua::NodeId>{arguments.status_code(), arguments.shared_detail()},
          callback = std::move(callback)]() mutable { callback(std::move(result)); }));
    return;
  }
  const std::string methodName = params.newKeyPair ? "StartNewKeyPairRequest" : "StartSigningRequest";
  call_certificate_directory_method_async(connection,
    *namespaceIndex,
    methodName,
    std::move(arguments).value(),
    [connection, callback = std::move(callback)](ua::Result<ua::CallResult> call) mutable
    { callback(decode_start_certificate_request_result(std::move(call))); });
}

void PullCertificateManagerClientHost::finish_certificate_request_async(ua::NodeId applicationId,
  ua::NodeId requestId, std::function<void(ua::Result<FinishCertificateResult>)> callback)
{
  std::shared_ptr<ua::client::Connection> connection;
  {
    const std::lock_guard<std::mutex> lock(mGdsMutex);
    connection = mGdsConnection;
  }
  if (!connection)
  {
    complete_bad_on_executor<FinishCertificateResult>(mExecutor,
      ua::Status::BadNotConnected,
      "PullCertGdsNotOpen",
      "no GDS Connection is open; cannot poll the certificate request",
      finishRequestGdsClosedSource,
      std::move(callback));
    return;
  }
  const auto namespaceTable = connection->namespace_table();
  const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
  if (!namespaceIndex)
  {
    complete_bad_on_executor<FinishCertificateResult>(mExecutor,
      ua::Status::BadNodeIdUnknown,
      "PullCertGdsNamespaceMissing",
      "the connected server does not expose the standard GDS namespace",
      finishRequestNamespaceSource,
      std::move(callback));
    return;
  }
  const auto client = mClient.lock();
  const auto crypto = client ? client->crypto() : nullptr;
  if (!crypto)
  {
    complete_bad_on_executor<FinishCertificateResult>(mExecutor,
      ua::Status::BadInvalidState,
      "PullCertCryptoAbsent",
      "the Client crypto provider is unavailable while decoding FinishRequest",
      finishRequestCertificateSource,
      std::move(callback));
    return;
  }

  call_certificate_directory_method_async(connection,
    *namespaceIndex,
    "FinishRequest",
    build_finish_certificate_request_arguments(std::move(applicationId), std::move(requestId)),
    [connection, crypto, callback = std::move(callback)](ua::Result<ua::CallResult> call) mutable
    {
      auto decoded = decode_finish_certificate_request_result(std::move(call));
      if (!decoded.is_good())
      {
        callback({decoded.status_code(), decoded.shared_detail()});
        return;
      }
      try
      {
        auto wire = std::move(decoded).value();
        FinishCertificateResult result;
        result.certificate = crypto->read_certificate_from_der(ua::span<const ua::byte>{wire.certificate});
        if (!wire.privateKey.empty())
        {
          result.privateKey = std::move(wire.privateKey);
        }
        result.issuerChain.reserve(wire.issuerCertificates.size());
        for (const auto& issuer : wire.issuerCertificates)
        {
          result.issuerChain.push_back(crypto->read_certificate_from_der(ua::span<const ua::byte>{issuer}));
        }
        callback({std::move(result)});
      }
      catch (const ua::UaException& exception)
      {
        callback({exception.status_code(),
          ua::ErrorDetail::build("PullCertFinishCertificateDecodeFailed",
            "FinishRequest returned certificate bytes that could not be parsed",
            std::string{finishRequestCertificateSource})
            .cause(exception.status_code())});
      }
      catch (...)
      {
        const auto status = ua::exception_to_status_code(std::current_exception());
        callback({status,
          ua::ErrorDetail::build("PullCertFinishCertificateDecodeFailed",
            "FinishRequest returned certificate bytes that could not be parsed",
            std::string{finishRequestCertificateSource})
            .cause(status)});
      }
    });
}

// -------- Atomic persistence (H4(b) binding validation + CertificateStore staging) --------

void PullCertificateManagerClientHost::apply_cert_update_async(
  CertUpdate update, std::function<void(ua::VoidResult)> callback)
{
  const auto client = mClient.lock();
  if (!client)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadInvalidState,
      "PullCertClientGone",
      "the Client was destroyed before the pulled cert/trust-list update could be staged",
      applyClientGoneSource,
      std::move(callback));
    return;
  }
  const auto store = client->certificate_store();
  if (!store)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadConfigurationError,
      "PullCertStoreAbsent",
      "the Client has no CertificateStore; cannot stage the pulled cert/trust-list update",
      applyStoreAbsentSource,
      std::move(callback));
    return;
  }
  const auto crypto = client->crypto();
  // Fail CLOSED on a null crypto: the H4b key binding + the TrustList DER decode both REQUIRE crypto, so a
  // null provider cannot bind the cert/key  -  never skip-and-stage. (crypto is defaulted in CoreClientImpl,
  // so this is defensive; the interface contract forbids silently accepting an unbindable cert.)
  if (!crypto)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadConfigurationError,
      "PullCertCryptoAbsent",
      "the Client has no crypto provider; cannot bind the pulled cert/key before staging (H4b)",
      applyCryptoAbsentSource,
      std::move(callback));
    return;
  }

  // A certificate whose key the store has no slot for is refused before anything is checked or staged.
  if (update.newOwnCert && certificate_type_of(*update.newOwnCert) == ua::CertificateType::Invalid)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadCertificateInvalid,
      "PullCertTypeUnsupported",
      "the renewed certificate's key algorithm has no application certificate type in the store",
      applyTypeUnsupportedSource,
      std::move(callback));
    return;
  }

  // H4(b) binding validation FIRST (the strand-core treats the cert/key/chain as opaque  -  the interface is
  // REQUIRED to bind them before promoting staging; a mismatch is rejected, the runtime store untouched).
  std::shared_ptr<const ua::AsymmetricKeyPair> ownKeys;
  if (update.newOwnCert)
  {
    // Issuer binding.
    if (!update.newIssuerChain.empty() && update.newIssuerChain.front())
    {
      // A chain IS delivered: the front cert must sign the renewed leaf.
      if (!update.newOwnCert->issued_by(*update.newIssuerChain.front()))
      {
        complete_bad_on_executor<void>(mExecutor,
          ua::Status::BadSecurityChecksFailed,
          "PullCertIssuerUnbound",
          "the renewed certificate is not signed by the delivered issuer chain (H4b binding)",
          applyIssuerUnboundSource,
          std::move(callback));
        return;
      }
    }
    else if (!update.newOwnCert->self_signed())
    {
      // No issuer chain AND the leaf is NOT self-anchored: it cannot be bound to a trust anchor from what was
      // delivered, so it MUST be rejected (never silently accepted). Full chain-to-current-store validation
      // (accepting an unchained leaf that already chains to the CURRENT trust store) is a follow-up that
      // needs an async store-validate pass; W6 rejects the unanchored leaf.
      complete_bad_on_executor<void>(mExecutor,
        ua::Status::BadSecurityChecksFailed,
        "PullCertIssuerUnanchored",
        "the renewed certificate is not self-anchored and carries no issuer chain to a trusted anchor (H4b)",
        applyIssuerUnanchoredSource,
        std::move(callback));
      return;
    }

    // Key binding.
    if (update.newPrivateKey)
    {
      // StartNewKeyPairRequest: the server returned a fresh key pair; the renewed leaf's public key must
      // match the delivered private key.
      try
      {
        std::vector<ua::byte> pemCopy(update.newPrivateKey->size());
        if (!pemCopy.empty())
        {
          std::memcpy(pemCopy.data(), update.newPrivateKey->data(), update.newPrivateKey->size());
        }
        // The key was requested unprotected (no privateKeyPassword, OPC 10000-12 7.9.5), so the application's
        // own Crypto reads it, and the key pair keeps that Crypto's credential at rest.
        ownKeys =
          crypto->get_private_key_from_pem(update.newOwnCert->key_algorithm(), ua::span<ua::byte>{pemCopy});
      }
      catch (...)
      {
        complete_bad_on_executor<void>(mExecutor,
          ua::Status::BadSecurityChecksFailed,
          "PullCertKeyParseFailed",
          "the delivered private key could not be parsed for the H4b cert-key binding check",
          applyKeyParseFailedSource,
          std::move(callback));
        return;
      }
      if (ownKeys->public_key_der() != update.newOwnCert->public_key())
      {
        complete_bad_on_executor<void>(mExecutor,
          ua::Status::BadSecurityChecksFailed,
          "PullCertKeyMismatch",
          "the renewed certificate's public key does not match the delivered private key (H4b binding)",
          applyKeyMismatchSource,
          std::move(callback));
        return;
      }
    }
    else
    {
      // StartSigningRequest: the client RETAINS its existing private key, so the renewed leaf's public key
      // must match the CURRENT own cert's public key. The current own cert is the shim's on-channel snapshot.
      // Only a certificate of the same type: with several configured types the snapshot holds the channel's
      // certificate, which another type's renewal does not replace (its key pair is looked up in the store
      // below, step 0).
      const auto currentOwnCert = mOwnCert.load(std::memory_order_acquire);
      if (currentOwnCert && currentOwnCert->key_algorithm() == update.newOwnCert->key_algorithm())
      {
        if (update.newOwnCert->public_key() != currentOwnCert->public_key())
        {
          complete_bad_on_executor<void>(mExecutor,
            ua::Status::BadSecurityChecksFailed,
            "PullCertSigningKeyMismatch",
            "the renewed certificate's public key does not match the client's current key (H4b binding)",
            applySigningKeyMismatchSource,
            std::move(callback));
          return;
        }
      }
      // FLAGGED GAP (maintainer): when the current own cert snapshot is null the shim has NO source for the
      // retained key, so the StartSigningRequest key binding cannot run. The on-channel own-cert snapshot is
      // seeded null in W6 (the live GDS-connection cert-rotation tracking is the deferred W6b wiring), so
      // this check is skipped until W6b wires the snapshot. Since W6 never reaches apply in production (the
      // GDS open is a DEFER-STUB  to  the manager bootstraps to Failed), this gap is not a production
      // exposure.
    }
  }

  // Decode the TrustList DER blobs up-front (malformed input throws  to  a source-tagged Bad, not a partial
  // commit; the runtime store is untouched because no step has run yet).
  ua::CertificateList trustedCerts;
  ua::CrlList trustedCrls;
  ua::CertificateList trustListIssuerCerts;
  ua::CrlList issuerCrls;
  if (update.newTrustList)
  {
    try
    {
      for (const auto& der : update.newTrustList->trusted_certificates())
      {
        trustedCerts.push_back(crypto->read_certificate_from_der(ua::span<const ua::byte>{der}));
      }
      for (const auto& der : update.newTrustList->trusted_crls())
      {
        trustedCrls.push_back(crypto->read_crl_from_der(ua::span<const ua::byte>{der}));
      }
      for (const auto& der : update.newTrustList->issuer_certificates())
      {
        trustListIssuerCerts.push_back(crypto->read_certificate_from_der(ua::span<const ua::byte>{der}));
      }
      for (const auto& der : update.newTrustList->issuer_crls())
      {
        issuerCrls.push_back(crypto->read_crl_from_der(ua::span<const ua::byte>{der}));
      }
    }
    catch (...)
    {
      complete_bad_on_executor<void>(mExecutor,
        ua::Status::BadSecurityChecksFailed,
        "PullCertTrustDecodeFailed",
        "a certificate/CRL in the pulled TrustList could not be decoded",
        applyTrustDecodeFailedSource,
        std::move(callback));
      return;
    }
  }

  // Build the ordered staging steps. ORDER (H2 least-reversible-LAST): the idempotent trust-list / issuer
  // replaces run FIRST; the own-cert swap (the most visible, hardest-to-undo change) runs LAST  -  so a
  // trust-list-step failure leaves the own cert UNCHANGED and the manager's Bad-apply retry re-converges.
  auto steps = std::make_shared<std::vector<StoreStep>>();

  // 0. A signing-request renewal (no delivered private key) is stored with the key pair the store
  // already holds for its public key, under that certificate's type. The lookup is read-only and runs
  // before anything is staged: handing the store a null key pair crashed the client after the
  // certificate file had been overwritten, and a missing pair must stage nothing (security review
  // B3-5).
  std::shared_ptr<ua::CertificateStore::ApplicationCertificate> appCert;
  if (update.newOwnCert)
  {
    appCert = std::make_shared<ua::CertificateStore::ApplicationCertificate>();
    appCert->certificate = update.newOwnCert;
    appCert->certificateType = certificate_type_of(*update.newOwnCert);
    appCert->keys = ownKeys;
    if (!ownKeys)
    {
      steps->push_back(
        [store, appCert, renewed = update.newOwnCert](std::function<void(ua::VoidResult)> stepCb) mutable
        {
          store->get_application_certificates_async(
            [appCert, renewed, stepCb = std::move(stepCb)](
              ua::CertificateStore::ApplicationCertificateListResult held) mutable
            {
              if (!held.is_good())
              {
                // A Bad answer is passed on as it is; an Uncertain one is refused, since the held key pairs
                // are used only from a Good answer.
                stepCb(
                  ua::VoidResult{held.is_uncertain() ? ua::client::detail::certificate_store_answer_refused(
                                                         held.status_code(), applyExistingKeyAbsentSource)
                                                     : held.status_code()});
                return;
              }
              for (const auto& existing : held.value())
              {
                if (existing.keys && existing.certificate &&
                    existing.certificate->public_key() == renewed->public_key())
                {
                  appCert->keys = existing.keys;
                  appCert->certificateType = existing.certificateType;
                  break;
                }
              }
              if (!appCert->keys)
              {
                stepCb(ua::VoidResult{ua::StatusCode{ua::Status::BadSecurityChecksFailed},
                  ua::ErrorDetail::build("PullCertExistingKeyAbsent",
                    "the store holds no key pair for the renewed certificate's public key; nothing is "
                    "staged",
                    std::string{applyExistingKeyAbsentSource})});
                return;
              }
              stepCb(ua::VoidResult{});
            });
        });
    }
  }

  // 1. Trusted set (idempotent replace)  -  an atomic swap of the whole trusted cert+CRL set.
  if (update.newTrustList)
  {
    steps->push_back(
      [store, trustedCerts = std::move(trustedCerts), trustedCrls = std::move(trustedCrls)](
        std::function<void(ua::VoidResult)> stepCb) mutable
      {
        store->replace_trusted_certificates_async(
          std::move(trustedCerts), std::move(trustedCrls), std::move(stepCb));
      });
  }

  // 2. Issuer set  -  compose ONE set so the delivered chain is never wiped (H1): with a trust list present
  // the issuer set is the trust-list issuers UNIONED with newIssuerChain, applied as a SINGLE replace;
  // without a trust list the chain is merely added. Never add-then-replace (the replace would clobber the
  // add).
  if (update.newTrustList)
  {
    ua::CertificateList issuerUnion = std::move(trustListIssuerCerts);
    for (const auto& chainCert : update.newIssuerChain)
    {
      if (!chainCert)
      {
        continue;
      }
      const ua::ByteString chainDer = chainCert->der_encoding();
      const bool alreadyPresent =
        !chainDer.empty() && std::any_of(issuerUnion.begin(),
                               issuerUnion.end(),
                               [&chainDer](const std::shared_ptr<const ua::X509Certificate>& held)
                               { return held && held->der_encoding() == chainDer; });
      if (!alreadyPresent)
      {
        issuerUnion.push_back(chainCert);
      }
    }
    steps->push_back(
      [store, issuerUnion = std::move(issuerUnion), issuerCrls = std::move(issuerCrls)](
        std::function<void(ua::VoidResult)> stepCb) mutable
      {
        store->replace_issuer_certificates_async(
          std::move(issuerUnion), std::move(issuerCrls), std::move(stepCb));
      });
  }
  else if (!update.newIssuerChain.empty())
  {
    steps->push_back([store, issuers = update.newIssuerChain](std::function<void(ua::VoidResult)> stepCb)
      { store->add_to_issuer_certificates_async(issuers, std::move(stepCb)); });
  }

  // 3. The renewed certificate is validated through the store (dates, chain, revocation, basic
  // constraints, and the SAN URI against THIS client's ApplicationUri) before it is staged: the issuer
  // binding above compares names and key identifiers, it verifies no signature and no identity
  // (security review B3-5). It runs after the delivered trust list and issuers are installed, because
  // the anchor and the CRL the renewed certificate needs may arrive in this same update (a first
  // registration, a GDS CA rotation); an empty configured ApplicationUri is no identity to check.
  if (update.newOwnCert)
  {
    const std::string& configuredUri = client->configuration().application_description_part().applicationUri;
    ua::optional<std::string> applicationUri;
    if (!configuredUri.empty())
      applicationUri = configuredUri;
    steps->push_back(
      [store, certificate = update.newOwnCert, chain = update.newIssuerChain, applicationUri](
        std::function<void(ua::VoidResult)> stepCb) mutable
      {
        ua::CertificateValidationRequest request;
        request.certificate = certificate;
        request.presentedIssuers = std::move(chain);
        request.applicationUri = applicationUri;
        // The client's own certificate: an RSA certificate must allow clientAuth (OPC 10000-6 Table 50).
        request.use = ua::CertificateUse::ClientApplicationInstance;
        store->validate_certificate_async(std::move(request),
          [stepCb = std::move(stepCb)](ua::VoidResult result) mutable
          {
            if (result.is_bad())
            {
              stepCb(ua::VoidResult{ua::StatusCode{ua::Status::BadSecurityChecksFailed},
                ua::ErrorDetail::build("PullCertRenewedCertificateInvalid",
                  "the renewed certificate did not validate against the store, the delivered chain and "
                  "this client's ApplicationUri; the certificate is not staged",
                  std::string{applyValidationFailedSource})
                  .cause(result.status_code())
                  .cause(result.shared_detail())});
              return;
            }
            stepCb(ua::VoidResult{});
          });
      });
  }

  // 4. Own cert (the least-recoverable change) LAST.
  if (appCert)
  {
    steps->push_back([store, appCert](std::function<void(ua::VoidResult)> stepCb) mutable
      { store->add_to_application_certificates_async(*appCert, std::move(stepCb)); });
  }

  const auto newOwnCert = update.newOwnCert;
  const auto weakSelf = weak_from_this();
  run_store_steps(std::move(steps),
    0,
    [weakSelf, newOwnCert, callback = std::move(callback)](ua::VoidResult result) mutable
    {
      if (result.is_good() && newOwnCert)
      {
        if (const auto self = weakSelf.lock())
        {
          // The snapshot is the certificate the GDS channel presents (CL-PULLCRT-004): a renewal with the
          // same key algorithm (RSA, or the same ECC curve) replaces it; another type's certificate does not,
          // or every other group's pending request would be dropped as stamped with a different certificate.
          const auto current = self->mOwnCert.load(std::memory_order_acquire);
          if (!current || current->key_algorithm() == newOwnCert->key_algorithm())
          {
            self->mOwnCert.store(newOwnCert, std::memory_order_release);
          }
        }
      }
      callback(std::move(result));
    });
}

// -------- PersistedRequest IO (in-memory store, J59) --------

void PullCertificateManagerClientHost::read_persisted_requests_async(
  std::function<void(ua::Result<std::vector<PersistedRequest>>)> callback)
{
  std::vector<PersistedRequest> snapshot;
  {
    const std::lock_guard<std::mutex> lock(mPersistMutex);
    snapshot = mPersistedRequests;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(ua::Logger{},
      [snapshot = std::move(snapshot), callback = std::move(callback)]() mutable
      { callback(ua::Result<std::vector<PersistedRequest>>{std::move(snapshot)}); }));
}

void PullCertificateManagerClientHost::write_persisted_requests_async(
  std::vector<PersistedRequest> requests, std::function<void(ua::VoidResult)> callback)
{
  {
    const std::lock_guard<std::mutex> lock(mPersistMutex);
    mPersistedRequests = std::move(requests);
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(
      ua::Logger{}, [callback = std::move(callback)]() mutable { callback(ua::VoidResult{}); }));
}

// -------- Revalidation broadcast ( to  CoreClientImpl::revalidate_connections_async, W5) --------

void PullCertificateManagerClientHost::revalidate_connections_async(
  bool ownCertificateChanged, bool revalidateServerCertificate, std::function<void(ua::VoidResult)> callback)
{
  const auto client = mClient.lock();
  if (!client)
  {
    complete_bad_on_executor<void>(mExecutor,
      ua::Status::BadInvalidState,
      "PullCertClientGone",
      "the Client was destroyed before the post-commit revalidation broadcast could be dispatched",
      revalidateClientGoneSource,
      std::move(callback));
    return;
  }
  client->revalidate_connections_async(
    ownCertificateChanged, revalidateServerCertificate, std::move(callback));
}

// -------- Observer fan-out (routed to the Client-scoped sink; the sink posts each hook to the executor)
// -----

void PullCertificateManagerClientHost::fire_observer_certificate_rotated(
  std::shared_ptr<const ua::X509Certificate> newCert)
{
  if (mSink)
  {
    mSink->fire_certificate_rotated(std::move(newCert));
  }
}

void PullCertificateManagerClientHost::fire_observer_pull_cert_lifecycle(
  ua::client::PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail)
{
  if (mSink)
  {
    mSink->fire_pull_cert_management_lifecycle(event, std::move(detail));
  }
}

// -------- Rule 4 cross-strand snapshot --------

void PullCertificateManagerClientHost::publish_info_snapshot(
  std::shared_ptr<const ua::client::PullCertManagementInfo> info)
{
  mInfoSnapshot.store(std::move(info), std::memory_order_release);
}

std::shared_ptr<const ua::client::PullCertManagementInfo>
  PullCertificateManagerClientHost::info_snapshot() const noexcept
{
  return mInfoSnapshot.load(std::memory_order_acquire);
}

// -------- Test-inject interfaces --------

void PullCertificateManagerClientHost::set_gds_connection_for_test(
  std::shared_ptr<ua::client::Connection> connection)
{
  const std::lock_guard<std::mutex> lock(mGdsMutex);
  mGdsConnection = std::move(connection);
}

void PullCertificateManagerClientHost::set_own_cert_for_test(
  std::shared_ptr<const ua::X509Certificate> ownCert)
{
  mOwnCert.store(std::move(ownCert), std::memory_order_release);
}

}  // namespace ua::client::detail
