// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FAKE_PULL_CERT_MANAGER_HOST_H
#define FAKE_PULL_CERT_MANAGER_HOST_H

/// @file
/// @brief Scriptable @ref ua::client::detail::PullCertificateManagerHost test double for the tier-2
///        @ref ua::client::detail::PullCertificateManagerImpl (client design section 8.1A). Lets every
///        section 8.1A.4 state and transition be exercised with NO GDS, certificate store, or wire stack:
///        each host primitive is scriptable (GDS open/close, `LastUpdateTime` read, TrustList download, Start
///        / Finish cert requests, atomic apply, persisted-request IO, revalidation broadcast), and every
///        observer / snapshot call is captured for falsifiable assertions. Results are delivered
///        synchronously to the manager's post-borrowing wrappers, which re-post onto the manager's strand -
///        so replies land on strand turns; the test drives them by draining the io_context.

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_pull_certificate_manager.h"
#include "ua_pull_certificate_manager_host.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_trust_list_data_type.h"
#include "ua_x509_certificate.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::testing
{

/// The scriptable host for the pull-cert manager unit tests.
class FakePullCertificateManagerHost : public ua::client::detail::PullCertificateManagerHost
{
public:
  using Host = ua::client::detail::PullCertificateManagerHost;
  using PersistedRequest = ua::client::detail::PersistedRequest;
  using FinishResult = ua::Result<Host::FinishCertificateResult>;

  boost::asio::any_io_executor injectedExecutor;

  // ================= runtime / identity =================
  std::string ownCertThumbprint = "thumb-A";

  [[nodiscard]] boost::asio::any_io_executor executor() override
  {
    return injectedExecutor;
  }

  [[nodiscard]] std::string current_own_cert_thumbprint_sha1() const override
  {
    return ownCertThumbprint;
  }

  // ================= GDS bootstrap =================
  std::vector<Host::GdsConnectionRequest> openGdsCalls;
  std::optional<ua::VoidResult> openGdsResponse;  ///< default Good.
  int closeGdsCalls = 0;

  void fail_open_gds(ua::Status status)
  {
    openGdsResponse = ua::VoidResult{ua::StatusCode{status}};
  }

  void open_gds_connection_async(
    Host::GdsConnectionRequest request, std::function<void(ua::VoidResult)> callback) override
  {
    openGdsCalls.push_back(request);
    callback(openGdsResponse.value_or(ua::VoidResult{}));
  }

  void close_gds_connection_async(std::function<void(ua::VoidResult)> callback) override
  {
    ++closeGdsCalls;
    callback(ua::VoidResult{});
  }

  // ================= persisted requests =================
  std::optional<ua::Result<std::vector<PersistedRequest>>> persistedResponse;  ///< default empty vector.
  std::vector<std::vector<PersistedRequest>> persistedWrites;  ///< every write captured.

  void set_persisted(std::vector<PersistedRequest> requests)
  {
    persistedResponse = ua::Result<std::vector<PersistedRequest>>{std::move(requests)};
  }

  void fail_persisted_load(ua::Status status)
  {
    persistedResponse = ua::Result<std::vector<PersistedRequest>>{ua::StatusCode{status}};
  }

  void read_persisted_requests_async(
    std::function<void(ua::Result<std::vector<PersistedRequest>>)> callback) override
  {
    callback(
      persistedResponse.value_or(ua::Result<std::vector<PersistedRequest>>{std::vector<PersistedRequest>{}}));
  }

  std::optional<ua::VoidResult> persistedWriteResponse;  ///< default Good.

  void fail_persisted_write(ua::Status status)
  {
    persistedWriteResponse = ua::VoidResult{ua::StatusCode{status}};
  }

  void write_persisted_requests_async(
    std::vector<PersistedRequest> requests, std::function<void(ua::VoidResult)> callback) override
  {
    persistedWrites.push_back(std::move(requests));
    callback(persistedWriteResponse.value_or(ua::VoidResult{}));
  }

  // ================= TrustList =================
  std::vector<ua::NodeId> lastUpdateReads;
  std::optional<ua::Result<std::optional<ua::DateTime>>> lastUpdateResponse;
  std::vector<ua::NodeId> trustListReads;
  std::optional<ua::Result<ua::TrustListDataType>> trustListResponse;

  void set_last_update_time(ua::DateTime time)
  {
    lastUpdateResponse = ua::Result<std::optional<ua::DateTime>>{std::optional<ua::DateTime>{time}};
  }

  void set_last_update_time_missing()
  {
    lastUpdateResponse = ua::Result<std::optional<ua::DateTime>>{std::optional<ua::DateTime>{std::nullopt}};
  }

  void fail_last_update_time(ua::Status status)
  {
    lastUpdateResponse = ua::Result<std::optional<ua::DateTime>>{ua::StatusCode{status}};
  }

  void set_trust_list(ua::TrustListDataType list)
  {
    trustListResponse = ua::Result<ua::TrustListDataType>{std::move(list)};
  }

  void fail_trust_list(ua::Status status)
  {
    trustListResponse = ua::Result<ua::TrustListDataType>{ua::StatusCode{status}};
  }

  void read_trust_list_last_update_time_async(ua::NodeId /*applicationId*/, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<std::optional<ua::DateTime>>)> callback) override
  {
    lastUpdateReads.push_back(certificateGroupId);
    callback(lastUpdateResponse.value_or(
      ua::Result<std::optional<ua::DateTime>>{std::optional<ua::DateTime>{std::nullopt}}));
  }

  void read_trust_list_async(ua::NodeId /*applicationId*/, ua::NodeId certificateGroupId,
    std::function<void(ua::Result<ua::TrustListDataType>)> callback) override
  {
    trustListReads.push_back(certificateGroupId);
    callback(trustListResponse.value_or(ua::Result<ua::TrustListDataType>{ua::TrustListDataType{}}));
  }

  // ================= cert renewal =================
  struct StatusCall
  {
    ua::NodeId applicationId;
    ua::NodeId certificateGroupId;
    ua::NodeId certificateTypeId;
  };

  std::vector<StatusCall> statusCalls;
  bool captureStatus = false;  ///< when true, hold the GetCertificateStatus callback (rotation tests).
  std::function<void(ua::Result<bool>)> capturedStatusCallback;
  std::deque<ua::Result<bool>> statusScript;  ///< successive `GetCertificateStatus` replies (pop-front).
  /// When the script is exhausted: an update is required, so a cycle requests a certificate as it always
  /// did before the status step existed.
  ua::Result<bool> statusFallback{true};

  void get_certificate_status_async(ua::NodeId applicationId, ua::NodeId certificateGroupId,
    ua::NodeId certificateTypeId, std::function<void(ua::Result<bool>)> callback) override
  {
    statusCalls.push_back(
      {std::move(applicationId), std::move(certificateGroupId), std::move(certificateTypeId)});
    if (captureStatus)
    {
      capturedStatusCallback = std::move(callback);  // never answered unless a test completes it.
      return;
    }
    if (statusScript.empty())
    {
      callback(statusFallback);
      return;
    }
    auto reply = std::move(statusScript.front());
    statusScript.pop_front();
    callback(std::move(reply));
  }

  std::vector<Host::CertRequestParams> startCalls;
  std::optional<ua::Result<ua::NodeId>> startResponse;  ///< default Good with @ref nextRequestId.
  ua::NodeId nextRequestId = ua::NodeId{2, 0xA1U};

  struct FinishCall
  {
    ua::NodeId applicationId;
    ua::NodeId requestId;
  };

  std::vector<FinishCall> finishCalls;
  std::deque<FinishResult> finishScript;  ///< successive `FinishRequest` replies (pop-front).
  FinishResult finishFallback{ua::StatusCode{ua::Status::BadNothingToDo}};  ///< when the script is exhausted.
  bool captureFinish = false;  ///< when true, hold the callback for @ref complete_finish (staleness tests).
  std::function<void(FinishResult)> capturedFinishCallback;

  void fail_start_request(ua::Status status)
  {
    startResponse = ua::Result<ua::NodeId>{ua::StatusCode{status}};
  }

  void push_finish_nothing_to_do()
  {
    finishScript.emplace_back(ua::StatusCode{ua::Status::BadNothingToDo});
  }

  void push_finish_bad(ua::Status status)
  {
    finishScript.emplace_back(ua::StatusCode{status});
  }

  void push_finish_certificate(
    std::shared_ptr<const ua::X509Certificate> cert, std::optional<ua::ByteString> key = std::nullopt)
  {
    Host::FinishCertificateResult result;
    result.certificate = std::move(cert);
    result.privateKey = std::move(key);
    finishScript.emplace_back(std::move(result));
  }

  void push_finish_certificate_with_issuers(std::shared_ptr<const ua::X509Certificate> cert,
    std::vector<std::shared_ptr<const ua::X509Certificate>> issuers)
  {
    Host::FinishCertificateResult result;
    result.certificate = std::move(cert);
    result.issuerChain = std::move(issuers);
    finishScript.emplace_back(std::move(result));
  }

  void start_certificate_request_async(
    Host::CertRequestParams params, std::function<void(ua::Result<ua::NodeId>)> callback) override
  {
    startCalls.push_back(params);
    callback(startResponse.value_or(ua::Result<ua::NodeId>{nextRequestId}));
  }

  void finish_certificate_request_async(
    ua::NodeId applicationId, ua::NodeId requestId, std::function<void(FinishResult)> callback) override
  {
    finishCalls.push_back(FinishCall{applicationId, requestId});
    if (captureFinish)
    {
      capturedFinishCallback = std::move(callback);  // held; answered by complete_finish (staleness tests).
      return;
    }
    if (!finishScript.empty())
    {
      FinishResult next = std::move(finishScript.front());
      finishScript.pop_front();
      callback(std::move(next));
      return;
    }
    callback(finishFallback);
  }

  /// Completes a held `FinishRequest` (for the stale-generation-callback test).
  void complete_finish(FinishResult result)
  {
    if (capturedFinishCallback)
    {
      auto callback = std::move(capturedFinishCallback);
      capturedFinishCallback = nullptr;
      callback(std::move(result));
    }
  }

  // ================= atomic apply =================
  std::vector<Host::CertUpdate> applyCalls;
  std::optional<ua::VoidResult> applyResponse;  ///< default Good.

  void fail_apply(ua::Status status)
  {
    applyResponse = ua::VoidResult{ua::StatusCode{status}};
  }

  void apply_cert_update_async(Host::CertUpdate update, std::function<void(ua::VoidResult)> callback) override
  {
    applyCalls.push_back(update);
    callback(applyResponse.value_or(ua::VoidResult{}));
  }

  // ================= revalidation broadcast =================
  int revalidateCalls = 0;
  std::vector<bool> revalidateOwnCertificateChanges;
  std::vector<bool> revalidateServerCertificateRequests;
  bool captureRevalidate = false;  ///< when true, hold the callback for @ref complete_revalidate.
  std::function<void(ua::VoidResult)> capturedRevalidateCallback;
  std::optional<ua::VoidResult> revalidateResponse;  ///< default Good.

  void fail_revalidate(ua::Status status)
  {
    revalidateResponse = ua::VoidResult{ua::StatusCode{status}};
  }

  void revalidate_connections_async(bool ownCertificateChanged, bool revalidateServerCertificate,
    std::function<void(ua::VoidResult)> callback) override
  {
    ++revalidateCalls;
    revalidateOwnCertificateChanges.push_back(ownCertificateChanged);
    revalidateServerCertificateRequests.push_back(revalidateServerCertificate);
    if (captureRevalidate)
    {
      capturedRevalidateCallback = std::move(callback);
      return;
    }
    callback(revalidateResponse.value_or(ua::VoidResult{}));
  }

  /// Completes a held revalidation broadcast (for the stop-during-revalidating test).
  void complete_revalidate(ua::VoidResult result = ua::VoidResult{})
  {
    if (capturedRevalidateCallback)
    {
      auto callback = std::move(capturedRevalidateCallback);
      capturedRevalidateCallback = nullptr;
      callback(std::move(result));
    }
  }

  // ================= observer fan-out (captured) =================
  std::vector<std::shared_ptr<const ua::X509Certificate>> certRotatedFires;
  std::vector<std::pair<ua::client::PullCertLifecycleEvent, std::shared_ptr<const ua::ErrorDetail>>>
    lifecycleFires;

  void fire_observer_certificate_rotated(std::shared_ptr<const ua::X509Certificate> newCert) override
  {
    certRotatedFires.push_back(std::move(newCert));
  }

  void fire_observer_pull_cert_lifecycle(
    ua::client::PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    lifecycleFires.emplace_back(event, std::move(detail));
  }

  // ================= snapshot publish (captured) =================
  std::vector<std::shared_ptr<const ua::client::PullCertManagementInfo>> snapshots;

  void publish_info_snapshot(std::shared_ptr<const ua::client::PullCertManagementInfo> info) override
  {
    snapshots.push_back(std::move(info));
  }

  // ================= convenience assertions =================
  [[nodiscard]] std::size_t count_lifecycle(ua::client::PullCertLifecycleEvent event) const
  {
    std::size_t count = 0;
    for (const auto& entry : lifecycleFires)
    {
      if (entry.first == event)
      {
        ++count;
      }
    }
    return count;
  }

  [[nodiscard]] bool has_lifecycle(ua::client::PullCertLifecycleEvent event) const
  {
    return count_lifecycle(event) > 0;
  }

  /// The detail carried by the most recent fire of @p event (null if none / no detail).
  [[nodiscard]] std::shared_ptr<const ua::ErrorDetail> last_lifecycle_detail(
    ua::client::PullCertLifecycleEvent event) const
  {
    std::shared_ptr<const ua::ErrorDetail> detail;
    for (const auto& entry : lifecycleFires)
    {
      if (entry.first == event)
      {
        detail = entry.second;
      }
    }
    return detail;
  }
};

}  // namespace ua::testing

#endif  // FAKE_PULL_CERT_MANAGER_HOST_H
