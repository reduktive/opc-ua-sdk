// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Local fake SecureChannelDependencies for the 4.7a server-secure-channel pin corpus.
//
// Scoped to tests/behaviour_pins/phase_4_7_server_secure_channel/ per the runbook section 4.0.1
// "each consumer sub-phase ships its own fake" rule. Implements every virtual on the
// abstract SecureChannelDependencies interface with recording semantics for the entries
// the channel actually invokes from the dispatcher pins (`create_session`,
// `remove_secure_channel`, `activate_session_on_channel`) plus a recording observer.

#ifndef UA_TESTS_BEHAVIOUR_PINS_PHASE_4_7_FAKE_SECURE_CHANNEL_DEPENDENCIES_H
#define UA_TESTS_BEHAVIOUR_PINS_PHASE_4_7_FAKE_SECURE_CHANNEL_DEPENDENCIES_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ua_application_configuration.h"
#include "ua_create_session_request.h"
#include "ua_node_id.h"
#include "ua_server_configuration.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_observer.h"
#include "ua_server_secure_channel.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_structure_factory.h"

namespace ua::test::behaviour_pins::phase_4_7
{

/// Recording ServerObserver - captures every event signal so pins can observe
/// lifecycle invocations and the StatusCode argument.
struct RecordingServerObserver : public ::ua::server::ServerObserver
{
  std::atomic<int> openedCount{0};
  std::atomic<int> closedCount{0};
  std::atomic<int> renewedCount{0};
  std::atomic<int> openFailedCount{0};
  std::atomic<int> renewFailedCount{0};
  std::atomic<int> internalErrorCount{0};
  std::atomic<int> certificateRejectedCount{0};
  std::atomic<int> connectionClosedCount{0};

  std::mutex mutex;
  ::ua::StatusCode lastOpenFailedStatus{::ua::Status::Good};
  ::ua::StatusCode lastRenewFailedStatus{::ua::Status::Good};
  ::ua::StatusCode lastInternalErrorStatus{::ua::Status::Good};
  std::string lastInternalErrorDescription;

  void on_secure_channel_opened(const ::ua::server::SecureChannelEventInfo&) override
  {
    openedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_secure_channel_closed(const ::ua::server::SecureChannelEventInfo&, ::ua::StatusCode) override
  {
    closedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_secure_channel_renewed(const ::ua::server::SecureChannelEventInfo&) override
  {
    renewedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_secure_channel_open_failed(
    const ::ua::server::SecureChannelEventInfo&, ::ua::StatusCode reason) override
  {
    {
      std::lock_guard<std::mutex> lock{mutex};
      lastOpenFailedStatus = reason;
    }
    openFailedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_secure_channel_renew_failed(
    const ::ua::server::SecureChannelEventInfo&, ::ua::StatusCode reason) override
  {
    {
      std::lock_guard<std::mutex> lock{mutex};
      lastRenewFailedStatus = reason;
    }
    renewFailedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_internal_error(::ua::StatusCode status, const std::string& description) override
  {
    {
      std::lock_guard<std::mutex> lock{mutex};
      lastInternalErrorStatus = status;
      lastInternalErrorDescription = description;
    }
    internalErrorCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_certificate_rejected(const ::ua::server::CertificateEventInfo&) override
  {
    certificateRejectedCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_connection_closed(
    const std::string&, ::ua::server::ConnectionCloseReason, ::ua::StatusCode) override
  {
    connectionClosedCount.fetch_add(1, std::memory_order_relaxed);
  }
};

/// FakeSecureChannelDependencies - implements every virtual on the abstract
/// `SecureChannelDependencies` interface (`ua_server_secure_channel.h:59-89`).
///
/// Recording surface (queryable from the main test thread):
///   - `wait_create_session_called(timeout)` - blocks until `create_session` fires.
///   - `create_session_request_id()` - last requestId routed to `create_session`.
///   - `create_session_endpoint_policy_id()` - endpoint policy id observed.
///   - `wait_activate_session_on_channel_called(timeout)` - blocks until cross-channel
///       Activate dispatch fires.
///   - `wait_remove_called(timeout)` - blocks until `remove_secure_channel` fires.
///   - `observer_recorder()` - RecordingServerObserver shared with the channel.
class FakeSecureChannelDependencies : public ::ua::server::SecureChannelDependencies
{
public:
  explicit FakeSecureChannelDependencies(::boost::asio::any_io_executor executor);

  // --- SecureChannelDependencies overrides ---
  ::ua::weak_ptr<::ua::server::DiscoveryDependencies> discovery_dependencies() override;
  ::boost::asio::any_io_executor executor() override;
  ::ua::shared_ptr<const ::ua::Crypto> crypto() override;
  ::ua::WeakAddressSpace address_space() override;
  const ::ua::ApplicationConfig& configuration() override;
  const ::ua::server::ServerConfig& server_configuration() override;
  ::ua::shared_ptr<::ua::CertificateStore> default_application_group_certificate_store() override;
  uint32_t get_next_secure_channel_id() override;
  void create_session(::ua::server::SecureChannelInfo secureChannelInfo, uint32_t requestId,
    ::ua::CreateSessionRequest&& request) override;
  ::ua::StructureFactory& structure_factory() override;
  std::vector<::ua::server::ServerEndpointConfig> endpoints(::ua::server::ListenerHandle listener) override;
  std::shared_ptr<::ua::server::ServerObserver> observer() override;
  ::ua::Logger logger() override;

  /// Installs a sink so a test can assert on what the channel LOGS, not only on what it hands
  /// the test-only validation observer. The pre-authentication reject path has no public
  /// observer and its detail is stripped at the wire, so the log is the only production-visible
  /// record of the reason - and therefore the only place a test can pin it.
  void set_log_sink(std::shared_ptr<::ua::LogSink> sink)
  {
    logSink = std::move(sink);
  }

  std::shared_ptr<::ua::LogSink> logSink;
  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override;
  std::shared_ptr<std::atomic<uint32_t>> in_flight_requests() override;
  void remove_secure_channel(const ::ua::shared_ptr<::ua::server::SecureChannel>& channel) override;
  void activate_session_on_channel(::ua::server::SecureChannelInfo newChannelInfo, uint32_t requestId,
    ::ua::ActivateSessionRequest&& request) override;

  // --- Test inspection / configuration ---
  void set_endpoints(std::vector<::ua::server::ServerEndpointConfig> endpoints);

  /// Mutable access to the ServerConfig the channel reads at construction (set the
  /// maxInFlightRequests caps here BEFORE creating the SecureChannel).
  ::ua::server::ServerConfig& mutable_server_configuration()
  {
    return mServerCfg;
  }

  /// The shared server-wide in-flight counter returned by `in_flight_requests()`; preload it to
  /// drive the server-wide cap, or read it to assert increment/decrement.
  std::shared_ptr<std::atomic<uint32_t>> in_flight_requests_counter() const
  {
    return mInFlightRequests;
  }

  bool wait_create_session_called(std::chrono::milliseconds timeout);
  bool wait_activate_session_on_channel_called(std::chrono::milliseconds timeout);
  bool wait_remove_called(std::chrono::milliseconds timeout);
  uint32_t create_session_request_id() const;
  std::string create_session_endpoint_policy_id() const;
  uint32_t activate_session_request_id() const;
  uint32_t activate_session_channel_id() const;
  size_t remove_call_count() const;

  std::shared_ptr<RecordingServerObserver> observer_recorder() const
  {
    return mObserver;
  }

private:
  ::boost::asio::any_io_executor mExecutor;
  ::ua::ApplicationConfig mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  std::vector<::ua::server::ServerEndpointConfig> mEndpoints;
  std::shared_ptr<RecordingServerObserver> mObserver;
  std::shared_ptr<std::atomic<uint32_t>> mInFlightDiscovery;
  std::shared_ptr<std::atomic<uint32_t>> mInFlightRequests;
  mutable std::shared_ptr<const ::ua::Crypto> mCrypto;

  mutable std::mutex mMutex;
  std::condition_variable mCv;
  bool mCreateSessionCalled{false};
  uint32_t mCreateSessionRequestId{0};
  std::string mCreateSessionEndpointPolicyId;
  bool mActivateSessionOnChannelCalled{false};
  uint32_t mActivateSessionRequestId{0};
  uint32_t mActivateSessionChannelId{0};
  size_t mRemoveCallCount{0};
};

}  // namespace ua::test::behaviour_pins::phase_4_7

#endif  // UA_TESTS_BEHAVIOUR_PINS_PHASE_4_7_FAKE_SECURE_CHANNEL_DEPENDENCIES_H
