// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Strand-serialized driver that keeps a server registered with discovery servers (LDS).
/// @ingroup app

#ifndef UA_DISCOVERY_REGISTRATION_H
#define UA_DISCOVERY_REGISTRATION_H

#include "ua_crypto_types.h"
#include "ua_error_detail.h"
#include "ua_lds_registrar.h"
#include "ua_logger.h"
#include "ua_message_security_mode.h"
#include "ua_registered_server.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_timer.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::app
{

/// Explicit trust material for the LDS registration channel.
///
/// When supplied, these certificates and CRLs override the server's application-group trust store
/// for the channel opened to each discovery server. Each item is shared and immutable; the
/// configuration retains shared ownership.
///
/// The registration channel validates the discovery server's certificate with the server's
/// application-group validation options, which check revocation by default
/// (`CheckRevocationStatusOffline`). A CA-issued discovery-server certificate therefore needs the
/// CRL of every CA in its chain here, or it is refused as revocation-unknown; a self-signed
/// certificate needs none.
/// @ingroup app
struct TrustOverride
{
  std::vector<std::shared_ptr<const ua::X509Certificate>>
    trustedCertificates;  ///< Certificates trusted to identify the discovery server.
  std::vector<std::shared_ptr<const ua::X509Certificate>>
    issuerCertificates;  ///< Intermediate CA certificates used to build the trust chain.
  std::vector<std::shared_ptr<const ua::X509Crl>>
    trustedCrls;  ///< CRLs issued by the CAs in @ref trustedCertificates.
  std::vector<std::shared_ptr<const ua::X509Crl>>
    issuerCrls;  ///< CRLs issued by the CAs in @ref issuerCertificates.
};

/// A single discovery endpoint the server registers with.
///
/// By default the registration channel is `SignAndEncrypt` with the strongest SecurityPolicy the discovery
/// server offers for that mode, read from its endpoints each cycle: OPC 10000-4 5.4.5.1 requires a discovery
/// server to refuse RegisterServer over an insecure channel, and the SDK's own LDS answers
/// `Bad_SecurityModeInsufficient`. `None` is used only when set explicitly.
/// @ingroup app
struct DiscoveryTarget
{
  std::string discoveryUrl;  ///< Endpoint URL of the discovery server (LDS) to register with.
  /// Security mode for the registration channel. `None` needs `securityPolicyId` unset or `None`;
  /// a secured mode refuses `SecurityPolicyId::None` (`Bad_InvalidArgument`,
  /// `DiscoveryTargetSecurityMismatch`).
  ua::MessageSecurityMode messageSecurityMode{ua::MessageSecurityMode::SignAndEncrypt};
  /// Security policy for the registration channel. Unset: the strongest non-deprecated policy the
  /// discovery server offers for `messageSecurityMode` (the client's endpoint ranking,
  /// @ref ua::client::default_easy_connect_ranker, then the advertised `securityLevel`).
  std::optional<ua::SecurityPolicyId> securityPolicyId;
};

/// Configuration for the discovery-registration driver.
/// @ingroup app
struct DiscoveryRegistrationConfig
{
  std::vector<DiscoveryTarget> targets;  ///< Discovery servers the driver keeps registrations with.
  std::chrono::seconds cadence{60};  ///< Interval between successful re-registration cycles.
  std::chrono::seconds backoffInitial{1};  ///< First retry delay after a failed cycle.
  std::chrono::seconds backoffCap{60};  ///< Upper bound on the exponential retry backoff.
  std::chrono::seconds shutdownDeregisterTimeout{
    5};  ///< Bound on the final deregister cycle during @ref DiscoveryRegistration::stop_async.
  std::optional<TrustOverride> ldsTrustOverride;  ///< Trust material for the registration channel; @c nullopt
                                                  ///< uses the server's application-group store.
};

/// Per-target registration phase.
enum class RegistrationState
{
  Idle,  ///< No cycle in progress; awaiting the next scheduled attempt.
  Opening,  ///< Opening the channel to the discovery server.
  Registering,  ///< Sending RegisterServer2 to the discovery server.
  FallbackRegistering,  ///< Sending the RegisterServer v1 fallback after RegisterServer2 was
                        ///< rejected.
  Closing,  ///< Closing the channel after the register call completed.
  BackingOff  ///< Waiting out the retry backoff after a failed cycle.
};

/// Per-target context passed to every observer notification.
///
/// Identifies which discovery endpoint a notification concerns and how the most recent
/// registration cycle reached it. A fresh value is constructed for each notification; observers
/// must copy any field they wish to retain beyond the call.
/// @ingroup app
struct DiscoveryRegistrationInfo
{
  /// Discovery endpoint URL of the target this notification concerns.
  std::string discoveryUrl;

  /// True when the cycle used the legacy RegisterServer service instead of RegisterServer2.
  ///
  /// The driver falls back to RegisterServer after a target rejects RegisterServer2 with
  /// Bad_ServiceUnsupported; the fallback drops the mDNS discovery-configuration extension.
  bool usingFallbackRegisterServer{false};
};

/// Observer for the discovery-registration lifecycle of a @ref DiscoveryRegistration driver.
///
/// Implementations receive edge-triggered notifications as each target transitions between
/// established, failed, fallback, and deregistered states. The default implementations are
/// no-ops, so a subclass overrides only the events it cares about.
///
/// All notifications are posted off the driver's internal strand and may run on an unspecified
/// worker thread; implementations must not block and must not assume any particular thread.
/// Notifications for a single target are delivered in order, but no ordering is guaranteed
/// across different targets. The observer is held by `shared_ptr` for the lifetime of the
/// registration; see @ref DiscoveryRegistration::set_observer.
/// @ingroup app
/// @see DiscoveryRegistration
class DiscoveryRegistrationObserver
{
public:
  DiscoveryRegistrationObserver() = default;

  /// Destroys the observer.
  virtual ~DiscoveryRegistrationObserver() = default;

  DiscoveryRegistrationObserver(const DiscoveryRegistrationObserver&) = delete;
  DiscoveryRegistrationObserver& operator=(const DiscoveryRegistrationObserver&) = delete;
  DiscoveryRegistrationObserver(DiscoveryRegistrationObserver&&) = delete;
  DiscoveryRegistrationObserver& operator=(DiscoveryRegistrationObserver&&) = delete;

  /// Called when a target's registration is successfully established or renewed.
  ///
  /// @param info Target context, including whether the legacy RegisterServer fallback was used.
  virtual void on_registration_established([[maybe_unused]] const DiscoveryRegistrationInfo& info)
  {}

  /// Called when a registration cycle for a target fails and a retry has been scheduled. A cycle whose
  /// outcome is not Good fails: an Uncertain outcome is not counted as a registration.
  ///
  /// @param info        Target context for the failed cycle.
  /// @param status      Status code summarising the failure; always Bad. An Uncertain outcome is
  ///                    reported as Bad_InternalError whose ErrorDetail ("RegistrationAnswerUncertain")
  ///                    has the outcome's code as its cause.
  /// @param detail      Structured error detail for the failure; may be null when none is
  ///                    available. Ownership is shared and the observer may retain it.
  /// @param nextAttempt Steady-clock time point at which the next registration attempt is
  ///                    scheduled, reflecting the current backoff.
  virtual void on_registration_failed([[maybe_unused]] const DiscoveryRegistrationInfo& info,
    [[maybe_unused]] ua::StatusCode status, [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> detail,
    [[maybe_unused]] std::chrono::steady_clock::time_point nextAttempt)
  {}

  /// Called when a target transitions to using the legacy RegisterServer fallback.
  ///
  /// Signals that RegisterServer2 was rejected with Bad_ServiceUnsupported and subsequent cycles
  /// will use RegisterServer, which omits the mDNS discovery-configuration extension.
  ///
  /// @param info Target context; @ref DiscoveryRegistrationInfo::usingFallbackRegisterServer is
  ///             true.
  virtual void on_registration_fallback([[maybe_unused]] const DiscoveryRegistrationInfo& info)
  {}

  /// Called when a target has been deregistered, typically during driver shutdown.
  ///
  /// @param info Target context for the deregistered endpoint.
  virtual void on_registration_deregistered([[maybe_unused]] const DiscoveryRegistrationInfo& info)
  {}
};

/// Strand-serialized driver that keeps a server registered with one or more discovery servers (LDS).
///
/// Each configured @ref DiscoveryTarget runs an independent registration flow: an
/// open -> register -> close cycle that repeats at the configured cadence and retries failed
/// cycles with exponential backoff. The driver owns a private strand; every public method posts
/// work to it internally, so callers may invoke from any thread. Lifetime is shared: construct
/// via @ref create and hold the returned @c shared_ptr. Observer notifications are posted off the
/// strand with weak capture, so the observer must not block.
/// @ingroup app
class DiscoveryRegistration : public std::enable_shared_from_this<DiscoveryRegistration>
{
public:
  /// Snapshot of one target's registration flow.
  struct Status
  {
    std::string discoveryUrl;  ///< Discovery server this status describes.
    RegistrationState state{RegistrationState::Idle};  ///< Current phase of the flow.
    std::optional<std::chrono::steady_clock::time_point>
      lastSuccess;  ///< When the last cycle succeeded; @c nullopt if none has yet.
    std::optional<std::chrono::steady_clock::time_point>
      nextAttempt;  ///< When the next cycle is scheduled; @c nullopt if not scheduled.
    bool fallbackActive{false};  ///< Whether the flow is using the RegisterServer v1 fallback.
    ua::StatusCode lastError{};  ///< Status of the most recent cycle; good if it succeeded.
  };

  /// Creates a driver and returns shared ownership of it.
  ///
  /// The driver is created idle; call @ref start_async to begin registering. All async work runs
  /// on a private strand bound to @p executor.
  ///
  /// @param executor       Executor the driver binds its private strand to.
  /// @param registrar      Interface performing each open -> register -> close cycle; must outlive the
  ///                       driver.
  /// @param serverIdentity Identity advertised to each discovery server.
  /// @param config         Targets, cadence, backoff, and trust configuration.
  /// @return Shared owner of the new driver.
  static std::shared_ptr<DiscoveryRegistration> create(boost::asio::any_io_executor executor,
    std::shared_ptr<LdsRegistrar> registrar, ua::RegisteredServer serverIdentity,
    DiscoveryRegistrationConfig config);

  /// Starts the registration flows for all configured targets.
  ///
  /// Posts the start to the private strand and completes asynchronously. Starting an
  /// already-running driver is a no-op that still completes the callback.
  ///
  /// @param done Receives the outcome on an unspecified worker thread: a good @ref VoidResult once
  ///             the flows are started, or one carrying an @ref ErrorDetail on failure. Never
  ///             throws.
  /// @see stop_async
  void start_async(std::function<void(ua::VoidResult)> done) noexcept;

  /// Stops the driver and performs a bounded final deregister of every target.
  ///
  /// Posts the stop to the private strand and completes asynchronously. A single best-effort
  /// deregister cycle is attempted per target, bounded by
  /// @ref DiscoveryRegistrationConfig::shutdownDeregisterTimeout; the callback completes once those
  /// cycles finish or the bound elapses.
  ///
  /// @param done Receives the outcome on an unspecified worker thread: a good @ref VoidResult once
  ///             the driver has stopped, or one carrying an @ref ErrorDetail on failure. Never
  ///             throws.
  /// @see start_async
  void stop_async(std::function<void(ua::VoidResult)> done) noexcept;

  /// Retrieves a snapshot of every target's registration status.
  ///
  /// Posts the query to the private strand and completes asynchronously.
  ///
  /// @param done Receives one @ref Status per configured target, in target order, on an unspecified
  ///             worker thread. Never throws.
  void status_async(std::function<void(std::vector<Status>)> done) noexcept;

  /// Sets the observer that receives lifecycle notifications.
  ///
  /// Notifications are posted off the private strand with weak capture; the observer must not
  /// block. Pass @c nullptr to clear a previously set observer. Replaces any prior observer.
  ///
  /// @param observer Observer to notify, or @c nullptr to clear. Shared ownership is retained.
  void set_observer(std::shared_ptr<DiscoveryRegistrationObserver> observer) noexcept;

  /// Destroys the driver.
  ///
  /// Does not perform a final deregister; call @ref stop_async beforehand to deregister cleanly.
  ~DiscoveryRegistration();

  DiscoveryRegistration(const DiscoveryRegistration&) = delete;
  DiscoveryRegistration& operator=(const DiscoveryRegistration&) = delete;
  DiscoveryRegistration(DiscoveryRegistration&&) = delete;
  DiscoveryRegistration& operator=(DiscoveryRegistration&&) = delete;

private:
  DiscoveryRegistration(boost::asio::any_io_executor executor, std::shared_ptr<LdsRegistrar> registrar,
    ua::RegisteredServer serverIdentity, DiscoveryRegistrationConfig config);

  /// Per-target Step machine + backoff/fallback memo + cadence timer. Strand-owned.
  struct TargetState;

  // --- strand-serialized internals ---
  void begin_cycle(std::size_t index);
  void on_cycle_complete(std::size_t index, ua::Result<LdsRegistrar::RegisterOutcome> result);
  void handle_cycle_success(std::size_t index, bool usedFallback);
  void handle_cycle_failure(std::size_t index, ua::StatusCode status);
  void schedule_next(std::size_t index, std::chrono::seconds delay);
  void begin_shutdown_deregister(std::function<void(ua::VoidResult)> done);

  // --- observer notifications (posted off-strand, edge-triggered) ---
  void notify_established(std::size_t index, bool usedFallback);
  void notify_fallback(std::size_t index);
  void notify_failed(
    std::size_t index, ua::StatusCode status, std::chrono::steady_clock::time_point nextAttempt);
  void notify_deregistered(std::size_t index);

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;  // PRIVATE
  std::shared_ptr<LdsRegistrar> mRegistrar;
  const ua::RegisteredServer mServerIdentity;
  const DiscoveryRegistrationConfig mConfig;
  ua::Logger mLogger;

  bool mRunning{false};
  std::vector<std::unique_ptr<TargetState>> mTargets;
  std::shared_ptr<DiscoveryRegistrationObserver> mObserver;
  ua::Timer mShutdownTimer;
};

}  // namespace ua::app

#endif  // !UA_DISCOVERY_REGISTRATION_H
