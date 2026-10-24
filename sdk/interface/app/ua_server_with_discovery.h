// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Convenience wrapper pairing a server with a discovery-registration driver on one
/// executor.
/// @ingroup app

#ifndef UA_SERVER_WITH_DISCOVERY_H
#define UA_SERVER_WITH_DISCOVERY_H

#include "ua_discovery_registration.h"
#include "ua_result.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_x509_certificate.h"

#include <boost/asio/any_io_executor.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace ua::test_helpers
{
class ServerWithDiscoveryTestAccess;
}

namespace ua::app
{

/// Convenience wrapper pairing a @ref ua::server::Server with a @ref DiscoveryRegistration driver
/// that share a single injected executor.
///
/// The wrapper owns both halves and drives their combined lifecycle: @ref start_async brings the
/// server up and, once it has bound, creates and starts the discovery driver that keeps it
/// registered with its configured discovery servers (LDS); @ref shutdown_async tears both down in
/// order. A move-only Pimpl handle whose @c State address is stable across moves so in-flight async
/// continuations stay valid.
///
/// @ref server() is an explicit override exposing the full server API (not re-wrapped);
/// @ref registration() exposes the driver for status and observer access once start has completed.
/// @ingroup app
class ServerWithDiscovery
{
public:
  /// Creates the wrapper from an executor, the server's configuration and components, and the
  /// discovery configuration.
  ///
  /// Neither half is started; call @ref start_async to bring them up. The same executor is shared
  /// by the server and the discovery driver, and the discovery driver's registration client uses the
  /// same crypto provider as the server.
  ///
  /// @param executor         Executor on which the server and discovery driver run their async work.
  /// @param serverConfig     Configuration used to create the wrapped server.
  /// @param serverComponents The server's crypto provider (required), certificate stores,
  ///                         authenticator, Role configuration and log sink; see
  ///                         @ref ua::server::ServerComponents.
  /// @param discoveryConfig  Configuration for the discovery-registration driver (targets, cadence,
  ///                         backoff, trust override).
  /// @return The created wrapper.
  /// @throws UaException as @ref ua::server::Server::create does, including `BadConfigurationError`
  ///         for a missing crypto provider.
  /// @see try_create
  [[nodiscard]] static ServerWithDiscovery create(boost::asio::any_io_executor executor,
    ua::server::CreateConfig serverConfig, ua::server::ServerComponents serverComponents,
    DiscoveryRegistrationConfig discoveryConfig);

  /// The created @ref ServerWithDiscovery on success, or an @ref ErrorDetail on failure.
  using CreateResult = ua::Result<ServerWithDiscovery>;

  /// Creates the wrapper, returning a bad @ref CreateResult instead of throwing on failure.
  ///
  /// @param executor         Executor on which the server and discovery driver run their async work.
  /// @param serverConfig     Configuration used to create the wrapped server.
  /// @param serverComponents The server's components; see @ref ua::server::ServerComponents.
  /// @param discoveryConfig  Configuration for the discovery-registration driver.
  /// @return The constructed wrapper, or an @ref ErrorDetail on failure. Never throws.
  [[nodiscard]] static CreateResult try_create(boost::asio::any_io_executor executor,
    ua::server::CreateConfig serverConfig, ua::server::ServerComponents serverComponents,
    DiscoveryRegistrationConfig discoveryConfig) noexcept;

  /// Destroys the wrapper and both owned halves.
  ///
  /// @warning Does not perform a graceful discovery deregistration; call @ref shutdown_async and
  ///          await its completion first for an orderly teardown.
  ~ServerWithDiscovery();

  // Defined out-of-line in the .cpp where the pimpl State is complete (move-only handle).
  /// Move-constructs the wrapper, transferring ownership of both halves.
  ServerWithDiscovery(ServerWithDiscovery&&) noexcept;

  /// Move-assigns the wrapper, transferring ownership of both halves.
  ///
  /// @return Reference to this wrapper after the move.
  ServerWithDiscovery& operator=(ServerWithDiscovery&&) noexcept;

  ServerWithDiscovery(const ServerWithDiscovery&) = delete;
  ServerWithDiscovery& operator=(const ServerWithDiscovery&) = delete;

  /// Starts the server and, once it has bound, creates and starts the discovery driver.
  ///
  /// Posts the start sequence to the shared executor and completes asynchronously. The discovery
  /// driver is created only after the server has bound (so it can register the bound identity);
  /// @ref registration() becomes valid once @p done reports success.
  ///
  /// The wrapper must outlive @p done. A @ref shutdown_async begun while start is still seeding trust
  /// (before the driver is created) makes the start complete with `Bad_Shutdown` and creates no driver;
  /// one begun after the driver is created stops it once it has started. @ref shutdown_async may be
  /// called from any thread, including while start is in flight.
  ///
  /// @param done Receives the outcome: an empty @ref ua::VoidResult on success, or one carrying an
  ///             @ref ua::ErrorDetail if the server or driver failed to start. This overload never
  ///             throws.
  /// @see shutdown_async, registration, start_sync
  void start_async(std::function<void(ua::VoidResult)> done) noexcept;

  /// Starts the server and the discovery driver, blocking until complete.
  ///
  /// @throws UaException carrying the failure, including `Bad_WouldBlock` when called on a thread of
  ///         the wrapper's executor, which would have to run the start.
  /// @see start_async, try_start_sync
  void start_sync();

  /// Starts the server and the discovery driver, blocking until complete.
  ///
  /// @return An empty @ref ua::VoidResult on success, or one carrying an @ref ua::ErrorDetail, with
  ///         `Bad_WouldBlock` on a thread of the wrapper's executor and otherwise as @ref start_async.
  ///         Never throws.
  /// @see start_async, start_sync
  [[nodiscard]] ua::VoidResult try_start_sync() noexcept;

  /// Stops the discovery driver (with a bounded final deregister) and then shuts the server down with
  /// default @ref ua::server::ShutdownOptions (the server's configured grace period, no reason).
  ///
  /// Posts the teardown sequence to the shared executor and completes asynchronously. The wrapper must
  /// outlive @p done.
  ///
  /// @param done Receives the outcome: an empty @ref ua::VoidResult on success, or one carrying an
  ///             @ref ua::ErrorDetail on failure. This overload never throws.
  /// @see start_async, shutdown_sync
  void shutdown_async(std::function<void(ua::VoidResult)> done) noexcept;

  /// Stops the discovery driver and then shuts the server down with @p options, as
  /// @ref ua::server::Server::shutdown_async does.
  ///
  /// @param options The grace period and reason passed to the server's shutdown.
  /// @param done    Receives the outcome, as for the overload without options. Never throws.
  void shutdown_async(ua::server::ShutdownOptions options, std::function<void(ua::VoidResult)> done) noexcept;

  /// Stops the discovery driver and then shuts the server down, blocking until complete.
  ///
  /// @param options The grace period and reason passed to the server's shutdown.
  /// @throws UaException carrying the failure, including `Bad_WouldBlock` when called on a thread of
  ///         the wrapper's executor.
  /// @see shutdown_async, try_shutdown_sync
  void shutdown_sync(ua::server::ShutdownOptions options = {});

  /// Stops the discovery driver and then shuts the server down, blocking until complete.
  ///
  /// @param options The grace period and reason passed to the server's shutdown.
  /// @return An empty @ref ua::VoidResult on success, or one carrying an @ref ua::ErrorDetail, with
  ///         `Bad_WouldBlock` on a thread of the wrapper's executor and otherwise as @ref shutdown_async.
  ///         Never throws.
  /// @see shutdown_async, shutdown_sync
  [[nodiscard]] ua::VoidResult try_shutdown_sync(ua::server::ShutdownOptions options = {}) noexcept;

  /// Returns the wrapped server, exposing the full server API.
  ///
  /// The returned reference is owned by this wrapper and remains valid for its lifetime.
  ///
  /// @return The wrapped @ref ua::server::Server (explicit override - not re-wrapped).
  ua::server::Server& server() noexcept;  // explicit override - full server API, not re-wrapped

  /// Returns the discovery-registration driver for status and observer access.
  ///
  /// The returned reference is owned by this wrapper and remains valid for its lifetime.
  ///
  /// @return The @ref DiscoveryRegistration driver.
  /// @throws UaException with `Bad_InvalidState` and an @ref ErrorDetail (`RegistrationNotStarted`)
  ///         before a successful @ref start_async has created the driver.
  DiscoveryRegistration& registration();

private:
  friend class ::ua::test_helpers::ServerWithDiscoveryTestAccess;

  ServerWithDiscovery(boost::asio::any_io_executor executor, ua::server::CreateConfig serverConfig,
    ua::server::ServerComponents serverComponents, DiscoveryRegistrationConfig discoveryConfig);

  struct State;

  /// Seeds the registration client's trust store: from `ldsTrustOverride` when set, otherwise by
  /// mirroring the server's application-group store - trusted and issuer certificates AND their
  /// CRLs, because the client store validates with the server's revocation policy and a
  /// CA-issued LDS certificate whose CRL is missing fails as revocation-unknown. Static + takes
  /// `State*` (not `this`) so async continuations survive a move of the wrapper handle: the pimpl
  /// State address is stable across a move, whereas `this`/mState is not.
  ///
  /// @param state  Stable pimpl @c State pointer (not @c this).
  /// @param seeded Receives an empty @ref ua::VoidResult once seeding has run (a list that cannot be
  ///               read or added is skipped: seeding is best-effort and SecurityMode::None
  ///               registration needs none of it), or a failure when the work could not be queued.
  static void seed_client_trust(State* state, std::function<void(ua::VoidResult)> seeded) noexcept;

  /// The rest of start once trust is seeded: creates and starts the registration driver, unless a
  /// @ref shutdown_async has begun, in which case @p done receives `Bad_Shutdown` and no driver is
  /// created. Static + `State*` for the same reason as `seed_client_trust`.
  static void finish_start(State* state, ua::RegisteredServer serverIdentity, ua::VoidResult seeded,
    std::function<void(ua::VoidResult)> done) noexcept;

  std::unique_ptr<State> mState;
};

/// Stops a @ref ua::app::ServerWithDiscovery as part of a @ref ua::Runtime shutdown: deregisters, then
/// shuts the server down with the policy's grace period and reason.
///
/// Declared in `ua::app` so argument-dependent lookup finds it from @ref ua::Runtime::attach. An unset
/// @ref ua::ShutdownPolicy::grace stays unset, so the server uses its own configured grace period, as
/// for an attached @ref ua::server::Server.
///
/// @param wrapper The wrapper being stopped.
/// @param context The resolved policy, deadline and logger for this shutdown.
inline void runtime_shutdown(ServerWithDiscovery& wrapper, const ua::ShutdownContext& context)
{
  wrapper.shutdown_sync(
    ua::server::ShutdownOptions{.grace = context.policy.grace, .reason = context.policy.reason});
}

}  // namespace ua::app

#endif  // !UA_SERVER_WITH_DISCOVERY_H
