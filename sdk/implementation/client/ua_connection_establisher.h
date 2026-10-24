// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_ESTABLISHER_H
#define UA_CONNECTION_ESTABLISHER_H

/// @file
/// @brief Tier-0 connect interface for the managed connect path (section 8.2A): open channel -> CreateSession
/// ->
///        ActivateSession -> construct a ConnectionImpl.
/// @ingroup client

#include "ua_connect_plan.h"  // ConnectPlan (+ CoreClient::OpenChannelConfig, detail::ConnectionConfig, ...)
#include "ua_byte_string.h"
#include "ua_logger.h"
#include "ua_observer_sink.h"  // ObserverSlots
#include "ua_result.h"
#include "ua_session_ops.h"  // ReopenChannelOps, ChannelOps, SessionOps

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>

namespace ua::client::detail
{

class ConnectionImpl;

/// Tier-0 connect interface (the design specification): runs open-channel -> CreateSession -> ActivateSession
/// per
/// a
/// @ref ConnectPlan and constructs (does NOT start) a @ref ConnectionImpl. Abstracted so
/// @ref CoreClientImpl::connect_async's registration / start / handle-delivery orchestration is unit-tested
/// against a trivial fake, while the concrete @ref RealConnectionEstablisher's own sequencing +
/// partial-failure cleanup is unit-tested over the tier-0 fakes.
class ConnectionEstablisher
{
public:
  virtual ~ConnectionEstablisher() = default;

  /// Establishes the tier-0 session and constructs the tier-1 orchestrator.
  ///
  /// @pre @p plan `.valid == true`  -  @ref CoreClientImpl::connect_async rejects an invalid plan (endpoint
  ///      selection / URL) before establishing, so the establisher only ever sees runnable plans.
  /// @param plan The translated connect parameters (channel open / CreateSession / Activate / impl config /
  ///             reconnect). Consumed.
  /// @param clientObserverDefaults The Client-level observer defaults, resolved against the plan's
  ///        per-Connection slots inside @ref ConnectionImpl::create_from_ops (per-Connection non-null wins).
  /// @param callback Receives a ready-but-UNSTARTED @ref ConnectionImpl on success (the caller then runs
  ///        @ref ConnectionImpl::start_async), or a bad Result carrying the failing tier-0 step's status +
  ///        ErrorDetail. Delivered on the client executor.
  virtual void establish_async(ConnectPlan plan, ObserverSlots clientObserverDefaults,
    std::function<void(ua::Result<std::shared_ptr<ConnectionImpl>>)> callback) = 0;

protected:
  ConnectionEstablisher() = default;
  ConnectionEstablisher(const ConnectionEstablisher&) = default;
  ConnectionEstablisher& operator=(const ConnectionEstablisher&) = default;
  ConnectionEstablisher(ConnectionEstablisher&&) = default;
  ConnectionEstablisher& operator=(ConnectionEstablisher&&) = default;
};

/// Production @ref ConnectionEstablisher. Drives the tier-0 connect over an INJECTABLE open-channel interface
/// (so its own logic is unit-testable without a real server): open a channel via the interface ->
/// @ref ChannelOps::create_session_async -> @ref SessionOps::activate_on_bound_channel_async (identity from
/// the plan) -> @ref ConnectionImpl::create_from_ops. The SAME open interface is reused verbatim as the
/// reconnect reopen wiring, so a reconnect re-opens with the identical secured config (no downgrade).
///
/// Partial-failure cleanup: an ActivateSession failure `CloseSession`s the freshly-created (Created) session
/// so it does not linger to the server session-timeout (resource-leak / DoS); a CreateSession failure drops
/// the channel (its transport is closed on destruction  -  @ref ChannelOps exposes no explicit close).
class RealConnectionEstablisher : public ConnectionEstablisher
{
public:
  /// Given the plan's channel-open parameters, yields a @ref ReopenChannelOps that opens a fresh channel to
  /// that endpoint (reused verbatim for reconnect reopens). Production binds a weak `CoreClientImpl`; tests
  /// inject a fake that yields a scripted channel.
  using OpenChannelOpsFactory =
    std::function<ReopenChannelOps(const ua::client::CoreClient::OpenChannelConfig&)>;

  /// Given the plan's channel-open parameters, yields a @ref detail::ServerCertValidator (the type is spelled
  /// out here  -  `std::function<void(std::function<void(ua::VoidResult)>)>`  -  so this header need not pull
  /// in the heavy `ua_connection_impl.h`). The returned interface re-validates the connection's server
  /// certificate against the Client certificate store on demand (CL-SECADMIN-004 / CL-PULLCRT-006 /
  /// CL-RECONN-006). Production binds a weak `CoreClientImpl` (store read at validation time so it sees the
  /// CURRENT trust material); an EMPTY factory (or one that returns an empty interface) leaves the Connection
  /// without immediate revalidation (single-shot / no-store paths).
  using ServerCertValidatorFactory = std::function<std::function<void(std::function<void(ua::VoidResult)>)>(
    const ua::client::CoreClient::OpenChannelConfig&)>;

  /// Decodes the DER certificate advertised by GetEndpoints. Discovery-driven selection needs the concrete
  /// certificate before it can verify the certificate ApplicationUri and open the final SecureChannel.
  using ServerCertificateDecoder =
    std::function<ua::Result<std::shared_ptr<const ua::X509Certificate>>(const ua::ByteString&)>;

  RealConnectionEstablisher(boost::asio::any_io_executor executor, ua::Logger logger,
    OpenChannelOpsFactory openOpsFactory, ServerCertValidatorFactory serverCertValidatorFactory = {},
    ServerCertificateDecoder serverCertificateDecoder = {}, bool allowDeprecatedSecurityPolicies = false);

  void establish_async(ConnectPlan plan, ObserverSlots clientObserverDefaults,
    std::function<void(ua::Result<std::shared_ptr<ConnectionImpl>>)> callback) override;

private:
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;
  OpenChannelOpsFactory mOpenOpsFactory;
  ServerCertValidatorFactory mServerCertValidatorFactory;
  ServerCertificateDecoder mServerCertificateDecoder;
  /// The application's `mAllowDeprecatedSecurityPolicies`: AutoBest skips a deprecated policy unless it is
  /// set, the way the Discovery facade filters the list easy_connect ranks (CL-DISC-019).
  bool mAllowDeprecatedSecurityPolicies = false;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_ESTABLISHER_H
