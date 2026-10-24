// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECT_PLAN_H
#define UA_CONNECT_PLAN_H

/// @file
/// @brief Pure translation of a user @ref ua::client::ConnectionConfig into the tier-0/tier-1 sub-configs
///        the managed connect path drives (client section 7.3 / section 8.2A).
/// @ingroup client

#include "ua_core_client.h"  // ua::client::Client::OpenChannelConfig, ConnectMode
#include "ua_client_secure_channel.h"  // ua::client::SecureChannel::CreateSessionConfig
#include "ua_client_session.h"  // ua::client::Session::ActivateConfig
#include "ua_connection_config.h"  // ua::client::ConnectionConfig (public input)
#include "ua_connection_impl.h"  // detail::ConnectionConfig, detail::KeepAlivePolicy
#include "ua_reconnect_policy.h"  // ua::client::ReconnectPolicy
#include "ua_status_code.h"

#include <chrono>
#include <optional>
#include <vector>

namespace ua::client::detail
{

/// The fully-translated, interface-neutral connect parameters produced by @ref build_connect_plan.
///
/// This is PURE DATA: it holds NO closures and NO live @ref ua::client::Client. In particular the reconnect
/// reopen step is represented by @ref channelOpen (the exact @ref ua::client::Client::OpenChannelConfig,
/// security preserved verbatim)  -  the `ReopenChannel` closure that binds a weak Client to it is assembled
/// by the establisher, NOT here, which is what keeps this translation unit-testable in isolation.
struct ConnectPlan
{
  /// True when the config translated to a runnable plan; when false @ref error explains why and the other
  /// fields are unspecified.
  bool valid = false;

  /// `Good` when @ref valid; otherwise a source-tagged bad status (e.g. `Bad_NotImplemented` for a
  /// not-yet-wired @ref ua::client::EndpointSelection, `Bad_InvalidArgument` for an empty URL).
  ua::StatusCode error;

  /// The SecureChannel open parameters  -  used for the INITIAL open AND every reconnect reopen (so the full
  /// secured config is preserved; a reconnect cannot silently downgrade to a URL-only reopen).
  ua::client::CoreClient::OpenChannelConfig channelOpen;

  /// The CreateSession parameters (name / requested timeout).
  ua::client::SecureChannel::CreateSessionConfig createSession;

  /// Whether the managed path uses the explicit endpoint verbatim or performs an unauthenticated
  /// GetEndpoints selection before opening the final SecureChannel.
  ua::client::EndpointSelection endpointSelection{ua::client::EndpointSelection::ExactUrl};

  /// Mirrors @ref ua::client::ConnectionConfig::allowUnsecuredEndpoint: whether AutoBest may select an
  /// endpoint with mode None or policy None for this connection (CL-DISC-019).
  bool allowUnsecuredEndpoint = false;

  /// The ActivateSession parameters (user-token policy id / identity / locales). Also reused verbatim as the
  /// reconnect re-activation config so a reconnect re-authenticates with the same identity (CL-RECONN-002).
  ua::client::Session::ActivateConfig activate;

  /// The tier-1 @ref ConnectionImpl dispatch/observer/endpoint config.
  ConnectionConfig implConfig;

  /// True when @ref ua::client::ConnectionConfig::reconnect is engaged (auto-reconnect + keep-alive); false
  /// for a single-shot Connection (no FSM, no keep-alive).
  bool autoReconnect = false;

  /// The reconnect backoff/attempt policy (meaningful only when @ref autoReconnect).
  ua::client::ReconnectPolicy reconnectPolicy;

  /// The keep-alive poll policy (meaningful only when @ref autoReconnect  -  a miss drives the FSM).
  KeepAlivePolicy keepAlive;

  /// Opt in to server-redundancy monitoring (CL-REDUN). Mirrors @ref ConnectionConfig::enableRedundancy.
  bool enableRedundancy = false;

  /// Overall connect deadline covering channel-open + CreateSession + ActivateSession + bootstrap
  /// (`ConnectionConfig::connectTimeout`). `nullopt` (or `<= 0`) means no overall deadline. `connect_async`
  /// arms a single soft timer for the whole chain: on expiry it delivers `Bad_Timeout` through the fire-once
  /// gate (in-flight tier-0 work continues but its result is discarded).
  std::optional<std::chrono::milliseconds> connectTimeout;
};

/// Translates a user @ref ua::client::ConnectionConfig into a @ref ConnectPlan. Pure and deterministic: no
/// I/O, no clock, no `Client`. Rejects (via @ref ConnectPlan::valid = false + a source-tagged
/// @ref ConnectPlan::error) an unwired @ref ua::client::EndpointSelection or an empty endpoint URL.
/// @p discoveryEndpoints is internal evidence captured by EasyConnect; when present it is carried
/// into CreateSession so OPC 10000-4 section 5.4.1 cross-checks cannot be skipped.
[[nodiscard]] ConnectPlan build_connect_plan(
  const ua::client::ConnectionConfig& config, std::vector<ua::EndpointDescription> discoveryEndpoints = {});

/// Whether @p endpoint offers a UserName or IssuedToken token policy, the token types whose secret an
/// EphemeralKey protects (OPC 10000-6 section 6.8.2). A CreateSession to an endpoint offering neither asks
/// for no EphemeralKey: no activation there could use it, and a Server may fault the request instead of
/// answering in the ECDHKey slot (AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY;
/// interoperability finding 021). One pass over the endpoint's token policies.
[[nodiscard]] bool offers_secret_token_policy(const ua::EndpointDescription& endpoint);

}  // namespace ua::client::detail

#endif  // UA_CONNECT_PLAN_H
