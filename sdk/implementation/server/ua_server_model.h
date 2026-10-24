// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_MODEL_H
#define UA_SERVER_MODEL_H

#include "ua_server_object.h"
#include "ua_server.h"
#include "ua_address_space.h"
#include "ua_server_configuration.h"
#include "ua_build_info.h"
#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_server_state.h"
#include "ua_subscription_router.h"

#include <atomic>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

namespace ua
{

namespace server
{

struct CombinedConfig;
struct ServerSummaryCounters;
struct SecureChannelCounters;
struct ConnectionCounters;
struct SessionCounters;
struct SessionSecurityState;
struct SessionDescriptiveState;
struct SubscriptionInfo;

/// A thread-safe snapshot of one live session's diagnostic state. The shared_ptrs keep
/// the counters/security state alive while an array read handler builds the record, even
/// if the session is torn down concurrently.
struct SessionDiagnosticsEntry
{
  std::shared_ptr<SessionCounters> counters;
  std::shared_ptr<SessionSecurityState> securityState;
  std::shared_ptr<SessionDescriptiveState> descriptiveState;
};

/// Provider returning a snapshot of all currently live sessions' diagnostic state.
/// Invoked by the SessionDiagnosticsArray / SessionSecurityDiagnosticsArray read handlers.
/// May run on any thread; the implementation takes a safe snapshot under its own lock and
/// must not hold that lock while a handler builds records.
using SessionDiagnosticsProvider = std::function<std::vector<SessionDiagnosticsEntry>()>;

/// A thread-safe snapshot of one live subscription's diagnostic state plus the NodeId of its
/// owning session. The `info` snapshot is taken from the subscription's mutex-guarded `get_info()`
/// and copied into a shared_ptr so the array read handler can build records lock-free.
struct SubscriptionDiagnosticsEntry
{
  std::shared_ptr<const SubscriptionInfo> info;
  NodeId sessionId;
};

/// Provider returning a snapshot of all currently live subscriptions' diagnostic state. Invoked by
/// the SubscriptionDiagnosticsArray / SamplingIntervalDiagnosticsArray read handlers. May run on any
/// thread; the implementation reads each subscription's cross-strand snapshot via the router.
using SubscriptionDiagnosticsProvider = std::function<std::vector<SubscriptionDiagnosticsEntry>()>;

/// Groups shared diagnostic state passed to ServerModel for handler registration.
struct DiagnosticState
{
  std::shared_ptr<ServerSummaryCounters> summaryCounters;
  std::shared_ptr<SecureChannelCounters> secureChannelCounters;
  std::shared_ptr<ConnectionCounters> connectionCounters;
  std::shared_ptr<std::atomic<bool>> enabled;

  /// Optional callback invoked when the EnabledFlag value is written. ServerImpl uses it to bring the
  /// Sessions' diagnostics objects in line with the flag, and calls the second argument once they are;
  /// the Write is answered then.
  std::function<void(bool, std::function<void()>)> onEnabledFlagChanged;

  /// Provides live-session snapshots for the session-diagnostics array nodes.
  SessionDiagnosticsProvider sessionDiagnosticsProvider;

  /// Provides live-subscription snapshots for the SubscriptionDiagnosticsArray /
  /// SamplingIntervalDiagnosticsArray nodes.
  SubscriptionDiagnosticsProvider subscriptionDiagnosticsProvider;
};

/// Heap-allocated shared state for dynamic server status / shutdown value handlers.
/// Owned by ServerImpl via shared_ptr; ExternalValueSource handler lambdas co-own it
/// so reads remain safe even if ServerImpl is destroyed while AddressSpace is still alive.
struct ServerDynamicState
{
  std::atomic<ServerState> serverState{ServerState::NoConfiguration};
  std::atomic<uint32_t> secondsTillShutdown{0};
  std::atomic<uint8_t> serviceLevel{255};  // 255 = healthy, 0 = maintenance/shutdown

  mutable std::shared_mutex mutex;
  LocalizedText shutdownReason;  // guarded by mutex
  DateTime startTime;  // set once at start()
  BuildInfo buildInfo;  // copied at construction, immutable after
};

/// One advertised ServerProfile whose required feature is not actually enabled in this configuration
/// - a conformance inconsistency surfaced at startup (logged as a warning, non-fatal).
struct ProfileFeatureInconsistency
{
  std::string profileUri;  ///< The advertised ServerProfileArray URI.
  std::string feature;  ///< Human-readable feature the profile requires.
  std::string disabledSetting;  ///< The ServerConfig setting that is currently off.
};

/// Scan the advertised `ServerProfileArray` against the SDK feature toggles and return one entry per
/// profile that claims a feature this configuration has disabled (empty = fully consistent).
///
/// A deliberately lightweight consistency check: it covers the unambiguous, boolean-gated features
/// (auditing, durable subscriptions) where advertising the profile while the feature is off would
/// mislead clients. It is NOT a feature->URI derivation engine and does not attempt a full
/// profile->capability model. The result is logged at startup; advertising is left untouched (the
/// operator chooses the profile list, so a partial claim is a warning, not a fatal error).
std::vector<ProfileFeatureInconsistency> find_advertised_profile_inconsistencies(
  const ServerConfig& serverConfig);

/// Callback to trigger graceful shutdown from the RequestServerStateChange method handler.
using ShutdownRequestHandler = std::function<void(ShutdownOptions, Server::CompleteCallback)>;

class ServerModel
{
public:
  ServerModel() = default;

  // The NS0 standard nodes (including the Server object subtree) are already imported before this
  // is called (see ServerImpl::create_standard_nodes_from_nodeset); this attaches handles and wires
  // dynamic value/method handlers.
  static ServerModel create(AddressSpace addressSpace, const CombinedConfig& config,
    const DiagnosticState& diagnostics, std::shared_ptr<ServerDynamicState> dynamicState,
    ShutdownRequestHandler shutdownHandler, Logger logger, SubscriptionRouter::Weak subscriptionRouter);

  /// Populate HistoryServerCapabilities properties by aggregating delegate capabilities, then call
  /// @p done. Called from the start continuation after all namespaces have been registered; every
  /// address-space step is awaited, so it never blocks the strand it is started from. @p done runs on
  /// an unspecified thread and receives the failure that should fail the start, if any.
  static void populate_history_capabilities_async(AddressSpace addressSpace,
    ServerConfig::HistoryConfig histConfig, ServerConfig::ServerCapabilities serverCapabilities,
    std::function<void(VoidResult)> done);

private:
  ua::ServerObject mServer;
};

}  // namespace server

}  // namespace ua

#endif  // UA_SERVER_MODEL_H
