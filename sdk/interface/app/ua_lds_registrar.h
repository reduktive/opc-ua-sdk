// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstraction that performs one LDS register/deregister cycle per call.
/// @ingroup app

#ifndef UA_LDS_REGISTRAR_H
#define UA_LDS_REGISTRAR_H

#include "ua_registered_server.h"
#include "ua_result.h"
#include "ua_structure.h"

#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{
class CoreClient;
}  // namespace ua::client

namespace ua::app
{

struct DiscoveryTarget;

/// Performs a single open -> register -> close cycle against one discovery server (LDS).
///
/// This is the narrow interface the discovery-registration driver depends on, so the driver's state
/// machine can be exercised without a real socket. One @ref register_async call encapsulates the
/// whole cycle against one @ref DiscoveryTarget. Deregistration is not a separate method: it is a
/// @ref register_async call whose @ref ua::RegisteredServer carries `isOnline == false`.
///
/// @ingroup app
class LdsRegistrar
{
public:
  LdsRegistrar() = default;
  virtual ~LdsRegistrar() = default;

  LdsRegistrar(const LdsRegistrar&) = delete;
  LdsRegistrar& operator=(const LdsRegistrar&) = delete;
  LdsRegistrar(LdsRegistrar&&) = delete;
  LdsRegistrar& operator=(LdsRegistrar&&) = delete;

  /// Result of a successful register/deregister cycle.
  struct RegisterOutcome
  {
    bool usedFallback{false};  ///< True when the cycle fell back to RegisterServer (v1) because
                               ///< the discovery server did not support RegisterServer2.
  };

  /// Receives the outcome of a @ref register_async cycle: on success the @ref RegisterOutcome,
  /// on failure an @ref ua::ErrorDetail.
  using RegisterResultCallback = std::function<void(ua::Result<RegisterOutcome>)>;

  /// Runs one open -> register -> close cycle against @p target.
  ///
  /// Opens a fresh session-less secure channel to @p target, sends RegisterServer2 (or the
  /// memoised RegisterServer fallback), and closes - all within this single call. The cycle
  /// completes asynchronously and never throws; the outcome is delivered through @p callback.
  ///
  /// @param target                 Discovery endpoint to register with.
  /// @param server                 Fully-populated server registration to publish. `isOnline` is
  ///                               set by the caller: `true` registers, `false` deregisters.
  /// @param discoveryConfiguration mDNS discovery-configuration extensions. Carried by
  ///                               RegisterServer2 and dropped by the RegisterServer (v1) fallback.
  /// @param preferFallback         When `true`, skips RegisterServer2 and goes straight to
  ///                               RegisterServer.
  /// @param callback               Receives the outcome. On success the @ref RegisterOutcome
  ///                               reports whether the v1 fallback was used: the implementation
  ///                               falls back from RegisterServer2 to RegisterServer transparently
  ///                               within this one cycle, so a `usedFallback` of `true` is the
  ///                               caller's cue to memoise @p preferFallback for later cycles. On
  ///                               failure the Result carries an @ref ua::ErrorDetail whose status
  ///                               reflects where the cycle failed (open, RegisterServer2, or the
  ///                               fallback RegisterServer). @ref DiscoveryRegistration counts
  ///                               only a Good Result as a registered cycle; an Uncertain one, with
  ///                               or without a RegisterOutcome, is a failed cycle. This overload
  ///                               never throws.
  virtual void register_async(DiscoveryTarget target, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool preferFallback,
    RegisterResultCallback callback) noexcept = 0;
};

/// Client-backed @ref LdsRegistrar that drives each cycle through a long-lived OPC UA client.
///
/// Holds a shared @ref ua::client::Client for the registrar's lifetime and uses it to run one
/// open -> register -> close cycle per @ref register_async call.
///
/// @ingroup app
class ClientLdsRegistrar : public LdsRegistrar
{
public:
  /// Constructs a registrar backed by @p client.
  ///
  /// @param client Client used to open the registration channel. Retained for the registrar's
  ///               lifetime; must not be null.
  explicit ClientLdsRegistrar(std::shared_ptr<ua::client::CoreClient> client) noexcept;

  ~ClientLdsRegistrar() override;

  ClientLdsRegistrar(const ClientLdsRegistrar&) = delete;
  ClientLdsRegistrar& operator=(const ClientLdsRegistrar&) = delete;
  ClientLdsRegistrar(ClientLdsRegistrar&&) = delete;
  ClientLdsRegistrar& operator=(ClientLdsRegistrar&&) = delete;

  /// Runs one open -> register -> close cycle against @p target using the held client.
  ///
  /// @param target                 Discovery endpoint to register with.
  /// @param server                 Server registration to publish; `isOnline` selects registering
  ///                               (`true`) or deregistering (`false`).
  /// @param discoveryConfiguration mDNS discovery-configuration extensions, carried by
  ///                               RegisterServer2 and dropped by the RegisterServer (v1) fallback.
  /// @param preferFallback         When `true`, skips RegisterServer2 and goes straight to
  ///                               RegisterServer.
  /// @param callback               Receives the outcome: the `RegisterOutcome` on success or an
  ///                               @ref ua::ErrorDetail on failure. The code the discovery server
  ///                               answered RegisterServer2 or RegisterServer with is kept on the
  ///                               outcome: a Good subcode, or an Uncertain code with the outcome.
  ///                               A channel or GetEndpoints answer that is not Good is not used:
  ///                               the cycle fails, an Uncertain answer with Bad_InternalError and
  ///                               that code as the cause. Never throws.
  /// @see LdsRegistrar::register_async for the full parameter and result contract.
  void register_async(DiscoveryTarget target, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool preferFallback,
    RegisterResultCallback callback) noexcept override;

private:
  std::shared_ptr<ua::client::CoreClient> mClient;
};

}  // namespace ua::app

#endif  // !UA_LDS_REGISTRAR_H
