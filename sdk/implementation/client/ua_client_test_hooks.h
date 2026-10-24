// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_TEST_HOOKS_H
#define UA_CLIENT_TEST_HOOKS_H

#include "ua_core_client.h"
#include "ua_security_policy.h"
#include "ua_transport_connection.h"

#include <cstddef>
#include <functional>
#include <memory>

namespace ua
{
class X509Certificate;
}  // namespace ua

namespace ua::client
{

class PullCertificateManager;

namespace detail
{
class PullCertificateManagerClientHost;
class ConnectionEstablisher;
}  // namespace detail

/// Test/fuzzer injection hooks for client internals.
/// These are NOT part of the public API - they exist for the fuzzer framework
/// and compliance tests to inject transport/security decorators.
struct ClientTestHooks
{
  using TransportDecorator =
    std::function<std::shared_ptr<ua::TransportConnection>(std::shared_ptr<ua::TransportConnection>)>;
  TransportDecorator transportDecorator;

  using SecurityPolicyFactory = std::function<std::shared_ptr<ua::SecurityPolicy>(ua::SecurityPolicyId)>;
  SecurityPolicyFactory securityPolicyFactory;
};

/// Friend-based accessor for setting test hooks on a Client instance.
/// Implementation is in ua_client_test_hooks.cpp.
class CoreClientTestAccess
{
public:
  static void set_test_hooks(const CoreClient& client, ClientTestHooks hooks);

  /// The shared @ref CoreClientImpl behind @p client, so a unit test can reach the impl-level surface that is
  /// not exposed on the move-only @ref Client facade (e.g. `register_connection` /
  /// `revalidate_connections_async`, W5). A friend of both @ref Client and @ref CoreClientImpl.
  [[nodiscard]] static std::shared_ptr<CoreClientImpl> impl(const CoreClient& client);

  /// The Client's Pull-Model certificate manager handle (section 8.1A / W6), or null if never started.
  /// Reaches the write-once `CoreClientImpl::mPullCertManager` for the start / CL-MULTI-001 tests.
  [[nodiscard]] static std::shared_ptr<PullCertificateManager> pull_cert_manager(const CoreClientImpl& impl);

  /// The Client's Pull-Model certificate host shim (section 8.1A / W6), or null if never started. Lets a test
  /// inject a GDS `Connection` / own-cert snapshot into the shim owned by the Client.
  [[nodiscard]] static std::shared_ptr<detail::PullCertificateManagerClientHost> pull_cert_host(
    const CoreClientImpl& impl);

  /// Swaps the Client's managed-connect tier-0 interface (section 8.2A) for @p establisher, so a unit test drives
  /// `connect_async`'s orchestration (plan -> establish -> register -> start -> deliver) against a fake
  /// establisher without a real server. Must be called before the first `connect_async`.
  static void set_connection_establisher(
    CoreClientImpl& impl, std::shared_ptr<detail::ConnectionEstablisher> establisher);

  /// The RAW size of the W5 Connection registry (`CoreClientImpl::mConnections`), including any
  /// still-registered but dead weak entries. Lets a test assert that `connect_async`'s teardown hook
  /// UNREGISTERED a Connection (the map shrinks back to 0 once every handle drops)  -  the memory-hygiene
  /// guarantee.
  [[nodiscard]] static std::size_t connection_registry_size(const CoreClientImpl& impl);
};

}  // namespace ua::client

#endif  // !UA_CLIENT_TEST_HOOKS_H
