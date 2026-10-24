// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The pimpl State of ServerWithDiscovery. Private to the implementation: included by
// ua_server_with_discovery.cpp and by the header-only test access, never by the public interface.

#ifndef UA_SERVER_WITH_DISCOVERY_STATE_H
#define UA_SERVER_WITH_DISCOVERY_STATE_H

#include "ua_certificate_store.h"
#include "ua_core_client.h"
#include "ua_discovery_registration.h"
#include "ua_lds_registrar.h"
#include "ua_server.h"
#include "ua_server_with_discovery.h"

#include <boost/asio/any_io_executor.hpp>

#include <filesystem>
#include <memory>
#include <mutex>
#include <system_error>

namespace ua::app
{

// The wrapper owns the Server by unique_ptr (Server is move-only and we hand out a reference);
// the Client/registrar/cert-store/registration are shared so the (defaulted) move keeps the
// move-only wrapper cheap and so the registrar can hold the long-lived Client strong.
struct ServerWithDiscovery::State
{
  State() = default;
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  State(State&&) = delete;
  State& operator=(State&&) = delete;

  ~State()
  {
    // The registrar's trust belongs to this instance alone; nothing else reads the directory.
    if (!clientTrustDirectory.empty())
    {
      std::error_code ignored;
      std::filesystem::remove_all(clientTrustDirectory, ignored);
    }
  }

  boost::asio::any_io_executor executor;
  DiscoveryRegistrationConfig discoveryConfig;

  std::unique_ptr<ua::server::Server> server;
  std::filesystem::path clientTrustDirectory;
  std::shared_ptr<ua::CertificateStore> clientCertStore;
  std::shared_ptr<ua::client::CoreClient> client;
  std::shared_ptr<ClientLdsRegistrar> registrar;
  std::shared_ptr<DiscoveryRegistration> registration;
  /// Orders the end of start against the start of shutdown on a multi-threaded executor: start checks
  /// stopping, creates the driver and posts its start under it; shutdown sets stopping and takes the
  /// driver under it. So either start sees the shutdown and creates nothing, or the shutdown sees the
  /// driver and its stop is posted after the driver's start. Recursive because a completion that runs
  /// inline (a post that failed) may call shutdown_async from inside start.
  std::recursive_mutex lifecycleMutex;
  /// Set when shutdown_async begins; a start that has not yet created the driver then completes with
  /// Bad_Shutdown instead of creating it over a registrar the shutdown is releasing.
  bool stopping{false};
};

}  // namespace ua::app

#endif  // !UA_SERVER_WITH_DISCOVERY_STATE_H
