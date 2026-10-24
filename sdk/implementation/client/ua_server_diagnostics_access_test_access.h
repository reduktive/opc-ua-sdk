// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_DIAGNOSTICS_ACCESS_TEST_ACCESS_H
#define UA_SERVER_DIAGNOSTICS_ACCESS_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::ServerDiagnosticsAccessor over fake interface roles, for
///        the ServerDiagnostics unit suite (see the design specification).
///
/// A friend of the accessor. It builds the accessor over a `FakeWireOps` / `FakeSupportOps` with no real
/// `ConnectionImpl`, and lets a test inject the shared @ref ua::client::detail::ServerDiagnosticsCacheState -
/// in particular its now-provider  -  so the 60 s EnabledFlag TTL behaviour is deterministically testable.

#include "ua_server_diagnostics_access.h"
#include "ua_server_diagnostics_access_state.h"

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <utility>

namespace ua::client::detail
{

/// Friend constructor for the ServerDiagnostics unit tests.
struct ServerDiagnosticsClientTestAccess
{
  /// Builds a @ref ServerDiagnosticsAccessor over @p wireOps / @p supportOps delivering on @p executor, with
  /// an explicit shared @p cacheState (its injectable now-provider drives the deterministic TTL tests).
  static ServerDiagnosticsAccessor make_accessor(std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, boost::asio::any_io_executor executor,
    std::shared_ptr<ServerDiagnosticsCacheState> cacheState, ua::Logger logger = {},
    std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory = {})
  {
    return ServerDiagnosticsAccessor{std::move(wireOps),
      std::move(supportOps),
      std::move(executor),
      std::move(logger),
      std::move(cacheState),
      std::move(emitAdvisory)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_SERVER_DIAGNOSTICS_ACCESS_TEST_ACCESS_H
