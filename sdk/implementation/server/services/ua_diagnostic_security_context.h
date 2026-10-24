// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIAGNOSTIC_SECURITY_CONTEXT_H
#define UA_DIAGNOSTIC_SECURITY_CONTEXT_H

#include "ua_server_configuration.h"

namespace ua::server
{

/// Captures the security posture of a request for diagnostic gating decisions.
///
/// Created at the Session/SecureChannel shell level and passed to the service.
/// Internal to the service core - not exposed to namespace implementations or user code.
struct DiagnosticSecurityContext
{
  /// True if the session is in the Activated state (post-authentication).
  bool authenticated = false;

  /// True if the secure channel uses a non-None SecurityPolicy.
  bool securedChannel = false;

  /// The effective diagnostic level for this session - already resolved from
  /// the server's DiagnosticPolicy and the authenticated user's claims via
  /// resolve_diagnostic_level(). For pre-auth requests, this is Level::None.
  ServerConfig::DiagnosticPolicy::Level effectiveLevel = ServerConfig::DiagnosticPolicy::Level::None;

  /// Whether to mask pre-auth StatusCodes (from server policy).
  bool maskPreAuthErrors = true;
};

}  // namespace ua::server

#endif  // !UA_DIAGNOSTIC_SECURITY_CONTEXT_H
