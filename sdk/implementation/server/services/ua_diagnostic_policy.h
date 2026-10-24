// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIAGNOSTIC_POLICY_H
#define UA_DIAGNOSTIC_POLICY_H

#include "ua_claim_keys.h"
#include "ua_server_authentication.h"
#include "ua_diagnostic_security_context.h"
#include "ua_message_security_mode.h"
#include "ua_server_configuration.h"

namespace ua::server::detail
{

/// Resolve the effective diagnostic level for a session from the server's
/// policy and the authenticated user's claims.
///
/// The server's maxLevel is the absolute ceiling. The user's claims can
/// elevate from defaultLevel up to maxLevel, but never beyond it.
/// The authenticator does not need to know about diagnostics - it returns
/// claims, and this function interprets them.
///
/// A session holding the SecurityAdmin Role counts as claiming DiagnosticsFull (owner decision
/// 2026-10-03, D-b): OPC 10000-12 7.8.2.3 requires a refused TrustList update to name the invalid
/// Certificate(s) in its DiagnosticInfo, and only SecurityAdmin may make that update. maxLevel still caps
/// it.
inline ServerConfig::DiagnosticPolicy::Level resolve_diagnostic_level(
  const ServerConfig::DiagnosticPolicy& policy, const UserIdentity& user, bool holdsSecurityAdmin = false)
{
  using Level = ServerConfig::DiagnosticPolicy::Level;

  // Ceiling check - if the server disallows all diagnostics, done.
  if (policy.maxLevel == Level::None)
  {
    return Level::None;
  }

  // Check claims in descending privilege order.
  if (policy.maxLevel == Level::Full &&
      (holdsSecurityAdmin || user.claims.contains(ClaimKeys::diagnosticsFull)))
  {
    return Level::Full;
  }

  if (policy.maxLevel >= Level::Summary &&
      (holdsSecurityAdmin || user.claims.contains(ClaimKeys::diagnosticsSummary)))
  {
    return Level::Summary;
  }

  // No diagnostic claims - use server default.
  return policy.defaultLevel;
}

/// Build a DiagnosticSecurityContext for an authenticated session.
/// Called from services that have access to both the session security context
/// and the server configuration.
inline DiagnosticSecurityContext make_diagnostic_security_context(const EndpointSecurityContext& endpoint,
  const UserIdentity& user, const ServerConfig::DiagnosticPolicy& policy, bool holdsSecurityAdmin = false)
{
  DiagnosticSecurityContext ctx;
  ctx.authenticated = true;  // services are only dispatched for activated sessions
  ctx.securedChannel = (endpoint.messageSecurityMode != ua::MessageSecurityMode::None);
  ctx.effectiveLevel = resolve_diagnostic_level(policy, user, holdsSecurityAdmin);
  ctx.maskPreAuthErrors = false;  // post-auth - no masking
  return ctx;
}

}  // namespace ua::server::detail

#endif  // !UA_DIAGNOSTIC_POLICY_H
