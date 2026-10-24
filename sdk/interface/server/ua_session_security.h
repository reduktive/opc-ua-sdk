// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-session security state backing the SessionSecurityDiagnostics node, and the read-only
///        security context a server session exposes to service handlers.
/// @ingroup server

#ifndef UA_SESSION_SECURITY_H
#define UA_SESSION_SECURITY_H

#include "ua_server_authentication.h"

#include "ua_byte_string.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_namespace_authorization.h"
#include "ua_error_detail.h"
#include "ua_request_info.h"

#include <memory>
#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

// Forward-declared in the namespace that OWNS them. Declaring them inside ua::server instead
// created DIFFERENT types - ua::server::UserIdentity distinct from ua::UserIdentity - which
// collided with the `using ::ua::UserIdentity;` that ua_server_authentication.h brings into the
// same namespace. Clang 17 rejects it outright ("declaration conflicts with target of using
// declaration already in scope", then every later reference ambiguous); GCC happened to tolerate
// it, which is why the primary toolchain never noticed.
namespace ua
{
struct EndpointSecurityContext;
struct UserIdentity;
}  // namespace ua

namespace ua::server
{

// Same aliasing ua_server_authentication.h declares, so ua::server::UserIdentity and
// ua::UserIdentity are one type rather than two that merely share a name.
using ::ua::EndpointSecurityContext;
using ::ua::UserIdentity;

/// Per-session security facts exposed as SessionSecurityDiagnosticsDataType.
///
/// Mirrors the OPC UA `SessionSecurityDiagnosticsDataType` (Part 5) for one
/// session: the bound user, the negotiated channel security, and the client
/// certificate. Populated at activation and read back to service the session's
/// diagnostics node.
///
/// @note The fields are written on the owning session's strand and read by the
///       diagnostics Variables' value sources on whichever thread serves the Read, so
///       both sides hold @ref mutex. @ref update_on_activate takes it itself.
/// @ingroup server
struct SessionSecurityState
{
  /// Guards every field below. Writers on the session's strand and the diagnostics readers both
  /// hold it; it is held only to copy fields, never across a call out.
  mutable std::mutex mutex;

  NodeId sessionId;  ///< NodeId of the session these diagnostics describe.

  std::string clientUserId;  ///< User identifier currently bound to the session; empty before activation.

  /// Active user identifiers observed by the session, oldest first, with the current user last.
  ///
  /// An entry is appended only when @ref update_on_activate changes the active user; the empty
  /// pre-activation identity is never recorded. A session re-activated with the same identity leaves
  /// this list unchanged. The list keeps the most recent @ref maxClientUserIdHistory entries: a client
  /// that alternates between identities on one session would otherwise grow it without end.
  std::vector<std::string> clientUserIdHistory;

  /// The most entries @ref clientUserIdHistory holds; the oldest is dropped when another is appended.
  static constexpr std::size_t maxClientUserIdHistory{32};

  /// URI of the user-token policy / authentication mechanism used at activation.
  std::string authenticationMechanism;

  std::string encoding{"UA Binary"};  ///< Message encoding negotiated for the session.

  std::string transportProtocol{"opc.tcp"};  ///< URL scheme of the session's transport.

  MessageSecurityMode securityMode{};  ///< Message security mode negotiated on the secure channel.

  std::string securityPolicyUri;  ///< URI of the security policy negotiated on the secure channel.

  ByteString
    clientCertificate;  ///< Client application instance certificate (DER); empty when none was provided.

  /// Refreshes the user-identity and channel-security fields for a session activation.
  ///
  /// Sets @ref clientUserId, @ref authenticationMechanism, @ref securityMode and
  /// @ref securityPolicyUri from @p user and @p endpoint. When the active user
  /// actually changes, the newly active identifier is appended to
  /// @ref clientUserIdHistory (per the Part 5 rule "each time the active user
  /// changes, an entry shall be made at the end of the array"), dropping the oldest entry once
  /// the history holds @ref maxClientUserIdHistory; a re-activation with
  /// the same identity leaves the history untouched. Does not modify @ref encoding or
  /// @ref transportProtocol. Call once per successful activation.
  ///
  /// @param user     Identity bound to the session by the completed authentication.
  /// @param endpoint Negotiated endpoint security context for the activating channel.
  /// @pre Invoked on the owning session's strand, without @ref mutex held.
  void update_on_activate(const UserIdentity& user, const EndpointSecurityContext& endpoint);
};

/// Read-only view of a session's security state, exposed to service handlers.
///
/// Implemented by server sessions to surface the identity, negotiated endpoint,
/// and authorization state that services need for per-item access gating. The
/// interface is intentionally minimal and never exposes stack secrets (no
/// passwords, private keys, or channel secrets).
///
/// Accessors are called on the session's service-dispatch path. The returned
/// `shared_ptr`s are snapshots: services should use them within a single
/// service call and must not cache them across calls, because the underlying
/// identity may be replaced on re-activation.
///
/// @ingroup security
/// @see EndpointSecurityContext, UserIdentity
class SessionSecurityContext
{
public:
  virtual ~SessionSecurityContext() = default;

  SessionSecurityContext(const SessionSecurityContext&) = delete;
  SessionSecurityContext& operator=(const SessionSecurityContext&) = delete;
  SessionSecurityContext(SessionSecurityContext&&) = delete;
  SessionSecurityContext& operator=(SessionSecurityContext&&) = delete;

  /// Returns the `NodeId` identifying this session, as assigned at CreateSession.
  ///
  /// @return The NodeId identifying this session.
  virtual ua::NodeId session_id() const = 0;

  /// Returns the negotiated, non-secret endpoint security context.
  ///
  /// Carries the message security mode, security policy, and endpoint metadata
  /// the channel was established with. Never null for an active session; the
  /// pointed-to context is immutable for the session's lifetime.
  ///
  /// @return Shared snapshot of the endpoint security context.
  virtual std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const = 0;

  /// Returns the SDK-owned identity bound to the session at the last activation.
  ///
  /// The identity may change between activations - OPC UA permits re-activating
  /// a session with a different identity - so consumers must not cache the
  /// pointer across service calls. May be null before the session is activated.
  ///
  /// @return Shared snapshot of the active user identity, or null pre-activation.
  virtual std::shared_ptr<const ua::server::UserIdentity> user_identity() const = 0;

  /// Returns the complete access identity interned at the last successful activation.
  ///
  /// May be null before activation. The snapshot includes the granted Role NodeIds and every
  /// user/application/endpoint fact that partitions namespace permission state.
  ///
  /// @return the interned access identity, or null before a successful activation.
  virtual std::shared_ptr<const ua::AccessIdentity> access_identity() const
  {
    return nullptr;
  }

  /// The Session's current caller: its committed access identity with the Session facts a value source or a
  /// method handler may need (@ref ua::CallerInfo).
  ///
  /// The server's Session keeps one object, shared by all of its subscriptions, and replaces it when it
  /// replaces its identity: at ActivateSession and when a Role refresh commits a new identity. Its
  /// subscriptions' items are sampled for it. A context that does not override this answers null, and the
  /// items of its subscriptions are read as the server's own reads. Callable from any thread.
  ///
  /// @return The current caller, or null before activation.
  virtual std::shared_ptr<const ua::CallerInfo> caller() const
  {
    return nullptr;
  }

  /// Acquires the access identity for a new authorization operation.
  ///
  /// Server Sessions override this fallible surface to refresh RoleConfiguration epochs without losing a
  /// refresh failure. Fixed test and extension contexts inherit the ordinary snapshot wrapper.
  ///
  /// @return the access identity to authorize against, or the failure that prevented refreshing it.
  virtual Result<std::shared_ptr<const ua::AccessIdentity>> access_identity_result() const
  {
    auto identity = access_identity();
    if (identity)
    {
      return Result<std::shared_ptr<const ua::AccessIdentity>>{std::move(identity)};
    }
    return Result<std::shared_ptr<const ua::AccessIdentity>>{StatusCode{Status::BadUserAccessDenied},
      ErrorDetail::build(
        "AccessIdentityUnavailable", "The Session has no current access identity", "SessionSecurityContext")};
  }

protected:
  /// Default-constructs the base; only subclasses construct a `SessionSecurityContext`.
  SessionSecurityContext() = default;
};

}  // namespace ua::server

#endif  // !UA_SESSION_SECURITY_H
