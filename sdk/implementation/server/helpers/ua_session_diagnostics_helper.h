// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_DIAGNOSTICS_HELPER_H
#define UA_SESSION_DIAGNOSTICS_HELPER_H

/// @file
/// @brief Address-space backing for a session's SessionDiagnosticsObjectType node.
/// @ingroup server

#include "ua_session_diagnostics_object.h"
#include "ua_result.h"

#include <vector>

// Forward-declare the diagnostics data types built by the record builders below.
namespace ua
{
class SessionDiagnosticsDataType;
class SessionSecurityDiagnosticsDataType;
}  // namespace ua

namespace ua::server
{

struct SessionCounters;
struct SessionSecurityState;
struct SessionDescriptiveState;

/// Builds a `SessionDiagnosticsDataType` record from a session's counters and security state.
///
/// The snapshot is taken from @p counters and @p security at the moment of the call; the returned
/// record holds no reference to either. Reusable per session for both the per-session diagnostics
/// node and the server-wide summary array node.
///
/// @param counters    Per-session activity counters to encode.
/// @param security    Per-session security state to encode (client name, transport profile, etc.).
/// @param description Per-session descriptive facts (session name, client description, timestamps).
/// @return The populated diagnostics record.
SessionDiagnosticsDataType build_session_diagnostics(const SessionCounters& counters,
  const SessionSecurityState& security, const SessionDescriptiveState& description);

/// Builds a `SessionSecurityDiagnosticsDataType` record from a session's security state.
///
/// The snapshot is taken from @p security at the moment of the call; the returned record holds no
/// reference to it.
///
/// @param security Per-session security state to encode.
/// @return The populated security-diagnostics record.
SessionSecurityDiagnosticsDataType build_session_security_diagnostics(const SessionSecurityState& security);

class SessionDiagnosticsHelper;

/// Result of a @ref SessionDiagnosticsHelper create operation: the helper on success, an
/// @ref ErrorDetail on failure.
using SessionDiagnosticsHelperResult = Result<SessionDiagnosticsHelper>;

/// Convenience class that backs a session's `SessionDiagnosticsObjectType` node with live counters.
///
/// Instantiates a `SessionDiagnosticsObjectType` instance under a parent node and wires read
/// handlers for all diagnostic child Variables so that each read reports the current value from the
/// shared @ref SessionCounters / @ref SessionSecurityState the helper was given. The counters and
/// security state are held by `shared_ptr` and updated by the owning session; the read handlers
/// observe them live.
///
/// A helper created via `create_async`/`create_sync` owns the instantiated subtree and removes it
/// on destruction (RAII); call @ref release to detach that ownership.
/// @ingroup server
class SessionDiagnosticsHelper
{
public:
  /// Constructs an empty helper that backs no node.
  SessionDiagnosticsHelper() = default;

  /// Callback type reporting the outcome of @ref create_async.
  using CreateCompleteCallback = std::function<void(SessionDiagnosticsHelperResult)>;

  /// Creates a new SessionDiagnosticsObjectType instance under @p parent and wires its read handlers.
  ///
  /// Posts the instantiation and handler installation to the address space and completes
  /// asynchronously; the callback runs on an unspecified worker thread, so do not block it.
  ///
  /// @param addressSpace  Address space in which the node is created.
  /// @param parent        Node under which the new instance is created.
  /// @param browseName    Browse name of the new node.
  /// @param counters      Shared per-session counters the read handlers observe live; must outlive
  ///                      the helper.
  /// @param securityState Shared per-session security state the read handlers observe live; must
  ///                      outlive the helper.
  /// @param descriptiveState Shared per-session descriptive state (session name, client description,
  ///                      connection timestamps) the read handlers observe live; must outlive the helper.
  /// @param options       Instantiation options for the new subtree.
  /// @param complete      Receives the outcome: on success the Result holds the owning
  ///                      @ref SessionDiagnosticsHelper; on failure it carries an @ref ErrorDetail.
  ///                      This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    std::shared_ptr<SessionCounters> counters, std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new SessionDiagnosticsObjectType instance under @p parent, blocking until complete.
  ///
  /// @param addressSpace  Address space in which the node is created.
  /// @param parent        Node under which the new instance is created.
  /// @param browseName    Browse name of the new node.
  /// @param counters      Shared per-session counters the read handlers observe live; must outlive
  ///                      the helper.
  /// @param securityState Shared per-session security state the read handlers observe live; must
  ///                      outlive the helper.
  /// @param descriptiveState Shared per-session descriptive state (session name, client description,
  ///                      connection timestamps) the read handlers observe live; must outlive the helper.
  /// @param options       Instantiation options for the new subtree.
  /// @return The owning @ref SessionDiagnosticsHelper, or an @ref ErrorDetail on failure. Never
  ///         throws.
  /// @see create_async, create_sync
  static SessionDiagnosticsHelperResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::shared_ptr<SessionCounters> counters,
    std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options) noexcept;

  /// Creates a new SessionDiagnosticsObjectType instance under @p parent, blocking until complete.
  ///
  /// @param addressSpace  Address space in which the node is created.
  /// @param parent        Node under which the new instance is created.
  /// @param browseName    Browse name of the new node.
  /// @param counters      Shared per-session counters the read handlers observe live; must outlive
  ///                      the helper.
  /// @param securityState Shared per-session security state the read handlers observe live; must
  ///                      outlive the helper.
  /// @param descriptiveState Shared per-session descriptive state (session name, client description,
  ///                      connection timestamps) the read handlers observe live; must outlive the helper.
  /// @param options       Instantiation options for the new subtree.
  /// @return The owning @ref SessionDiagnosticsHelper. A Good subcode on the answer is not returned;
  ///         try_create_sync() returns it.
  /// @throws UaException if the creation's answer is not Good.
  /// @see create_async, try_create_sync
  static SessionDiagnosticsHelper create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::shared_ptr<SessionCounters> counters,
    std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options);

  /// Returns the node ids of the security-diagnostic child Variables.
  ///
  /// These identify the access-restricted Variables under SessionSecurityDiagnostics whose ordinary
  /// RolePermissions and AccessRestrictions confine reads to authorized administrators. The reference
  /// is valid for the lifetime of the helper.
  /// @return The node ids of the security-diagnostic child Variables, valid for the helper's lifetime.
  const std::vector<NodeId>& security_diagnostic_node_ids() const;

  /// Returns the node id of the backed SessionDiagnosticsObjectType instance.
  /// @return The NodeId of the backed SessionDiagnosticsObjectType instance.
  const NodeId& node_id() const;

  /// Detaches RAII ownership of the created subtree so it persists beyond this handle's lifetime.
  void release();

private:
  explicit SessionDiagnosticsHelper(SessionDiagnosticsObject object,
    std::shared_ptr<SessionCounters> counters, std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, std::vector<NodeId> securityDiagNodeIds);

  // Creation runs as one self-owning coroutine, defined in the .cpp. No coroutine type crosses this
  // header: the seven step functions it replaces were the shape a callback chain forced on a
  // strictly linear sequence.
  class CreateOperation;

  SessionDiagnosticsObject mObject;
  std::shared_ptr<SessionCounters> mCounters;
  std::shared_ptr<SessionSecurityState> mSecurityState;
  std::shared_ptr<SessionDescriptiveState> mDescriptiveState;
  std::vector<NodeId> mSecurityDiagnosticNodeIds;
};

}  // namespace ua::server

#endif  // UA_SESSION_DIAGNOSTICS_HELPER_H
