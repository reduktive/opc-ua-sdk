// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The eight role-cohesive client observer interfaces (client design section 7.8) plus the
/// discriminator /
///        support types their hooks carry that are not already generated or defined elsewhere.
///
/// Observer registration is split across eight role-cohesive interfaces rather than one monolithic
/// `ClientObserver` god-interface. Each is independently optional; a user implements only the families it
/// consumes. Every hook has a default-empty virtual body, so a partial implementation is the norm.
///
/// ## Threading contract (the design specification)
/// Every hook is invoked by the SDK ON THE EXECUTOR  -  never synchronously from a component (connection)
/// strand and never while any lock or connection strand is held. Delivery is serialized through a private
/// per-Connection observer strand, so hooks are delivered IN ORDER and ONE AT A TIME (a `ConnectionObserver`
/// never sees `on_connected` before `on_connecting`, and two hooks never run concurrently). Because of this,
/// an observer implementation does NOT need to be internally thread-safe with respect to the SDK's fan-out.
/// The delivery strand is DISTINCT from the connection strand, so re-entrancy is safe. Hooks are advisory: an
/// override MUST NOT block and MUST NOT call back into `Connection` from within the callback (schedule any
/// reaction on the executor). A hook that throws is caught and logged by the SDK (swallowed) rather than
/// propagating  -  but an override still MUST NOT throw. The `const Connection&` (or `const Connection*`) a
/// hook receives is BORROWED for the callback duration only  -  it MUST NOT be stashed past the hook body.
/// @ingroup client

#ifndef UA_CLIENT_OBSERVERS_H
#define UA_CLIENT_OBSERVERS_H

#include "ua_alarm_condition_tracker.h"  // ua::client::TrackedKey
#include "ua_client_monitored_item.h"  // ua::client::EventNotification
#include "ua_date_time.h"  // ua::DateTime
#include "ua_integer_id.h"  // ua::IntegerId
#include "ua_node_id.h"  // ua::NodeId
#include "ua_pull_certificate_manager.h"  // ua::client::PullCertLifecycleEvent
#include "ua_reconnect_types.h"  // ua::client::ReconnectCause / ReconnectOutcome
#include "ua_server_state.h"  // ua::ServerState
#include "ua_status_code.h"  // ua::StatusCode + ua::ErrorDetail (fwd)

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ua
{
class X509Certificate;  // borrowed by const-ref only (SecurityObserver::on_certificate_rotated)
}  // namespace ua

namespace ua::client
{

// The principal user-facing handle (section 7.2). Forward-declared: an observer hook receives it by borrowed
// reference / pointer, so the heavy `ua_connection.h` is not pulled into this public header.
class Connection;

// ---- Support / discriminator types the section 7.8 hooks carry (not already generated) ----

/// @ingroup client
/// The class of server-side invariant violation surfaced by `AlarmObserver::on_data_integrity_warning`
/// (section 7.8; produced by the section 8.8 AlarmConditionTracker  -  CL-AC-023/025).
enum class DataIntegrityKind
{
  LimitInequality,  ///< CL-AC-023  -  a limit ordering invariant (HighLimit <= HighHighLimit, ...) is
                    ///< violated.
  NonExclusiveCrossGroup,  ///< CL-AC-025  -  overlapping non-exclusive limit groups are simultaneously
                           ///< active.
};

/// @ingroup client
/// Identifies whether a SystemStatusChangeEvent describes the OPC UA Server itself or an underlying system.
enum class SystemStatusOrigin
{
  Server,
  UnderlyingSystem,
};

/// The adjustment the SubscriptionsPipeline proposes after exhausting its automated oversized-message
/// recovery (section 9.5, CL-SUB-005). Carried by @ref SubscriptionObserver::on_subscription_recovery_action
/// so the application can re-issue ModifySubscription / ModifyMonitoredItems with its own parameters.
/// @ingroup client
struct ProposedAdjustment
{
  /// The `maxNotificationsPerPublish` the automated halving arrived at before giving up (0 == unbounded).
  std::uint32_t maxNotificationsPerPublish = 0;
};

/// One entry of a model-change notification (section 7.8; the OPC-UA `ModelChangeStructureDataType` mapped to
/// a lightweight value type at the AddressSpaceObserver boundary). Delivered by
/// @ref AddressSpaceObserver::on_model_change.
/// @ingroup client
struct ModelChangeStructure
{
  ua::NodeId affected;  ///< The node the change concerns.
  ua::NodeId affectedType;  ///< The affected node's type (when applicable).
  std::uint8_t verb = 0;  ///< The `ModelChangeStructureVerbMask` bits describing the change.
};

/// One entry of a semantic-change notification (section 7.8; the OPC-UA `SemanticChangeStructureDataType`
/// mapped to a lightweight value type at the AddressSpaceObserver boundary). Delivered by
/// @ref AddressSpaceObserver::on_semantic_change.
/// @ingroup client
struct SemanticChangeStructure
{
  ua::NodeId affected;  ///< The node whose semantics changed.
  ua::NodeId affectedType;  ///< The affected node's type (when applicable).
};

// ---- ConnectionObserver  -  connection / session lifecycle ----

/// Observes the connection + session lifecycle of one @ref Connection (section 7.8). Registered
/// per-Connection
/// (`Connection::set_connection_observer`) or Client-wide (`Client::set_connection_observer`).
/// @ingroup client
class ConnectionObserver
{
public:
  ConnectionObserver() = default;
  ConnectionObserver(const ConnectionObserver&) = delete;
  ConnectionObserver& operator=(const ConnectionObserver&) = delete;
  ConnectionObserver(ConnectionObserver&&) = delete;
  ConnectionObserver& operator=(ConnectionObserver&&) = delete;
  virtual ~ConnectionObserver() = default;

  /// @param connection Connection that emitted the notification.
  /// The Connection has begun its initial connect (bootstrap starting).
  virtual void on_connecting([[maybe_unused]] const Connection& connection)
  {}

  /// @param connection Connection that emitted the notification.
  /// The Connection reached `Active` for the first time (bootstrap complete).
  virtual void on_connected([[maybe_unused]] const Connection& connection)
  {}

  /// The Connection left `Active` for a terminal state - either a reconnect that terminally gave up (`reason`
  /// carries the failure status and `detail` its cause chain) OR an intentional, graceful client-initiated
  /// @param connection Connection that emitted the notification.
  /// close (`reason == Good`, `detail == nullptr`). A consumer distinguishing the two cases must test
  /// `reason.is_good()`, not assume an error. `on_closed` always follows on a graceful close.
  ///
  /// @param reason The status categorising the disconnect (`Good` for a graceful close).
  /// @param detail The full `ErrorDetail` cause chain (null on a graceful close, or when unavailable).
  virtual void on_disconnected([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] ua::StatusCode reason, [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> detail)
  {}

  /// An automatic reconnect attempt has begun.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param attempt The 1-based attempt counter.
  /// @param cause   Why the reconnect is being attempted (`std::visit` the tagged sum).
  virtual void on_reconnecting([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::size_t attempt, [[maybe_unused]] ReconnectCause cause)
  {}

  /// A reconnect completed and the Connection is `Active` again.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param outcome What was preserved vs recreated across the reconnect.
  virtual void on_reconnected(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] ReconnectOutcome outcome)
  {}

  /// @param connection Connection that emitted the notification.
  /// The Connection reached `Closed` (graceful close completed).
  virtual void on_closed([[maybe_unused]] const Connection& connection)
  {}

  /// A Session was created on the server (CreateSession completed).
  ///
  /// @param connection Connection that emitted the notification.
  /// @param sessionId The server-assigned session identifier.
  virtual void on_session_created(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] ua::NodeId sessionId)
  {}

  /// @param connection Connection that emitted the notification.
  /// The Session was activated (ActivateSession completed).
  virtual void on_session_activated([[maybe_unused]] const Connection& connection)
  {}

  /// A fresh Session replaced the previous one across a reconnect (CL-RECONN-003).
  ///
  /// @param connection Connection that emitted the notification.
  /// @param oldId The previous (now invalid) session identifier.
  /// @param newId The new session identifier.
  virtual void on_session_recreated([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] ua::NodeId oldId, [[maybe_unused]] ua::NodeId newId)
  {}

  /// @param connection Connection that emitted the notification.
  /// The NamespaceArray snapshot was replaced with changed contents (CL-ADDRSP-004). Fires only when the
  /// array contents actually changed, so persisted-NodeId consumers can re-anchor.
  ///
  /// @param generation  The monotonically increasing namespace-table generation.
  /// @param sizeChanged Whether the number of namespaces changed.
  /// @param indexShifted Whether an existing URI moved to a different index.
  virtual void on_namespace_remap([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::size_t generation, [[maybe_unused]] bool sizeChanged,
    [[maybe_unused]] bool indexShifted)
  {}

  /// A completed error cause-chain crossed a tier/wire boundary (advisory; section 7.10, CL-DIAG-011).
  /// @param connection Connection that emitted the notification.
  /// Read-only  - the observer cannot suppress or rewrite it.
  ///
  /// @param terminalCode The terminal status of the chain.
  /// @param chain        The full `ErrorDetail` cause chain (may be null).
  /// @param operationTag The CL-DIAG source tag of the operation that failed.
  virtual void on_error_chain([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] ua::StatusCode terminalCode,
    [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> chain,
    [[maybe_unused]] std::string_view operationTag)
  {}

  /// @param connection Connection that emitted the notification.
  /// An advisory (non-fatal) diagnostic was produced (section 7.10, CL-DIAG-012). Read-only.
  ///
  /// @param detail The advisory `ErrorDetail` (may be null).
  virtual void on_advisory_diagnostic([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> detail)
  {}
};

// ---- SubscriptionObserver  -  Subscription / MonitoredItem lifecycle ----

/// Observes Subscription and MonitoredItem lifecycle events (section 7.8).
/// @ingroup client
class SubscriptionObserver
{
public:
  SubscriptionObserver() = default;
  SubscriptionObserver(const SubscriptionObserver&) = delete;
  SubscriptionObserver& operator=(const SubscriptionObserver&) = delete;
  SubscriptionObserver(SubscriptionObserver&&) = delete;
  SubscriptionObserver& operator=(SubscriptionObserver&&) = delete;
  virtual ~SubscriptionObserver() = default;

  /// @param subscriptionId The subscription id.
  /// A Subscription was transferred to the current Session (TransferSubscriptions succeeded).
  virtual void on_subscription_transferred([[maybe_unused]] ua::IntegerId subscriptionId)
  {}

  /// @param oldId The old id.
  /// @param newId The new id.
  /// A Subscription was recreated with a new id across a reconnect.
  virtual void on_subscription_recreated(
    [[maybe_unused]] ua::IntegerId oldId, [[maybe_unused]] ua::IntegerId newId)
  {}

  /// @param subscriptionId The subscription id.
  /// @param lostFrom The lost from.
  /// @param to The to.
  /// A publish sequence gap was detected (notifications `lostFrom`..`to` could not be recovered).
  virtual void on_publish_gap([[maybe_unused]] ua::IntegerId subscriptionId,
    [[maybe_unused]] std::uint32_t lostFrom, [[maybe_unused]] std::uint32_t to)
  {}

  /// The SubscriptionsPipeline exhausted its automated oversized-message recovery (CL-SUB-005, section 9.5).
  ///
  /// @param subscriptionId The subscription id.
  /// @param terminalCode The terminal status of the last recovery attempt.
  /// @param chain        The full `ErrorDetail` cause chain (may be null).
  /// @param proposed     The adjustment the automated halving arrived at before giving up.
  virtual void on_subscription_recovery_action([[maybe_unused]] ua::IntegerId subscriptionId,
    [[maybe_unused]] ua::StatusCode terminalCode,
    [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> chain,
    [[maybe_unused]] ProposedAdjustment proposed)
  {}

  /// A Subscription terminated without recreation (CL-SUB-008): the Server reported, in a
  /// StatusChangeNotification, that it no longer exists on this Session (OPC 10000-4 7.25.4). @p reason is
  /// the Server's code unchanged: Bad_Timeout when its lifetime expired, Good_SubscriptionTransferred when
  /// another Session took it over, so test the code rather than assume an error. A StatusChangeNotification
  /// with any other code does not end the Subscription; it is reported through
  /// `ConnectionObserver::on_advisory_diagnostic`, with the code as the detail's cause.
  ///
  /// @param subscriptionId The subscription id.
  /// @param reason The terminal status.
  /// @param chain  The full `ErrorDetail` cause chain (may be null).
  virtual void on_subscription_terminated([[maybe_unused]] ua::IntegerId subscriptionId,
    [[maybe_unused]] ua::StatusCode reason, [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> chain)
  {}
};

// ---- TypeObserver  -  type system events ----

/// Observes type-system registration events (section 7.8).
/// @ingroup client
class TypeObserver
{
public:
  TypeObserver() = default;
  TypeObserver(const TypeObserver&) = delete;
  TypeObserver& operator=(const TypeObserver&) = delete;
  TypeObserver(TypeObserver&&) = delete;
  TypeObserver& operator=(TypeObserver&&) = delete;
  virtual ~TypeObserver() = default;

  /// A structured type was registered with the type resolver (lazy or eager).
  ///
  /// @param encodingId The type's binary encoding NodeId.
  /// @param typeName   The type's name.
  virtual void on_type_registered(
    [[maybe_unused]] ua::NodeId encodingId, [[maybe_unused]] std::string typeName)
  {}
};

// ---- SecurityObserver  -  certificate lifecycle ----

/// Observes certificate-rotation lifecycle events (section 7.8). Pull-cert hooks are Client-level facilities,
/// so their `Connection` is NULLABLE (null when no / an expired Connection is associated).
/// @ingroup client
class SecurityObserver
{
public:
  SecurityObserver() = default;
  SecurityObserver(const SecurityObserver&) = delete;
  SecurityObserver& operator=(const SecurityObserver&) = delete;
  SecurityObserver(SecurityObserver&&) = delete;
  SecurityObserver& operator=(SecurityObserver&&) = delete;
  virtual ~SecurityObserver() = default;

  /// The client's application-instance certificate was rotated (CL-PULLCRT-*).
  ///
  /// @param newCert The new certificate (borrowed for the callback).
  virtual void on_certificate_rotated([[maybe_unused]] const ua::X509Certificate& newCert)
  {}

  /// A pull-cert management lifecycle transition occurred (CL-PULLCRT-*, section 8.1A). Client-level
  /// facility.
  ///
  /// @param connection The associated Connection, or null (Client-level / expired).
  /// @param event      The lifecycle event.
  /// @param detail     A `ErrorDetail` cause on a failure event (may be null).
  virtual void on_pull_cert_management_lifecycle([[maybe_unused]] const Connection* connection,
    [[maybe_unused]] PullCertLifecycleEvent event,
    [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> detail)
  {}
};

// ---- AddressSpaceObserver  -  model / semantic-change events ----

/// Observes address-space model + semantic-change events (section 7.8, routed from the EventSubscriber).
/// @ingroup client
class AddressSpaceObserver
{
public:
  AddressSpaceObserver() = default;
  AddressSpaceObserver(const AddressSpaceObserver&) = delete;
  AddressSpaceObserver& operator=(const AddressSpaceObserver&) = delete;
  AddressSpaceObserver(AddressSpaceObserver&&) = delete;
  AddressSpaceObserver& operator=(AddressSpaceObserver&&) = delete;
  virtual ~AddressSpaceObserver() = default;

  /// @param connection Connection that emitted the notification.
  /// @param changes The changes.
  /// A GeneralModelChangeEvent / BaseModelChangeEvent was observed (Base Info Client Change Events).
  virtual void on_model_change(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] std::vector<ModelChangeStructure> changes)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param changes The changes.
  /// A SemanticChangeEvent was observed (Data Access Client SemanticChange).
  virtual void on_semantic_change([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] std::vector<SemanticChangeStructure> changes)
  {}
};

// ---- ServerStateObserver  -  server-state / progress / device-failure events ----

/// Observes server-state, progress, and device-failure events (section 7.8).
/// @ingroup client
class ServerStateObserver
{
public:
  ServerStateObserver() = default;
  ServerStateObserver(const ServerStateObserver&) = delete;
  ServerStateObserver& operator=(const ServerStateObserver&) = delete;
  ServerStateObserver(ServerStateObserver&&) = delete;
  ServerStateObserver& operator=(ServerStateObserver&&) = delete;
  virtual ~ServerStateObserver() = default;

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// A DeviceFailureEventType event was observed.
  virtual void on_device_failure(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// A ProgressEventType event was observed.
  virtual void on_progress_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// A system's ServerState changed, as reported by SystemStatusChangeEventType.
  ///
  /// @param connection Connection that emitted the notification.
  /// @param sourceNode  Node identifying the affected system.
  /// @param sourceName  Human-readable identity of the affected system.
  /// @param newState    The system's new ServerState.
  /// @param origin      `Server` when sourceNode is NS0 Server; otherwise `UnderlyingSystem`.
  virtual void on_system_status_change([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] ua::NodeId sourceNode, [[maybe_unused]] ua::String sourceName,
    [[maybe_unused]] ua::ServerState newState, [[maybe_unused]] SystemStatusOrigin origin)
  {}
};

// ---- AlarmObserver  -  Alarms & Conditions broadcast / audit / data-integrity ----

/// Observes Alarms & Conditions broadcasts, audit events, and data-integrity warnings (section 7.8).
/// @ingroup client
class AlarmObserver
{
public:
  AlarmObserver() = default;
  AlarmObserver(const AlarmObserver&) = delete;
  AlarmObserver& operator=(const AlarmObserver&) = delete;
  AlarmObserver(AlarmObserver&&) = delete;
  AlarmObserver& operator=(AlarmObserver&&) = delete;
  virtual ~AlarmObserver() = default;

  /// The server lost confidence in its condition cache and asks clients to re-issue ConditionRefresh
  /// @param connection Connection that emitted the notification.
  /// (CL-AC-007). Advisory; the tracker drives the actual refresh.
  ///
  /// @param conditionCount The tracked-condition count at fire time (diagnostics).
  virtual void on_refresh_required(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] std::size_t conditionCount)
  {}

  /// @param connection Connection that emitted the notification.
  /// A tracker observed a server-side invariant violation (CL-AC-023 / CL-AC-025). Read-only.
  ///
  /// @param key     The tracked condition/branch the warning concerns.
  /// @param kind    The class of invariant violation.
  /// @param details A `ErrorDetail` describing the violation (may be null).
  virtual void on_data_integrity_warning([[maybe_unused]] const Connection& connection,
    [[maybe_unused]] TrackedKey key, [[maybe_unused]] DataIntegrityKind kind,
    [[maybe_unused]] std::shared_ptr<const ua::ErrorDetail> details)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// An AuditEventType-subtree event was routed from the EventSubscriber (CL-AUDIT-003).
  virtual void on_audit_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// Returns or updates the on audit security event.
  virtual void on_audit_security_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// Returns or updates the on audit channel event.
  virtual void on_audit_channel_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// Returns or updates the on audit session event.
  virtual void on_audit_session_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// Returns or updates the on audit update event.
  virtual void on_audit_update_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}

  /// @param connection Connection that emitted the notification.
  /// @param event The event.
  /// Returns or updates the on audit update method event.
  virtual void on_audit_update_method_event(
    [[maybe_unused]] const Connection& connection, [[maybe_unused]] EventNotification event)
  {}
};

}  // namespace ua::client

#endif  // UA_CLIENT_OBSERVERS_H
