// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-1 public `Connection` handle: the principal user-facing entry point of the managed client
///        API (client design section 7.2). A move-only pimpl over the strand-serialized `ConnectionImpl`.
/// @ingroup client

#ifndef UA_CONNECTION_H
#define UA_CONNECTION_H

#include "ua_alarm_condition_tracker.h"
#include "ua_connection_state.h"
#include "ua_data_access.h"
#include "ua_data_value.h"
#include "ua_event_subscriber.h"
#include "ua_expanded_node_id.h"
#include "ua_file_transfer_client.h"
#include "ua_history_facade.h"
#include "ua_property_accessor.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_server_diagnostics_access.h"
#include "ua_server_table.h"
#include "ua_service_set.h"
#include "ua_state_machine_access.h"
#include "ua_subscriptions.h"
#include "ua_typed_access.h"
#include "ua_user_identity.h"
#include "ua_variant.h"

#include <cstdint>
#include <functional>
#include <memory>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct ConnectionHandleFactory;
}  // namespace detail

// The eight role-cohesive observer interfaces (section 7.8). Forward-declared: the setters take
// `shared_ptr<...>`, so the definitions (`ua_client_observers.h`) are pulled into the .cpp, not this
// widely-included header.
class ConnectionObserver;
class SubscriptionObserver;
class SecurityObserver;
class TypeObserver;
class AddressSpaceObserver;
class ServerStateObserver;
class AlarmObserver;

/// The public lifecycle state of a Connection (section 8.2A.3). Re-exported from the detail enum so callers
/// name it as `ua::client::ConnectionState`.
using ConnectionState = detail::ConnectionState;

/// The principal user-facing handle in the managed (tier-1/2) client API (section 7.2).
///
/// One `Connection` represents one logical (endpoint, identity, security) tuple. It is a move-only handle
/// (`shared_ptr<ConnectionImpl>` pimpl) over a strand-serialized orchestrator that owns the managed
/// SecureChannel/Session pair, the reconnect FSM, the keep-alive poll, and the Subscriptions pipeline. Not
/// directly constructible: a `Connection` is produced by the client machinery (the connect path) and, in
/// tests, by the `detail::ConnectionHandleFactory` wrap interface.
///
/// `Connection` itself keeps a narrow surface  -  lifecycle, state accessors, and the most-common
/// `read_value` / `write_value` conveniences  -  and delegates its wire-shaped breadth to the
/// @ref ServiceSet sub-accessor (`service_requests()`) and its Subscription lifecycle to the
/// @ref Subscriptions sub-accessor (`subscriptions()`), each a lazy value handle over the same
/// `ConnectionImpl` (section 7.2A / section 7.4).
///
/// ## Graceful close
/// Destroying the handle does NOT close the Connection on the server. Call `close_async()` /
/// `close_sync()` and await completion to close gracefully; otherwise the server times the session out.
///
/// @note State accessors read an atomic cross-strand snapshot and are safe from any thread. `*_async`
///       methods never throw and deliver their callback on the executor. `*_sync` / `try_*_sync` block on
///       the async completion and MUST NOT be called from the Connection's executor thread.
/// @ingroup client
class Connection
{
public:
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;
  /// Returns or updates the connection.
  Connection(Connection&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  Connection& operator=(Connection&&) noexcept = default;

  /// Releases this handle's reference to the underlying Connection. Does NOT send a graceful close; call
  /// `close_async` / `close_sync` first if the server should observe the close.
  ~Connection() = default;

  // ============ Lifecycle ============

  /// Gracefully closes the Connection: drains the dispatch gate, closes the tier-0 session, transitions to
  /// @param callback Completion callback that receives the operation result.
  /// `Closed`. Idempotent. The callback runs on the executor. Never throws.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Gracefully closes the Connection, blocking until complete. A graceful close is always reported as
  /// success (the tier-0 close status is intentionally swallowed  -  see ConnectionImpl::close_async), so
  /// this
  /// @throws ua::UaException only on a moved-from handle (no underlying ConnectionImpl).
  void close_sync();

  /// @return The requested value.
  /// Gracefully closes the Connection, blocking until complete. Never throws.
  ua::VoidResult try_close_sync() noexcept;

  /// Re-authenticates the live Session with a new user identity without replacing the Session or its
  /// Subscriptions. Valid only while the Connection is Active. The callback runs on the executor.
  ///
  /// @param newIdentity Identity to encode in a fresh ActivateSession request.
  /// @param callback Receives Good after the identity change, otherwise a rich bad Result.
  void reactivate_async(UserIdentity newIdentity, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Re-authenticates the live Session, blocking until complete.
  ///
  /// @param newIdentity The new identity.
  /// @throws UaException if reactivation fails.
  void reactivate_sync(UserIdentity newIdentity);

  /// @param newIdentity The new identity.
  /// @return The requested value.
  /// Re-authenticates the live Session, blocking until complete. Never throws.
  ua::VoidResult try_reactivate_sync(UserIdentity newIdentity) noexcept;

  // ============ State (atomic snapshot  -  any thread) ============

  /// @return The requested value.
  /// The current lifecycle state (from the atomic cross-strand snapshot). Reports `Connecting` before the
  /// bootstrap snapshot is first published and `Closed` on a moved-from handle.
  [[nodiscard]] ConnectionState state() const;

  /// @return The operation result, including status and diagnostic detail on failure.
  /// The server-assigned session identifier, or a bad Result (`Bad_SessionIdInvalid`) before the session
  /// has been created on the server / on a moved-from handle.
  [[nodiscard]] ua::Result<ua::NodeId> session_id() const;

  /// The current immutable NamespaceTable snapshot, or null before the bootstrap NamespaceArray read
  /// @return An immutable snapshot of the current state.
  /// completes / on a moved-from handle. Republished on every visible state change.
  [[nodiscard]] std::shared_ptr<const NamespaceTable> namespace_table() const;

  /// The current immutable, Session-scoped ServerTable snapshot, or null before bootstrap completes / on a
  /// @return An immutable snapshot of the current state.
  /// moved-from handle. ServerIndex lookups are local, non-blocking cache reads.
  [[nodiscard]] std::shared_ptr<const ServerTable> server_table() const;

  // ============ Observer registration (section 7.8) ============
  // Role-cohesive setters, one per observer family. Each is independently optional and overrides the
  // Client-level default for that family on THIS Connection; passing `nullptr` clears the per-Connection slot
  // (the Client-level default then applies again). Every hook is delivered on the executor, never from a
  // strand and never while a lock is held (the design specification); a hook MUST NOT stash the borrowed
  // `const Connection&` / `const Connection*` it receives.

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the connection / session lifecycle observer for this Connection (section 7.8).
  void set_connection_observer(std::shared_ptr<ConnectionObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the Subscription / MonitoredItem lifecycle observer for this Connection (section 7.8).
  void set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the certificate security observer for this Connection (section 7.8).
  void set_security_observer(std::shared_ptr<SecurityObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the type-system observer for this Connection (section 7.8).
  void set_type_observer(std::shared_ptr<TypeObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the address-space model / semantic-change observer for this Connection (section 7.8).
  void set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the server-state / progress / device-failure observer for this Connection (section 7.8).
  void set_server_state_observer(std::shared_ptr<ServerStateObserver> observer) noexcept;

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Registers the Alarms & Conditions observer for this Connection (section 7.8).
  void set_alarm_observer(std::shared_ptr<AlarmObserver> observer) noexcept;

  // ============ Wire-shaped and subscription sub-accessors ============

  /// @return The requested value.
  /// The wire-shaped service-set sub-accessor (the 17 managed wire ops, section 7.2A). A lightweight value
  /// handle over the same `ConnectionImpl`.
  [[nodiscard]] ServiceSet service_requests();

  /// @return The requested value.
  /// The Subscription-lifecycle sub-accessor (section 7.4). A lightweight value handle over the same
  /// `ConnectionImpl`; the pipeline owns the Subscriptions and they survive reconnect.
  [[nodiscard]] Subscriptions subscriptions();

  /// Creates a Subscription on the server (thin convenience for `subscriptions().create_async`, section 7.4).
  ///
  /// @param config   The Subscription parameters (@ref SubscriptionConfig).
  /// @param callback Receives the typed @ref Subscription handle on success, or a bad Result (executor).
  void create_subscription_async(
    SubscriptionConfig config, std::function<void(ua::Result<Subscription>)> callback) noexcept;
  /// @param config The config.
  /// @return The requested value.
  /// Synchronously create subscription. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_create_subscription_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the answer is not Good.
  Subscription create_subscription_sync(SubscriptionConfig config);
  /// @param config The config.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to create subscription sync without throwing.
  ua::Result<Subscription> try_create_subscription_sync(SubscriptionConfig config) noexcept;

  // ============ Tier-2 typed conveniences (the most-common value read/write) ============

  /// Reads a Node's Value attribute (the most common case), decoded to a @ref ua::DataValue (section 7.2).
  ///
  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Composes a single-node Value Read through the managed wire-op funnel and returns `results[0]`. The
  /// outer Result is bad on a service-level failure, and carries the Read's ServiceResult when that is a
  /// Good subcode or an Uncertain code; the value quality lives on `DataValue::status()` (the two-layer
  /// model  -  the service status and the value quality are kept distinct, section 7.2).
  void read_value_async(ua::NodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;

  /// Reads a Node's Value attribute, blocking until complete. A Good subcode on the outer Result is put on
  /// the returned DataValue's status when that is plain Good (`ua::detail::good_data_value`).
  /// @param node Target node identifier.
  /// @return The requested value.
  /// @throws ua::UaException when the outer Result is not Good (not on a bad value quality).
  ua::DataValue read_value_sync(ua::NodeId node);

  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Reads a Node's Value attribute, blocking until complete. Never throws.
  ua::Result<ua::DataValue> try_read_value_sync(ua::NodeId node) noexcept;

  // ---- URI-tagged ExpandedNodeId overloads (OPC 10000-3 section 5.2.2; OPEN-NSREMAP) ----
  //
  // Accept a URI-carrying ExpandedNodeId and resolve its NamespaceIndex per-Session, at CALL time, against
  // the Connection's CURRENT NamespaceTable snapshot (@ref NamespaceTable::resolve_local). The user holds a
  // stable URI-ref; the SDK never mutates it and re-resolves each call, so a call issued AFTER a reconnect
  // renumbered the NamespaceArray maps to the new index (CL-ADDRSP-004 / CL-SESS-028). Resolution is at call
  // time, not wire-dispatch time: an op resolved while Active and then queued through a reconnect that
  // renumbers would carry the index it resolved to (dispatch-time re-resolution is deferred)  -  re-resolve
  // by re-issuing the call after the reconnect. A URI absent from the current Session fails LOCALLY
  // (Bad_NodeIdUnknown + the rich resolve_local ErrorDetail) with no wire request. An ExpandedNodeId with an
  // empty NamespaceUri falls back to its encoded index (backward-compatible). A non-zero ServerIndex is
  // refused with Bad_NotImplemented here (see CL-ATTR-029 for cross-Server routing).

  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Reads a URI-tagged Node's Value attribute; resolves the NamespaceUri per-Session before dispatch.
  void read_value_async(
    ua::ExpandedNodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;

  /// Reads a URI-tagged Node's Value attribute, blocking until complete. A Good subcode on the outer Result
  /// is put on the returned DataValue's status when that is plain Good.
  /// @param node Target node identifier.
  /// @return The requested value.
  /// @throws ua::UaException when the outer Result is not Good (including an unresolved NamespaceUri).
  ua::DataValue read_value_sync(ua::ExpandedNodeId node);

  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Reads a URI-tagged Node's Value attribute, blocking until complete. Never throws.
  ua::Result<ua::DataValue> try_read_value_sync(ua::ExpandedNodeId node) noexcept;

  // ---- Abstract-DataType-checked read (CL-ADDRSP-009; OPC 10000-3 section 5.8.3) ----
  //
  // Reads the Node's Value AND its declared DataType (one Read request), then validates that the value's
  // concrete DataType is a subtype of the declared DataType. A concrete value shall always be a subtype of an
  // abstract declared DataType (Number, BaseDataType, ...); a value in a genuinely disjoint type branch (a
  // `String` for a `Number`) is rejected LOCALLY with `Bad_TypeMismatch` and an ErrorDetail rather than
  // handed back. This is opt-in (the plain `read_value_async` stays lean, one attribute, no validation): use
  // it when you want the declared-DataType guarantee. Encoding-aliased types (enums, `Duration`, ...) and
  // not-yet-discovered relations fail OPEN (the value is delivered)  -  the SDK never rejects a value it
  // cannot prove is wrong.

  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// Reads a Node's Value attribute, validated against its declared DataType (section 5.8.3). Delivers the
  /// `DataValue` on Accept / fail-open, or a bad Result (`Bad_TypeMismatch`) on a proven type mismatch.
  void read_value_checked_async(
    ua::NodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;

  /// Reads a Node's Value attribute validated against its declared DataType, blocking until complete. A
  /// Good subcode on the outer Result is put on the returned DataValue's status when that is plain Good.
  /// @param node Target node identifier.
  /// @return The requested value.
  /// @throws ua::UaException when the outer Result is not Good (including a proven declared-DataType
  ///         mismatch).
  ua::DataValue read_value_checked_sync(ua::NodeId node);

  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Reads a Node's Value attribute validated against its declared DataType, blocking until complete. Never
  /// throws.
  ua::Result<ua::DataValue> try_read_value_checked_sync(ua::NodeId node) noexcept;

  // ---- Typed-value sugar (T): the value Variant decoded to a native C++ `T` (section 7.2) ----
  //
  // Convenience over `read_value_async`: composes the single-node Value Read, then decodes the value
  // Variant to a native `T` via `Variant::to<T>()`. The outer `Result<T>` is bad if the service
  // failed OR the value did not decode to a `T` (empty / wrong type).
  //
  // BAD-QUALITY FLATTEN (CL-ATTR-005/006). The typed sugar surfaces a Bad-SEVERITY inner
  // `DataValue.status_code` (the *value quality*  -  e.g. `Bad_DeviceFailure`) AS the outer `Result<T>`,
  // WITHOUT decoding the Variant  -  it never hands back a `T` the server marked bad. Uncertain /
  // DA-substatus qualities are PRESERVED: the `Result<T>` holds the decoded value with the one code the
  // read answered, the combined status of the `Result<DataValue>` and the DataValue's own status
  // (`detail::typed_value`), so a Good subcode or an Uncertain code reaches the caller. An Uncertain
  // DataValue with a null value is answered with its code and no value. The BULK typed read
  // (`TypedAccess::read_values_async<T>`, design section 7.2A) decodes each element the same way  -  single
  // and bulk agree.
  //
  // TWO-LAYER MODEL (CL-DA-015 / CL-SM-002) applies to the `Result<DataValue>` form, NOT this typed sugar: a
  // Bad value quality rides on `DataValue::status()` while the outer `Result<DataValue>` stays Good. Callers
  // who need the value quality distinct from the service status read the `read_value_async` (DataValue) form.

  /// Reads a Node's Value attribute and decodes it to a native `T`; a Bad-severity value quality flattens
  /// into the `Result<T>`, and a Good subcode or an Uncertain code is the status of the `Result<T>` holding
  /// the decoded value. section 7.2 / CL-ATTR-005/006.
  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  ///
  /// @tparam T Native C++ type the value Variant is decoded to (via @ref ua::Variant::to).
  template<class T>
  void read_value_async(ua::NodeId node, std::function<void(ua::Result<T>)> callback) noexcept
  {
    read_value_async(std::move(node),
      std::function<void(ua::Result<ua::DataValue>)>{
        [callback = std::move(callback)](ua::Result<ua::DataValue> result) mutable
        {
          // Bad-quality short-circuit (CL-ATTR-005/006): a Bad-SEVERITY value quality is surfaced AS the
          // typed Result WITHOUT decoding the Variant, matching the bulk read (ua_typed_access.h). A Good
          // subcode or an Uncertain code stays with the decoded value; the status carries its own
          // ErrorDetail.
          callback(detail::typed_value<T>(result));
        }});
  }

  /// Reads a Node's Value attribute decoded to `T`, blocking until complete. A Good subcode on the answer is
  /// not returned; try_read_value_sync() returns it.
  /// @param node Target node identifier.
  /// @return The requested value.
  /// @throws ua::UaException when the answer is not Good (service failure, decode failure, or an Uncertain
  ///         answer, whose value try_read_value_sync() returns).
  template<class T>
  T read_value_sync(ua::NodeId node)
  {
    return ua::detail::good_value(try_read_value_sync<T>(std::move(node)));
  }

  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Reads a Node's Value attribute decoded to `T`, blocking until complete. Never throws.
  template<class T>
  ua::Result<T> try_read_value_sync(ua::NodeId node) noexcept
  {
    // Reuse the non-templated blocking DataValue read, then decode. Bad-severity value quality flattens
    // (CL-ATTR-005/006), parity with the async path; a Good subcode or an Uncertain code stays with the
    // decoded value.
    return detail::typed_value<T>(try_read_value_sync(std::move(node)));
  }

  /// Reads a URI-tagged Node's Value attribute decoded to a native `T`; resolves the NamespaceUri
  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// per-Session. Same bad-quality flatten as the NodeId form (CL-ATTR-005/006).
  ///
  /// @tparam T Native C++ type the value Variant is decoded to (via @ref ua::Variant::to).
  template<class T>
  void read_value_async(ua::ExpandedNodeId node, std::function<void(ua::Result<T>)> callback) noexcept
  {
    read_value_async(std::move(node),
      std::function<void(ua::Result<ua::DataValue>)>{
        [callback = std::move(callback)](ua::Result<ua::DataValue> result) mutable
        {
          callback(detail::typed_value<T>(result));
        }});
  }

  /// Reads a URI-tagged Node's Value attribute decoded to `T`, blocking until complete. A Good subcode on the
  /// answer is not returned; try_read_value_sync() returns it.
  /// @param node Target node identifier.
  /// @return The requested value.
  /// @throws ua::UaException when the answer is not Good (unresolved URI, service failure, decode failure,
  ///         or an Uncertain answer, whose value try_read_value_sync() returns).
  template<class T>
  T read_value_sync(ua::ExpandedNodeId node)
  {
    return ua::detail::good_value(try_read_value_sync<T>(std::move(node)));
  }

  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Reads a URI-tagged Node's Value attribute decoded to `T`, blocking until complete. Never throws.
  template<class T>
  ua::Result<T> try_read_value_sync(ua::ExpandedNodeId node) noexcept
  {
    return detail::typed_value<T>(try_read_value_sync(std::move(node)));
  }

  /// Writes a Node's Value attribute (the most common case, section 7.2).
  ///
  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// Composes a single Write of @p value to the node's Value attribute through the managed wire-op funnel
  /// and flattens the per-item write status into the returned `VoidResult`.
  void write_value_async(
    ua::NodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Writes a Node's Value attribute, blocking until complete.
  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @throws ua::UaException on a bad Result.
  void write_value_sync(ua::NodeId node, ua::Variant value);

  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @return The requested value.
  /// Writes a Node's Value attribute, blocking until complete. Never throws.
  ua::VoidResult try_write_value_sync(ua::NodeId node, ua::Variant value) noexcept;

  /// Writes a URI-tagged Node's Value attribute; resolves the NamespaceUri per-Session before dispatch.
  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// An unresolved URI fails LOCALLY (Bad_NodeIdUnknown + the rich resolve_local ErrorDetail), no wire write.
  void write_value_async(
    ua::ExpandedNodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Writes a URI-tagged Node's Value attribute, blocking until complete.
  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @throws ua::UaException on a bad Result (including an unresolved NamespaceUri).
  void write_value_sync(ua::ExpandedNodeId node, ua::Variant value);

  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @return The requested value.
  /// Writes a URI-tagged Node's Value attribute, blocking until complete. Never throws.
  ua::VoidResult try_write_value_sync(ua::ExpandedNodeId node, ua::Variant value) noexcept;

  // ---- NoSubDataTypes-checked write (CL-ATTR-025; OPC 10000-4 section 5.10.4.2, Part 3 section 8.58) ----
  //
  // Before writing, reads the target's declared DataType and `AccessLevelEx`. A server accepts a subtype of a
  // Variable's declared DataType by default; but when the Variable sets `AccessLevelEx.NoSubDataTypes` (bit
  // 11) it accepts ONLY the exact declared DataType. A checked write refuses a strict-subtype value LOCALLY
  // with `Bad_TypeMismatch` (sparing the round-trip the server would reject)  -  but ONLY when it can PROVE
  // the value is a strict subtype (`is_subtype_of(valueType, declared)` decidably true and not the exact
  // type); an encoding-aliased value (an enum wired as Int32, a Duration as Double), an undecidable relation,
  // or a target without NoSubDataTypes is forwarded unchanged. This is opt-in (the plain `write_value_async`
  // stays lean, no pre-read); the SDK never rejects a write it cannot prove the server would reject.

  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// Writes a Node's Value, refusing a strict-subtype value locally when the target is `NoSubDataTypes`
  /// (section 8.58).
  void write_value_checked_async(
    ua::NodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Writes a Node's Value with the NoSubDataTypes check, blocking until complete.
  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @throws ua::UaException on a bad Result (including a local NoSubDataTypes subtype refusal).
  void write_value_checked_sync(ua::NodeId node, ua::Variant value);

  /// @param node Target node identifier.
  /// @param value Value to write or evaluate.
  /// @return The requested value.
  /// Writes a Node's Value with the NoSubDataTypes check, blocking until complete. Never throws.
  ua::VoidResult try_write_value_checked_sync(ua::NodeId node, ua::Variant value) noexcept;

  // ============ Typed sugar sub-accessor ============

  /// The typed-value convenience sub-accessor (section 7.2A)  -  arbitrary-attribute read/write, bulk
  /// @return The requested value.
  /// reads/writes, browse-path translation, and typed method calls. A lightweight value handle over
  /// the same `ConnectionImpl` (lazy singleton, idempotent).
  [[nodiscard]] TypedAccess typed();

  // ============ Event / Alarm domain facades (Slice 10a, section 8.13 / section 8.8) ============

  /// @return The requested value.
  /// The per-`Connection` collapsing event backbone (section 8.13). Returns a move-only @ref EventSubscriber
  /// value handle over the lazily-constructed, co-owned `detail::EventSubscriberImpl` (own private strand). N
  /// logical consumers coalesce onto one server-side event MonitoredItem; inbound events are demultiplexed
  /// client-side to each consumer's callback by its filter.
  [[nodiscard]] EventSubscriber events();

  /// @return The requested value.
  /// The per-`Connection` Alarm & Condition tracker (section 8.8). Returns a move-only @ref
  /// AlarmConditionTracker value handle over a no-own-strand sub-object of the event subsystem (constructed
  /// by + co-owned with the `detail::EventSubscriberImpl`, running on ITS strand). Ensures the @ref events
  /// subscriber exists first.
  [[nodiscard]] AlarmConditionTracker alarms();

  // ============ Historical-access domain facade (Slice 10b, section 8.9) ============

  /// The flattened, one-hop per-`Connection` facade for the Historical Access service set (section 8.9, D2).
  /// @return The requested value.
  /// Returns a move-only @ref HistoryFacade value handle over the same tier-1 wire interface; history reads
  /// (`read_raw_async`  to  @ref HistoryReadCursor) and writes (`update_data_async`  to
  /// `HistoryUpdateResult`) are reached directly off it (no reader()/updater() sub-hop).
  [[nodiscard]] HistoryFacade history();

  // ============ File-transfer domain facade (Slice 10c, section 8.10) ============

  /// @return The requested value.
  /// The per-`Connection` facade for the File Transfer service set (section 8.10). Returns a copyable
  /// @ref FileTransferClient value handle over the same tier-1 wire interface; `open_async` hands back a
  /// move-only, close-on-destruct @ref FileHandle carrying the server `fileHandle`, and `read_all_async`
  /// drives the Open  to  Read*  to  Close sequence with a bounded aggregate ceiling (section 9.6.23.2).
  [[nodiscard]] FileTransferClient files();

  // ============ DataAccess + generic Property facades (Slice 10d, section 8.18) ============

  /// @return The requested value.
  /// The per-`Connection` tier-2 DataAccess factory (section 8.18.1.a). Returns a copyable @ref
  /// DataAccessAccessor value handle over the same tier-1 wire interface; each typed factory
  /// (`analog_item_async`, etc.) performs the DA Property pre-flight (Browse `HasProperty` + Read each
  /// Property Value) then yields a fully-populated typed handle that combines the Variable's typed Value with
  /// its resolved DA Properties.
  [[nodiscard]] DataAccessAccessor data_access() noexcept;

  /// The per-`Connection`, per-NodeId generic Property accessor explicit override (section 8.18.1.d,
  /// CL-AC-022).
  /// @param nodeId Target node identifier.
  /// @return The requested value.
  /// Returns a copyable @ref PropertyAccessor value handle over the same tier-1 wire interface;
  /// `read_property_async` Browses one level (`HasProperty`), matches a BrowseName, and Reads the matched
  /// child's Value Attribute.
  [[nodiscard]] PropertyAccessor node(ua::NodeId nodeId) noexcept;

  /// @return The requested value.
  /// The per-`Connection` tier-2 StateMachine typed-access factory (section 8.18.1.b). Returns a copyable
  /// @ref StateMachineAccessor value handle over the same tier-1 wire interface; each factory
  /// (`state_machine_async` / `finite_state_machine_async` / `program_state_machine_async`) performs the
  /// address-space pre-flight (Browse the machine's `CurrentState` / `LastTransition` + topology) then yields
  /// a fully-resolved typed handle over the Part-5 / Part-10 state-machine hierarchy.
  [[nodiscard]] StateMachineAccessor state_machine_accessor() noexcept;

  /// @return The requested value.
  /// The per-`Connection` tier-2 ServerDiagnostics typed-read accessor (section 8.18.1.c). Returns a copyable
  /// @ref ServerDiagnosticsAccessor value handle over the same tier-1 wire interface; `summary_async` reads
  /// the `ServerDiagnosticsSummary`, the array reads (`sessions_async`, etc.) read the diagnostic arrays with
  /// a cached `EnabledFlag` + disabled-advisory, and `set_enabled_flag_async` toggles diagnostics. Every copy
  /// shares one `EnabledFlag` TTL cache. CL-BASEDIAG-004 subscribe-over-poll is deferred to Slice 10d-4.
  [[nodiscard]] ServerDiagnosticsAccessor server_diagnostics() noexcept;

  // The non-transparent redundancy / failover facade (section 8.11) is deliberately NOT exposed here
  // for the initial release. The engine, its host interface and its 109 tests remain under
  // sdk/implementation/client/; only the public entry points were withdrawn, because this SDK's own
  // server publishes RedundancySupport = None and so can never be a redundancy peer -- the surface
  // cannot be tested end to end, and nothing untested ships in the public API. Re-exposure requires
  // completing and proving the two remaining host stubs.

  // ============ DEFERRED surface (declared in section 7.2; built in later slices) ============
  // The following section 7.2 surface is NOT declared here because its return types / ConnectionImpl plumbing
  // are not yet built; each lands in its own later slice:
  //   - active_endpoint() / with_current_session_async                                    (tier-1 follow-up)
  //   - ServerDiagnosticsAccessor::subscribe_sessions_async (CL-BASEDIAG-004)              (Slice 10d-4)
  //   - StateMachineAccessor::subscribe_transitions_async (CL-SM-010/011)                  (Slice 10d-2b)

private:
  friend class Client;
  friend struct ua::client::detail::ConnectionHandleFactory;

  explicit Connection(std::shared_ptr<detail::ConnectionImpl> impl);

  std::shared_ptr<detail::ConnectionImpl> mImpl;
};

}  // namespace ua::client

#endif  // UA_CONNECTION_H
