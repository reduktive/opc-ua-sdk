// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OBSERVER_SINK_H
#define UA_OBSERVER_SINK_H

/// @file
/// @brief The observer fan-out infrastructure for the tier-1 client (client design section 7.8 / wiring
/// section 1): the
///        resolved @ref ua::client::detail::ObserverSlots snapshot, the per-Connection
///        @ref ua::client::detail::ObserverSink, and the Client-scoped
///        @ref ua::client::detail::ClientObserverSink.
///
/// A sink is NOT a strand component in the Rule-1..6 sense  -  its only mutable STATE is the Rule-4 atomic
/// `shared_ptr<const ObserverSlots>` snapshot (plus a monotonic `mClosed` latch). It DOES own a private
/// per-sink delivery `strand` (`mDeliveryStrand`), but that strand only serializes the fan-out POSTS; it
/// guards no state, is never exposed, and is intentionally DISTINCT from the orchestrator's connection
/// strand. Every `fire_*` routes through ONE private `post_fire` primitive that POSTS to `mDeliveryStrand`
/// (FIFO + mutual exclusion, so the section 7.8 lifecycle hooks are delivered in order, one-at-a-time  -  a
/// ConnectionObserver can never see `on_connected` before `on_connecting`), atomic-loads the slots,
/// null-checks the target family slot, locks the weak `ConnectionImpl`, builds a borrowed public
/// @ref ua::client::Connection, and invokes the hook off the connection strand (the design specification).
/// Because delivery is on a DIFFERENT strand from the connection, a hook that re-enters a wire op or a
/// `set_*_observer` (which post to the connection strand) is reentrancy-safe  -  no deadlock. A hook that
/// THROWS is caught and logged (swallowed), never reaching `std::terminate`. Host shims hold the sink STRONG
/// and forward `fire_observer_*` -> `sink.fire_*`; they never touch the orchestrator strand and never lock
/// `ConnectionImpl`.
/// @ingroup client

#include "ua_client_observers.h"
// RedundancyObserver + RedundancyDegradeReason. Internal since the client redundancy surface was
// withdrawn from the public API; the sink still fires it.
#include "ua_redundancy_manager.h"
#include "ua_logger.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ua::client
{
class Connection;
}  // namespace ua::client

namespace ua::client::detail
{

class ConnectionImpl;

/// The eight resolved observer slots for one Connection (section 7.8). Each family is an
/// independently-nullable `shared_ptr`; null == no observer for that family (a cheap fire no-op).
/// Registration holds the observer STRONG; observers only ever receive a borrowed `const Connection&`
/// (documented MUST-NOT-stash).
struct ObserverSlots
{
  std::shared_ptr<ConnectionObserver> connection;
  std::shared_ptr<SubscriptionObserver> subscription;
  std::shared_ptr<SecurityObserver> security;
  std::shared_ptr<TypeObserver> type;
  std::shared_ptr<AddressSpaceObserver> addressSpace;
  std::shared_ptr<ServerStateObserver> serverState;
  std::shared_ptr<AlarmObserver> alarm;
  std::shared_ptr<RedundancyObserver> redundancy;
};

/// Resolves the effective per-Connection slots (section 7.3/section 7.7): for each family the per-Connection
/// slot wins when non-null, else the Client-level default is used. Pure  -  the resolution is captured once
/// at connect into an immutable snapshot and re-resolved when a runtime setter fires.
[[nodiscard]] ObserverSlots resolve_observer_slots(
  const ObserverSlots& perConnection, const ObserverSlots& clientDefaults) noexcept;

/// Wraps a live @ref ConnectionImpl in a borrowed public @ref ua::client::Connection value handle for the
/// duration of an observer callback (via the friend @ref ConnectionHandleFactory). The returned handle holds
/// a strong reference to @p impl only for its (callback-scoped) lifetime; the observer MUST NOT stash it.
[[nodiscard]] ua::client::Connection make_borrowed_connection(std::shared_ptr<ConnectionImpl> impl);

/// The per-Connection observer fan-out sink (section 7.8 / wiring section 1). One per @ref ConnectionImpl.
///
/// Holds only a Rule-4 atomic slots snapshot + the executor + a weak @ref ConnectionImpl (never strong  -  no
/// cycle back into the orchestrator). Every `fire_*` posts to the executor and delivers the hook only if the
/// family slot is non-null AND the Connection is still alive (a borrowed `const Connection&` locked for the
/// callback). Client-scoped SecurityObserver hooks fire on @ref ClientObserverSink.
class ObserverSink : public std::enable_shared_from_this<ObserverSink>
{
public:
  /// @param executor   The executor every hook is delivered on (section 8.2A.1). Outlives the ConnectionImpl.
  /// A
  ///                   private delivery strand is derived from it so fan-out stays ordered + serialized.
  /// @param connection The orchestrator whose live @ref ua::client::Connection is borrowed per fire (weak).
  /// @param logger     Used only to log (and swallow) a user observer hook that throws (NOTE-6).
  [[nodiscard]] static std::shared_ptr<ObserverSink> create(
    boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger = {});

  ObserverSink(const ObserverSink&) = delete;
  ObserverSink& operator=(const ObserverSink&) = delete;
  ObserverSink(ObserverSink&&) = delete;
  ObserverSink& operator=(ObserverSink&&) = delete;
  ~ObserverSink() = default;

  /// Atomically installs a fresh resolved slots snapshot (wholesale replacement; section 7.3 re-resolution).
  /// Once
  /// @ref close has latched the sink this is a NO-OP: a setter that lands after close can never repopulate
  /// the severed sink (HIGH-1).
  void set_slots(ObserverSlots slots);

  /// The current resolved slots snapshot (atomic-load; any thread). Null before the first @ref set_slots and
  /// after @ref close.
  [[nodiscard]] std::shared_ptr<const ObserverSlots> slots() const noexcept;

  /// Severs delivery: sets the terminal @ref mClosed latch synchronously (so every subsequent @ref set_slots
  /// is at once a no-op - the sink can never be re-armed) AND FIFO-posts the slots-snapshot clear onto the
  /// private delivery strand. Ordering the sever ON the delivery strand - rather than storing null on the
  /// caller's thread - guarantees a fire posted BEFORE close() is DELIVERED (it was enqueued first) and only
  /// a fire posted AFTER close() is dropped, holding on a multi-thread pool where a synchronous store would
  /// race the in-flight fires and silently drop a terminal on_disconnected/on_closed (HIGH-1). Idempotent.
  void close();

  // ---- ConnectionObserver ----
  void fire_connecting();
  void fire_connected();
  void fire_disconnected(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail);
  void fire_reconnecting(std::size_t attempt, ReconnectCause cause);
  void fire_reconnected(ReconnectOutcome outcome);
  void fire_closed();
  void fire_session_created(ua::NodeId sessionId);
  void fire_session_activated();
  void fire_session_recreated(ua::NodeId oldId, ua::NodeId newId);
  void fire_namespace_remap(std::size_t generation, bool sizeChanged, bool indexShifted);
  void fire_error_chain(
    ua::StatusCode terminalCode, std::shared_ptr<const ua::ErrorDetail> chain, std::string operationTag);
  void fire_advisory_diagnostic(std::shared_ptr<const ua::ErrorDetail> detail);

  // ---- SubscriptionObserver (no Connection param; still gated on a live Connection) ----
  void fire_subscription_transferred(ua::IntegerId subscriptionId);
  void fire_subscription_recreated(ua::IntegerId oldId, ua::IntegerId newId);
  void fire_publish_gap(ua::IntegerId subscriptionId, std::uint32_t lostFrom, std::uint32_t to);
  void fire_subscription_recovery_action(ua::IntegerId subscriptionId, ua::StatusCode terminalCode,
    std::shared_ptr<const ua::ErrorDetail> chain, ProposedAdjustment proposed);
  void fire_subscription_terminated(
    ua::IntegerId subscriptionId, ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> chain);

  // ---- TypeObserver ----
  void fire_type_registered(ua::NodeId encodingId, std::string typeName);

  // ---- AddressSpaceObserver ----
  void fire_model_change(std::vector<ModelChangeStructure> changes);
  void fire_semantic_change(std::vector<SemanticChangeStructure> changes);

  // ---- ServerStateObserver ----
  void fire_device_failure(EventNotification event);
  void fire_progress_event(EventNotification event);
  void fire_system_status_change(
    ua::NodeId sourceNode, ua::String sourceName, ua::ServerState newState, SystemStatusOrigin origin);

  // ---- AlarmObserver ----
  void fire_refresh_required(std::size_t conditionCount);
  void fire_data_integrity_warning(
    TrackedKey key, DataIntegrityKind kind, std::shared_ptr<const ua::ErrorDetail> details);
  void fire_audit_event(EventNotification event);

  // ---- RedundancyObserver ----
  void fire_redundancy_degraded(std::string activeUri, RedundancyDegradeReason reason);
  void fire_redundancy_failover_started(std::string fromUri, std::string toUri, ReconnectCause cause);
  void fire_redundancy_failover_completed(std::string nowActiveUri, ReconnectOutcome outcome);
  void fire_redundancy_recovered(std::string activeUri);

private:
  ObserverSink(
    boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger);

  /// The single callback-safety dispatch primitive: posts to the private delivery strand (ordered +
  /// serialized), atomic-loads the slots, resolves the family slot @p slot, requires it non-null AND the
  /// Connection alive, then invokes @p invoke with the live observer and the borrowed
  /// @ref ua::client::Connection under a throw-guard (a hook that throws is logged and swallowed). Defined in
  /// the .cpp (only instantiated by the `fire_*` bodies there), so this header stays free of a complete
  /// `Connection`.
  ///
  /// @tparam Observer The observer interface type (deduced from the slot member pointer).
  /// @tparam Invoke   A callable `void(Observer&, const ua::client::Connection&)`.
  template<typename Observer, typename Invoke>
  void post_fire(std::shared_ptr<Observer> ObserverSlots::*slot, Invoke invoke);

  boost::asio::any_io_executor mExecutor;
  // Serializes the fan-out posts so lifecycle hooks stay ordered + one-at-a-time (WARN-2). Distinct from the
  // orchestrator's connection strand: a hook re-entering a wire op / set_*_observer is reentrancy-safe.
  boost::asio::strand<boost::asio::any_io_executor> mDeliveryStrand;
  std::weak_ptr<ConnectionImpl> mConnection;
  ua::Logger mLogger;
  std::atomic<std::shared_ptr<const ObserverSlots>> mSlots;
  // Monotonic terminal latch: once close() sets it, set_slots is a no-op forever (HIGH-1). Atomic because the
  // sink is touched from any thread (fires + setters) with no strand of its own for state.
  std::atomic<bool> mClosed{false};
};

/// The Client-scoped observer fan-out sink (section 7.8 / wiring section 1). Fires the Client-level
/// SecurityObserver hooks for pull-cert management, whose `Connection` is NULLABLE. Carries an OPTIONAL weak
/// @ref ConnectionImpl (empty when the facility is purely Client-scoped), and passes a
/// `const Connection*` that is null when no Connection is associated or it has expired.
class ClientObserverSink : public std::enable_shared_from_this<ClientObserverSink>
{
public:
  /// @param executor   The executor every hook is delivered on. A private delivery strand is derived from it
  ///                   so fan-out stays ordered + serialized.
  /// @param connection An OPTIONAL associated ConnectionImpl (weak; pass an empty `weak_ptr` when the
  ///                   facility is purely Client-scoped). A live one is borrowed as a non-null
  ///                   `const Connection*`; an empty/expired one delivers a null `const Connection*`.
  /// @param logger     Used only to log (and swallow) a user observer hook that throws (NOTE-6).
  [[nodiscard]] static std::shared_ptr<ClientObserverSink> create(boost::asio::any_io_executor executor,
    std::weak_ptr<ConnectionImpl> connection = {}, ua::Logger logger = {});

  ClientObserverSink(const ClientObserverSink&) = delete;
  ClientObserverSink& operator=(const ClientObserverSink&) = delete;
  ClientObserverSink(ClientObserverSink&&) = delete;
  ClientObserverSink& operator=(ClientObserverSink&&) = delete;
  ~ClientObserverSink() = default;

  /// Atomically installs a fresh slots snapshot (only the @ref ObserverSlots::security slot is consulted).
  /// A no-op once @ref close has latched the sink (HIGH-1).
  void set_slots(ObserverSlots slots);

  /// The current slots snapshot (atomic-load; any thread).
  [[nodiscard]] std::shared_ptr<const ObserverSlots> slots() const noexcept;

  /// Severs delivery (see @ref ObserverSink::close): latches @ref mClosed synchronously and FIFO-posts the
  /// snapshot clear onto the delivery strand so it runs behind any already-queued fires (HIGH-1).
  void close();

  // ---- SecurityObserver (Client-scoped) ----
  void fire_certificate_rotated(std::shared_ptr<const ua::X509Certificate> newCert);
  void fire_pull_cert_management_lifecycle(
    PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail);

private:
  ClientObserverSink(
    boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger);

  /// The Client-scoped dispatch primitive: posts to the private delivery strand (ordered + serialized),
  /// atomic-loads the slots, resolves the family slot, requires it non-null (the Connection is OPTIONAL  -  a
  /// null `const Connection*` is passed when it is absent / expired), then invokes @p invoke under a
  /// throw-guard (a hook that throws is logged and swallowed). Defined in the .cpp.
  ///
  /// @tparam Observer The observer interface type (deduced from the slot member pointer).
  /// @tparam Invoke   A callable `void(Observer&, const ua::client::Connection*)`.
  template<typename Observer, typename Invoke>
  void post_fire(std::shared_ptr<Observer> ObserverSlots::*slot, Invoke invoke);

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mDeliveryStrand;
  std::weak_ptr<ConnectionImpl> mConnection;
  ua::Logger mLogger;
  std::atomic<std::shared_ptr<const ObserverSlots>> mSlots;
  std::atomic<bool> mClosed{false};
};

}  // namespace ua::client::detail

#endif  // UA_OBSERVER_SINK_H
