// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_observer_sink.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_x509_certificate.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <exception>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client::detail
{

// ---- Resolution + borrowed-Connection factory ----

ObserverSlots resolve_observer_slots(
  const ObserverSlots& perConnection, const ObserverSlots& clientDefaults) noexcept
{
  // Per-family: the per-Connection slot wins when non-null, else fall back to the Client-level default.
  ObserverSlots resolved;
  resolved.connection = perConnection.connection ? perConnection.connection : clientDefaults.connection;
  resolved.subscription =
    perConnection.subscription ? perConnection.subscription : clientDefaults.subscription;
  resolved.security = perConnection.security ? perConnection.security : clientDefaults.security;
  resolved.type = perConnection.type ? perConnection.type : clientDefaults.type;
  resolved.addressSpace =
    perConnection.addressSpace ? perConnection.addressSpace : clientDefaults.addressSpace;
  resolved.serverState = perConnection.serverState ? perConnection.serverState : clientDefaults.serverState;
  resolved.alarm = perConnection.alarm ? perConnection.alarm : clientDefaults.alarm;
  resolved.redundancy = perConnection.redundancy ? perConnection.redundancy : clientDefaults.redundancy;
  return resolved;
}

ua::client::Connection make_borrowed_connection(std::shared_ptr<ConnectionImpl> impl)
{
  return ConnectionHandleFactory::make_connection(std::move(impl));
}

// ---- ObserverSink ----

std::shared_ptr<ObserverSink> ObserverSink::create(
  boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
{
  return std::shared_ptr<ObserverSink>(
    new ObserverSink(std::move(executor), std::move(connection), std::move(logger)));
}

ObserverSink::ObserverSink(
  boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
  : mExecutor(std::move(executor)), mDeliveryStrand(boost::asio::make_strand(mExecutor)),
    mConnection(std::move(connection)), mLogger(std::move(logger))
{}

void ObserverSink::set_slots(ObserverSlots slots)
{
  if (mClosed.load())
  {
    return;  // HIGH-1: a setter after close() must never re-arm the severed sink.
  }
  mSlots.store(std::make_shared<const ObserverSlots>(std::move(slots)));
}

std::shared_ptr<const ObserverSlots> ObserverSink::slots() const noexcept
{
  return mSlots.load();
}

void ObserverSink::close()
{
  // Latch synchronously so any set_slots that observes the latch is IMMEDIATELY a no-op (the sink can never
  // be re-armed). But the SEVER of the slots snapshot must be FIFO-ordered ON THE DELIVERY STRAND, not stored
  // here on the caller's (connection-strand) thread: a fire posted before this close() is already enqueued on
  // the delivery strand, and a synchronous store on a different thread races it - on a multi-thread pool the
  // store can win and silently drop an in-flight terminal on_disconnected/on_closed (HIGH-1). Posting the
  // sever BEHIND the queued fires makes "delivered-then-severed" hold regardless of scheduling; only a fire
  // posted AFTER close() (enqueued behind the sever) drops. shared_from_this keeps the sink alive until the
  // sever runs. Idempotent: a redundant close posts a second harmless null-store.
  mClosed.store(true);
  ua::async::post_owning(this,
    mDeliveryStrand,
    ua::Logger{},
    [work = [self = shared_from_this()]()
      {
        self->mSlots.store(nullptr);
      }](auto&) mutable { work(); })();
}

template<typename Observer, typename Invoke>
void ObserverSink::post_fire(std::shared_ptr<Observer> ObserverSlots::*slot, Invoke invoke)
{
  // WARNING-2: deliver through the per-sink strand so hooks arrive FIFO + one-at-a-time (section 7.8
  // lifecycle order) even on a multi-thread pool  -  still OFF the orchestrator/connection strand, so
  // callback-safety holds.
  ua::async::post_owning(this,
    mDeliveryStrand,
    ua::Logger{},
    [work = [self = shared_from_this(), slot, invoke = std::move(invoke)]() mutable
      {
        const std::shared_ptr<const ObserverSlots> snapshot = self->mSlots.load();
        if (!snapshot)
        {
          return;  // closed / never-registered => no-op.
        }
        const std::shared_ptr<Observer>& observer = (*snapshot).*slot;
        if (!observer)
        {
          return;  // null family slot => cheap no-op.
        }
        const std::shared_ptr<ConnectionImpl> impl = self->mConnection.lock();
        if (!impl)
        {
          return;  // Connection gone => drop (no crash).
        }
        const ua::client::Connection borrowed = make_borrowed_connection(impl);
        // NOTE-6: a third-party observer hook that throws must not escape the posted handler ( to
        // std::terminate).
        try
        {
          invoke(*observer, borrowed);
        }
        catch (const std::exception& error)
        {
          self->mLogger.warning(
            "client.observer: a user observer hook threw ({}) - swallowed; observer hooks must not throw",
            error.what());
        }
        catch (...)
        {
          self->mLogger.warning(
            "client.observer: a user observer hook threw a non-std exception - swallowed");
        }
      }](auto&) mutable { work(); })();
}

// ---- ObserverSink::fire_*  -  ConnectionObserver ----

void ObserverSink::fire_connecting()
{
  post_fire(&ObserverSlots::connection,
    [](ConnectionObserver& observer, const ua::client::Connection& conn) { observer.on_connecting(conn); });
}

void ObserverSink::fire_connected()
{
  post_fire(&ObserverSlots::connection,
    [](ConnectionObserver& observer, const ua::client::Connection& conn) { observer.on_connected(conn); });
}

void ObserverSink::fire_disconnected(ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> detail)
{
  post_fire(&ObserverSlots::connection,
    [reason, detail = std::move(detail)](
      ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_disconnected(conn, reason, std::move(detail)); });
}

void ObserverSink::fire_reconnecting(std::size_t attempt, ReconnectCause cause)
{
  post_fire(&ObserverSlots::connection,
    [attempt, cause = std::move(cause)](
      ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_reconnecting(conn, attempt, std::move(cause)); });
}

void ObserverSink::fire_reconnected(ReconnectOutcome outcome)
{
  post_fire(&ObserverSlots::connection,
    [outcome = std::move(outcome)](ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_reconnected(conn, std::move(outcome)); });
}

void ObserverSink::fire_closed()
{
  post_fire(&ObserverSlots::connection,
    [](ConnectionObserver& observer, const ua::client::Connection& conn) { observer.on_closed(conn); });
}

void ObserverSink::fire_session_created(ua::NodeId sessionId)
{
  post_fire(&ObserverSlots::connection,
    [sessionId = std::move(sessionId)](
      ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_session_created(conn, std::move(sessionId)); });
}

void ObserverSink::fire_session_activated()
{
  post_fire(&ObserverSlots::connection,
    [](ConnectionObserver& observer, const ua::client::Connection& conn)
    { observer.on_session_activated(conn); });
}

void ObserverSink::fire_session_recreated(ua::NodeId oldId, ua::NodeId newId)
{
  post_fire(&ObserverSlots::connection,
    [oldId = std::move(oldId), newId = std::move(newId)](
      ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_session_recreated(conn, std::move(oldId), std::move(newId)); });
}

void ObserverSink::fire_namespace_remap(std::size_t generation, bool sizeChanged, bool indexShifted)
{
  post_fire(&ObserverSlots::connection,
    [generation, sizeChanged, indexShifted](ConnectionObserver& observer, const ua::client::Connection& conn)
    { observer.on_namespace_remap(conn, generation, sizeChanged, indexShifted); });
}

void ObserverSink::fire_error_chain(
  ua::StatusCode terminalCode, std::shared_ptr<const ua::ErrorDetail> chain, std::string operationTag)
{
  post_fire(&ObserverSlots::connection,
    [terminalCode, chain = std::move(chain), operationTag = std::move(operationTag)](
      ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_error_chain(conn, terminalCode, std::move(chain), operationTag); });
}

void ObserverSink::fire_advisory_diagnostic(std::shared_ptr<const ua::ErrorDetail> detail)
{
  post_fire(&ObserverSlots::connection,
    [detail = std::move(detail)](ConnectionObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_advisory_diagnostic(conn, std::move(detail)); });
}

// ---- ObserverSink::fire_*  -  SubscriptionObserver (no Connection param; still gated on a live Connection)
// ----

void ObserverSink::fire_subscription_transferred(ua::IntegerId subscriptionId)
{
  post_fire(&ObserverSlots::subscription,
    [subscriptionId](SubscriptionObserver& observer, const ua::client::Connection&)
    { observer.on_subscription_transferred(subscriptionId); });
}

void ObserverSink::fire_subscription_recreated(ua::IntegerId oldId, ua::IntegerId newId)
{
  post_fire(&ObserverSlots::subscription,
    [oldId, newId](SubscriptionObserver& observer, const ua::client::Connection&)
    { observer.on_subscription_recreated(oldId, newId); });
}

void ObserverSink::fire_publish_gap(ua::IntegerId subscriptionId, std::uint32_t lostFrom, std::uint32_t to)
{
  post_fire(&ObserverSlots::subscription,
    [subscriptionId, lostFrom, to](SubscriptionObserver& observer, const ua::client::Connection&)
    { observer.on_publish_gap(subscriptionId, lostFrom, to); });
}

void ObserverSink::fire_subscription_recovery_action(ua::IntegerId subscriptionId,
  ua::StatusCode terminalCode, std::shared_ptr<const ua::ErrorDetail> chain, ProposedAdjustment proposed)
{
  post_fire(&ObserverSlots::subscription,
    [subscriptionId, terminalCode, chain = std::move(chain), proposed](
      SubscriptionObserver& observer, const ua::client::Connection&) mutable
    { observer.on_subscription_recovery_action(subscriptionId, terminalCode, std::move(chain), proposed); });
}

void ObserverSink::fire_subscription_terminated(
  ua::IntegerId subscriptionId, ua::StatusCode reason, std::shared_ptr<const ua::ErrorDetail> chain)
{
  post_fire(&ObserverSlots::subscription,
    [subscriptionId, reason, chain = std::move(chain)](
      SubscriptionObserver& observer, const ua::client::Connection&) mutable
    { observer.on_subscription_terminated(subscriptionId, reason, std::move(chain)); });
}

// ---- ObserverSink::fire_*  -  TypeObserver ----

void ObserverSink::fire_type_registered(ua::NodeId encodingId, std::string typeName)
{
  post_fire(&ObserverSlots::type,
    [encodingId = std::move(encodingId), typeName = std::move(typeName)](
      TypeObserver& observer, const ua::client::Connection&) mutable
    { observer.on_type_registered(std::move(encodingId), std::move(typeName)); });
}

// ---- ObserverSink::fire_*  -  AddressSpaceObserver ----

void ObserverSink::fire_model_change(std::vector<ModelChangeStructure> changes)
{
  post_fire(&ObserverSlots::addressSpace,
    [changes = std::move(changes)](AddressSpaceObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_model_change(conn, std::move(changes)); });
}

void ObserverSink::fire_semantic_change(std::vector<SemanticChangeStructure> changes)
{
  post_fire(&ObserverSlots::addressSpace,
    [changes = std::move(changes)](AddressSpaceObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_semantic_change(conn, std::move(changes)); });
}

// ---- ObserverSink::fire_*  -  ServerStateObserver ----

void ObserverSink::fire_device_failure(EventNotification event)
{
  post_fire(&ObserverSlots::serverState,
    [event = std::move(event)](ServerStateObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_device_failure(conn, std::move(event)); });
}

void ObserverSink::fire_progress_event(EventNotification event)
{
  post_fire(&ObserverSlots::serverState,
    [event = std::move(event)](ServerStateObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_progress_event(conn, std::move(event)); });
}

void ObserverSink::fire_system_status_change(
  ua::NodeId sourceNode, ua::String sourceName, ua::ServerState newState, SystemStatusOrigin origin)
{
  post_fire(&ObserverSlots::serverState,
    [sourceNode = std::move(sourceNode), sourceName = std::move(sourceName), newState, origin](
      ServerStateObserver& observer, const ua::client::Connection& conn) mutable {
      observer.on_system_status_change(conn, std::move(sourceNode), std::move(sourceName), newState, origin);
    });
}

// ---- ObserverSink::fire_*  -  AlarmObserver ----

void ObserverSink::fire_refresh_required(std::size_t conditionCount)
{
  post_fire(&ObserverSlots::alarm,
    [conditionCount](AlarmObserver& observer, const ua::client::Connection& conn)
    { observer.on_refresh_required(conn, conditionCount); });
}

void ObserverSink::fire_data_integrity_warning(
  TrackedKey key, DataIntegrityKind kind, std::shared_ptr<const ua::ErrorDetail> details)
{
  post_fire(&ObserverSlots::alarm,
    [key = std::move(key), kind, details = std::move(details)](
      AlarmObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_data_integrity_warning(conn, std::move(key), kind, std::move(details)); });
}

void ObserverSink::fire_audit_event(EventNotification event)
{
  post_fire(&ObserverSlots::alarm,
    [event = std::move(event)](AlarmObserver& observer, const ua::client::Connection& conn) mutable
    {
      if (event.auditSubtype)
      {
        switch (event.auditSubtype->category)
        {
        case AuditEventCategory::Security:
          observer.on_audit_security_event(conn, event);
          break;
        case AuditEventCategory::Channel:
          observer.on_audit_channel_event(conn, event);
          break;
        case AuditEventCategory::Session:
          observer.on_audit_session_event(conn, event);
          break;
        case AuditEventCategory::Update:
          observer.on_audit_update_event(conn, event);
          break;
        case AuditEventCategory::UpdateMethod:
          observer.on_audit_update_method_event(conn, event);
          break;
        case AuditEventCategory::Base:
        case AuditEventCategory::UnknownSubtype:
          break;
        }
      }
      observer.on_audit_event(conn, std::move(event));
    });
}

// ---- ObserverSink::fire_*  -  RedundancyObserver ----

void ObserverSink::fire_redundancy_degraded(std::string activeUri, RedundancyDegradeReason reason)
{
  post_fire(&ObserverSlots::redundancy,
    [activeUri = std::move(activeUri), reason](
      RedundancyObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_redundancy_degraded(conn, std::move(activeUri), reason); });
}

void ObserverSink::fire_redundancy_failover_started(
  std::string fromUri, std::string toUri, ReconnectCause cause)
{
  post_fire(&ObserverSlots::redundancy,
    [fromUri = std::move(fromUri), toUri = std::move(toUri), cause = std::move(cause)](
      RedundancyObserver& observer, const ua::client::Connection& conn) mutable {
      observer.on_redundancy_failover_started(conn, std::move(fromUri), std::move(toUri), std::move(cause));
    });
}

void ObserverSink::fire_redundancy_failover_completed(std::string nowActiveUri, ReconnectOutcome outcome)
{
  post_fire(&ObserverSlots::redundancy,
    [nowActiveUri = std::move(nowActiveUri), outcome = std::move(outcome)](
      RedundancyObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_redundancy_failover_completed(conn, std::move(nowActiveUri), std::move(outcome)); });
}

void ObserverSink::fire_redundancy_recovered(std::string activeUri)
{
  post_fire(&ObserverSlots::redundancy,
    [activeUri = std::move(activeUri)](
      RedundancyObserver& observer, const ua::client::Connection& conn) mutable
    { observer.on_redundancy_recovered(conn, std::move(activeUri)); });
}

// ---- ClientObserverSink ----

std::shared_ptr<ClientObserverSink> ClientObserverSink::create(
  boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
{
  return std::shared_ptr<ClientObserverSink>(
    new ClientObserverSink(std::move(executor), std::move(connection), std::move(logger)));
}

ClientObserverSink::ClientObserverSink(
  boost::asio::any_io_executor executor, std::weak_ptr<ConnectionImpl> connection, ua::Logger logger)
  : mExecutor(std::move(executor)), mDeliveryStrand(boost::asio::make_strand(mExecutor)),
    mConnection(std::move(connection)), mLogger(std::move(logger))
{}

void ClientObserverSink::set_slots(ObserverSlots slots)
{
  if (mClosed.load())
  {
    return;  // HIGH-1: a setter after close() must never re-arm the severed sink.
  }
  mSlots.store(std::make_shared<const ObserverSlots>(std::move(slots)));
}

std::shared_ptr<const ObserverSlots> ClientObserverSink::slots() const noexcept
{
  return mSlots.load();
}

void ClientObserverSink::close()
{
  // See ObserverSink::close (HIGH-1): latch synchronously so set_slots is at once a no-op, but FIFO-post the
  // slots sever onto the delivery strand so it runs behind any already-queued fires rather than racing them
  // on a multi-thread pool.
  mClosed.store(true);
  ua::async::post_owning(this,
    mDeliveryStrand,
    ua::Logger{},
    [work = [self = shared_from_this()]()
      {
        self->mSlots.store(nullptr);
      }](auto&) mutable { work(); })();
}

template<typename Observer, typename Invoke>
void ClientObserverSink::post_fire(std::shared_ptr<Observer> ObserverSlots::*slot, Invoke invoke)
{
  // WARNING-2: deliver through the per-sink strand so hooks arrive FIFO + one-at-a-time (section 7.8
  // lifecycle order) even on a multi-thread pool  -  still OFF the orchestrator/connection strand, so
  // callback-safety holds.
  ua::async::post_owning(this,
    mDeliveryStrand,
    ua::Logger{},
    [work = [self = shared_from_this(), slot, invoke = std::move(invoke)]() mutable
      {
        const std::shared_ptr<const ObserverSlots> snapshot = self->mSlots.load();
        if (!snapshot)
        {
          return;  // closed / never-registered => no-op.
        }
        const std::shared_ptr<Observer>& observer = (*snapshot).*slot;
        if (!observer)
        {
          return;  // null family slot => cheap no-op.
        }
        // The Connection is OPTIONAL for a Client-scoped facility: pass a live borrow when present, else
        // null.
        const std::shared_ptr<ConnectionImpl> impl = self->mConnection.lock();
        // NOTE-6: a third-party observer hook that throws must not escape the posted handler ( to
        // std::terminate).
        try
        {
          if (impl)
          {
            const ua::client::Connection borrowed = make_borrowed_connection(impl);
            invoke(*observer, &borrowed);
          }
          else
          {
            invoke(*observer, nullptr);
          }
        }
        catch (const std::exception& error)
        {
          self->mLogger.warning(
            "client.observer: a user observer hook threw ({}) - swallowed; observer hooks must not throw",
            error.what());
        }
        catch (...)
        {
          self->mLogger.warning(
            "client.observer: a user observer hook threw a non-std exception - swallowed");
        }
      }](auto&) mutable { work(); })();
}

void ClientObserverSink::fire_certificate_rotated(std::shared_ptr<const ua::X509Certificate> newCert)
{
  if (!newCert)
  {
    return;  // a null cert is a producer bug; nothing to deliver.
  }
  post_fire(&ObserverSlots::security,
    [newCert = std::move(newCert)](SecurityObserver& observer, const ua::client::Connection*)
    { observer.on_certificate_rotated(*newCert); });
}

void ClientObserverSink::fire_pull_cert_management_lifecycle(
  PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail> detail)
{
  post_fire(&ObserverSlots::security,
    [event, detail = std::move(detail)](
      SecurityObserver& observer, const ua::client::Connection* conn) mutable
    { observer.on_pull_cert_management_lifecycle(conn, event, std::move(detail)); });
}

}  // namespace ua::client::detail
