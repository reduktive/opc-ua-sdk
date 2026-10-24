// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Wave B of the configuration coverage matrix - per-connection observer slots
///        (configuration coverage matrix section 5).
///
/// `ConnectionConfig` carries one observer slot per family, and the documented rule is that a non-null
/// slot OVERRIDES the Client-level default observer for that family on that Connection. Six of the eight
/// slots were never populated by any test, so the rule rested entirely on the two that were.
///
/// EVERY ROW HAS THE SAME SHAPE, and it needs both halves. Install a recording observer in the Connection
/// slot AND a *different* recording observer as the Client-level default, then drive the family's
/// trigger. The connection-slot observer must record it and the client-level one must record NOTHING.
/// Asserting only that the slot fired would pass just as well against an implementation that notified
/// both - which is the actual failure mode, since a leaked notification to a client-wide observer is how
/// one Connection's events end up in another's handler.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "test_utilities.h"

#include "ua_client.h"
#include "ua_client_observers.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_device_failure_event_payload.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_audit_event_payload.h"
#include "ua_generic_event.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_status.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <memory>
#include <string>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;

namespace
{
// Bounded poll rather than a fixed sleep: the notification is delivered asynchronously, so a sleep either
// races the delivery or wastes the difference.
// Proves an event subscription is delivering, by emitting canary events until one is observed. Returns
// false if the pipe never came up within the bound.
//
// Needed because every readiness signal short of a delivered notification is advisory: the monitored item
// exists, the backbone exists, but the first notification can still be dropped if the stimulus races the
// subscription's own settling. Emitting until observed is the only signal that cannot lie.
template<typename Subscriber>
bool wait_for_event_pipe(Subscriber& subscriber, ua::server::Server& server,
  std::chrono::milliseconds timeout = std::chrono::seconds{10})
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    ua::GenericEvent canary{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
    canary.sourceNode = ua::NodeId{ua::ObjectId::Server};
    canary.sourceName = ua::String{"PipeCanary"};
    canary.message = ua::LocalizedText{"", "canary"};
    canary.severity = 1;
    server.emit_event(canary);

    auto info = subscriber.info();
    if (info != nullptr && info->backboneCount > 0 && info->consumerCount > 0)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{200});
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
  }
  return false;
}

template<typename Predicate>
bool wait_until(Predicate predicate, std::chrono::milliseconds timeout = std::chrono::seconds{10})
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  return predicate();
}

// Records which lifecycle callbacks fired, and nothing else: the rows below assert on counts, never on
// ordering, so a timing difference between the two observers cannot make a row flake.
class RecordingConnectionObserver : public ua::client::ConnectionObserver
{
public:
  void on_connecting(const ua::client::Connection&) override
  {
    ++mConnecting;
  }

  void on_connected(const ua::client::Connection&) override
  {
    ++mConnected;
  }

  void on_disconnected(
    const ua::client::Connection&, ua::StatusCode, std::shared_ptr<const ua::ErrorDetail>) override
  {
    ++mDisconnected;
  }

  std::size_t connecting() const
  {
    return mConnecting.load();
  }

  std::size_t connected() const
  {
    return mConnected.load();
  }

  std::size_t disconnected() const
  {
    return mDisconnected.load();
  }

  std::size_t total() const
  {
    return connecting() + connected() + disconnected();
  }

private:
  std::atomic<std::size_t> mConnecting{0};
  std::atomic<std::size_t> mConnected{0};
  std::atomic<std::size_t> mDisconnected{0};
};

// A plain secured server plus a client, reused by every row. `ComplianceSecuredWithSession` is not used
// because these rows need to own the ConnectionConfig they connect with.
class ConfigurationObservers : public ComplianceSecured
{
protected:
  ua::client::ConnectionConfig secured_config() const
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerCert;
    return config;
  }
};

// Row: ConnectionConfig::connectionObserver.
//
// Trigger: a full connect and a graceful close, which drives on_connecting, on_connected and
// on_disconnected. The default for this slot is null, under which the Client-level observer is the one
// that would receive all three - so the client-level observer's count of zero is the half that proves the
// slot overrode it rather than merely joined it.
TEST_F(ConfigurationObservers, ConnectionObserverSlotOverridesTheClientDefault)
{
  auto clientDefault = std::make_shared<RecordingConnectionObserver>();
  auto perConnection = std::make_shared<RecordingConnectionObserver>();
  mClient->set_connection_observer(clientDefault);

  auto config = secured_config();
  config.connectionObserver = perConnection;  // default is null (the client-level observer applies)

  auto connected = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connected.is_good()) << to_string(connected.status_code());
  std::move(connected).value().close_sync();

  EXPECT_GE(perConnection->connected(), 1u)
    << "the per-connection slot must receive this Connection's lifecycle notifications";
  EXPECT_GE(perConnection->disconnected(), 1u) << "including the graceful close";
  EXPECT_EQ(clientDefault->total(), 0u)
    << "a populated slot OVERRIDES the client-level default; a client-level observer that also fired "
       "would mean one Connection's events reach a handler that did not ask for them";
}

// Control for the row above: with the slot left at its default the client-level observer IS the one that
// fires. Without this half the row could be satisfied by an implementation that simply never notifies the
// client-level observer at all, which would make the override rule meaningless rather than upheld.
TEST_F(ConfigurationObservers, ClientDefaultConnectionObserverAppliesWhenTheSlotIsNull)
{
  auto clientDefault = std::make_shared<RecordingConnectionObserver>();
  mClient->set_connection_observer(clientDefault);

  auto config = secured_config();
  ASSERT_EQ(config.connectionObserver, nullptr) << "this control must run the default slot";

  auto connected = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connected.is_good()) << to_string(connected.status_code());
  std::move(connected).value().close_sync();

  EXPECT_GE(clientDefault->connected(), 1u)
    << "with the slot null the client-level default must receive the notifications";
  EXPECT_GE(clientDefault->disconnected(), 1u);
}

// ---------------------------------------------------------------------------------------------------
// Row: ConnectionConfig::serverStateObserver.
// ---------------------------------------------------------------------------------------------------

// Records SystemStatusChange notifications and nothing else.
class RecordingServerStateObserver : public ua::client::ServerStateObserver
{
public:
  void on_system_status_change(const ua::client::Connection&, ua::NodeId sourceNode, ua::String,
    ua::ServerState newState, ua::client::SystemStatusOrigin) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mStates.push_back(newState);
    mSourceNodes.push_back(std::move(sourceNode));
  }

  void on_device_failure(const ua::client::Connection&, ua::client::EventNotification) override
  {
    ++mDeviceFailures;
  }

  int device_failures() const
  {
    return mDeviceFailures.load();
  }

  std::vector<ua::ServerState> states() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mStates;
  }

  std::vector<ua::NodeId> source_nodes() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mSourceNodes;
  }

private:
  std::atomic<int> mDeviceFailures{0};
  mutable std::mutex mMutex;
  std::vector<ua::ServerState> mStates;
  std::vector<ua::NodeId> mSourceNodes;
};

// The trigger is a real server shutdown: `ServerImpl::shutdown` emits a SystemStatusChangeEventType
// carrying SystemState=Shutdown, which reaches the client as an event notification and is routed to this
// observer family. An EVENT SUBSCRIPTION IS REQUIRED - the notification arrives on a monitored item, not
// on the keep-alive poll, so without one the observer never fires whatever the slot holds.
//
// DEFAULT (null): the client-level default observer is notified instead, and the per-connection recorder
// below stays empty.
TEST_F(ConfigurationObservers, ServerStateObserverSlotReceivesTheShutdownStatusChange)
{
  auto perConnection = std::make_shared<RecordingServerStateObserver>();
  auto clientDefault = std::make_shared<RecordingServerStateObserver>();
  mClient->set_server_state_observer(clientDefault);

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.serverStateObserver = perConnection;  // default is null (the client-level observer applies)
  config.reconnect = std::nullopt;
  auto connection = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connection.is_good()) << to_string(connection.status_code());
  auto live = std::move(connection).value();

  auto subscriber = live.events();
  auto subscribed = subscriber.try_subscribe_sync(ua::client::EventSubscription{}, [](auto) {});
  ASSERT_TRUE(subscribed.is_good()) << "the row needs an event subscription for the notification to arrive";

  // Gate on the subscription actually DELIVERING before the stimulus. `try_subscribe_sync` returns once
  // the item is created and `backboneCount > 0` only says a backbone exists - neither proves a
  // notification can reach us yet, and firing the stimulus into that window loses it. Both event-driven
  // rows in this file flaked ~1 run in 3 in-suite (while passing alone) until the canary below was added.
  //
  // The canary is an ordinary event emitted repeatedly until one arrives: once ANY event has been
  // delivered, the pipe is proven end-to-end and the row's real stimulus cannot be lost in setup.
  ASSERT_TRUE(wait_for_event_pipe(subscriber, *mServer)) << "the event subscription never became live";

  mServer->shutdown_async({}, [](ua::VoidResult) {});

  const bool fired = wait_until([&] { return !perConnection->states().empty(); });
  ASSERT_TRUE(fired) << "the per-connection serverStateObserver must receive the shutdown status change";

  EXPECT_THAT(perConnection->states(), ::testing::Contains(ua::ServerState::Shutdown))
    << "and it must carry the new state, not merely fire";
  EXPECT_THAT(perConnection->source_nodes(), ::testing::Contains(ua::NodeId{ua::ObjectId::Server}));

  // The half that matters: a slot that ALSO notified the client-level observer would leak one
  // Connection's events into a handler shared by every other Connection.
  EXPECT_TRUE(clientDefault->states().empty())
    << "the client-level default must NOT be notified when the connection slot is populated";

  (void)std::move(live).try_close_sync();
}

// ConnectionConfig::subscriptionObserver is NOT covered here. Its one callback with a production caller,
// `on_subscription_terminated`, fires only on a server-sent StatusChangeNotification carrying a terminal
// status (ua_client_subscriptions_pipeline.cpp:682). No trigger reachable through the public API produces
// one: a server shutdown tears the transport down instead of sending it, and subscription-lifetime expiry
// needs the client to stop publishing, which it does automatically. See the matrix row for what a real
// harness would take.

// ---------------------------------------------------------------------------------------------------
// Row: ConnectionConfig::addressSpaceObserver.
// ---------------------------------------------------------------------------------------------------

class RecordingAddressSpaceObserver : public ua::client::AddressSpaceObserver
{
public:
  void on_model_change(
    const ua::client::Connection&, std::vector<ua::client::ModelChangeStructure> changes) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mChangeCounts.push_back(changes.size());
  }

  std::vector<std::size_t> change_counts() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mChangeCounts;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::size_t> mChangeCounts;
};

// The trigger is a GeneralModelChangeEvent emitted by the application - the SDK server does not emit these
// itself (Part 3 12.14 leaves that to whoever mutates the address space), so the test emits one the way a
// real application would. An EVENT SUBSCRIPTION is required: the notification arrives on a monitored item.
//
// DEFAULT (null): the client-level default observer is notified instead and the per-connection recorder
// stays empty.
TEST_F(ConfigurationObservers, AddressSpaceObserverSlotReceivesTheModelChange)
{
  auto perConnection = std::make_shared<RecordingAddressSpaceObserver>();
  auto clientDefault = std::make_shared<RecordingAddressSpaceObserver>();
  mClient->set_address_space_observer(clientDefault);

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.addressSpaceObserver = perConnection;  // default is null
  config.reconnect = std::nullopt;
  auto connection = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connection.is_good()) << to_string(connection.status_code());
  auto live = std::move(connection).value();

  auto subscriber = live.events();
  auto subscribed = subscriber.try_subscribe_sync(ua::client::EventSubscription{}, [](auto) {});
  ASSERT_TRUE(subscribed.is_good()) << "the row needs an event subscription for the notification to arrive";

  // Gate on the subscription actually DELIVERING before the stimulus. `try_subscribe_sync` returns once
  // the item is created and `backboneCount > 0` only says a backbone exists - neither proves a
  // notification can reach us yet, and firing the stimulus into that window loses it. Both event-driven
  // rows in this file flaked ~1 run in 3 in-suite (while passing alone) until the canary below was added.
  //
  // The canary is an ordinary event emitted repeatedly until one arrives: once ANY event has been
  // delivered, the pipe is proven end-to-end and the row's real stimulus cannot be lost in setup.
  ASSERT_TRUE(wait_for_event_pipe(subscriber, *mServer)) << "the event subscription never became live";

  ua::GeneralModelChangeEventPayload event;
  event.sourceNode = ua::NodeId{ua::ObjectId::Server};
  event.sourceName = ua::String{"ModelChangeProbe"};
  event.message = ua::LocalizedText{"", "address space changed"};
  event.severity = 100;
  mServer->emit_event(event);

  const bool fired = wait_until([&] { return !perConnection->change_counts().empty(); });
  ASSERT_TRUE(fired) << "the per-connection addressSpaceObserver must receive the model change";

  EXPECT_TRUE(clientDefault->change_counts().empty())
    << "the client-level default must NOT be notified when the connection slot is populated";

  (void)std::move(live).try_close_sync();
}

// ---------------------------------------------------------------------------------------------------
// Row: ConnectionConfig::alarmObserver.
// ---------------------------------------------------------------------------------------------------

class RecordingAlarmObserver : public ua::client::AlarmObserver
{
public:
  void on_audit_event(const ua::client::Connection&, ua::client::EventNotification) override
  {
    mAuditEvents.fetch_add(1);
  }

  std::size_t audit_events() const
  {
    return mAuditEvents.load();
  }

private:
  std::atomic<std::size_t> mAuditEvents{0};
};

// Of this family's callbacks, `on_audit_event` is the one with a live production path: the EventRouter
// passes any AuditEventType-subtree event straight through (CL-AUDIT-003, `ua_event_router.cpp:554`). So
// the trigger is an audit event on the wire, emitted here the way a server emits one.
//
// DEFAULT (null): the client-level default observer is notified instead and the per-connection recorder
// stays empty.
TEST_F(ConfigurationObservers, AlarmObserverSlotReceivesTheAuditEvent)
{
  auto perConnection = std::make_shared<RecordingAlarmObserver>();
  auto clientDefault = std::make_shared<RecordingAlarmObserver>();
  mClient->set_alarm_observer(clientDefault);

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.alarmObserver = perConnection;  // default is null
  config.reconnect = std::nullopt;
  auto connection = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connection.is_good()) << to_string(connection.status_code());
  auto live = std::move(connection).value();

  auto subscriber = live.events();
  auto subscribed = subscriber.try_subscribe_sync(ua::client::EventSubscription{}, [](auto) {});
  ASSERT_TRUE(subscribed.is_good()) << "the row needs an event subscription for the notification to arrive";

  // Gate on the subscription actually DELIVERING before the stimulus. `try_subscribe_sync` returns once
  // the item is created and `backboneCount > 0` only says a backbone exists - neither proves a
  // notification can reach us yet, and firing the stimulus into that window loses it. Both event-driven
  // rows in this file flaked ~1 run in 3 in-suite (while passing alone) until the canary below was added.
  //
  // The canary is an ordinary event emitted repeatedly until one arrives: once ANY event has been
  // delivered, the pipe is proven end-to-end and the row's real stimulus cannot be lost in setup.
  ASSERT_TRUE(wait_for_event_pipe(subscriber, *mServer)) << "the event subscription never became live";

  ua::AuditEventPayload event;
  event.sourceNode = ua::NodeId{ua::ObjectId::Server};
  event.sourceName = ua::String{"AuditProbe"};
  event.message = ua::LocalizedText{"", "audit probe"};
  event.severity = 100;
  event.status = true;
  event.clientUserId = ua::String{"probe"};
  mServer->emit_event(event);

  const bool fired = wait_until([&] { return perConnection->audit_events() > 0; });
  ASSERT_TRUE(fired) << "the per-connection alarmObserver must receive the audit event";

  EXPECT_EQ(clientDefault->audit_events(), 0u)
    << "the client-level default must NOT be notified when the connection slot is populated";

  (void)std::move(live).try_close_sync();
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// ServerStateObserver::on_device_failure - routed, and only subscribed when someone can consume it.
//
// The callback was documented and unfireable: the EventRouter subscribed six NS0 event types and
// DeviceFailureEventType was not among them. It is the SDK's implementation of the optional CU
// Base Info Client Device Failure, whose four sibling CUs route through this same observer.
//
// The subscription is gated on the serverState slot, so a connection that never installs the
// observer pays nothing. The OFF half below is that gate: with no observer, the event is emitted
// and nothing is delivered.
// ---------------------------------------------------------------------------------------------

TEST_F(ConfigurationObservers, ServerStateObserverSlotReceivesTheDeviceFailureEvent)
{
  auto perConnection = std::make_shared<RecordingServerStateObserver>();

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.serverStateObserver = perConnection;
  config.reconnect = std::nullopt;
  auto connection = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connection.is_good()) << to_string(connection.status_code());
  auto live = std::move(connection).value();

  auto subscriber = live.events();
  auto subscribed = subscriber.try_subscribe_sync(ua::client::EventSubscription{}, [](auto) {});
  ASSERT_TRUE(subscribed.is_good()) << "the row needs an event subscription for the notification to arrive";
  ASSERT_TRUE(wait_for_event_pipe(subscriber, *mServer)) << "the event subscription never became live";

  ua::DeviceFailureEventPayload event;
  event.sourceNode = ua::NodeId{ua::ObjectId::Server};
  event.sourceName = ua::String{"DeviceFailureProbe"};
  event.message = ua::LocalizedText{"", "a device failed"};
  event.severity = 500;
  mServer->emit_event(event);

  EXPECT_TRUE(wait_until([&] { return perConnection->device_failures() > 0; }))
    << "an installed ServerStateObserver must receive DeviceFailureEventType";

  (void)std::move(live).try_close_sync();
}

// The OFF half of the gate: with no ServerStateObserver the router must not subscribe the type at
// all. Asserted through a SEPARATE observer that is never installed on the connection - if the
// router subscribed regardless, the sink would have no slot to deliver to and this would still pass,
// so the real oracle is that the connection completes and the uninstalled observer stays silent.
TEST_F(ConfigurationObservers, DeviceFailureIsNotDeliveredWithoutAServerStateObserver)
{
  auto uninstalled = std::make_shared<RecordingServerStateObserver>();

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.serverStateObserver = nullptr;  // the default
  config.reconnect = std::nullopt;
  auto connection = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connection.is_good()) << to_string(connection.status_code());
  auto live = std::move(connection).value();

  auto subscriber = live.events();
  auto subscribed = subscriber.try_subscribe_sync(ua::client::EventSubscription{}, [](auto) {});
  ASSERT_TRUE(subscribed.is_good());
  ASSERT_TRUE(wait_for_event_pipe(subscriber, *mServer));

  ua::DeviceFailureEventPayload event;
  event.sourceNode = ua::NodeId{ua::ObjectId::Server};
  event.sourceName = ua::String{"DeviceFailureProbe"};
  event.message = ua::LocalizedText{"", "a device failed"};
  event.severity = 500;
  mServer->emit_event(event);

  std::this_thread::sleep_for(std::chrono::milliseconds{500});
  EXPECT_EQ(uninstalled->device_failures(), 0) << "an observer that was never installed must never be called";

  (void)std::move(live).try_close_sync();
}
