// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7 companion-spec integration tests - PROFINET events / conditions.
///
/// Row 10: event emission + observation - a generated companion event payload
///         (PnAssetChangedEventPayload) is emitted through the server, and the
///         server resolves its EventType NodeId into the PROFINET namespace at
///         emit time (the context-free-payload -> server-resolved design).
/// Row 11: condition-derived event - the generated PnDiagnosisAlarmPayload (a
///         subtype of NS0's AlarmConditionType) emits with its companion EventType
///         resolved, exercising a cross-spec condition event type end-to-end.

#include <boost/asio/thread_pool.hpp>
#include <chrono>
#include <future>
#include <mutex>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_application_configuration.h"
#include "ua_base_event.h"
#include "ua_default_namespace.h"
#include "ua_localized_text.h"
#include "ua_namespace_array.h"
#include "ua_node_id.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_server_config_bundle.h"

#include "ua_pn_objecttype_id.h"
#include "ua_pn_pn_asset_changed_event_payload.h"
#include "ua_pn_pn_diagnosis_alarm_payload.h"

#include "test_components.h"
using namespace ua;
using namespace std::chrono_literals;

namespace
{
constexpr auto pnUri = "http://opcfoundation.org/UA/PROFINET/";

server::Server make_server(boost::asio::thread_pool& pool)
{
  server::CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = server::ServerConfig{}};
  return server::Server::create(pool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
}

// Emit one event through the server and return the EventType NodeId observed by
// the local event listener. The listener fires asynchronously on the event-bus
// dispatch strand, so we synchronise on it via a promise.
NodeId emit_and_observe_event_type(server::Server& server, boost::asio::thread_pool& pool, BaseEvent& event)
{
  // The listener fires on the event-bus dispatch strand (a pool thread). It shares its state with
  // this (main) thread, so that state must NOT be a local of this function: set_value() wakes our
  // wait_for() below, and we would then return and destroy the locals WHILE the strand thread is
  // still finishing std::call_once's bookkeeping on the flag / unwinding the listener call - a
  // use-after-free (intermittent segfault). Hold the shared state in a shared_ptr captured BY VALUE
  // so it outlives the listener; the event bus destroys the listener on its own strand (after any
  // in-flight invocation completes), releasing the last reference safely.
  struct Observed
  {
    std::promise<NodeId> typePromise;
    std::once_flag once;
  };

  auto observed = std::make_shared<Observed>();
  auto typeFuture = observed->typePromise.get_future();
  server.set_event_listener([observed](const BaseEvent& ev)
    { std::call_once(observed->once, [&] { observed->typePromise.set_value(ev.eventType); }); });
  server.emit_event(event);
  EXPECT_EQ(typeFuture.wait_for(5s), std::future_status::ready) << "event listener was not invoked";
  // Detach the listener so a later event cannot re-enter it; the shared state is kept alive by the
  // listener's own captured shared_ptr until the bus tears it down on-strand.
  server.set_event_listener({});
  return typeFuture.get();
}
}  // namespace

// Row 10 - companion event emission with server-resolved EventType namespace.
TEST(ProfinetEventTests, AssetChangedEventResolvesItsCompanionNamespaceOnEmit)
{
  boost::asio::thread_pool threadPool;
  auto server = make_server(threadPool);

  // Register the PROFINET namespace so the server can resolve the companion
  // event type's URI to a concrete index at emit time.
  const uint16_t pnIndex = server.address_space().add_namespace_sync(
    default_ns::Namespace::create(pnUri, threadPool.get_executor()));
  ASSERT_NE(pnIndex, 0);

  ua::pn::PnAssetChangedEventPayload event;
  event.severity = 500;
  event.message = LocalizedText{"", "asset changed"};

  const NodeId observedType = emit_and_observe_event_type(server, threadPool, event);
  EXPECT_EQ(observedType.namespace_index(), pnIndex)
    << "companion event type must resolve into the PROFINET namespace, not NS0";
  ASSERT_TRUE(observedType.is_numeric());
  EXPECT_EQ(observedType.identifier().get_numeric(),
    static_cast<uint32_t>(ua::pn::ObjectTypeId::PnAssetChangedEventType));

  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Row 11 - a cross-spec condition-derived event (PnDiagnosisAlarmType, a subtype
// of NS0's AlarmConditionType) emits with its companion EventType resolved.
TEST(ProfinetEventTests, DiagnosisAlarmConditionEventResolvesCompanionNamespace)
{
  boost::asio::thread_pool threadPool;
  auto server = make_server(threadPool);

  const uint16_t pnIndex = server.address_space().add_namespace_sync(
    default_ns::Namespace::create(pnUri, threadPool.get_executor()));
  ASSERT_NE(pnIndex, 0);

  // PnDiagnosisAlarmPayload derives from ::ua::AlarmConditionPayload - cross-spec
  // inheritance from an NS0 condition event type.
  ua::pn::PnDiagnosisAlarmPayload alarm;
  alarm.severity = 800;

  const NodeId observedType = emit_and_observe_event_type(server, threadPool, alarm);
  EXPECT_EQ(observedType.namespace_index(), pnIndex);
  ASSERT_TRUE(observedType.is_numeric());
  EXPECT_EQ(observedType.identifier().get_numeric(),
    static_cast<uint32_t>(ua::pn::ObjectTypeId::PnDiagnosisAlarmType));

  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// NOTE: EventFilter OfType subtype matching is resolved at runtime against the
// server's address-space HasSubtype hierarchy by the EventBus (it attaches the
// resolved supertype chain to each dispatched event) and tested end-to-end
// through real subscriptions in the integration event-filter suite - not via a
// per-event method here.
