// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Surviving a server that goes away and comes back.
///
/// It talks to `examples/server/minimal`. Start that first, run this, and then stop and restart
/// the server while this is waiting: the client notices, reconnects on its own, and its
/// Subscription keeps delivering afterwards.
///
/// This is the difference between a demonstration and something you can deploy. A client that
/// gives up on the first dropped TCP connection is not usable in a plant, where switches reboot,
/// links flap, and servers are restarted for maintenance.

#include "example_pki.h"
#include "example_queue.h"
#include "reconnect_observer.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_connection_state.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_reconnect_policy.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4840";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:minimal";
constexpr double valueAfterRecovery = 64.0;
// A ceiling on waiting for the operator to restart the server, not a delay anyone expects to spend.
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;
constexpr auto notificationBudget = 30000ms;
// The backoff this example asks for. Tune it to the outage you expect; the SDK's default
// ceiling is sixty seconds, which is patient for a server restarted for maintenance.
constexpr auto backoffBase = 500ms;
constexpr auto backoffMax = 5s;
// How often the server samples the node, how often it publishes what it collected, and how many
// notifications it may hold for the item before the oldest is dropped.
constexpr double publishingIntervalMs = 100.0;
constexpr double samplingIntervalMs = 50.0;
constexpr std::uint32_t queueSize = 10;

/// Creates the client and hands it to the Runtime to own.
ua::client::Client& create_client(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Client)};

  return runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));
}

/// Connects with a reconnect policy, which is what makes this client survive an outage.
///
/// Without `reconnect`, a dropped connection is terminal and every later operation fails. With it,
/// the SDK re-establishes the channel and Session, and recovers the Subscriptions: it tries to
/// transfer them to the new Session first, and recreates them if the server cannot.
ua::client::Connection connect(ua::Runtime& runtime, std::string_view endpointUrl)
{
  // Identity, client, connection: the three steps every client performs, in one place, so that
  // main() gets to the part this example is actually about.
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  ua::client::Client& client = create_client(runtime, pki);
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  policy.customize = [](ua::client::ConnectionConfig& config)
  {
    ua::client::ReconnectPolicy reconnect;
    // Tune the backoff to the outage you expect. The default doubles from one second up to a
    // sixty-second ceiling, which is right for a link that may be down for hours but means a
    // client can still be waiting a minute after a server that restarted in five seconds is back.
    // A half-second start and a five-second ceiling suit a server that is restarted for
    // maintenance; the jitter keeps a fleet of clients from retrying in lockstep.
    reconnect.backoff.base = backoffBase;
    reconnect.backoff.max = backoffMax;
    // Recover the Subscriptions with the connection: transfer them to the new Session if the
    // server can, and recreate them if it cannot.
    reconnect.subscriptionRecovery = ua::client::SubscriptionRecovery::TransferThenRecreate;
    config.reconnect = reconnect;
  };
  return client.easy_connect_sync(std::move(policy));
}

/// Resolves `Demo/Setpoint` to the NodeId this server gave it.
ua::NodeId resolve_setpoint(ua::client::Connection& connection)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, ua::hierarchical_path(namespaceIndex, {"Demo", "Setpoint"}));
}

/// Creates a Subscription on Demo/Setpoint that appends every reported value to @p values.
ua::client::Subscription subscribe_to_setpoint(ua::client::Connection& connection, const ua::NodeId& setpoint,
  std::shared_ptr<examples::Queue<double>> values)
{
  ua::client::SubscriptionConfig config;
  config.publishingIntervalMs = publishingIntervalMs;
  ua::client::Subscription subscription = connection.subscriptions().create_sync(config);

  ua::client::MonitorRequest request;
  request.nodeId = setpoint;
  request.samplingIntervalMs = samplingIntervalMs;
  request.queueSize = queueSize;
  subscription.monitor_sync(std::move(request),
    [values](ua::client::DataChangeEvent event)
    {
      const auto value = event.value.value().to<double>();
      if (value.is_good())
      {
        values->push(value.value());
      }
    });
  return subscription;
}

/// Installs the reconnect observer and returns the queue its notifications land in.
std::shared_ptr<examples::Queue<examples::reconnect::Notification>> observe_reconnects(
  ua::client::Connection& connection, std::shared_ptr<examples::reconnect::ReconnectObserver>& observer)
{
  auto notifications = std::make_shared<examples::Queue<examples::reconnect::Notification>>();
  observer = std::make_shared<examples::reconnect::ReconnectObserver>(notifications);
  connection.set_connection_observer(observer);
  return notifications;
}

/// Reports what the completed reconnect preserved: the point of a reconnect policy in one line.
void report_outcome(const ua::client::ReconnectOutcome& outcome)
{
  examples::detail(fmt::format("Session {}, subscriptions {}, monitored items recreated: {}",
    outcome.sessionPreserved ? "preserved" : "recreated",
    outcome.subscriptionsTransferred ? "transferred" : "recreated",
    outcome.monitoredItemsRecreated));
}

/// Writes a value and waits for the recovered Subscription to report it back.
void require_delivery_after_recovery(
  ua::client::Connection& connection, const ua::NodeId& setpoint, examples::Queue<double>& values)
{
  connection.write_value_sync(setpoint, ua::Variant{valueAfterRecovery});
  if (!values.wait_for_value(valueAfterRecovery, notificationBudget))
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
      ua::ErrorDetail::build("ExampleSubscriptionLost",
        "The Subscription delivered nothing after the reconnect",
        "client.reconnect")}};
  }
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/reconnect_and_keepalive", "Survive a server that goes away and comes back.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    std::shared_ptr<examples::reconnect::ReconnectObserver> observer;
    auto notifications = observe_reconnects(connection, observer);
    const ua::NodeId setpoint = resolve_setpoint(connection);
    examples::step(1, fmt::format("Connected to {} with a reconnect policy", endpointUrl));

    auto values = std::make_shared<examples::Queue<double>>();
    ua::client::Subscription subscription = subscribe_to_setpoint(connection, setpoint, values);
    examples::step(2, "Subscribed to Demo/Setpoint");

    // Everything above is ordinary. What follows is the part that matters: the server disappears.
    examples::step(3, "Waiting for the server to restart");
    examples::reconnect::await(*notifications,
      examples::reconnect::Notification::Reconnecting,
      "The Connection never reported a reconnect, so no outage was observed");
    examples::step(4, "Server went away; the Connection is reconnecting, not failed");

    examples::reconnect::await(*notifications,
      examples::reconnect::Notification::Reconnected,
      "The Connection did not report a completed reconnect within the budget");
    examples::step(5, "Server came back; the Connection recovered on its own");
    report_outcome(observer->outcome());

    // The Subscription was recovered with the Session, so this write is reported the same way it
    // would have been before the outage. Nothing above had to be rebuilt by hand.
    require_delivery_after_recovery(connection, setpoint, *values);
    examples::step(6, fmt::format("Subscription still delivering: reported {}", valueAfterRecovery));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(7, "Closed the Session and stopped the client");

    examples::finished("client/reconnect_and_keepalive");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/reconnect_and_keepalive", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/reconnect_and_keepalive: {}\n", failure.what());
  }
  return 1;
}
