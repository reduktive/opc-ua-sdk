// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "demo.h"

#include "example_support.h"

#include "ua_browse_cursor.h"
#include "ua_call_method_result.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace reduktive::reference
{
namespace
{
constexpr std::string_view demoNamespaceUri = "urn:reduktive:reference-server:demo";
// How often the server samples the node, how often it publishes what it collected, and how many
// notifications it may hold for the item before the oldest is dropped.
constexpr double publishingIntervalMs = 100.0;
constexpr double samplingIntervalMs = 50.0;
constexpr std::uint32_t queueSize = 1;
constexpr double setpointFromWrite = 37.5;
constexpr double setpointFromSubscription = 61.25;
constexpr auto notificationBudget = 5s;

/// Resolves one BrowseName path beneath Objects to the one node it names on this server.
ua::NodeId resolve(ua::client::Connection& connection, std::uint16_t namespaceIndex,
  std::initializer_list<std::string_view> targetNames)
{
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, std::vector<std::string>(targetNames.begin(), targetNames.end())));
}

}  // namespace

DemoNodes resolve_demo_nodes(ua::client::Connection& connection)
{
  // The Connection keeps a snapshot of the server's NamespaceArray. Resolve the stable URI to the
  // index this server assigned before building any QualifiedName.
  const auto namespaces = connection.namespace_table();
  const auto namespaceIndex = namespaces->lookup_index(demoNamespaceUri);
  if (!namespaceIndex)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadNotFound,
      ua::ErrorDetail::build("ReferenceNamespaceMissing",
        "The server does not publish the reference demo namespace",
        "reference_client.model")}};
  }

  return {.object = resolve(connection, *namespaceIndex, {"Demo"}),
    .uptime = resolve(connection, *namespaceIndex, {"Demo", "UptimeSeconds"}),
    .setpoint = resolve(connection, *namespaceIndex, {"Demo", "Setpoint"}),
    .divide = resolve(connection, *namespaceIndex, {"Demo", "Divide"})};
}

void list_demo_children(ua::client::Connection& connection, const DemoNodes& nodes)
{
  // A browse cursor hides continuation points: it fetches the next batch when the current one is
  // exhausted, and must be closed so the server can release the continuation it is holding.
  ua::client::BrowseOptions options;
  options.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences};
  options.includeSubtypes = true;

  ua::client::BrowseCursor cursor = connection.typed().browse(nodes.object, options);
  std::string children;
  while (cursor.has_more())
  {
    const auto entry = cursor.next_sync();
    children += children.empty() ? "" : ", ";
    children += std::string_view{entry.browseName.name()};
  }
  cursor.close_sync();
  examples::detail(fmt::format("Demo contains: {}", children));
}

void read_uptime(ua::client::Connection& connection, const DemoNodes& nodes)
{
  // The typed read decodes into the built-in type the model declares, and fails if the server
  // sends something else.
  const auto uptime = connection.read_value_sync<std::uint32_t>(nodes.uptime);
  examples::detail(fmt::format("UptimeSeconds = {}", uptime));
}

void update_setpoint(ua::client::Connection& connection, const DemoNodes& nodes)
{
  connection.write_value_sync(nodes.setpoint, ua::Variant{setpointFromWrite});

  // Read it back over its own request. A write that the server accepted is not the same claim as
  // a value the server now reports, and only the second one is visible to other clients.
  const auto readBack = connection.read_value_sync<double>(nodes.setpoint);
  examples::detail(fmt::format("Setpoint written, read back = {}", readBack));
}

void watch_setpoint(ua::client::Connection& connection, const DemoNodes& nodes)
{
  // The callback runs on the Connection's executor. It must not block, perform slow work, or call
  // a synchronous SDK operation, so it does the least possible: hand the value to whoever waits.
  auto notified = std::make_shared<std::promise<double>>();
  auto arrived = notified->get_future();
  auto delivered = std::make_shared<std::atomic<bool>>(false);

  ua::client::SubscriptionConfig subscriptionConfig;
  subscriptionConfig.publishingIntervalMs = publishingIntervalMs;
  ua::client::Subscription subscription = connection.subscriptions().create_sync(subscriptionConfig);

  ua::client::MonitorRequest request;
  request.nodeId = nodes.setpoint;
  request.samplingIntervalMs = samplingIntervalMs;
  request.queueSize = queueSize;
  subscription.monitor_sync(request,
    [notified, delivered](ua::client::DataChangeEvent event)
    {
      const auto value = event.value.value().to<double>();
      // A Subscription reports the current value first, then every change. Complete on the value
      // this function goes on to write, and exactly once.
      if (value.is_good() && value.value() == setpointFromSubscription && !delivered->exchange(true))
      {
        notified->set_value(value.value());
      }
    });

  connection.write_value_sync(nodes.setpoint, ua::Variant{setpointFromSubscription});
  if (arrived.wait_for(notificationBudget) != std::future_status::ready)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
      ua::ErrorDetail::build("ReferenceSetpointNotificationTimeout",
        "No data-change notification reported the written Setpoint in time",
        "reference_client.demo.setpoint")}};
  }
  examples::detail(fmt::format("Data-change notification reported {}", arrived.get()));
  subscription.close_sync();
}

void call_divide(ua::client::Connection& connection, const DemoNodes& nodes)
{
  const ua::CallResult result = connection.typed().call_method_sync(
    nodes.object, nodes.divide, ua::client::args(std::int32_t{84}, std::int32_t{2}));
  const auto quotient = result.value().output_arguments()[0].to<std::int32_t>().value();
  examples::detail(fmt::format("Divide(84, 2) = {}", quotient));
}

void call_divide_by_zero(ua::client::Connection& connection, const DemoNodes& nodes)
{
  // A Call has two result layers. The outer one says whether the Call service completed, and
  // reaching this line means it did. The inner CallResult says whether this Method succeeded.
  const ua::CallResult result = connection.typed().call_method_sync(
    nodes.object, nodes.divide, ua::client::args(std::int32_t{84}, std::int32_t{0}));

  // This is the one call the client expects to fail, so it inspects the inner result rather than
  // letting it throw. A bad inner result owns no outputs; it owns the reason.
  if (result.is_good())
  {
    examples::detail("Divide(84, 0) unexpectedly succeeded");
    return;
  }
  examples::detail(fmt::format("Divide(84, 0) rejected: {}", ua::to_string(result.status_code())));
  if (const auto detail = result.status_code().shared_detail())
  {
    // The server built this ErrorDetail and it survived the round trip, because the client asked
    // for operation diagnostics and the server's policy permits sending them.
    examples::detail(fmt::format("Server detail: {}", ua::to_string(*detail, 0)));
  }
}

}  // namespace reduktive::reference
