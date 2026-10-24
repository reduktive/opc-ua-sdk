// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef REDUKTIVE_REFERENCE_CLIENT_DEMO_H
#define REDUKTIVE_REFERENCE_CLIENT_DEMO_H

/// @file
/// @brief The protocol workflow the reference client performs once it is connected.
///
/// Each function is one operation against the reference server's demo model, in the order a
/// reader meets them: find the nodes, list them, read one, write one, watch one, call a Method,
/// and handle a Method the server rejects.

#include "ua_node_id.h"

namespace ua::client
{
class Connection;
}

namespace reduktive::reference
{

/// The demo model's NodeIds, as this server assigned them.
struct DemoNodes
{
  ua::NodeId object;
  ua::NodeId uptime;
  ua::NodeId setpoint;
  ua::NodeId divide;
};

/// Resolves the demo model by namespace URI and BrowseName path.
///
/// Nothing here assumes a NodeId. A namespace index is assigned by each server, and the NodeId
/// behind a BrowseName is the server's to choose, so both are looked up at run time.
DemoNodes resolve_demo_nodes(ua::client::Connection& connection);

/// Lists the Demo object's children through a browse cursor, closing it when done.
void list_demo_children(ua::client::Connection& connection, const DemoNodes& nodes);

/// Reads UptimeSeconds as the native type the model declares for it.
void read_uptime(ua::client::Connection& connection, const DemoNodes& nodes);

/// Writes Setpoint and reads the value back over a separate request.
void update_setpoint(ua::client::Connection& connection, const DemoNodes& nodes);

/// Creates a Subscription on Setpoint, writes a new value, and waits to be told about it.
void watch_setpoint(ua::client::Connection& connection, const DemoNodes& nodes);

/// Calls Divide with operands it accepts, and decodes the output.
void call_divide(ua::client::Connection& connection, const DemoNodes& nodes);

/// Calls Divide with a zero divisor and consumes the failure the server reports.
///
/// This is the one place the client expects to fail. It shows the two result layers of a Call,
/// and that the server's ErrorDetail survives the round trip.
void call_divide_by_zero(ua::client::Connection& connection, const DemoNodes& nodes);

}  // namespace reduktive::reference

#endif  // REDUKTIVE_REFERENCE_CLIENT_DEMO_H
