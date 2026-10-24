// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The protected operations per-node access control decides about.
/// @ingroup security

#ifndef UA_ACCESS_OPERATION_H
#define UA_ACCESS_OPERATION_H

namespace ua::server
{

/// Protected operation a per-node access decision is made about.
///
/// The union of every operation that may be denied by per-node access control. Discovery services
/// (`FindServers`, `GetEndpoints`, `FindServersOnNetwork`) are decided before any node is resolved and
/// have no slot here.
///
/// History writes and monitored-item creation are modelled at the granularity of the Part 3 Table 37
/// permission bits rather than as coarse umbrella operations: a history update is gated as
/// @c InsertHistory / @c ModifyHistory / @c DeleteHistory, because a node may grant insert but not
/// delete, and a monitored item is gated by @c Read for a data item (Part 4 5.12.2.1) or by
/// @c ReceiveEvents for an event item.
///
/// **It lives in the server layer and does not move down.** A namespace is asked what an identity may
/// do with one of its nodes, never which service is asking - so the operation never crosses the interface,
/// and the mapping from an operation to the bit that gates it stays beside the services that know.
///
/// @ingroup security
enum class AccessOperation
{
  Browse,  ///< Browse a node or read an Attribute other than Value or RolePermissions (bit 0).
  ReadRolePermissions,  ///< Read the RolePermissions Attribute (bit 1).
  WriteAttribute,  ///< Write an Attribute other than Value, Historizing or RolePermissions (bit 2).
  WriteRolePermissions,  ///< Write the RolePermissions Attribute (bit 3).
  WriteHistorizing,  ///< Write the Historizing Attribute (bit 4).
  Read,  ///< Read a Variable Value (also gates a data MonitoredItem, Part 4 5.12.2.1).
  Write,  ///< Write a Variable Value.
  HistoryRead,  ///< Read historical values or events.
  InsertHistory,  ///< Insert new history (Part 3 Table 37 InsertHistory bit).
  ModifyHistory,  ///< Replace/update existing history (Part 3 Table 37 ModifyHistory bit).
  DeleteHistory,  ///< Delete history (Part 3 Table 37 DeleteHistory bit).
  Call,  ///< Invoke a Method.
  TranslateBrowsePaths,  ///< Translate a BrowsePath to NodeIds.
  ReceiveEvents,  ///< Receive events from an event-notifier node (gates an event MonitoredItem).
  AddNodes,  ///< Add a node to the address space.
  DeleteNodes,  ///< Delete a node from the address space.
  AddReferences,  ///< Add a reference between nodes.
  DeleteReferences  ///< Delete a reference between nodes.
};

}  // namespace ua::server

#endif  // UA_ACCESS_OPERATION_H
