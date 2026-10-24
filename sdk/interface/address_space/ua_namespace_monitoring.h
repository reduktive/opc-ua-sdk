// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-item input and result payloads for the Namespace monitoring API.
/// @ingroup address_space

#ifndef UA_NAMESPACE_MONITORING_H
#define UA_NAMESPACE_MONITORING_H

#include "ua_attribute_id.h"
#include "ua_duration.h"
#include "ua_integer_id.h"
#include "ua_node_id.h"
#include "ua_numeric_range.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstdint>
#include <memory>

namespace ua
{

class Node;
class SampleSink;

/// Opaque handle that identifies one monitoring registration within a namespace.
///
/// Returned in @ref MonitoringCreateSuccess::handle from a successful
/// `Namespace::create_monitoring_async()` item. The caller passes it back to
/// `Namespace::delete_monitoring_async()` or in @ref MonitoringModifyItem::handle to
/// reference the same registration. Values are opaque and meaningful only to
/// the issuing namespace; do not assume any ordering or numeric structure.
///
/// @ingroup address_space
using MonitoringHandle = uint32_t;

/// Per-item input describing one node attribute to begin monitoring.
///
/// One element of the batch passed to `Namespace::create_monitoring_async()`.
/// @see MonitoringCreateItemResult, MonitoringModifyItem
/// @ingroup address_space
struct MonitoringCreateItem
{
  NodeId nodeId;  ///< Node whose attribute is sampled.
  /// The Node this namespace returned for @ref nodeId when CreateMonitoredItems looked it up for the same
  /// request, so the namespace need not look it up again; CreateMonitoredItems refuses an item whose lookup
  /// finds no Node, so its items always carry one. Null when the caller holds no Node, and the namespace then
  /// looks @ref nodeId up itself; the base `Namespace` default does not, and answers such an item
  /// `Bad_NodeIdUnknown`. The namespace may keep it for the registration's life. Before using it, a
  /// namespace checks that the Node is one of its own and not deleted: a direct caller of `create_monitoring_async`
  /// may pass any Node. The base `Namespace` default does not check it; it passes the Node to the monitoring
  /// helper as it was given.
  std::shared_ptr<Node> node{};
  AttributeId attributeId{AttributeId::Value};  ///< Attribute of @ref nodeId to monitor.
  /// The monitored item's IndexRange (OPC 10000-4 7.27); empty for the whole value. The namespace narrows
  /// every sample it delivers to it, as a Read of the same range would answer, so the item receives no more
  /// than it asked for: the monitored item does not narrow the value again, and fails a value larger than
  /// its range with `Bad_InternalError`. CreateMonitoredItems has already checked the syntax. An item on
  /// UserAccessLevel, UserWriteMask, UserExecutable, RolePermissions or UserRolePermissions is registered
  /// on the attribute the namespace holds with an empty range: the server narrows the value it produces
  /// from that attribute for the user.
  NumericRange indexRange{};
  IntegerId monitoredItemId{0};  ///< Caller's identifier, echoed back to @ref sink on delivery.
  Duration samplingInterval{0};  ///< Requested sampling interval in milliseconds; 0 requests the
                                 ///< fastest practical rate, subject to revision.
  uint32_t queueSize{1};  ///< Maximum samples buffered before older values are overwritten.
  /// Shared sink that receives sampled values; one per subscription. The namespace retains a strong
  /// reference for the lifetime of the registration. Must not be null. The caller the item is sampled
  /// for is the sink's `caller()` when the namespace reads it, not a value fixed at creation.
  std::shared_ptr<SampleSink> sink;
};

/// Successful per-item outcome of `Namespace::create_monitoring_async()`.
///
/// @see MonitoringCreateItemResult
/// @ingroup address_space
struct MonitoringCreateSuccess
{
  MonitoringHandle handle{0};  ///< Handle identifying the new registration; pass to
                               ///< delete_monitoring_async() / modify_monitoring_async().
  Duration revisedSamplingInterval{0};  ///< Interval the namespace will actually sample at, in
                                        ///< milliseconds; may differ from the requested value.
};

/// Per-item result of `Namespace::create_monitoring_async()`.
///
/// Holds a `MonitoringCreateSuccess` on success, or an `ErrorDetail`
/// carrying the per-item `StatusCode` on failure.
/// @see MonitoringCreateItem, MonitoringCreateSuccess
using MonitoringCreateItemResult = Result<MonitoringCreateSuccess>;

/// Per-item input describing a change to an existing monitoring registration.
///
/// One element of the batch passed to `Namespace::modify_monitoring_async()`.
/// @see MonitoringModifyItemResult, MonitoringCreateItem
/// @ingroup address_space
struct MonitoringModifyItem
{
  MonitoringHandle handle{0};  ///< Handle of the registration to modify, from
                               ///< @ref MonitoringCreateSuccess::handle.
  Duration samplingInterval{0};  ///< New requested sampling interval in milliseconds; 0 requests
                                 ///< the fastest practical rate, subject to revision.
  uint32_t queueSize{1};  ///< New maximum number of buffered samples.
};

/// Successful per-item outcome of `Namespace::modify_monitoring_async()`.
///
/// @see MonitoringModifyItemResult
/// @ingroup address_space
struct MonitoringModifySuccess
{
  Duration revisedSamplingInterval{0};  ///< Interval the namespace will actually sample at after
                                        ///< the change, in milliseconds; may differ from requested.
};

/// Per-item result of `Namespace::modify_monitoring_async()`.
///
/// Holds a `MonitoringModifySuccess` on success, or an `ErrorDetail`
/// carrying the per-item `StatusCode` on failure.
/// @see MonitoringModifyItem, MonitoringModifySuccess
using MonitoringModifyItemResult = Result<MonitoringModifySuccess>;

}  // namespace ua

#endif  // !UA_NAMESPACE_MONITORING_H
