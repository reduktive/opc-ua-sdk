// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_METRICS_H
#define UA_ALARM_METRICS_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"
#include "ua_alarm_rate_variable.h"

namespace ua
{

struct MethodCallContext;

class AlarmMetrics;
using AlarmMetricsResult = Result<AlarmMetrics>;

/// Address-space handle for the OPC UA AlarmMetricsType ObjectType.
/// @ingroup ua_information_model
class AlarmMetrics : public BaseObject
{
public:
  /// Constructs an empty `AlarmMetrics` handle that references no node.
  AlarmMetrics() = default;

  /// Synchronous handler for Reset(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using ResetHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Reset(): starts the work and completes it through the callback, once, from any
  /// thread.
  using ResetAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `AlarmMetrics` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AlarmMetricsResult)>;
  /// Completion callback for attach_async: receives the attached `AlarmMetrics` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AlarmMetricsResult)>;

  /// Creates a new `AlarmMetricsType` instance under `parent`.
  ///
  /// Instantiates the type's full child tree and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param complete     Receives the outcome: on success a `AlarmMetrics` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `AlarmMetricsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static AlarmMetricsResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `AlarmMetricsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `AlarmMetrics` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AlarmMetrics create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `AlarmMetricsType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `AlarmMetrics` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AlarmMetricsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AlarmMetricsResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AlarmMetricsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `AlarmMetrics` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AlarmMetrics attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Reset` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_reset_method_sync, reset_method_sync
  void reset_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_reset_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_reset_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor reset_method_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `Reset` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset_handler_sync, set_reset_handler_sync
  void set_reset_handler_async(ResetHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Reset` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset_handler_sync(ResetHandler handler) const noexcept;
  /// Registers the synchronous `Reset` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset_handler_sync(ResetHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Reset` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset_handler_sync, set_reset_handler_sync
  void set_reset_handler_async(
    ResetAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Reset` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset_handler_sync(ResetAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Reset` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset_handler_sync(ResetAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `AlarmCount` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_alarm_count_sync, alarm_count_sync
  void alarm_count_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `AlarmCount` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_alarm_count_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `AlarmCount` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_alarm_count_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable alarm_count_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `StartTime` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_time_sync, start_time_sync
  void start_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `StartTime` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_start_time_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `StartTime` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_start_time_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable start_time_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `MaximumActiveState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_maximum_active_state_sync, maximum_active_state_sync
  void maximum_active_state_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumActiveState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_maximum_active_state_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumActiveState` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_maximum_active_state_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable maximum_active_state_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `MaximumUnAck` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_maximum_un_ack_sync, maximum_un_ack_sync
  void maximum_un_ack_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumUnAck` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_maximum_un_ack_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumUnAck` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_maximum_un_ack_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable maximum_un_ack_sync() const;

  /// Attaches a typed `AlarmRateVariable` handle for the `CurrentAlarmRate` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_current_alarm_rate_sync, current_alarm_rate_sync
  void current_alarm_rate_async(std::function<void(AlarmRateVariableResult)> complete) const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `CurrentAlarmRate` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AlarmRateVariableResult try_current_alarm_rate_sync() const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `CurrentAlarmRate` child, blocking until complete.
  /// @return The `AlarmRateVariable` handle. A Good subcode is not returned; @ref try_current_alarm_rate_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AlarmRateVariable current_alarm_rate_sync() const;

  /// Attaches a typed `AlarmRateVariable` handle for the `MaximumAlarmRate` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_maximum_alarm_rate_sync, maximum_alarm_rate_sync
  void maximum_alarm_rate_async(std::function<void(AlarmRateVariableResult)> complete) const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `MaximumAlarmRate` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AlarmRateVariableResult try_maximum_alarm_rate_sync() const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `MaximumAlarmRate` child, blocking until complete.
  /// @return The `AlarmRateVariable` handle. A Good subcode is not returned; @ref try_maximum_alarm_rate_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AlarmRateVariable maximum_alarm_rate_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `MaximumReAlarmCount` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_maximum_re_alarm_count_sync, maximum_re_alarm_count_sync
  void maximum_re_alarm_count_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumReAlarmCount` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_maximum_re_alarm_count_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `MaximumReAlarmCount` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_maximum_re_alarm_count_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable maximum_re_alarm_count_sync() const;

  /// Attaches a typed `AlarmRateVariable` handle for the `AverageAlarmRate` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_average_alarm_rate_sync, average_alarm_rate_sync
  void average_alarm_rate_async(std::function<void(AlarmRateVariableResult)> complete) const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `AverageAlarmRate` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AlarmRateVariableResult try_average_alarm_rate_sync() const noexcept;
  /// Attaches a typed `AlarmRateVariable` handle for the `AverageAlarmRate` child, blocking until complete.
  /// @return The `AlarmRateVariable` handle. A Good subcode is not returned; @ref try_average_alarm_rate_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AlarmRateVariable average_alarm_rate_sync() const;

private:
  explicit AlarmMetrics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ALARM_METRICS_H
