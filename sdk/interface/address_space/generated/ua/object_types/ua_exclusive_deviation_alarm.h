// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EXCLUSIVE_DEVIATION_ALARM_H
#define UA_EXCLUSIVE_DEVIATION_ALARM_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class ExclusiveDeviationAlarm;
using ExclusiveDeviationAlarmResult = Result<ExclusiveDeviationAlarm>;

/// Address-space handle for the OPC UA ExclusiveDeviationAlarmType ObjectType.
/// @ingroup ua_information_model
class ExclusiveDeviationAlarm : public BaseObject
{
public:
  /// Constructs an empty `ExclusiveDeviationAlarm` handle that references no node.
  ExclusiveDeviationAlarm() = default;

  /// Completion callback for create_async: receives the created `ExclusiveDeviationAlarm` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ExclusiveDeviationAlarmResult)>;
  /// Completion callback for attach_async: receives the attached `ExclusiveDeviationAlarm` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ExclusiveDeviationAlarmResult)>;

  /// Creates a new `ExclusiveDeviationAlarmType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ExclusiveDeviationAlarm` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ExclusiveDeviationAlarmType` instance under `parent`, blocking until complete.  ///
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
  static ExclusiveDeviationAlarmResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ExclusiveDeviationAlarmType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ExclusiveDeviationAlarm` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ExclusiveDeviationAlarm create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ExclusiveDeviationAlarmType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ExclusiveDeviationAlarm` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ExclusiveDeviationAlarmType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ExclusiveDeviationAlarmResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ExclusiveDeviationAlarmType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ExclusiveDeviationAlarm` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ExclusiveDeviationAlarm attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `SetpointNode` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_setpoint_node_property_sync, setpoint_node_property_sync
  void setpoint_node_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SetpointNode` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_setpoint_node_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SetpointNode` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_setpoint_node_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property setpoint_node_property_sync() const;

  /// Attaches a `Property` handle for the `BaseSetpointNode` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_base_setpoint_node_property_sync, base_setpoint_node_property_sync
  void base_setpoint_node_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BaseSetpointNode` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_base_setpoint_node_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BaseSetpointNode` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_base_setpoint_node_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property base_setpoint_node_property_sync() const;

  /// Attaches a `Property` handle for the `HighHighLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_high_limit_property_sync, high_high_limit_property_sync
  void high_high_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighHighLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_high_high_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighHighLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_high_high_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property high_high_limit_property_sync() const;

  /// Attaches a `Property` handle for the `HighLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_limit_property_sync, high_limit_property_sync
  void high_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_high_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_high_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property high_limit_property_sync() const;

  /// Attaches a `Property` handle for the `LowLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_limit_property_sync, low_limit_property_sync
  void low_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LowLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_low_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LowLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_low_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property low_limit_property_sync() const;

  /// Attaches a `Property` handle for the `LowLowLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_low_limit_property_sync, low_low_limit_property_sync
  void low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LowLowLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_low_low_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LowLowLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_low_low_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property low_low_limit_property_sync() const;

  /// Attaches a `Property` handle for the `BaseHighHighLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_base_high_high_limit_property_sync, base_high_high_limit_property_sync
  void base_high_high_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BaseHighHighLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_base_high_high_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BaseHighHighLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_base_high_high_limit_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property base_high_high_limit_property_sync() const;

  /// Attaches a `Property` handle for the `BaseHighLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_base_high_limit_property_sync, base_high_limit_property_sync
  void base_high_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BaseHighLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_base_high_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BaseHighLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_base_high_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property base_high_limit_property_sync() const;

  /// Attaches a `Property` handle for the `BaseLowLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_base_low_limit_property_sync, base_low_limit_property_sync
  void base_low_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BaseLowLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_base_low_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BaseLowLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_base_low_limit_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property base_low_limit_property_sync() const;

  /// Attaches a `Property` handle for the `BaseLowLowLimit` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_base_low_low_limit_property_sync, base_low_low_limit_property_sync
  void base_low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BaseLowLowLimit` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_base_low_low_limit_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BaseLowLowLimit` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_base_low_low_limit_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property base_low_low_limit_property_sync() const;

  /// Attaches a `Property` handle for the `SeverityHighHigh` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_severity_high_high_property_sync, severity_high_high_property_sync
  void severity_high_high_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SeverityHighHigh` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_severity_high_high_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SeverityHighHigh` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_severity_high_high_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property severity_high_high_property_sync() const;

  /// Attaches a `Property` handle for the `SeverityHigh` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_severity_high_property_sync, severity_high_property_sync
  void severity_high_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SeverityHigh` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_severity_high_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SeverityHigh` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_severity_high_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property severity_high_property_sync() const;

  /// Attaches a `Property` handle for the `SeverityLow` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_severity_low_property_sync, severity_low_property_sync
  void severity_low_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SeverityLow` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_severity_low_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SeverityLow` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_severity_low_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property severity_low_property_sync() const;

  /// Attaches a `Property` handle for the `SeverityLowLow` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_severity_low_low_property_sync, severity_low_low_property_sync
  void severity_low_low_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SeverityLowLow` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_severity_low_low_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SeverityLowLow` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_severity_low_low_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property severity_low_low_property_sync() const;

  /// Attaches a `Property` handle for the `HighHighDeadband` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_high_deadband_property_sync, high_high_deadband_property_sync
  void high_high_deadband_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighHighDeadband` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_high_high_deadband_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighHighDeadband` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_high_high_deadband_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property high_high_deadband_property_sync() const;

  /// Attaches a `Property` handle for the `HighDeadband` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_deadband_property_sync, high_deadband_property_sync
  void high_deadband_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighDeadband` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_high_deadband_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighDeadband` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_high_deadband_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property high_deadband_property_sync() const;

  /// Attaches a `Property` handle for the `LowDeadband` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_deadband_property_sync, low_deadband_property_sync
  void low_deadband_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LowDeadband` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_low_deadband_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LowDeadband` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_low_deadband_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property low_deadband_property_sync() const;

  /// Attaches a `Property` handle for the `LowLowDeadband` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_low_deadband_property_sync, low_low_deadband_property_sync
  void low_low_deadband_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LowLowDeadband` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_low_low_deadband_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LowLowDeadband` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_low_low_deadband_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property low_low_deadband_property_sync() const;

  /// Attaches a `Property` handle for the `InputNode` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_input_node_property_sync, input_node_property_sync
  void input_node_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `InputNode` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_input_node_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `InputNode` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_input_node_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property input_node_property_sync() const;

  /// Attaches a `Property` handle for the `SuppressedOrShelved` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suppressed_or_shelved_property_sync, suppressed_or_shelved_property_sync
  void suppressed_or_shelved_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SuppressedOrShelved` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_suppressed_or_shelved_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SuppressedOrShelved` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_suppressed_or_shelved_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property suppressed_or_shelved_property_sync() const;

  /// Attaches a `Property` handle for the `MaxTimeShelved` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_time_shelved_property_sync, max_time_shelved_property_sync
  void max_time_shelved_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeShelved` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_time_shelved_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeShelved` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_time_shelved_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_time_shelved_property_sync() const;

  /// Attaches a `Property` handle for the `AudibleEnabled` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_audible_enabled_property_sync, audible_enabled_property_sync
  void audible_enabled_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AudibleEnabled` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_audible_enabled_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AudibleEnabled` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_audible_enabled_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property audible_enabled_property_sync() const;

  /// Attaches a `Property` handle for the `OnDelay` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_on_delay_property_sync, on_delay_property_sync
  void on_delay_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `OnDelay` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_on_delay_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `OnDelay` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_on_delay_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property on_delay_property_sync() const;

  /// Attaches a `Property` handle for the `OffDelay` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_off_delay_property_sync, off_delay_property_sync
  void off_delay_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `OffDelay` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_off_delay_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `OffDelay` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_off_delay_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property off_delay_property_sync() const;

  /// Attaches a `Property` handle for the `ReAlarmTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_re_alarm_time_property_sync, re_alarm_time_property_sync
  void re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ReAlarmTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_re_alarm_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ReAlarmTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_re_alarm_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property re_alarm_time_property_sync() const;

  /// Attaches a `Property` handle for the `ConditionClassId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_condition_class_id_property_sync, condition_class_id_property_sync
  void condition_class_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConditionClassId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_condition_class_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConditionClassId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_condition_class_id_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property condition_class_id_property_sync() const;

  /// Attaches a `Property` handle for the `ConditionClassName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_condition_class_name_property_sync, condition_class_name_property_sync
  void condition_class_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConditionClassName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_condition_class_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConditionClassName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_condition_class_name_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property condition_class_name_property_sync() const;

  /// Attaches a `Property` handle for the `ConditionSubClassId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_condition_sub_class_id_property_sync, condition_sub_class_id_property_sync
  void condition_sub_class_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConditionSubClassId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_condition_sub_class_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConditionSubClassId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_condition_sub_class_id_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property condition_sub_class_id_property_sync() const;

  /// Attaches a `Property` handle for the `ConditionSubClassName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_condition_sub_class_name_property_sync, condition_sub_class_name_property_sync
  void condition_sub_class_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConditionSubClassName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_condition_sub_class_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConditionSubClassName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_condition_sub_class_name_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property condition_sub_class_name_property_sync() const;

  /// Attaches a `Property` handle for the `ConditionName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_condition_name_property_sync, condition_name_property_sync
  void condition_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConditionName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_condition_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConditionName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_condition_name_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property condition_name_property_sync() const;

  /// Attaches a `Property` handle for the `BranchId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_branch_id_property_sync, branch_id_property_sync
  void branch_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `BranchId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_branch_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `BranchId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_branch_id_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property branch_id_property_sync() const;

  /// Attaches a `Property` handle for the `Retain` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_retain_property_sync, retain_property_sync
  void retain_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Retain` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_retain_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Retain` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_retain_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property retain_property_sync() const;

  /// Attaches a `Property` handle for the `SupportsFilteredRetain` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_supports_filtered_retain_property_sync, supports_filtered_retain_property_sync
  void supports_filtered_retain_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SupportsFilteredRetain` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_supports_filtered_retain_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SupportsFilteredRetain` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_supports_filtered_retain_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property supports_filtered_retain_property_sync() const;

  /// Attaches a `Property` handle for the `ClientUserId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_client_user_id_property_sync, client_user_id_property_sync
  void client_user_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ClientUserId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_client_user_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ClientUserId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_client_user_id_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property client_user_id_property_sync() const;

  /// Attaches a `Property` handle for the `EventId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_event_id_property_sync, event_id_property_sync
  void event_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EventId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_event_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EventId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_event_id_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property event_id_property_sync() const;

  /// Attaches a `Property` handle for the `EventType` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_event_type_property_sync, event_type_property_sync
  void event_type_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EventType` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_event_type_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EventType` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_event_type_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property event_type_property_sync() const;

  /// Attaches a `Property` handle for the `SourceNode` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_source_node_property_sync, source_node_property_sync
  void source_node_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SourceNode` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_source_node_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SourceNode` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_source_node_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property source_node_property_sync() const;

  /// Attaches a `Property` handle for the `SourceName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_source_name_property_sync, source_name_property_sync
  void source_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SourceName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_source_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SourceName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_source_name_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property source_name_property_sync() const;

  /// Attaches a `Property` handle for the `Time` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_time_property_sync, time_property_sync
  void time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Time` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Time` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_time_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property time_property_sync() const;

  /// Attaches a `Property` handle for the `ReceiveTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_receive_time_property_sync, receive_time_property_sync
  void receive_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ReceiveTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_receive_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ReceiveTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_receive_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property receive_time_property_sync() const;

  /// Attaches a `Property` handle for the `LocalTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_local_time_property_sync, local_time_property_sync
  void local_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LocalTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_local_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LocalTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_local_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property local_time_property_sync() const;

  /// Attaches a `Property` handle for the `Message` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_message_property_sync, message_property_sync
  void message_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Message` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_message_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Message` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_message_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property message_property_sync() const;

  /// Attaches a `Property` handle for the `Severity` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_severity_property_sync, severity_property_sync
  void severity_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Severity` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_severity_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Severity` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_severity_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property severity_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `SetpointNode` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_setpoint_node_sync, read_setpoint_node_sync
  void read_setpoint_node_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `SetpointNode` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_setpoint_node_async gives it. Never throws.
  NodeIdResult try_read_setpoint_node_sync() const noexcept;
  /// Reads the `SetpointNode` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_setpoint_node_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_setpoint_node_sync() const;

  /// Reads the `BaseSetpointNode` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_base_setpoint_node_sync, read_base_setpoint_node_sync
  void read_base_setpoint_node_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `BaseSetpointNode` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_base_setpoint_node_async gives it. Never throws.
  NodeIdResult try_read_base_setpoint_node_sync() const noexcept;
  /// Reads the `BaseSetpointNode` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_base_setpoint_node_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_base_setpoint_node_sync() const;

  /// Reads the `HighHighLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_high_high_limit_sync, read_high_high_limit_sync
  void read_high_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `HighHighLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_high_high_limit_async gives it. Never throws.
  DoubleResult try_read_high_high_limit_sync() const noexcept;
  /// Reads the `HighHighLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_high_high_limit_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_high_high_limit_sync() const;

  /// Reads the `HighLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_high_limit_sync, read_high_limit_sync
  void read_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `HighLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_high_limit_async gives it. Never throws.
  DoubleResult try_read_high_limit_sync() const noexcept;
  /// Reads the `HighLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_high_limit_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_high_limit_sync() const;

  /// Reads the `LowLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_low_limit_sync, read_low_limit_sync
  void read_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `LowLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_low_limit_async gives it. Never throws.
  DoubleResult try_read_low_limit_sync() const noexcept;
  /// Reads the `LowLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_low_limit_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_low_limit_sync() const;

  /// Reads the `LowLowLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_low_low_limit_sync, read_low_low_limit_sync
  void read_low_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `LowLowLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_low_low_limit_async gives it. Never throws.
  DoubleResult try_read_low_low_limit_sync() const noexcept;
  /// Reads the `LowLowLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_low_low_limit_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_low_low_limit_sync() const;

  /// Reads the `BaseHighHighLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_base_high_high_limit_sync, read_base_high_high_limit_sync
  void read_base_high_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `BaseHighHighLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_base_high_high_limit_async gives it. Never throws.
  DoubleResult try_read_base_high_high_limit_sync() const noexcept;
  /// Reads the `BaseHighHighLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_base_high_high_limit_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_base_high_high_limit_sync() const;

  /// Reads the `BaseHighLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_base_high_limit_sync, read_base_high_limit_sync
  void read_base_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `BaseHighLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_base_high_limit_async gives it. Never throws.
  DoubleResult try_read_base_high_limit_sync() const noexcept;
  /// Reads the `BaseHighLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_base_high_limit_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_base_high_limit_sync() const;

  /// Reads the `BaseLowLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_base_low_limit_sync, read_base_low_limit_sync
  void read_base_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `BaseLowLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_base_low_limit_async gives it. Never throws.
  DoubleResult try_read_base_low_limit_sync() const noexcept;
  /// Reads the `BaseLowLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_base_low_limit_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_base_low_limit_sync() const;

  /// Reads the `BaseLowLowLimit` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_base_low_low_limit_sync, read_base_low_low_limit_sync
  void read_base_low_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `BaseLowLowLimit` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_base_low_low_limit_async gives it. Never throws.
  DoubleResult try_read_base_low_low_limit_sync() const noexcept;
  /// Reads the `BaseLowLowLimit` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_base_low_low_limit_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_base_low_low_limit_sync() const;

  /// Reads the `SeverityHighHigh` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_severity_high_high_sync, read_severity_high_high_sync
  void read_severity_high_high_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `SeverityHighHigh` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_severity_high_high_async gives it. Never throws.
  UInt16Result try_read_severity_high_high_sync() const noexcept;
  /// Reads the `SeverityHighHigh` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_severity_high_high_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_severity_high_high_sync() const;

  /// Reads the `SeverityHigh` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_severity_high_sync, read_severity_high_sync
  void read_severity_high_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `SeverityHigh` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_severity_high_async gives it. Never throws.
  UInt16Result try_read_severity_high_sync() const noexcept;
  /// Reads the `SeverityHigh` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_severity_high_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_severity_high_sync() const;

  /// Reads the `SeverityLow` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_severity_low_sync, read_severity_low_sync
  void read_severity_low_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `SeverityLow` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_severity_low_async gives it. Never throws.
  UInt16Result try_read_severity_low_sync() const noexcept;
  /// Reads the `SeverityLow` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_severity_low_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_severity_low_sync() const;

  /// Reads the `SeverityLowLow` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_severity_low_low_sync, read_severity_low_low_sync
  void read_severity_low_low_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `SeverityLowLow` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_severity_low_low_async gives it. Never throws.
  UInt16Result try_read_severity_low_low_sync() const noexcept;
  /// Reads the `SeverityLowLow` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_severity_low_low_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_severity_low_low_sync() const;

  /// Reads the `HighHighDeadband` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_high_high_deadband_sync, read_high_high_deadband_sync
  void read_high_high_deadband_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `HighHighDeadband` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_high_high_deadband_async gives it. Never throws.
  DoubleResult try_read_high_high_deadband_sync() const noexcept;
  /// Reads the `HighHighDeadband` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_high_high_deadband_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_high_high_deadband_sync() const;

  /// Reads the `HighDeadband` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_high_deadband_sync, read_high_deadband_sync
  void read_high_deadband_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `HighDeadband` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_high_deadband_async gives it. Never throws.
  DoubleResult try_read_high_deadband_sync() const noexcept;
  /// Reads the `HighDeadband` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_high_deadband_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_high_deadband_sync() const;

  /// Reads the `LowDeadband` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_low_deadband_sync, read_low_deadband_sync
  void read_low_deadband_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `LowDeadband` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_low_deadband_async gives it. Never throws.
  DoubleResult try_read_low_deadband_sync() const noexcept;
  /// Reads the `LowDeadband` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_low_deadband_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_low_deadband_sync() const;

  /// Reads the `LowLowDeadband` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_low_low_deadband_sync, read_low_low_deadband_sync
  void read_low_low_deadband_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `LowLowDeadband` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_low_low_deadband_async gives it. Never throws.
  DoubleResult try_read_low_low_deadband_sync() const noexcept;
  /// Reads the `LowLowDeadband` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_low_low_deadband_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_low_low_deadband_sync() const;

  /// Reads the `InputNode` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_input_node_sync, read_input_node_sync
  void read_input_node_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `InputNode` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_input_node_async gives it. Never throws.
  NodeIdResult try_read_input_node_sync() const noexcept;
  /// Reads the `InputNode` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_input_node_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_input_node_sync() const;

  /// Reads the `SuppressedOrShelved` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_suppressed_or_shelved_sync, read_suppressed_or_shelved_sync
  void read_suppressed_or_shelved_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `SuppressedOrShelved` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_suppressed_or_shelved_async gives it. Never throws.
  BoolResult try_read_suppressed_or_shelved_sync() const noexcept;
  /// Reads the `SuppressedOrShelved` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_suppressed_or_shelved_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_suppressed_or_shelved_sync() const;

  /// Reads the `AudibleEnabled` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_audible_enabled_sync, read_audible_enabled_sync
  void read_audible_enabled_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `AudibleEnabled` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_audible_enabled_async gives it. Never throws.
  BoolResult try_read_audible_enabled_sync() const noexcept;
  /// Reads the `AudibleEnabled` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_audible_enabled_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_audible_enabled_sync() const;

  /// Reads the `ConditionClassId` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_condition_class_id_sync, read_condition_class_id_sync
  void read_condition_class_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `ConditionClassId` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_condition_class_id_async gives it. Never throws.
  NodeIdResult try_read_condition_class_id_sync() const noexcept;
  /// Reads the `ConditionClassId` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_condition_class_id_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_condition_class_id_sync() const;

  /// Reads the `ConditionClassName` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_condition_class_name_sync, read_condition_class_name_sync
  void read_condition_class_name_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `ConditionClassName` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_condition_class_name_async gives it. Never throws.
  LocalizedTextResult try_read_condition_class_name_sync() const noexcept;
  /// Reads the `ConditionClassName` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_condition_class_name_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_condition_class_name_sync() const;

  /// Reads the `ConditionSubClassId` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_condition_sub_class_id_sync, read_condition_sub_class_id_sync
  void read_condition_sub_class_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `ConditionSubClassId` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_condition_sub_class_id_async gives it. Never
  /// throws.
  NodeIdResult try_read_condition_sub_class_id_sync() const noexcept;
  /// Reads the `ConditionSubClassId` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_condition_sub_class_id_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_condition_sub_class_id_sync() const;

  /// Reads the `ConditionSubClassName` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_condition_sub_class_name_sync, read_condition_sub_class_name_sync
  void read_condition_sub_class_name_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `ConditionSubClassName` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_condition_sub_class_name_async gives it. Never
  /// throws.
  LocalizedTextResult try_read_condition_sub_class_name_sync() const noexcept;
  /// Reads the `ConditionSubClassName` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_condition_sub_class_name_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_condition_sub_class_name_sync() const;

  /// Reads the `ConditionName` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_condition_name_sync, read_condition_name_sync
  void read_condition_name_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ConditionName` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_condition_name_async gives it. Never throws.
  StringResult try_read_condition_name_sync() const noexcept;
  /// Reads the `ConditionName` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_condition_name_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_condition_name_sync() const;

  /// Reads the `BranchId` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_branch_id_sync, read_branch_id_sync
  void read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `BranchId` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_branch_id_async gives it. Never throws.
  NodeIdResult try_read_branch_id_sync() const noexcept;
  /// Reads the `BranchId` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_branch_id_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_branch_id_sync() const;

  /// Reads the `Retain` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_retain_sync, read_retain_sync
  void read_retain_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Retain` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_retain_async gives it. Never throws.
  BoolResult try_read_retain_sync() const noexcept;
  /// Reads the `Retain` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_retain_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_retain_sync() const;

  /// Reads the `SupportsFilteredRetain` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_supports_filtered_retain_sync, read_supports_filtered_retain_sync
  void read_supports_filtered_retain_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `SupportsFilteredRetain` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_supports_filtered_retain_async gives it. Never
  /// throws.
  BoolResult try_read_supports_filtered_retain_sync() const noexcept;
  /// Reads the `SupportsFilteredRetain` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_supports_filtered_retain_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_supports_filtered_retain_sync() const;

  /// Reads the `ClientUserId` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_client_user_id_sync, read_client_user_id_sync
  void read_client_user_id_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ClientUserId` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_client_user_id_async gives it. Never throws.
  StringResult try_read_client_user_id_sync() const noexcept;
  /// Reads the `ClientUserId` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_client_user_id_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_client_user_id_sync() const;

  /// Reads the `EventId` property value, typed as `ByteString`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_event_id_sync, read_event_id_sync
  void read_event_id_async(std::function<void(ByteStringResult)> complete) const noexcept;
  /// Reads the `EventId` property value as `ByteString`, blocking until complete.
  /// @return The value with the read's code, as @ref read_event_id_async gives it. Never throws.
  ByteStringResult try_read_event_id_sync() const noexcept;
  /// Reads the `EventId` property value as `ByteString`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_event_id_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  ByteString read_event_id_sync() const;

  /// Reads the `EventType` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_event_type_sync, read_event_type_sync
  void read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `EventType` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_event_type_async gives it. Never throws.
  NodeIdResult try_read_event_type_sync() const noexcept;
  /// Reads the `EventType` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_event_type_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_event_type_sync() const;

  /// Reads the `SourceNode` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_source_node_sync, read_source_node_sync
  void read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `SourceNode` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_source_node_async gives it. Never throws.
  NodeIdResult try_read_source_node_sync() const noexcept;
  /// Reads the `SourceNode` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_source_node_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_source_node_sync() const;

  /// Reads the `SourceName` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_source_name_sync, read_source_name_sync
  void read_source_name_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `SourceName` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_source_name_async gives it. Never throws.
  StringResult try_read_source_name_sync() const noexcept;
  /// Reads the `SourceName` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_source_name_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_source_name_sync() const;

  /// Reads the `Message` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_message_sync, read_message_sync
  void read_message_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `Message` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_message_async gives it. Never throws.
  LocalizedTextResult try_read_message_sync() const noexcept;
  /// Reads the `Message` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_message_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_message_sync() const;

  /// Reads the `Severity` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_severity_sync, read_severity_sync
  void read_severity_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `Severity` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_severity_async gives it. Never throws.
  UInt16Result try_read_severity_sync() const noexcept;
  /// Reads the `Severity` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_severity_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_severity_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `SetpointNode` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_setpoint_node_sync, write_setpoint_node_sync
  void write_setpoint_node_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SetpointNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_setpoint_node_sync(NodeId value) const noexcept;
  /// Writes the `SetpointNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_setpoint_node_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_setpoint_node_sync(NodeId value) const;

  /// Writes the `BaseSetpointNode` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_base_setpoint_node_sync, write_base_setpoint_node_sync
  void write_base_setpoint_node_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BaseSetpointNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_base_setpoint_node_sync(NodeId value) const noexcept;
  /// Writes the `BaseSetpointNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_base_setpoint_node_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_base_setpoint_node_sync(NodeId value) const;

  /// Writes the `HighHighLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_high_high_limit_sync, write_high_high_limit_sync
  void write_high_high_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_high_high_limit_sync(double value) const noexcept;
  /// Writes the `HighHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_high_high_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_high_high_limit_sync(double value) const;

  /// Writes the `HighLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_high_limit_sync, write_high_limit_sync
  void write_high_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_high_limit_sync(double value) const noexcept;
  /// Writes the `HighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_high_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_high_limit_sync(double value) const;

  /// Writes the `LowLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_low_limit_sync, write_low_limit_sync
  void write_low_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_low_limit_sync(double value) const noexcept;
  /// Writes the `LowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_low_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_low_limit_sync(double value) const;

  /// Writes the `LowLowLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_low_low_limit_sync, write_low_low_limit_sync
  void write_low_low_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LowLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_low_low_limit_sync(double value) const noexcept;
  /// Writes the `LowLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_low_low_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_low_low_limit_sync(double value) const;

  /// Writes the `BaseHighHighLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_base_high_high_limit_sync, write_base_high_high_limit_sync
  void write_base_high_high_limit_async(
    double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BaseHighHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_base_high_high_limit_sync(double value) const noexcept;
  /// Writes the `BaseHighHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_base_high_high_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_base_high_high_limit_sync(double value) const;

  /// Writes the `BaseHighLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_base_high_limit_sync, write_base_high_limit_sync
  void write_base_high_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BaseHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_base_high_limit_sync(double value) const noexcept;
  /// Writes the `BaseHighLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_base_high_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_base_high_limit_sync(double value) const;

  /// Writes the `BaseLowLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_base_low_limit_sync, write_base_low_limit_sync
  void write_base_low_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BaseLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_base_low_limit_sync(double value) const noexcept;
  /// Writes the `BaseLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_base_low_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_base_low_limit_sync(double value) const;

  /// Writes the `BaseLowLowLimit` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_base_low_low_limit_sync, write_base_low_low_limit_sync
  void write_base_low_low_limit_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BaseLowLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_base_low_low_limit_sync(double value) const noexcept;
  /// Writes the `BaseLowLowLimit` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_base_low_low_limit_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_base_low_low_limit_sync(double value) const;

  /// Writes the `SeverityHighHigh` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_severity_high_high_sync, write_severity_high_high_sync
  void write_severity_high_high_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SeverityHighHigh` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_severity_high_high_sync(uint16_t value) const noexcept;
  /// Writes the `SeverityHighHigh` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_severity_high_high_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_severity_high_high_sync(uint16_t value) const;

  /// Writes the `SeverityHigh` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_severity_high_sync, write_severity_high_sync
  void write_severity_high_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SeverityHigh` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_severity_high_sync(uint16_t value) const noexcept;
  /// Writes the `SeverityHigh` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_severity_high_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_severity_high_sync(uint16_t value) const;

  /// Writes the `SeverityLow` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_severity_low_sync, write_severity_low_sync
  void write_severity_low_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SeverityLow` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_severity_low_sync(uint16_t value) const noexcept;
  /// Writes the `SeverityLow` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_severity_low_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_severity_low_sync(uint16_t value) const;

  /// Writes the `SeverityLowLow` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_severity_low_low_sync, write_severity_low_low_sync
  void write_severity_low_low_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SeverityLowLow` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_severity_low_low_sync(uint16_t value) const noexcept;
  /// Writes the `SeverityLowLow` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_severity_low_low_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_severity_low_low_sync(uint16_t value) const;

  /// Writes the `HighHighDeadband` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_high_high_deadband_sync, write_high_high_deadband_sync
  void write_high_high_deadband_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighHighDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_high_high_deadband_sync(double value) const noexcept;
  /// Writes the `HighHighDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_high_high_deadband_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_high_high_deadband_sync(double value) const;

  /// Writes the `HighDeadband` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_high_deadband_sync, write_high_deadband_sync
  void write_high_deadband_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_high_deadband_sync(double value) const noexcept;
  /// Writes the `HighDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_high_deadband_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_high_deadband_sync(double value) const;

  /// Writes the `LowDeadband` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_low_deadband_sync, write_low_deadband_sync
  void write_low_deadband_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LowDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_low_deadband_sync(double value) const noexcept;
  /// Writes the `LowDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_low_deadband_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_low_deadband_sync(double value) const;

  /// Writes the `LowLowDeadband` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_low_low_deadband_sync, write_low_low_deadband_sync
  void write_low_low_deadband_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LowLowDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_low_low_deadband_sync(double value) const noexcept;
  /// Writes the `LowLowDeadband` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_low_low_deadband_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_low_low_deadband_sync(double value) const;

  /// Writes the `InputNode` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_input_node_sync, write_input_node_sync
  void write_input_node_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `InputNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_input_node_sync(NodeId value) const noexcept;
  /// Writes the `InputNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_input_node_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_input_node_sync(NodeId value) const;

  /// Writes the `SuppressedOrShelved` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_suppressed_or_shelved_sync, write_suppressed_or_shelved_sync
  void write_suppressed_or_shelved_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SuppressedOrShelved` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_suppressed_or_shelved_sync(bool value) const noexcept;
  /// Writes the `SuppressedOrShelved` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_suppressed_or_shelved_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_suppressed_or_shelved_sync(bool value) const;

  /// Writes the `AudibleEnabled` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_audible_enabled_sync, write_audible_enabled_sync
  void write_audible_enabled_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `AudibleEnabled` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_audible_enabled_sync(bool value) const noexcept;
  /// Writes the `AudibleEnabled` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_audible_enabled_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_audible_enabled_sync(bool value) const;

  /// Writes the `ConditionClassId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_condition_class_id_sync, write_condition_class_id_sync
  void write_condition_class_id_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConditionClassId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_condition_class_id_sync(NodeId value) const noexcept;
  /// Writes the `ConditionClassId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_condition_class_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_condition_class_id_sync(NodeId value) const;

  /// Writes the `ConditionClassName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_condition_class_name_sync, write_condition_class_name_sync
  void write_condition_class_name_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConditionClassName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_condition_class_name_sync(LocalizedText value) const noexcept;
  /// Writes the `ConditionClassName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_condition_class_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_condition_class_name_sync(LocalizedText value) const;

  /// Writes the `ConditionSubClassId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_condition_sub_class_id_sync, write_condition_sub_class_id_sync
  void write_condition_sub_class_id_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConditionSubClassId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_condition_sub_class_id_sync(NodeId value) const noexcept;
  /// Writes the `ConditionSubClassId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_condition_sub_class_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_condition_sub_class_id_sync(NodeId value) const;

  /// Writes the `ConditionSubClassName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_condition_sub_class_name_sync, write_condition_sub_class_name_sync
  void write_condition_sub_class_name_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConditionSubClassName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept;
  /// Writes the `ConditionSubClassName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_condition_sub_class_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_condition_sub_class_name_sync(LocalizedText value) const;

  /// Writes the `ConditionName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_condition_name_sync, write_condition_name_sync
  void write_condition_name_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConditionName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_condition_name_sync(String value) const noexcept;
  /// Writes the `ConditionName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_condition_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_condition_name_sync(String value) const;

  /// Writes the `BranchId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_branch_id_sync, write_branch_id_sync
  void write_branch_id_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `BranchId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_branch_id_sync(NodeId value) const noexcept;
  /// Writes the `BranchId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_branch_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_branch_id_sync(NodeId value) const;

  /// Writes the `Retain` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_retain_sync, write_retain_sync
  void write_retain_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Retain` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_retain_sync(bool value) const noexcept;
  /// Writes the `Retain` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_retain_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_retain_sync(bool value) const;

  /// Writes the `SupportsFilteredRetain` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_supports_filtered_retain_sync, write_supports_filtered_retain_sync
  void write_supports_filtered_retain_async(
    bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SupportsFilteredRetain` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_supports_filtered_retain_sync(bool value) const noexcept;
  /// Writes the `SupportsFilteredRetain` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_supports_filtered_retain_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_supports_filtered_retain_sync(bool value) const;

  /// Writes the `ClientUserId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_client_user_id_sync, write_client_user_id_sync
  void write_client_user_id_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ClientUserId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_client_user_id_sync(String value) const noexcept;
  /// Writes the `ClientUserId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_client_user_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_client_user_id_sync(String value) const;

  /// Writes the `EventId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_event_id_sync, write_event_id_sync
  void write_event_id_async(ByteString value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EventId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_event_id_sync(ByteString value) const noexcept;
  /// Writes the `EventId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_event_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_event_id_sync(ByteString value) const;

  /// Writes the `EventType` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_event_type_sync, write_event_type_sync
  void write_event_type_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EventType` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_event_type_sync(NodeId value) const noexcept;
  /// Writes the `EventType` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_event_type_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_event_type_sync(NodeId value) const;

  /// Writes the `SourceNode` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_source_node_sync, write_source_node_sync
  void write_source_node_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SourceNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_source_node_sync(NodeId value) const noexcept;
  /// Writes the `SourceNode` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_source_node_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_source_node_sync(NodeId value) const;

  /// Writes the `SourceName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_source_name_sync, write_source_name_sync
  void write_source_name_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SourceName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_source_name_sync(String value) const noexcept;
  /// Writes the `SourceName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_source_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_source_name_sync(String value) const;

  /// Writes the `Message` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_message_sync, write_message_sync
  void write_message_async(LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Message` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_message_sync(LocalizedText value) const noexcept;
  /// Writes the `Message` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_message_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_message_sync(LocalizedText value) const;

  /// Writes the `Severity` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_severity_sync, write_severity_sync
  void write_severity_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Severity` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_severity_sync(uint16_t value) const noexcept;
  /// Writes the `Severity` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_severity_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_severity_sync(uint16_t value) const;

private:
  explicit ExclusiveDeviationAlarm(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_EXCLUSIVE_DEVIATION_ALARM_H
