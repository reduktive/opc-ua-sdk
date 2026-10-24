// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_STATE_VARIABLE_H
#define UA_ALARM_STATE_VARIABLE_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class AlarmStateVariable;
using AlarmStateVariableResult = Result<AlarmStateVariable>;

/// Address-space handle for the OPC UA AlarmStateVariableType VariableType.
/// @ingroup ua_information_model
class AlarmStateVariable final : public BaseDataVariable
{
public:
  /// Constructs an empty `AlarmStateVariable` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  AlarmStateVariable() = default;

  /// Completion callback for create_async: receives the new `AlarmStateVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AlarmStateVariableResult)>;
  /// Completion callback for attach_async: receives the wrapped `AlarmStateVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AlarmStateVariableResult)>;

  /// Creates a new `AlarmStateVariableType` variable under `parent`.
  ///
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @param complete     Receives the outcome: on success a `AlarmStateVariable` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `AlarmStateVariableType` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static AlarmStateVariableResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `AlarmStateVariableType` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new `AlarmStateVariable` handle. A Good subcode is not returned; @ref try_create_sync
  /// returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AlarmStateVariable create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `AlarmStateVariableType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `AlarmStateVariable` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AlarmStateVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AlarmStateVariableResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AlarmStateVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `AlarmStateVariable` handle. A Good subcode is not returned; @ref try_attach_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AlarmStateVariable attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `HighestActiveSeverity` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_highest_active_severity_property_sync, highest_active_severity_property_sync
  void highest_active_severity_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighestActiveSeverity` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_highest_active_severity_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighestActiveSeverity` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_highest_active_severity_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property highest_active_severity_property_sync() const;

  /// Attaches a `Property` handle for the `HighestUnackSeverity` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_highest_unack_severity_property_sync, highest_unack_severity_property_sync
  void highest_unack_severity_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HighestUnackSeverity` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_highest_unack_severity_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HighestUnackSeverity` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_highest_unack_severity_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property highest_unack_severity_property_sync() const;

  /// Attaches a `Property` handle for the `ActiveCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_active_count_property_sync, active_count_property_sync
  void active_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ActiveCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_active_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ActiveCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_active_count_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property active_count_property_sync() const;

  /// Attaches a `Property` handle for the `UnacknowledgedCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unacknowledged_count_property_sync, unacknowledged_count_property_sync
  void unacknowledged_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UnacknowledgedCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_unacknowledged_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UnacknowledgedCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_unacknowledged_count_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property unacknowledged_count_property_sync() const;

  /// Attaches a `Property` handle for the `UnconfirmedCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unconfirmed_count_property_sync, unconfirmed_count_property_sync
  void unconfirmed_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UnconfirmedCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_unconfirmed_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UnconfirmedCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_unconfirmed_count_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property unconfirmed_count_property_sync() const;

  /// Attaches a `Property` handle for the `Filter` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_filter_property_sync, filter_property_sync
  void filter_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Filter` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_filter_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Filter` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_filter_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property filter_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `HighestActiveSeverity` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_highest_active_severity_sync, read_highest_active_severity_sync
  void read_highest_active_severity_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `HighestActiveSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_highest_active_severity_async gives it. Never
  /// throws.
  UInt16Result try_read_highest_active_severity_sync() const noexcept;
  /// Reads the `HighestActiveSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_highest_active_severity_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_highest_active_severity_sync() const;

  /// Reads the `HighestUnackSeverity` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_highest_unack_severity_sync, read_highest_unack_severity_sync
  void read_highest_unack_severity_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `HighestUnackSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_highest_unack_severity_async gives it. Never
  /// throws.
  UInt16Result try_read_highest_unack_severity_sync() const noexcept;
  /// Reads the `HighestUnackSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_highest_unack_severity_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_highest_unack_severity_sync() const;

  /// Reads the `ActiveCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_active_count_sync, read_active_count_sync
  void read_active_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `ActiveCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_active_count_async gives it. Never throws.
  UInt32Result try_read_active_count_sync() const noexcept;
  /// Reads the `ActiveCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_active_count_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_active_count_sync() const;

  /// Reads the `UnacknowledgedCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_unacknowledged_count_sync, read_unacknowledged_count_sync
  void read_unacknowledged_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `UnacknowledgedCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_unacknowledged_count_async gives it. Never throws.
  UInt32Result try_read_unacknowledged_count_sync() const noexcept;
  /// Reads the `UnacknowledgedCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_unacknowledged_count_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_unacknowledged_count_sync() const;

  /// Reads the `UnconfirmedCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_unconfirmed_count_sync, read_unconfirmed_count_sync
  void read_unconfirmed_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `UnconfirmedCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_unconfirmed_count_async gives it. Never throws.
  UInt32Result try_read_unconfirmed_count_sync() const noexcept;
  /// Reads the `UnconfirmedCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_unconfirmed_count_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_unconfirmed_count_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `HighestActiveSeverity` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_highest_active_severity_sync, write_highest_active_severity_sync
  void write_highest_active_severity_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighestActiveSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_highest_active_severity_sync(uint16_t value) const noexcept;
  /// Writes the `HighestActiveSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_highest_active_severity_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_highest_active_severity_sync(uint16_t value) const;

  /// Writes the `HighestUnackSeverity` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_highest_unack_severity_sync, write_highest_unack_severity_sync
  void write_highest_unack_severity_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `HighestUnackSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_highest_unack_severity_sync(uint16_t value) const noexcept;
  /// Writes the `HighestUnackSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_highest_unack_severity_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_highest_unack_severity_sync(uint16_t value) const;

  /// Writes the `ActiveCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_active_count_sync, write_active_count_sync
  void write_active_count_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ActiveCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_active_count_sync(uint32_t value) const noexcept;
  /// Writes the `ActiveCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_active_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_active_count_sync(uint32_t value) const;

  /// Writes the `UnacknowledgedCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_unacknowledged_count_sync, write_unacknowledged_count_sync
  void write_unacknowledged_count_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `UnacknowledgedCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_unacknowledged_count_sync(uint32_t value) const noexcept;
  /// Writes the `UnacknowledgedCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_unacknowledged_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_unacknowledged_count_sync(uint32_t value) const;

  /// Writes the `UnconfirmedCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_unconfirmed_count_sync, write_unconfirmed_count_sync
  void write_unconfirmed_count_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `UnconfirmedCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_unconfirmed_count_sync(uint32_t value) const noexcept;
  /// Writes the `UnconfirmedCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_unconfirmed_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_unconfirmed_count_sync(uint32_t value) const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  AlarmStateVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

private:
  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ALARM_STATE_VARIABLE_H
