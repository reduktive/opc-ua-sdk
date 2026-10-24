// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ANALOG_ITEM_H
#define UA_ANALOG_ITEM_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class AnalogItem;
using AnalogItemResult = Result<AnalogItem>;

/// Address-space handle for the OPC UA AnalogItemType VariableType.
/// @ingroup ua_information_model
class AnalogItem : public BaseDataVariable
{
public:
  /// Constructs an empty `AnalogItem` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  AnalogItem() = default;

  /// Completion callback for create_async: receives the new `AnalogItem` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AnalogItemResult)>;
  /// Completion callback for attach_async: receives the wrapped `AnalogItem` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AnalogItemResult)>;

  /// Creates a new `AnalogItemType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `AnalogItem` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `AnalogItemType` variable under `parent`, blocking until complete.
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
  static AnalogItemResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `AnalogItemType` variable under `parent`, blocking until complete.
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
  /// @return The new `AnalogItem` handle. A Good subcode is not returned; @ref try_create_sync returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AnalogItem create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `AnalogItemType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `AnalogItem` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AnalogItemType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AnalogItemResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AnalogItemType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `AnalogItem` handle. A Good subcode is not returned; @ref try_attach_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AnalogItem attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `EURange` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_eu_range_property_sync, eu_range_property_sync
  void eu_range_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EURange` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_eu_range_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EURange` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_eu_range_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property eu_range_property_sync() const;

  /// Attaches a `Property` handle for the `InstrumentRange` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_instrument_range_property_sync, instrument_range_property_sync
  void instrument_range_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `InstrumentRange` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_instrument_range_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `InstrumentRange` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_instrument_range_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property instrument_range_property_sync() const;

  /// Attaches a `Property` handle for the `EngineeringUnits` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_engineering_units_property_sync, engineering_units_property_sync
  void engineering_units_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EngineeringUnits` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_engineering_units_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EngineeringUnits` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_engineering_units_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property engineering_units_property_sync() const;

  /// Attaches a `Property` handle for the `Definition` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_definition_property_sync, definition_property_sync
  void definition_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Definition` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_definition_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Definition` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_definition_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property definition_property_sync() const;

  /// Attaches a `Property` handle for the `ValuePrecision` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_value_precision_property_sync, value_precision_property_sync
  void value_precision_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ValuePrecision` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_value_precision_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ValuePrecision` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_value_precision_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property value_precision_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Definition` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_definition_sync, read_definition_sync
  void read_definition_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `Definition` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_definition_async gives it. Never throws.
  StringResult try_read_definition_sync() const noexcept;
  /// Reads the `Definition` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_definition_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_definition_sync() const;

  /// Reads the `ValuePrecision` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_value_precision_sync, read_value_precision_sync
  void read_value_precision_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `ValuePrecision` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_value_precision_async gives it. Never throws.
  DoubleResult try_read_value_precision_sync() const noexcept;
  /// Reads the `ValuePrecision` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_value_precision_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_value_precision_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Definition` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_definition_sync, write_definition_sync
  void write_definition_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Definition` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_definition_sync(String value) const noexcept;
  /// Writes the `Definition` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_definition_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_definition_sync(String value) const;

  /// Writes the `ValuePrecision` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_value_precision_sync, write_value_precision_sync
  void write_value_precision_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ValuePrecision` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_value_precision_sync(double value) const noexcept;
  /// Writes the `ValuePrecision` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_value_precision_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_value_precision_sync(double value) const;

protected:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  AnalogItem(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

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

#endif  // UA_ANALOG_ITEM_H
