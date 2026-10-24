// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PROGRAM_STATE_MACHINE_H
#define UA_PROGRAM_STATE_MACHINE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_finite_state_variable.h"
#include "ua_finite_transition_variable.h"
#include "ua_program_diagnostic2.h"
#include "ua_base_object.h"
#include "ua_state.h"
#include "ua_transition.h"

namespace ua
{

struct MethodCallContext;

class ProgramStateMachine;
using ProgramStateMachineResult = Result<ProgramStateMachine>;

/// Address-space handle for the OPC UA ProgramStateMachineType ObjectType.
/// @ingroup ua_information_model
class ProgramStateMachine : public BaseObject
{
public:
  /// Constructs an empty `ProgramStateMachine` handle that references no node.
  ProgramStateMachine() = default;

  /// Completion callback for create_async: receives the created `ProgramStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ProgramStateMachineResult)>;
  /// Completion callback for attach_async: receives the attached `ProgramStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ProgramStateMachineResult)>;

  /// Creates a new `ProgramStateMachineType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ProgramStateMachine` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ProgramStateMachineType` instance under `parent`, blocking until complete.  ///
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
  static ProgramStateMachineResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ProgramStateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ProgramStateMachine` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ProgramStateMachine create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ProgramStateMachineType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ProgramStateMachine` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ProgramStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ProgramStateMachineResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ProgramStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ProgramStateMachine` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ProgramStateMachine attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Creatable` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_creatable_property_sync, creatable_property_sync
  void creatable_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Creatable` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_creatable_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Creatable` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_creatable_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property creatable_property_sync() const;

  /// Attaches a `Property` handle for the `Deletable` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_deletable_property_sync, deletable_property_sync
  void deletable_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Deletable` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_deletable_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Deletable` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_deletable_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property deletable_property_sync() const;

  /// Attaches a `Property` handle for the `AutoDelete` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_auto_delete_property_sync, auto_delete_property_sync
  void auto_delete_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AutoDelete` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_auto_delete_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AutoDelete` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_auto_delete_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property auto_delete_property_sync() const;

  /// Attaches a `Property` handle for the `RecycleCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_recycle_count_property_sync, recycle_count_property_sync
  void recycle_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `RecycleCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_recycle_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `RecycleCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_recycle_count_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property recycle_count_property_sync() const;

  /// Attaches a `Property` handle for the `InstanceCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_instance_count_property_sync, instance_count_property_sync
  void instance_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `InstanceCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_instance_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `InstanceCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_instance_count_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property instance_count_property_sync() const;

  /// Attaches a `Property` handle for the `MaxInstanceCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_instance_count_property_sync, max_instance_count_property_sync
  void max_instance_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxInstanceCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_instance_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxInstanceCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_instance_count_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_instance_count_property_sync() const;

  /// Attaches a `Property` handle for the `MaxRecycleCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_recycle_count_property_sync, max_recycle_count_property_sync
  void max_recycle_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxRecycleCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_recycle_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxRecycleCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_recycle_count_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_recycle_count_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Creatable` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_creatable_sync, read_creatable_sync
  void read_creatable_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Creatable` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_creatable_async gives it. Never throws.
  BoolResult try_read_creatable_sync() const noexcept;
  /// Reads the `Creatable` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_creatable_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_creatable_sync() const;

  /// Reads the `Deletable` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_deletable_sync, read_deletable_sync
  void read_deletable_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Deletable` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_deletable_async gives it. Never throws.
  BoolResult try_read_deletable_sync() const noexcept;
  /// Reads the `Deletable` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_deletable_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_deletable_sync() const;

  /// Reads the `AutoDelete` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_auto_delete_sync, read_auto_delete_sync
  void read_auto_delete_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `AutoDelete` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_auto_delete_async gives it. Never throws.
  BoolResult try_read_auto_delete_sync() const noexcept;
  /// Reads the `AutoDelete` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_auto_delete_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_auto_delete_sync() const;

  /// Reads the `RecycleCount` property value, typed as `int32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_recycle_count_sync, read_recycle_count_sync
  void read_recycle_count_async(std::function<void(Int32Result)> complete) const noexcept;
  /// Reads the `RecycleCount` property value as `int32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_recycle_count_async gives it. Never throws.
  Int32Result try_read_recycle_count_sync() const noexcept;
  /// Reads the `RecycleCount` property value as `int32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_recycle_count_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  int32_t read_recycle_count_sync() const;

  /// Reads the `InstanceCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_instance_count_sync, read_instance_count_sync
  void read_instance_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `InstanceCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_instance_count_async gives it. Never throws.
  UInt32Result try_read_instance_count_sync() const noexcept;
  /// Reads the `InstanceCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_instance_count_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_instance_count_sync() const;

  /// Reads the `MaxInstanceCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_instance_count_sync, read_max_instance_count_sync
  void read_max_instance_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxInstanceCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_instance_count_async gives it. Never throws.
  UInt32Result try_read_max_instance_count_sync() const noexcept;
  /// Reads the `MaxInstanceCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_instance_count_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_instance_count_sync() const;

  /// Reads the `MaxRecycleCount` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_recycle_count_sync, read_max_recycle_count_sync
  void read_max_recycle_count_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxRecycleCount` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_recycle_count_async gives it. Never throws.
  UInt32Result try_read_max_recycle_count_sync() const noexcept;
  /// Reads the `MaxRecycleCount` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_recycle_count_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_recycle_count_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Creatable` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_creatable_sync, write_creatable_sync
  void write_creatable_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Creatable` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_creatable_sync(bool value) const noexcept;
  /// Writes the `Creatable` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_creatable_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_creatable_sync(bool value) const;

  /// Writes the `Deletable` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_deletable_sync, write_deletable_sync
  void write_deletable_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Deletable` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_deletable_sync(bool value) const noexcept;
  /// Writes the `Deletable` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_deletable_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_deletable_sync(bool value) const;

  /// Writes the `AutoDelete` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_auto_delete_sync, write_auto_delete_sync
  void write_auto_delete_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `AutoDelete` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_auto_delete_sync(bool value) const noexcept;
  /// Writes the `AutoDelete` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_auto_delete_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_auto_delete_sync(bool value) const;

  /// Writes the `RecycleCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_recycle_count_sync, write_recycle_count_sync
  void write_recycle_count_async(int32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `RecycleCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_recycle_count_sync(int32_t value) const noexcept;
  /// Writes the `RecycleCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_recycle_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_recycle_count_sync(int32_t value) const;

  /// Writes the `InstanceCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_instance_count_sync, write_instance_count_sync
  void write_instance_count_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `InstanceCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_instance_count_sync(uint32_t value) const noexcept;
  /// Writes the `InstanceCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_instance_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_instance_count_sync(uint32_t value) const;

  /// Writes the `MaxInstanceCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_instance_count_sync, write_max_instance_count_sync
  void write_max_instance_count_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxInstanceCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_instance_count_sync(uint32_t value) const noexcept;
  /// Writes the `MaxInstanceCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_instance_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_instance_count_sync(uint32_t value) const;

  /// Writes the `MaxRecycleCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_recycle_count_sync, write_max_recycle_count_sync
  void write_max_recycle_count_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxRecycleCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_recycle_count_sync(uint32_t value) const noexcept;
  /// Writes the `MaxRecycleCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_recycle_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_recycle_count_sync(uint32_t value) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `FiniteStateVariable` handle for the `CurrentState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_current_state_sync, current_state_sync
  void current_state_async(std::function<void(FiniteStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `FiniteStateVariable` handle for the `CurrentState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FiniteStateVariableResult try_current_state_sync() const noexcept;
  /// Attaches a typed `FiniteStateVariable` handle for the `CurrentState` child, blocking until complete.
  /// @return The `FiniteStateVariable` handle. A Good subcode is not returned; @ref try_current_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  FiniteStateVariable current_state_sync() const;

  /// Attaches a typed `FiniteTransitionVariable` handle for the `LastTransition` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_transition_sync, last_transition_sync
  void last_transition_async(std::function<void(FiniteTransitionVariableResult)> complete) const noexcept;
  /// Attaches a typed `FiniteTransitionVariable` handle for the `LastTransition` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FiniteTransitionVariableResult try_last_transition_sync() const noexcept;
  /// Attaches a typed `FiniteTransitionVariable` handle for the `LastTransition` child, blocking until
  /// complete.
  /// @return The `FiniteTransitionVariable` handle. A Good subcode is not returned; @ref
  /// try_last_transition_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  FiniteTransitionVariable last_transition_sync() const;

  /// Attaches a typed `ProgramDiagnostic2` handle for the `ProgramDiagnostic` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_program_diagnostic_sync, program_diagnostic_sync
  void program_diagnostic_async(std::function<void(ProgramDiagnostic2Result)> complete) const noexcept;
  /// Attaches a typed `ProgramDiagnostic2` handle for the `ProgramDiagnostic` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ProgramDiagnostic2Result try_program_diagnostic_sync() const noexcept;
  /// Attaches a typed `ProgramDiagnostic2` handle for the `ProgramDiagnostic` child, blocking until complete.
  /// @return The `ProgramDiagnostic2` handle. A Good subcode is not returned; @ref
  /// try_program_diagnostic_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ProgramDiagnostic2 program_diagnostic_sync() const;

  /// Attaches a typed `BaseObject` handle for the `FinalResultData` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_final_result_data_sync, final_result_data_sync
  void final_result_data_async(std::function<void(BaseObjectResult)> complete) const noexcept;
  /// Attaches a typed `BaseObject` handle for the `FinalResultData` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseObjectResult try_final_result_data_sync() const noexcept;
  /// Attaches a typed `BaseObject` handle for the `FinalResultData` child, blocking until complete.
  /// @return The `BaseObject` handle. A Good subcode is not returned; @ref try_final_result_data_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseObject final_result_data_sync() const;

  /// Attaches a typed `State` handle for the `Halted` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_halted_sync, halted_sync
  void halted_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Halted` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_halted_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Halted` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_halted_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State halted_sync() const;

  /// Attaches a typed `State` handle for the `Ready` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ready_sync, ready_sync
  void ready_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Ready` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_ready_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Ready` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_ready_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State ready_sync() const;

  /// Attaches a typed `State` handle for the `Running` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_running_sync, running_sync
  void running_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Running` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_running_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Running` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_running_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State running_sync() const;

  /// Attaches a typed `State` handle for the `Suspended` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suspended_sync, suspended_sync
  void suspended_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Suspended` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_suspended_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Suspended` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_suspended_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State suspended_sync() const;

  /// Attaches a typed `Transition` handle for the `HaltedToReady` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_halted_to_ready_sync, halted_to_ready_sync
  void halted_to_ready_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `HaltedToReady` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_halted_to_ready_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `HaltedToReady` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_halted_to_ready_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition halted_to_ready_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadyToRunning` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ready_to_running_sync, ready_to_running_sync
  void ready_to_running_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadyToRunning` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_ready_to_running_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadyToRunning` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_ready_to_running_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition ready_to_running_sync() const;

  /// Attaches a typed `Transition` handle for the `RunningToHalted` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_running_to_halted_sync, running_to_halted_sync
  void running_to_halted_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToHalted` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_running_to_halted_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToHalted` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_running_to_halted_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition running_to_halted_sync() const;

  /// Attaches a typed `Transition` handle for the `RunningToReady` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_running_to_ready_sync, running_to_ready_sync
  void running_to_ready_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToReady` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_running_to_ready_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToReady` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_running_to_ready_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition running_to_ready_sync() const;

  /// Attaches a typed `Transition` handle for the `RunningToSuspended` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_running_to_suspended_sync, running_to_suspended_sync
  void running_to_suspended_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToSuspended` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_running_to_suspended_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `RunningToSuspended` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_running_to_suspended_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition running_to_suspended_sync() const;

  /// Attaches a typed `Transition` handle for the `SuspendedToRunning` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suspended_to_running_sync, suspended_to_running_sync
  void suspended_to_running_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToRunning` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_suspended_to_running_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToRunning` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_suspended_to_running_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition suspended_to_running_sync() const;

  /// Attaches a typed `Transition` handle for the `SuspendedToHalted` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suspended_to_halted_sync, suspended_to_halted_sync
  void suspended_to_halted_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToHalted` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_suspended_to_halted_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToHalted` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_suspended_to_halted_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition suspended_to_halted_sync() const;

  /// Attaches a typed `Transition` handle for the `SuspendedToReady` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suspended_to_ready_sync, suspended_to_ready_sync
  void suspended_to_ready_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToReady` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_suspended_to_ready_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `SuspendedToReady` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_suspended_to_ready_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition suspended_to_ready_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadyToHalted` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ready_to_halted_sync, ready_to_halted_sync
  void ready_to_halted_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadyToHalted` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_ready_to_halted_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadyToHalted` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_ready_to_halted_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition ready_to_halted_sync() const;

private:
  explicit ProgramStateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_PROGRAM_STATE_MACHINE_H
