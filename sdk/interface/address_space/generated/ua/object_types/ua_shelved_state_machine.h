// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SHELVED_STATE_MACHINE_H
#define UA_SHELVED_STATE_MACHINE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_state.h"
#include "ua_transition.h"

namespace ua
{

struct MethodCallContext;

class ShelvedStateMachine;
using ShelvedStateMachineResult = Result<ShelvedStateMachine>;

/// Address-space handle for the OPC UA ShelvedStateMachineType ObjectType.
/// @ingroup ua_information_model
class ShelvedStateMachine : public BaseObject
{
public:
  /// Constructs an empty `ShelvedStateMachine` handle that references no node.
  ShelvedStateMachine() = default;

  /// Input arguments for the ShelvedStateMachineType TimedShelve() method.
  struct TimedShelveInputArguments
  {
    Variant shelvingTime;  ///< Shelving time.
  };

  /// Synchronous handler for TimedShelve(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using TimedShelveHandler =
    std::function<MethodResult<>(const MethodCall&, const TimedShelveInputArguments&)>;
  /// Asynchronous handler for TimedShelve(): starts the work and completes it through the callback, once,
  /// from any thread.
  using TimedShelveAsyncHandler =
    std::function<void(const MethodCall&, const TimedShelveInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the ShelvedStateMachineType TimedShelve2() method.
  struct TimedShelve2InputArguments
  {
    Variant shelvingTime;  ///< Shelving time.
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for TimedShelve2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using TimedShelve2Handler =
    std::function<MethodResult<>(const MethodCall&, const TimedShelve2InputArguments&)>;
  /// Asynchronous handler for TimedShelve2(): starts the work and completes it through the callback, once,
  /// from any thread.
  using TimedShelve2AsyncHandler =
    std::function<void(const MethodCall&, const TimedShelve2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for Unshelve(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using UnshelveHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Unshelve(): starts the work and completes it through the callback, once, from
  /// any thread.
  using UnshelveAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the ShelvedStateMachineType Unshelve2() method.
  struct Unshelve2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for Unshelve2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using Unshelve2Handler = std::function<MethodResult<>(const MethodCall&, const Unshelve2InputArguments&)>;
  /// Asynchronous handler for Unshelve2(): starts the work and completes it through the callback, once, from
  /// any thread.
  using Unshelve2AsyncHandler =
    std::function<void(const MethodCall&, const Unshelve2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for OneShotShelve(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using OneShotShelveHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for OneShotShelve(): starts the work and completes it through the callback, once,
  /// from any thread.
  using OneShotShelveAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the ShelvedStateMachineType OneShotShelve2() method.
  struct OneShotShelve2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for OneShotShelve2(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using OneShotShelve2Handler =
    std::function<MethodResult<>(const MethodCall&, const OneShotShelve2InputArguments&)>;
  /// Asynchronous handler for OneShotShelve2(): starts the work and completes it through the callback, once,
  /// from any thread.
  using OneShotShelve2AsyncHandler =
    std::function<void(const MethodCall&, const OneShotShelve2InputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `ShelvedStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ShelvedStateMachineResult)>;
  /// Completion callback for attach_async: receives the attached `ShelvedStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ShelvedStateMachineResult)>;

  /// Creates a new `ShelvedStateMachineType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ShelvedStateMachine` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ShelvedStateMachineType` instance under `parent`, blocking until complete.  ///
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
  static ShelvedStateMachineResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ShelvedStateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ShelvedStateMachine` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ShelvedStateMachine create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ShelvedStateMachineType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ShelvedStateMachine` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ShelvedStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ShelvedStateMachineResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ShelvedStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ShelvedStateMachine` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ShelvedStateMachine attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `TimedShelve` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_timed_shelve_method_sync, timed_shelve_method_sync
  void timed_shelve_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `TimedShelve` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_timed_shelve_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `TimedShelve` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_timed_shelve_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor timed_shelve_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `TimedShelve2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_timed_shelve2_method_sync, timed_shelve2_method_sync
  void timed_shelve2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `TimedShelve2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_timed_shelve2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `TimedShelve2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_timed_shelve2_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor timed_shelve2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Unshelve` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelve_method_sync, unshelve_method_sync
  void unshelve_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Unshelve` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_unshelve_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Unshelve` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_unshelve_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor unshelve_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Unshelve2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelve2_method_sync, unshelve2_method_sync
  void unshelve2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Unshelve2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_unshelve2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Unshelve2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_unshelve2_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor unshelve2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `OneShotShelve` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_one_shot_shelve_method_sync, one_shot_shelve_method_sync
  void one_shot_shelve_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `OneShotShelve` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_one_shot_shelve_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `OneShotShelve` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_one_shot_shelve_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor one_shot_shelve_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `OneShotShelve2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_one_shot_shelve2_method_sync, one_shot_shelve2_method_sync
  void one_shot_shelve2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `OneShotShelve2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_one_shot_shelve2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `OneShotShelve2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_one_shot_shelve2_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor one_shot_shelve2_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `UnshelveTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelve_time_property_sync, unshelve_time_property_sync
  void unshelve_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UnshelveTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_unshelve_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UnshelveTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_unshelve_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property unshelve_time_property_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `TimedShelve` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_timed_shelve_handler_sync, set_timed_shelve_handler_sync
  void set_timed_shelve_handler_async(
    TimedShelveHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `TimedShelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_timed_shelve_handler_sync(TimedShelveHandler handler) const noexcept;
  /// Registers the synchronous `TimedShelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_timed_shelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_timed_shelve_handler_sync(TimedShelveHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `TimedShelve` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_timed_shelve_handler_sync, set_timed_shelve_handler_sync
  void set_timed_shelve_handler_async(
    TimedShelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `TimedShelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_timed_shelve_handler_sync(TimedShelveAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `TimedShelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_timed_shelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_timed_shelve_handler_sync(TimedShelveAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `TimedShelve2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_timed_shelve2_handler_sync, set_timed_shelve2_handler_sync
  void set_timed_shelve2_handler_async(
    TimedShelve2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `TimedShelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_timed_shelve2_handler_sync(TimedShelve2Handler handler) const noexcept;
  /// Registers the synchronous `TimedShelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_timed_shelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_timed_shelve2_handler_sync(TimedShelve2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `TimedShelve2` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_timed_shelve2_handler_sync, set_timed_shelve2_handler_sync
  void set_timed_shelve2_handler_async(
    TimedShelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `TimedShelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_timed_shelve2_handler_sync(TimedShelve2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `TimedShelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_timed_shelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_timed_shelve2_handler_sync(TimedShelve2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Unshelve` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unshelve_handler_sync, set_unshelve_handler_sync
  void set_unshelve_handler_async(
    UnshelveHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Unshelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unshelve_handler_sync(UnshelveHandler handler) const noexcept;
  /// Registers the synchronous `Unshelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_unshelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unshelve_handler_sync(UnshelveHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Unshelve` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unshelve_handler_sync, set_unshelve_handler_sync
  void set_unshelve_handler_async(
    UnshelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Unshelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unshelve_handler_sync(UnshelveAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Unshelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_unshelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unshelve_handler_sync(UnshelveAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Unshelve2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unshelve2_handler_sync, set_unshelve2_handler_sync
  void set_unshelve2_handler_async(
    Unshelve2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Unshelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unshelve2_handler_sync(Unshelve2Handler handler) const noexcept;
  /// Registers the synchronous `Unshelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_unshelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unshelve2_handler_sync(Unshelve2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Unshelve2` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unshelve2_handler_sync, set_unshelve2_handler_sync
  void set_unshelve2_handler_async(
    Unshelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Unshelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unshelve2_handler_sync(Unshelve2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Unshelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_unshelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unshelve2_handler_sync(Unshelve2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `OneShotShelve` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_one_shot_shelve_handler_sync, set_one_shot_shelve_handler_sync
  void set_one_shot_shelve_handler_async(
    OneShotShelveHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `OneShotShelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_one_shot_shelve_handler_sync(OneShotShelveHandler handler) const noexcept;
  /// Registers the synchronous `OneShotShelve` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_one_shot_shelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_one_shot_shelve_handler_sync(OneShotShelveHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `OneShotShelve` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_one_shot_shelve_handler_sync, set_one_shot_shelve_handler_sync
  void set_one_shot_shelve_handler_async(
    OneShotShelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `OneShotShelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_one_shot_shelve_handler_sync(OneShotShelveAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `OneShotShelve` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_one_shot_shelve_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_one_shot_shelve_handler_sync(OneShotShelveAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `OneShotShelve2` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_one_shot_shelve2_handler_sync, set_one_shot_shelve2_handler_sync
  void set_one_shot_shelve2_handler_async(
    OneShotShelve2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `OneShotShelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_one_shot_shelve2_handler_sync(OneShotShelve2Handler handler) const noexcept;
  /// Registers the synchronous `OneShotShelve2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_one_shot_shelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_one_shot_shelve2_handler_sync(OneShotShelve2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `OneShotShelve2` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_one_shot_shelve2_handler_sync, set_one_shot_shelve2_handler_sync
  void set_one_shot_shelve2_handler_async(
    OneShotShelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `OneShotShelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_one_shot_shelve2_handler_sync(OneShotShelve2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `OneShotShelve2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_one_shot_shelve2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_one_shot_shelve2_handler_sync(OneShotShelve2AsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `State` handle for the `Unshelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelved_sync, unshelved_sync
  void unshelved_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Unshelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_unshelved_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Unshelved` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_unshelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State unshelved_sync() const;

  /// Attaches a typed `State` handle for the `TimedShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_timed_shelved_sync, timed_shelved_sync
  void timed_shelved_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `TimedShelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_timed_shelved_sync() const noexcept;
  /// Attaches a typed `State` handle for the `TimedShelved` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_timed_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State timed_shelved_sync() const;

  /// Attaches a typed `State` handle for the `OneShotShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_one_shot_shelved_sync, one_shot_shelved_sync
  void one_shot_shelved_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `OneShotShelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_one_shot_shelved_sync() const noexcept;
  /// Attaches a typed `State` handle for the `OneShotShelved` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_one_shot_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State one_shot_shelved_sync() const;

  /// Attaches a typed `Transition` handle for the `UnshelvedToTimedShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelved_to_timed_shelved_sync, unshelved_to_timed_shelved_sync
  void unshelved_to_timed_shelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `UnshelvedToTimedShelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_unshelved_to_timed_shelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `UnshelvedToTimedShelved` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_unshelved_to_timed_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition unshelved_to_timed_shelved_sync() const;

  /// Attaches a typed `Transition` handle for the `UnshelvedToOneShotShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unshelved_to_one_shot_shelved_sync, unshelved_to_one_shot_shelved_sync
  void unshelved_to_one_shot_shelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `UnshelvedToOneShotShelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_unshelved_to_one_shot_shelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `UnshelvedToOneShotShelved` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_unshelved_to_one_shot_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition unshelved_to_one_shot_shelved_sync() const;

  /// Attaches a typed `Transition` handle for the `TimedShelvedToUnshelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_timed_shelved_to_unshelved_sync, timed_shelved_to_unshelved_sync
  void timed_shelved_to_unshelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `TimedShelvedToUnshelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_timed_shelved_to_unshelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `TimedShelvedToUnshelved` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_timed_shelved_to_unshelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition timed_shelved_to_unshelved_sync() const;

  /// Attaches a typed `Transition` handle for the `TimedShelvedToOneShotShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_timed_shelved_to_one_shot_shelved_sync, timed_shelved_to_one_shot_shelved_sync
  void timed_shelved_to_one_shot_shelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `TimedShelvedToOneShotShelved` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_timed_shelved_to_one_shot_shelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `TimedShelvedToOneShotShelved` child, blocking until
  /// complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_timed_shelved_to_one_shot_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition timed_shelved_to_one_shot_shelved_sync() const;

  /// Attaches a typed `Transition` handle for the `OneShotShelvedToUnshelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_one_shot_shelved_to_unshelved_sync, one_shot_shelved_to_unshelved_sync
  void one_shot_shelved_to_unshelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `OneShotShelvedToUnshelved` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_one_shot_shelved_to_unshelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `OneShotShelvedToUnshelved` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_one_shot_shelved_to_unshelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition one_shot_shelved_to_unshelved_sync() const;

  /// Attaches a typed `Transition` handle for the `OneShotShelvedToTimedShelved` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_one_shot_shelved_to_timed_shelved_sync, one_shot_shelved_to_timed_shelved_sync
  void one_shot_shelved_to_timed_shelved_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `OneShotShelvedToTimedShelved` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_one_shot_shelved_to_timed_shelved_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `OneShotShelvedToTimedShelved` child, blocking until
  /// complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_one_shot_shelved_to_timed_shelved_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition one_shot_shelved_to_timed_shelved_sync() const;

private:
  explicit ShelvedStateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SHELVED_STATE_MACHINE_H
