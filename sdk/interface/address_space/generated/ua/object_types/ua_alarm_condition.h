// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_CONDITION_H
#define UA_ALARM_CONDITION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_two_state_variable.h"
#include "ua_shelved_state_machine.h"
#include "ua_audio_variable.h"
#include "ua_base_data_variable.h"
#include "ua_alarm_group.h"

namespace ua
{

struct MethodCallContext;

class AlarmCondition;
using AlarmConditionResult = Result<AlarmCondition>;

/// Address-space handle for the OPC UA AlarmConditionType ObjectType.
/// @ingroup ua_information_model
class AlarmCondition : public BaseObject
{
public:
  /// Constructs an empty `AlarmCondition` handle that references no node.
  AlarmCondition() = default;

  /// Synchronous handler for Silence(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using SilenceHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Silence(): starts the work and completes it through the callback, once, from
  /// any thread.
  using SilenceAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Synchronous handler for Suppress(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using SuppressHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Suppress(): starts the work and completes it through the callback, once, from
  /// any thread.
  using SuppressAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the AlarmConditionType Suppress2() method.
  struct Suppress2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for Suppress2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using Suppress2Handler = std::function<MethodResult<>(const MethodCall&, const Suppress2InputArguments&)>;
  /// Asynchronous handler for Suppress2(): starts the work and completes it through the callback, once, from
  /// any thread.
  using Suppress2AsyncHandler =
    std::function<void(const MethodCall&, const Suppress2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for Unsuppress(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using UnsuppressHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Unsuppress(): starts the work and completes it through the callback, once, from
  /// any thread.
  using UnsuppressAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the AlarmConditionType Unsuppress2() method.
  struct Unsuppress2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for Unsuppress2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using Unsuppress2Handler =
    std::function<MethodResult<>(const MethodCall&, const Unsuppress2InputArguments&)>;
  /// Asynchronous handler for Unsuppress2(): starts the work and completes it through the callback, once,
  /// from any thread.
  using Unsuppress2AsyncHandler =
    std::function<void(const MethodCall&, const Unsuppress2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for RemoveFromService(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RemoveFromServiceHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for RemoveFromService(): starts the work and completes it through the callback,
  /// once, from any thread.
  using RemoveFromServiceAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the AlarmConditionType RemoveFromService2() method.
  struct RemoveFromService2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for RemoveFromService2(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using RemoveFromService2Handler =
    std::function<MethodResult<>(const MethodCall&, const RemoveFromService2InputArguments&)>;
  /// Asynchronous handler for RemoveFromService2(): starts the work and completes it through the callback,
  /// once, from any thread.
  using RemoveFromService2AsyncHandler =
    std::function<void(const MethodCall&, const RemoveFromService2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for PlaceInService(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using PlaceInServiceHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for PlaceInService(): starts the work and completes it through the callback, once,
  /// from any thread.
  using PlaceInServiceAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the AlarmConditionType PlaceInService2() method.
  struct PlaceInService2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for PlaceInService2(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using PlaceInService2Handler =
    std::function<MethodResult<>(const MethodCall&, const PlaceInService2InputArguments&)>;
  /// Asynchronous handler for PlaceInService2(): starts the work and completes it through the callback, once,
  /// from any thread.
  using PlaceInService2AsyncHandler =
    std::function<void(const MethodCall&, const PlaceInService2InputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for Reset(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using ResetHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Reset(): starts the work and completes it through the callback, once, from any
  /// thread.
  using ResetAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Input arguments for the AlarmConditionType Reset2() method.
  struct Reset2InputArguments
  {
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for Reset2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using Reset2Handler = std::function<MethodResult<>(const MethodCall&, const Reset2InputArguments&)>;
  /// Asynchronous handler for Reset2(): starts the work and completes it through the callback, once, from any
  /// thread.
  using Reset2AsyncHandler =
    std::function<void(const MethodCall&, const Reset2InputArguments&, MethodResultCallback<>)>;

  /// Output arguments for the AlarmConditionType GetGroupMemberships() method.
  struct GetGroupMembershipsOutputArguments
  {
    std::vector<NodeId> groups;  ///< Groups.
  };

  /// Synchronous handler for GetGroupMemberships(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using GetGroupMembershipsHandler =
    std::function<MethodResult<GetGroupMembershipsOutputArguments>(const MethodCall&)>;
  /// Asynchronous handler for GetGroupMemberships(): starts the work and completes it through the callback,
  /// once, from any thread.
  using GetGroupMembershipsAsyncHandler =
    std::function<void(const MethodCall&, MethodResultCallback<GetGroupMembershipsOutputArguments>)>;

  /// Completion callback for create_async: receives the created `AlarmCondition` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AlarmConditionResult)>;
  /// Completion callback for attach_async: receives the attached `AlarmCondition` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AlarmConditionResult)>;

  /// Creates a new `AlarmConditionType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `AlarmCondition` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `AlarmConditionType` instance under `parent`, blocking until complete.  ///
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
  static AlarmConditionResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `AlarmConditionType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `AlarmCondition` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AlarmCondition create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `AlarmConditionType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `AlarmCondition` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AlarmConditionType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AlarmConditionResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AlarmConditionType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `AlarmCondition` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AlarmCondition attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Silence` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_silence_method_sync, silence_method_sync
  void silence_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Silence` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_silence_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Silence` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_silence_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor silence_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Suppress` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suppress_method_sync, suppress_method_sync
  void suppress_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Suppress` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_suppress_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Suppress` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_suppress_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor suppress_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Suppress2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suppress2_method_sync, suppress2_method_sync
  void suppress2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Suppress2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_suppress2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Suppress2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_suppress2_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor suppress2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Unsuppress` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unsuppress_method_sync, unsuppress_method_sync
  void unsuppress_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Unsuppress` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_unsuppress_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Unsuppress` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_unsuppress_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor unsuppress_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Unsuppress2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_unsuppress2_method_sync, unsuppress2_method_sync
  void unsuppress2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Unsuppress2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_unsuppress2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Unsuppress2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_unsuppress2_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor unsuppress2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveFromService` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_from_service_method_sync, remove_from_service_method_sync
  void remove_from_service_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveFromService` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_from_service_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveFromService` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_from_service_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_from_service_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveFromService2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_from_service2_method_sync, remove_from_service2_method_sync
  void remove_from_service2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveFromService2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_from_service2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveFromService2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_from_service2_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_from_service2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `PlaceInService` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_place_in_service_method_sync, place_in_service_method_sync
  void place_in_service_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `PlaceInService` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_place_in_service_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `PlaceInService` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_place_in_service_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor place_in_service_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `PlaceInService2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_place_in_service2_method_sync, place_in_service2_method_sync
  void place_in_service2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `PlaceInService2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_place_in_service2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `PlaceInService2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_place_in_service2_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor place_in_service2_method_sync() const;

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

  /// Attaches a `MethodAccessor` for client-side invocation of the `Reset2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_reset2_method_sync, reset2_method_sync
  void reset2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_reset2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_reset2_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor reset2_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GetGroupMemberships` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_group_memberships_method_sync, get_group_memberships_method_sync
  void get_group_memberships_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GetGroupMemberships` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_get_group_memberships_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GetGroupMemberships` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_get_group_memberships_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor get_group_memberships_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

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

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `Silence` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_silence_handler_sync, set_silence_handler_sync
  void set_silence_handler_async(SilenceHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Silence` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_silence_handler_sync(SilenceHandler handler) const noexcept;
  /// Registers the synchronous `Silence` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_silence_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_silence_handler_sync(SilenceHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Silence` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_silence_handler_sync, set_silence_handler_sync
  void set_silence_handler_async(
    SilenceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Silence` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_silence_handler_sync(SilenceAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Silence` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_silence_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_silence_handler_sync(SilenceAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Suppress` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_suppress_handler_sync, set_suppress_handler_sync
  void set_suppress_handler_async(
    SuppressHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Suppress` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_suppress_handler_sync(SuppressHandler handler) const noexcept;
  /// Registers the synchronous `Suppress` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_suppress_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_suppress_handler_sync(SuppressHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Suppress` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_suppress_handler_sync, set_suppress_handler_sync
  void set_suppress_handler_async(
    SuppressAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Suppress` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_suppress_handler_sync(SuppressAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Suppress` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_suppress_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_suppress_handler_sync(SuppressAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Suppress2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_suppress2_handler_sync, set_suppress2_handler_sync
  void set_suppress2_handler_async(
    Suppress2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Suppress2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_suppress2_handler_sync(Suppress2Handler handler) const noexcept;
  /// Registers the synchronous `Suppress2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_suppress2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_suppress2_handler_sync(Suppress2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Suppress2` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_suppress2_handler_sync, set_suppress2_handler_sync
  void set_suppress2_handler_async(
    Suppress2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Suppress2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_suppress2_handler_sync(Suppress2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Suppress2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_suppress2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_suppress2_handler_sync(Suppress2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Unsuppress` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unsuppress_handler_sync, set_unsuppress_handler_sync
  void set_unsuppress_handler_async(
    UnsuppressHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Unsuppress` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unsuppress_handler_sync(UnsuppressHandler handler) const noexcept;
  /// Registers the synchronous `Unsuppress` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_unsuppress_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unsuppress_handler_sync(UnsuppressHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Unsuppress` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unsuppress_handler_sync, set_unsuppress_handler_sync
  void set_unsuppress_handler_async(
    UnsuppressAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Unsuppress` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unsuppress_handler_sync(UnsuppressAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Unsuppress` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_unsuppress_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unsuppress_handler_sync(UnsuppressAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Unsuppress2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unsuppress2_handler_sync, set_unsuppress2_handler_sync
  void set_unsuppress2_handler_async(
    Unsuppress2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Unsuppress2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unsuppress2_handler_sync(Unsuppress2Handler handler) const noexcept;
  /// Registers the synchronous `Unsuppress2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_unsuppress2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unsuppress2_handler_sync(Unsuppress2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Unsuppress2` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_unsuppress2_handler_sync, set_unsuppress2_handler_sync
  void set_unsuppress2_handler_async(
    Unsuppress2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Unsuppress2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_unsuppress2_handler_sync(Unsuppress2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Unsuppress2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_unsuppress2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_unsuppress2_handler_sync(Unsuppress2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveFromService` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_from_service_handler_sync, set_remove_from_service_handler_sync
  void set_remove_from_service_handler_async(
    RemoveFromServiceHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveFromService` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_from_service_handler_sync(RemoveFromServiceHandler handler) const noexcept;
  /// Registers the synchronous `RemoveFromService` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_from_service_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_from_service_handler_sync(RemoveFromServiceHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveFromService` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_from_service_handler_sync, set_remove_from_service_handler_sync
  void set_remove_from_service_handler_async(
    RemoveFromServiceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveFromService` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_from_service_handler_sync(RemoveFromServiceAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveFromService` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_from_service_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_from_service_handler_sync(RemoveFromServiceAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveFromService2` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_from_service2_handler_sync, set_remove_from_service2_handler_sync
  void set_remove_from_service2_handler_async(
    RemoveFromService2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveFromService2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_from_service2_handler_sync(RemoveFromService2Handler handler) const noexcept;
  /// Registers the synchronous `RemoveFromService2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_from_service2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_from_service2_handler_sync(RemoveFromService2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveFromService2` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_from_service2_handler_sync, set_remove_from_service2_handler_sync
  void set_remove_from_service2_handler_async(
    RemoveFromService2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveFromService2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_from_service2_handler_sync(RemoveFromService2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveFromService2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_from_service2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_from_service2_handler_sync(RemoveFromService2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `PlaceInService` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_place_in_service_handler_sync, set_place_in_service_handler_sync
  void set_place_in_service_handler_async(
    PlaceInServiceHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `PlaceInService` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_place_in_service_handler_sync(PlaceInServiceHandler handler) const noexcept;
  /// Registers the synchronous `PlaceInService` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_place_in_service_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_place_in_service_handler_sync(PlaceInServiceHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `PlaceInService` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_place_in_service_handler_sync, set_place_in_service_handler_sync
  void set_place_in_service_handler_async(
    PlaceInServiceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `PlaceInService` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_place_in_service_handler_sync(PlaceInServiceAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `PlaceInService` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_place_in_service_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_place_in_service_handler_sync(PlaceInServiceAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `PlaceInService2` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_place_in_service2_handler_sync, set_place_in_service2_handler_sync
  void set_place_in_service2_handler_async(
    PlaceInService2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `PlaceInService2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_place_in_service2_handler_sync(PlaceInService2Handler handler) const noexcept;
  /// Registers the synchronous `PlaceInService2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_place_in_service2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_place_in_service2_handler_sync(PlaceInService2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `PlaceInService2` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_place_in_service2_handler_sync, set_place_in_service2_handler_sync
  void set_place_in_service2_handler_async(
    PlaceInService2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `PlaceInService2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_place_in_service2_handler_sync(PlaceInService2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `PlaceInService2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_place_in_service2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_place_in_service2_handler_sync(PlaceInService2AsyncHandler handler) const;

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

  /// Registers the synchronous handler invoked when a client calls the `Reset2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset2_handler_sync, set_reset2_handler_sync
  void set_reset2_handler_async(Reset2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Reset2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset2_handler_sync(Reset2Handler handler) const noexcept;
  /// Registers the synchronous `Reset2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset2_handler_sync(Reset2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Reset2` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset2_handler_sync, set_reset2_handler_sync
  void set_reset2_handler_async(
    Reset2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Reset2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset2_handler_sync(Reset2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Reset2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset2_handler_sync(Reset2AsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `GetGroupMemberships` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_group_memberships_handler_sync, set_get_group_memberships_handler_sync
  void set_get_group_memberships_handler_async(
    GetGroupMembershipsHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GetGroupMemberships` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_group_memberships_handler_sync(GetGroupMembershipsHandler handler) const noexcept;
  /// Registers the synchronous `GetGroupMemberships` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_group_memberships_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_group_memberships_handler_sync(GetGroupMembershipsHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GetGroupMemberships` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_group_memberships_handler_sync, set_get_group_memberships_handler_sync
  void set_get_group_memberships_handler_async(
    GetGroupMembershipsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GetGroupMemberships` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_group_memberships_handler_sync(
    GetGroupMembershipsAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GetGroupMemberships` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_group_memberships_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_group_memberships_handler_sync(GetGroupMembershipsAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `TwoStateVariable` handle for the `EnabledState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_enabled_state_sync, enabled_state_sync
  void enabled_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `EnabledState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_enabled_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `EnabledState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_enabled_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable enabled_state_sync() const;

  /// Attaches a typed `TwoStateVariable` handle for the `ActiveState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_active_state_sync, active_state_sync
  void active_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `ActiveState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_active_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `ActiveState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_active_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable active_state_sync() const;

  /// Attaches a typed `TwoStateVariable` handle for the `SuppressedState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_suppressed_state_sync, suppressed_state_sync
  void suppressed_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `SuppressedState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_suppressed_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `SuppressedState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_suppressed_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable suppressed_state_sync() const;

  /// Attaches a typed `TwoStateVariable` handle for the `OutOfServiceState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_out_of_service_state_sync, out_of_service_state_sync
  void out_of_service_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `OutOfServiceState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_out_of_service_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `OutOfServiceState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref
  /// try_out_of_service_state_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable out_of_service_state_sync() const;

  /// Attaches a typed `ShelvedStateMachine` handle for the `ShelvingState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_shelving_state_sync, shelving_state_sync
  void shelving_state_async(std::function<void(ShelvedStateMachineResult)> complete) const noexcept;
  /// Attaches a typed `ShelvedStateMachine` handle for the `ShelvingState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ShelvedStateMachineResult try_shelving_state_sync() const noexcept;
  /// Attaches a typed `ShelvedStateMachine` handle for the `ShelvingState` child, blocking until complete.
  /// @return The `ShelvedStateMachine` handle. A Good subcode is not returned; @ref try_shelving_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ShelvedStateMachine shelving_state_sync() const;

  /// Attaches a typed `AudioVariable` handle for the `AudibleSound` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_audible_sound_sync, audible_sound_sync
  void audible_sound_async(std::function<void(AudioVariableResult)> complete) const noexcept;
  /// Attaches a typed `AudioVariable` handle for the `AudibleSound` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AudioVariableResult try_audible_sound_sync() const noexcept;
  /// Attaches a typed `AudioVariable` handle for the `AudibleSound` child, blocking until complete.
  /// @return The `AudioVariable` handle. A Good subcode is not returned; @ref try_audible_sound_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AudioVariable audible_sound_sync() const;

  /// Attaches a typed `TwoStateVariable` handle for the `SilenceState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_silence_state_sync, silence_state_sync
  void silence_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `SilenceState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_silence_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `SilenceState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_silence_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable silence_state_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `FirstInGroupFlag` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_first_in_group_flag_sync, first_in_group_flag_sync
  void first_in_group_flag_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `FirstInGroupFlag` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_first_in_group_flag_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `FirstInGroupFlag` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_first_in_group_flag_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable first_in_group_flag_sync() const;

  /// Attaches a typed `AlarmGroup` handle for the `FirstInGroup` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_first_in_group_sync, first_in_group_sync
  void first_in_group_async(std::function<void(AlarmGroupResult)> complete) const noexcept;
  /// Attaches a typed `AlarmGroup` handle for the `FirstInGroup` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AlarmGroupResult try_first_in_group_sync() const noexcept;
  /// Attaches a typed `AlarmGroup` handle for the `FirstInGroup` child, blocking until complete.
  /// @return The `AlarmGroup` handle. A Good subcode is not returned; @ref try_first_in_group_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AlarmGroup first_in_group_sync() const;

  /// Attaches a typed `TwoStateVariable` handle for the `LatchedState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_latched_state_sync, latched_state_sync
  void latched_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `LatchedState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_latched_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `LatchedState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_latched_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable latched_state_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `ReAlarmRepeatCount` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_re_alarm_repeat_count_sync, re_alarm_repeat_count_sync
  void re_alarm_repeat_count_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ReAlarmRepeatCount` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_re_alarm_repeat_count_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ReAlarmRepeatCount` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_re_alarm_repeat_count_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable re_alarm_repeat_count_sync() const;

private:
  explicit AlarmCondition(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ALARM_CONDITION_H
