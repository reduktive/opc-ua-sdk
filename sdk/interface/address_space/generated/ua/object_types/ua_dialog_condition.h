// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIALOG_CONDITION_H
#define UA_DIALOG_CONDITION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_two_state_variable.h"

namespace ua
{

struct MethodCallContext;

class DialogCondition;
using DialogConditionResult = Result<DialogCondition>;

/// Address-space handle for the OPC UA DialogConditionType ObjectType.
/// @ingroup ua_information_model
class DialogCondition : public BaseObject
{
public:
  /// Constructs an empty `DialogCondition` handle that references no node.
  DialogCondition() = default;

  /// Input arguments for the DialogConditionType Respond() method.
  struct RespondInputArguments
  {
    int32_t selectedResponse{};  ///< Selected response.
  };

  /// Synchronous handler for Respond(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using RespondHandler = std::function<MethodResult<>(const MethodCall&, const RespondInputArguments&)>;
  /// Asynchronous handler for Respond(): starts the work and completes it through the callback, once, from
  /// any thread.
  using RespondAsyncHandler =
    std::function<void(const MethodCall&, const RespondInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the DialogConditionType Respond2() method.
  struct Respond2InputArguments
  {
    int32_t selectedResponse{};  ///< Selected response.
    LocalizedText comment;  ///< Comment.
  };

  /// Synchronous handler for Respond2(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using Respond2Handler = std::function<MethodResult<>(const MethodCall&, const Respond2InputArguments&)>;
  /// Asynchronous handler for Respond2(): starts the work and completes it through the callback, once, from
  /// any thread.
  using Respond2AsyncHandler =
    std::function<void(const MethodCall&, const Respond2InputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `DialogCondition` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(DialogConditionResult)>;
  /// Completion callback for attach_async: receives the attached `DialogCondition` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(DialogConditionResult)>;

  /// Creates a new `DialogConditionType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `DialogCondition` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `DialogConditionType` instance under `parent`, blocking until complete.  ///
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
  static DialogConditionResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `DialogConditionType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `DialogCondition` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static DialogCondition create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `DialogConditionType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `DialogCondition` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `DialogConditionType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static DialogConditionResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `DialogConditionType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `DialogCondition` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static DialogCondition attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Respond` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_respond_method_sync, respond_method_sync
  void respond_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Respond` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_respond_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Respond` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_respond_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor respond_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Respond2` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_respond2_method_sync, respond2_method_sync
  void respond2_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Respond2` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_respond2_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Respond2` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_respond2_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor respond2_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Prompt` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_prompt_property_sync, prompt_property_sync
  void prompt_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Prompt` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_prompt_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Prompt` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_prompt_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property prompt_property_sync() const;

  /// Attaches a `Property` handle for the `ResponseOptionSet` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_response_option_set_property_sync, response_option_set_property_sync
  void response_option_set_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ResponseOptionSet` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_response_option_set_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ResponseOptionSet` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_response_option_set_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property response_option_set_property_sync() const;

  /// Attaches a `Property` handle for the `DefaultResponse` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_response_property_sync, default_response_property_sync
  void default_response_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DefaultResponse` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_default_response_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DefaultResponse` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_default_response_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property default_response_property_sync() const;

  /// Attaches a `Property` handle for the `OkResponse` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ok_response_property_sync, ok_response_property_sync
  void ok_response_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `OkResponse` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_ok_response_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `OkResponse` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_ok_response_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property ok_response_property_sync() const;

  /// Attaches a `Property` handle for the `CancelResponse` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_cancel_response_property_sync, cancel_response_property_sync
  void cancel_response_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CancelResponse` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_cancel_response_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CancelResponse` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_cancel_response_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property cancel_response_property_sync() const;

  /// Attaches a `Property` handle for the `LastResponse` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_response_property_sync, last_response_property_sync
  void last_response_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastResponse` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_response_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastResponse` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_last_response_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_response_property_sync() const;

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

  /// Reads the `Prompt` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_prompt_sync, read_prompt_sync
  void read_prompt_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `Prompt` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_prompt_async gives it. Never throws.
  LocalizedTextResult try_read_prompt_sync() const noexcept;
  /// Reads the `Prompt` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_prompt_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_prompt_sync() const;

  /// Reads the `ResponseOptionSet` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_response_option_set_sync, read_response_option_set_sync
  void read_response_option_set_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `ResponseOptionSet` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_response_option_set_async gives it. Never throws.
  LocalizedTextResult try_read_response_option_set_sync() const noexcept;
  /// Reads the `ResponseOptionSet` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_response_option_set_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_response_option_set_sync() const;

  /// Reads the `DefaultResponse` property value, typed as `int32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_default_response_sync, read_default_response_sync
  void read_default_response_async(std::function<void(Int32Result)> complete) const noexcept;
  /// Reads the `DefaultResponse` property value as `int32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_default_response_async gives it. Never throws.
  Int32Result try_read_default_response_sync() const noexcept;
  /// Reads the `DefaultResponse` property value as `int32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_default_response_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  int32_t read_default_response_sync() const;

  /// Reads the `OkResponse` property value, typed as `int32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_ok_response_sync, read_ok_response_sync
  void read_ok_response_async(std::function<void(Int32Result)> complete) const noexcept;
  /// Reads the `OkResponse` property value as `int32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_ok_response_async gives it. Never throws.
  Int32Result try_read_ok_response_sync() const noexcept;
  /// Reads the `OkResponse` property value as `int32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_ok_response_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  int32_t read_ok_response_sync() const;

  /// Reads the `CancelResponse` property value, typed as `int32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_cancel_response_sync, read_cancel_response_sync
  void read_cancel_response_async(std::function<void(Int32Result)> complete) const noexcept;
  /// Reads the `CancelResponse` property value as `int32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_cancel_response_async gives it. Never throws.
  Int32Result try_read_cancel_response_sync() const noexcept;
  /// Reads the `CancelResponse` property value as `int32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_cancel_response_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  int32_t read_cancel_response_sync() const;

  /// Reads the `LastResponse` property value, typed as `int32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_last_response_sync, read_last_response_sync
  void read_last_response_async(std::function<void(Int32Result)> complete) const noexcept;
  /// Reads the `LastResponse` property value as `int32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_last_response_async gives it. Never throws.
  Int32Result try_read_last_response_sync() const noexcept;
  /// Reads the `LastResponse` property value as `int32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_last_response_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  int32_t read_last_response_sync() const;

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

  /// Writes the `Prompt` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_prompt_sync, write_prompt_sync
  void write_prompt_async(LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Prompt` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_prompt_sync(LocalizedText value) const noexcept;
  /// Writes the `Prompt` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_prompt_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_prompt_sync(LocalizedText value) const;

  /// Writes the `ResponseOptionSet` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_response_option_set_sync, write_response_option_set_sync
  void write_response_option_set_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ResponseOptionSet` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_response_option_set_sync(LocalizedText value) const noexcept;
  /// Writes the `ResponseOptionSet` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_response_option_set_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_response_option_set_sync(LocalizedText value) const;

  /// Writes the `DefaultResponse` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_default_response_sync, write_default_response_sync
  void write_default_response_async(int32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `DefaultResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_default_response_sync(int32_t value) const noexcept;
  /// Writes the `DefaultResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_default_response_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_default_response_sync(int32_t value) const;

  /// Writes the `OkResponse` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_ok_response_sync, write_ok_response_sync
  void write_ok_response_async(int32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `OkResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_ok_response_sync(int32_t value) const noexcept;
  /// Writes the `OkResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_ok_response_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_ok_response_sync(int32_t value) const;

  /// Writes the `CancelResponse` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_cancel_response_sync, write_cancel_response_sync
  void write_cancel_response_async(int32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CancelResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_cancel_response_sync(int32_t value) const noexcept;
  /// Writes the `CancelResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_cancel_response_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_cancel_response_sync(int32_t value) const;

  /// Writes the `LastResponse` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_last_response_sync, write_last_response_sync
  void write_last_response_async(int32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LastResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_last_response_sync(int32_t value) const noexcept;
  /// Writes the `LastResponse` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_last_response_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_last_response_sync(int32_t value) const;

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

  /// Registers the synchronous handler invoked when a client calls the `Respond` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_respond_handler_sync, set_respond_handler_sync
  void set_respond_handler_async(RespondHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Respond` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_respond_handler_sync(RespondHandler handler) const noexcept;
  /// Registers the synchronous `Respond` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_respond_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_respond_handler_sync(RespondHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Respond` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_respond_handler_sync, set_respond_handler_sync
  void set_respond_handler_async(
    RespondAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Respond` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_respond_handler_sync(RespondAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Respond` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_respond_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_respond_handler_sync(RespondAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `Respond2` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_respond2_handler_sync, set_respond2_handler_sync
  void set_respond2_handler_async(
    Respond2Handler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Respond2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_respond2_handler_sync(Respond2Handler handler) const noexcept;
  /// Registers the synchronous `Respond2` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_respond2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_respond2_handler_sync(Respond2Handler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Respond2` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_respond2_handler_sync, set_respond2_handler_sync
  void set_respond2_handler_async(
    Respond2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Respond2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_respond2_handler_sync(Respond2AsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Respond2` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_respond2_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_respond2_handler_sync(Respond2AsyncHandler handler) const;

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

  /// Attaches a typed `TwoStateVariable` handle for the `DialogState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_dialog_state_sync, dialog_state_sync
  void dialog_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `DialogState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TwoStateVariableResult try_dialog_state_sync() const noexcept;
  /// Attaches a typed `TwoStateVariable` handle for the `DialogState` child, blocking until complete.
  /// @return The `TwoStateVariable` handle. A Good subcode is not returned; @ref try_dialog_state_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TwoStateVariable dialog_state_sync() const;

private:
  explicit DialogCondition(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_DIALOG_CONDITION_H
