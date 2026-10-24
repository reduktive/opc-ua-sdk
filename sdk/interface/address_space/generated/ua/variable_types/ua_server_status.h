// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_STATUS_H
#define UA_SERVER_STATUS_H

#include "ua_base_data_variable.h"
#include "ua_base_data_variable.h"
#include "ua_build_info_variable.h"

namespace ua
{

class ServerStatus;
using ServerStatusResult = Result<ServerStatus>;

/// Address-space handle for the OPC UA ServerStatusType VariableType.
/// @ingroup ua_information_model
class ServerStatus final : public BaseDataVariable
{
public:
  /// Constructs an empty `ServerStatus` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  ServerStatus() = default;

  /// Completion callback for create_async: receives the new `ServerStatus` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ServerStatusResult)>;
  /// Completion callback for attach_async: receives the wrapped `ServerStatus` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ServerStatusResult)>;

  /// Creates a new `ServerStatusType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ServerStatus` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `ServerStatusType` variable under `parent`, blocking until complete.
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
  static ServerStatusResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `ServerStatusType` variable under `parent`, blocking until complete.
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
  /// @return The new `ServerStatus` handle. A Good subcode is not returned; @ref try_create_sync returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ServerStatus create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `ServerStatusType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `ServerStatus` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ServerStatusType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ServerStatusResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ServerStatusType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `ServerStatus` handle. A Good subcode is not returned; @ref try_attach_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ServerStatus attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

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

  /// Attaches a typed `BaseDataVariable` handle for the `CurrentTime` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_current_time_sync, current_time_sync
  void current_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CurrentTime` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_current_time_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CurrentTime` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_current_time_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable current_time_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `State` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_state_sync, state_sync
  void state_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `State` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_state_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `State` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_state_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable state_sync() const;

  /// Attaches a typed `BuildInfoVariable` handle for the `BuildInfo` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_build_info_sync, build_info_sync
  void build_info_async(std::function<void(BuildInfoVariableResult)> complete) const noexcept;
  /// Attaches a typed `BuildInfoVariable` handle for the `BuildInfo` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BuildInfoVariableResult try_build_info_sync() const noexcept;
  /// Attaches a typed `BuildInfoVariable` handle for the `BuildInfo` child, blocking until complete.
  /// @return The `BuildInfoVariable` handle. A Good subcode is not returned; @ref try_build_info_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BuildInfoVariable build_info_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `SecondsTillShutdown` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_seconds_till_shutdown_sync, seconds_till_shutdown_sync
  void seconds_till_shutdown_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SecondsTillShutdown` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_seconds_till_shutdown_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SecondsTillShutdown` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_seconds_till_shutdown_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable seconds_till_shutdown_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `ShutdownReason` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_shutdown_reason_sync, shutdown_reason_sync
  void shutdown_reason_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ShutdownReason` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_shutdown_reason_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ShutdownReason` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_shutdown_reason_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable shutdown_reason_sync() const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  ServerStatus(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

private:
  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;
};

}  // namespace ua

#endif  // UA_SERVER_STATUS_H
