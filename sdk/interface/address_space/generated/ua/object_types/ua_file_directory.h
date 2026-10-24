// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_DIRECTORY_H
#define UA_FILE_DIRECTORY_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class FileDirectory;
using FileDirectoryResult = Result<FileDirectory>;

/// Address-space handle for the OPC UA FileDirectoryType ObjectType.
/// @ingroup ua_information_model
class FileDirectory : public BaseObject
{
public:
  /// Constructs an empty `FileDirectory` handle that references no node.
  FileDirectory() = default;

  /// Input arguments for the FileDirectoryType CreateDirectory() method.
  struct CreateDirectoryInputArguments
  {
    String directoryName;  ///< Directory name.
  };

  /// Output arguments for the FileDirectoryType CreateDirectory() method.
  struct CreateDirectoryOutputArguments
  {
    NodeId directoryNodeId;  ///< Directory node id.
  };

  /// Synchronous handler for CreateDirectory(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using CreateDirectoryHandler = std::function<MethodResult<CreateDirectoryOutputArguments>(
    const MethodCall&, const CreateDirectoryInputArguments&)>;
  /// Asynchronous handler for CreateDirectory(): starts the work and completes it through the callback, once,
  /// from any thread.
  using CreateDirectoryAsyncHandler = std::function<void(const MethodCall&,
    const CreateDirectoryInputArguments&, MethodResultCallback<CreateDirectoryOutputArguments>)>;

  /// Input arguments for the FileDirectoryType CreateFile() method.
  struct CreateFileInputArguments
  {
    String fileName;  ///< File name.
    bool requestFileOpen{};  ///< Request file open.
  };

  /// Output arguments for the FileDirectoryType CreateFile() method.
  struct CreateFileOutputArguments
  {
    NodeId fileNodeId;  ///< File node id.
    uint32_t fileHandle{};  ///< File handle.
  };

  /// Synchronous handler for CreateFile(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using CreateFileHandler = std::function<MethodResult<CreateFileOutputArguments>(
    const MethodCall&, const CreateFileInputArguments&)>;
  /// Asynchronous handler for CreateFile(): starts the work and completes it through the callback, once, from
  /// any thread.
  using CreateFileAsyncHandler = std::function<void(
    const MethodCall&, const CreateFileInputArguments&, MethodResultCallback<CreateFileOutputArguments>)>;

  /// Input arguments for the FileDirectoryType DeleteFileSystemObject() method.
  struct DeleteFileSystemObjectInputArguments
  {
    NodeId objectToDelete;  ///< Object to delete.
  };

  /// Synchronous handler for DeleteFileSystemObject(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using DeleteFileSystemObjectHandler =
    std::function<MethodResult<>(const MethodCall&, const DeleteFileSystemObjectInputArguments&)>;
  /// Asynchronous handler for DeleteFileSystemObject(): starts the work and completes it through the
  /// callback, once, from any thread.
  using DeleteFileSystemObjectAsyncHandler = std::function<void(
    const MethodCall&, const DeleteFileSystemObjectInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the FileDirectoryType MoveOrCopy() method.
  struct MoveOrCopyInputArguments
  {
    NodeId objectToMoveOrCopy;  ///< Object to move or copy.
    NodeId targetDirectory;  ///< Target directory.
    bool createCopy{};  ///< Create copy.
    String newName;  ///< New name.
  };

  /// Output arguments for the FileDirectoryType MoveOrCopy() method.
  struct MoveOrCopyOutputArguments
  {
    NodeId newNodeId;  ///< New node id.
  };

  /// Synchronous handler for MoveOrCopy(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using MoveOrCopyHandler = std::function<MethodResult<MoveOrCopyOutputArguments>(
    const MethodCall&, const MoveOrCopyInputArguments&)>;
  /// Asynchronous handler for MoveOrCopy(): starts the work and completes it through the callback, once, from
  /// any thread.
  using MoveOrCopyAsyncHandler = std::function<void(
    const MethodCall&, const MoveOrCopyInputArguments&, MethodResultCallback<MoveOrCopyOutputArguments>)>;

  /// Completion callback for create_async: receives the created `FileDirectory` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(FileDirectoryResult)>;
  /// Completion callback for attach_async: receives the attached `FileDirectory` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(FileDirectoryResult)>;

  /// Creates a new `FileDirectoryType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `FileDirectory` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `FileDirectoryType` instance under `parent`, blocking until complete.  ///
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
  static FileDirectoryResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `FileDirectoryType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `FileDirectory` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static FileDirectory create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `FileDirectoryType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `FileDirectory` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `FileDirectoryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static FileDirectoryResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `FileDirectoryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `FileDirectory` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static FileDirectory attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `CreateDirectory` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_directory_method_sync, create_directory_method_sync
  void create_directory_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `CreateDirectory` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_create_directory_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `CreateDirectory` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_create_directory_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor create_directory_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `CreateFile` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_file_method_sync, create_file_method_sync
  void create_file_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `CreateFile` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_create_file_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `CreateFile` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_create_file_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor create_file_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `DeleteFileSystemObject` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_delete_file_system_object_method_sync, delete_file_system_object_method_sync
  void delete_file_system_object_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `DeleteFileSystemObject` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_delete_file_system_object_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `DeleteFileSystemObject` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_delete_file_system_object_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor delete_file_system_object_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `MoveOrCopy` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_move_or_copy_method_sync, move_or_copy_method_sync
  void move_or_copy_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `MoveOrCopy` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_move_or_copy_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `MoveOrCopy` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_move_or_copy_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor move_or_copy_method_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `CreateDirectory` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_create_directory_handler_sync, set_create_directory_handler_sync
  void set_create_directory_handler_async(
    CreateDirectoryHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `CreateDirectory` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_create_directory_handler_sync(CreateDirectoryHandler handler) const noexcept;
  /// Registers the synchronous `CreateDirectory` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_create_directory_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_create_directory_handler_sync(CreateDirectoryHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `CreateDirectory` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_create_directory_handler_sync, set_create_directory_handler_sync
  void set_create_directory_handler_async(
    CreateDirectoryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `CreateDirectory` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_create_directory_handler_sync(CreateDirectoryAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `CreateDirectory` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_create_directory_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_create_directory_handler_sync(CreateDirectoryAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `CreateFile` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_create_file_handler_sync, set_create_file_handler_sync
  void set_create_file_handler_async(
    CreateFileHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `CreateFile` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_create_file_handler_sync(CreateFileHandler handler) const noexcept;
  /// Registers the synchronous `CreateFile` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_create_file_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_create_file_handler_sync(CreateFileHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `CreateFile` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_create_file_handler_sync, set_create_file_handler_sync
  void set_create_file_handler_async(
    CreateFileAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `CreateFile` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_create_file_handler_sync(CreateFileAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `CreateFile` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_create_file_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_create_file_handler_sync(CreateFileAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `DeleteFileSystemObject` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_file_system_object_handler_sync, set_delete_file_system_object_handler_sync
  void set_delete_file_system_object_handler_async(
    DeleteFileSystemObjectHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `DeleteFileSystemObject` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_file_system_object_handler_sync(
    DeleteFileSystemObjectHandler handler) const noexcept;
  /// Registers the synchronous `DeleteFileSystemObject` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_file_system_object_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_file_system_object_handler_sync(DeleteFileSystemObjectHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `DeleteFileSystemObject` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_file_system_object_handler_sync, set_delete_file_system_object_handler_sync
  void set_delete_file_system_object_handler_async(
    DeleteFileSystemObjectAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `DeleteFileSystemObject` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_file_system_object_handler_sync(
    DeleteFileSystemObjectAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `DeleteFileSystemObject` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_file_system_object_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_file_system_object_handler_sync(DeleteFileSystemObjectAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `MoveOrCopy` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_move_or_copy_handler_sync, set_move_or_copy_handler_sync
  void set_move_or_copy_handler_async(
    MoveOrCopyHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `MoveOrCopy` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_move_or_copy_handler_sync(MoveOrCopyHandler handler) const noexcept;
  /// Registers the synchronous `MoveOrCopy` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_move_or_copy_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_move_or_copy_handler_sync(MoveOrCopyHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `MoveOrCopy` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_move_or_copy_handler_sync, set_move_or_copy_handler_sync
  void set_move_or_copy_handler_async(
    MoveOrCopyAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `MoveOrCopy` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_move_or_copy_handler_sync(MoveOrCopyAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `MoveOrCopy` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_move_or_copy_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_move_or_copy_handler_sync(MoveOrCopyAsyncHandler handler) const;

private:
  explicit FileDirectory(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_FILE_DIRECTORY_H
