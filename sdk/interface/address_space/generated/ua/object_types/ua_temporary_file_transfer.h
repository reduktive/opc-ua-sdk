// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEMPORARY_FILE_TRANSFER_H
#define UA_TEMPORARY_FILE_TRANSFER_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class TemporaryFileTransfer;
using TemporaryFileTransferResult = Result<TemporaryFileTransfer>;

/// Address-space handle for the OPC UA TemporaryFileTransferType ObjectType.
/// @ingroup ua_information_model
class TemporaryFileTransfer : public BaseObject
{
public:
  /// Constructs an empty `TemporaryFileTransfer` handle that references no node.
  TemporaryFileTransfer() = default;

  /// Input arguments for the TemporaryFileTransferType GenerateFileForRead() method.
  struct GenerateFileForReadInputArguments
  {
    Variant generateOptions;  ///< Generate options.
  };

  /// Output arguments for the TemporaryFileTransferType GenerateFileForRead() method.
  struct GenerateFileForReadOutputArguments
  {
    NodeId fileNodeId;  ///< File node id.
    uint32_t fileHandle{};  ///< File handle.
    NodeId completionStateMachine;  ///< Completion state machine.
  };

  /// Synchronous handler for GenerateFileForRead(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using GenerateFileForReadHandler = std::function<MethodResult<GenerateFileForReadOutputArguments>(
    const MethodCall&, const GenerateFileForReadInputArguments&)>;
  /// Asynchronous handler for GenerateFileForRead(): starts the work and completes it through the callback,
  /// once, from any thread.
  using GenerateFileForReadAsyncHandler = std::function<void(const MethodCall&,
    const GenerateFileForReadInputArguments&, MethodResultCallback<GenerateFileForReadOutputArguments>)>;

  /// Input arguments for the TemporaryFileTransferType GenerateFileForWrite() method.
  struct GenerateFileForWriteInputArguments
  {
    Variant generateOptions;  ///< Generate options.
  };

  /// Output arguments for the TemporaryFileTransferType GenerateFileForWrite() method.
  struct GenerateFileForWriteOutputArguments
  {
    NodeId fileNodeId;  ///< File node id.
    uint32_t fileHandle{};  ///< File handle.
  };

  /// Synchronous handler for GenerateFileForWrite(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using GenerateFileForWriteHandler = std::function<MethodResult<GenerateFileForWriteOutputArguments>(
    const MethodCall&, const GenerateFileForWriteInputArguments&)>;
  /// Asynchronous handler for GenerateFileForWrite(): starts the work and completes it through the callback,
  /// once, from any thread.
  using GenerateFileForWriteAsyncHandler = std::function<void(const MethodCall&,
    const GenerateFileForWriteInputArguments&, MethodResultCallback<GenerateFileForWriteOutputArguments>)>;

  /// Input arguments for the TemporaryFileTransferType CloseAndCommit() method.
  struct CloseAndCommitInputArguments
  {
    uint32_t fileHandle{};  ///< File handle.
  };

  /// Output arguments for the TemporaryFileTransferType CloseAndCommit() method.
  struct CloseAndCommitOutputArguments
  {
    NodeId completionStateMachine;  ///< Completion state machine.
  };

  /// Synchronous handler for CloseAndCommit(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using CloseAndCommitHandler = std::function<MethodResult<CloseAndCommitOutputArguments>(
    const MethodCall&, const CloseAndCommitInputArguments&)>;
  /// Asynchronous handler for CloseAndCommit(): starts the work and completes it through the callback, once,
  /// from any thread.
  using CloseAndCommitAsyncHandler = std::function<void(const MethodCall&,
    const CloseAndCommitInputArguments&, MethodResultCallback<CloseAndCommitOutputArguments>)>;

  /// Completion callback for create_async: receives the created `TemporaryFileTransfer` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(TemporaryFileTransferResult)>;
  /// Completion callback for attach_async: receives the attached `TemporaryFileTransfer` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(TemporaryFileTransferResult)>;

  /// Creates a new `TemporaryFileTransferType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `TemporaryFileTransfer` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `TemporaryFileTransferType` instance under `parent`, blocking until complete.  ///
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
  static TemporaryFileTransferResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `TemporaryFileTransferType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `TemporaryFileTransfer` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static TemporaryFileTransfer create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `TemporaryFileTransferType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `TemporaryFileTransfer` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `TemporaryFileTransferType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static TemporaryFileTransferResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `TemporaryFileTransferType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `TemporaryFileTransfer` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static TemporaryFileTransfer attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GenerateFileForRead` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_generate_file_for_read_method_sync, generate_file_for_read_method_sync
  void generate_file_for_read_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GenerateFileForRead` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_generate_file_for_read_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GenerateFileForRead` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_generate_file_for_read_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor generate_file_for_read_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GenerateFileForWrite` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_generate_file_for_write_method_sync, generate_file_for_write_method_sync
  void generate_file_for_write_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GenerateFileForWrite` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_generate_file_for_write_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GenerateFileForWrite` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_generate_file_for_write_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor generate_file_for_write_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `CloseAndCommit` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_close_and_commit_method_sync, close_and_commit_method_sync
  void close_and_commit_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `CloseAndCommit` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_close_and_commit_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `CloseAndCommit` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_close_and_commit_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor close_and_commit_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `ClientProcessingTimeout` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_client_processing_timeout_property_sync, client_processing_timeout_property_sync
  void client_processing_timeout_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ClientProcessingTimeout` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_client_processing_timeout_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ClientProcessingTimeout` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_client_processing_timeout_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property client_processing_timeout_property_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `GenerateFileForRead` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_generate_file_for_read_handler_sync, set_generate_file_for_read_handler_sync
  void set_generate_file_for_read_handler_async(
    GenerateFileForReadHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GenerateFileForRead` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_generate_file_for_read_handler_sync(GenerateFileForReadHandler handler) const noexcept;
  /// Registers the synchronous `GenerateFileForRead` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_generate_file_for_read_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_generate_file_for_read_handler_sync(GenerateFileForReadHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GenerateFileForRead` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_generate_file_for_read_handler_sync, set_generate_file_for_read_handler_sync
  void set_generate_file_for_read_handler_async(
    GenerateFileForReadAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GenerateFileForRead` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_generate_file_for_read_handler_sync(
    GenerateFileForReadAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GenerateFileForRead` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_generate_file_for_read_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_generate_file_for_read_handler_sync(GenerateFileForReadAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `GenerateFileForWrite` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_generate_file_for_write_handler_sync, set_generate_file_for_write_handler_sync
  void set_generate_file_for_write_handler_async(
    GenerateFileForWriteHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GenerateFileForWrite` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_generate_file_for_write_handler_sync(GenerateFileForWriteHandler handler) const noexcept;
  /// Registers the synchronous `GenerateFileForWrite` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_generate_file_for_write_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_generate_file_for_write_handler_sync(GenerateFileForWriteHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GenerateFileForWrite` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_generate_file_for_write_handler_sync, set_generate_file_for_write_handler_sync
  void set_generate_file_for_write_handler_async(
    GenerateFileForWriteAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GenerateFileForWrite` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_generate_file_for_write_handler_sync(
    GenerateFileForWriteAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GenerateFileForWrite` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_generate_file_for_write_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_generate_file_for_write_handler_sync(GenerateFileForWriteAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `CloseAndCommit` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_close_and_commit_handler_sync, set_close_and_commit_handler_sync
  void set_close_and_commit_handler_async(
    CloseAndCommitHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `CloseAndCommit` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_close_and_commit_handler_sync(CloseAndCommitHandler handler) const noexcept;
  /// Registers the synchronous `CloseAndCommit` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_close_and_commit_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_close_and_commit_handler_sync(CloseAndCommitHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `CloseAndCommit` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_close_and_commit_handler_sync, set_close_and_commit_handler_sync
  void set_close_and_commit_handler_async(
    CloseAndCommitAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `CloseAndCommit` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_close_and_commit_handler_sync(CloseAndCommitAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `CloseAndCommit` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_close_and_commit_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_close_and_commit_handler_sync(CloseAndCommitAsyncHandler handler) const;

private:
  explicit TemporaryFileTransfer(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_TEMPORARY_FILE_TRANSFER_H
