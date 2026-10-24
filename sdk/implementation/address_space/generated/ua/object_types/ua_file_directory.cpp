// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_directory.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct FileDirectoryTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::FileDirectoryType};
  }

  static QualifiedName create_directory_browse_name()
  {
    return QualifiedName{0, "CreateDirectory"};
  }

  static QualifiedName create_file_browse_name()
  {
    return QualifiedName{0, "CreateFile"};
  }

  static QualifiedName delete_file_system_object_browse_name()
  {
    return QualifiedName{0, "Delete"};
  }

  static QualifiedName move_or_copy_browse_name()
  {
    return QualifiedName{0, "MoveOrCopy"};
  }
};

}  // namespace

FileDirectory::FileDirectory(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void FileDirectory::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    FileDirectoryTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(FileDirectoryResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(FileDirectoryResult{
        FileDirectory{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

FileDirectoryResult FileDirectory::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileDirectoryResult>(addressSpace.executor(),
      [&](std::function<void(FileDirectoryResult)> complete)
      {
        FileDirectory::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FileDirectory FileDirectory::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void FileDirectory::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void FileDirectory::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // FileDirectoryType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    FileDirectoryTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(FileDirectoryResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(FileDirectoryResult{::ua::detail::address_space_gone("FileDirectory")});
        return;
      }
      complete(FileDirectory{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

FileDirectoryResult FileDirectory::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileDirectoryResult>(addressSpace.executor(),
      [&](std::function<void(FileDirectoryResult)> complete)
      {
        FileDirectory::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FileDirectory FileDirectory::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void FileDirectory::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void FileDirectory::create_directory_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileDirectoryTypeTraits::create_directory_browse_name(),
    std::move(complete));
}

MethodAccessorResult FileDirectory::try_create_directory_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { create_directory_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor FileDirectory::create_directory_method_sync() const
{
  return ::ua::detail::good_value(try_create_directory_method_sync());
}

void FileDirectory::create_file_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileDirectoryTypeTraits::create_file_browse_name(),
    std::move(complete));
}

MethodAccessorResult FileDirectory::try_create_file_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { create_file_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor FileDirectory::create_file_method_sync() const
{
  return ::ua::detail::good_value(try_create_file_method_sync());
}

void FileDirectory::delete_file_system_object_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileDirectoryTypeTraits::delete_file_system_object_browse_name(),
    std::move(complete));
}

MethodAccessorResult FileDirectory::try_delete_file_system_object_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { delete_file_system_object_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor FileDirectory::delete_file_system_object_method_sync() const
{
  return ::ua::detail::good_value(try_delete_file_system_object_method_sync());
}

void FileDirectory::move_or_copy_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileDirectoryTypeTraits::move_or_copy_browse_name(),
    std::move(complete));
}

MethodAccessorResult FileDirectory::try_move_or_copy_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { move_or_copy_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor FileDirectory::move_or_copy_method_sync() const
{
  return ::ua::detail::good_value(try_move_or_copy_method_sync());
}

// --- Method handler registration ---

void FileDirectory::set_create_directory_handler_async(
  CreateDirectoryHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_create_directory_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const String& in0) -> MethodResult<NodeId>
      {
        CreateDirectoryInputArguments typedIn{.directoryName = in0};
        return detail::method_result_from_struct<NodeId>(handler(call, typedIn),
          [](const CreateDirectoryOutputArguments& out) { return std::tuple<NodeId>{out.directoryNodeId}; });
      },
      Inputs<String>{{Arg<String>{.name = "DirectoryName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileDirectoryTypeTraits::create_directory_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_create_directory_handler_sync(CreateDirectoryHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_directory_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_create_directory_handler_sync(CreateDirectoryHandler handler) const
{
  try_set_create_directory_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_create_directory_handler_async(
  CreateDirectoryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_create_directory_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, MethodResultCallback<NodeId> complete)
      {
        CreateDirectoryInputArguments typedIn{.directoryName = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<CreateDirectoryOutputArguments>(
            std::move(complete),
            [](const CreateDirectoryOutputArguments& out) { return std::tuple<NodeId>{out.directoryNodeId}; },
            logger,
            call.method_id()));
      },
      Inputs<String>{{Arg<String>{.name = "DirectoryName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileDirectoryTypeTraits::create_directory_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_create_directory_handler_sync(
  CreateDirectoryAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_directory_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_create_directory_handler_sync(CreateDirectoryAsyncHandler handler) const
{
  try_set_create_directory_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_create_file_handler_async(
  CreateFileHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_create_file_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool>, std::tuple<NodeId, uint32_t>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const bool& in1) -> MethodResult<NodeId, uint32_t>
      {
        CreateFileInputArguments typedIn{.fileName = in0, .requestFileOpen = in1};
        return detail::method_result_from_struct<NodeId, uint32_t>(handler(call, typedIn),
          [](const CreateFileOutputArguments& out)
          { return std::tuple<NodeId, uint32_t>{out.fileNodeId, out.fileHandle}; });
      },
      Inputs<String, bool>{{Arg<String>{.name = "FileName"}, Arg<bool>{.name = "RequestFileOpen"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileDirectoryTypeTraits::create_file_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_create_file_handler_sync(CreateFileHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_file_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_create_file_handler_sync(CreateFileHandler handler) const
{
  try_set_create_file_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_create_file_handler_async(
  CreateFileAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_create_file_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool>, std::tuple<NodeId, uint32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const bool& in1,
        MethodResultCallback<NodeId, uint32_t>
          complete)
      {
        CreateFileInputArguments typedIn{.fileName = in0, .requestFileOpen = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<CreateFileOutputArguments>(
            std::move(complete),
            [](const CreateFileOutputArguments& out)
            { return std::tuple<NodeId, uint32_t>{out.fileNodeId, out.fileHandle}; },
            logger,
            call.method_id()));
      },
      Inputs<String, bool>{{Arg<String>{.name = "FileName"}, Arg<bool>{.name = "RequestFileOpen"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileDirectoryTypeTraits::create_file_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_create_file_handler_sync(CreateFileAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_file_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_create_file_handler_sync(CreateFileAsyncHandler handler) const
{
  try_set_create_file_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_delete_file_system_object_handler_async(
  DeleteFileSystemObjectHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_delete_file_system_object_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const NodeId& in0) -> MethodResult<>
      {
        DeleteFileSystemObjectInputArguments typedIn{.objectToDelete = in0};
        return handler(call, typedIn);
      },
      Inputs<NodeId>{{Arg<NodeId>{.name = "ObjectToDelete"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileDirectoryTypeTraits::delete_file_system_object_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_delete_file_system_object_handler_sync(
  DeleteFileSystemObjectHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_file_system_object_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_delete_file_system_object_handler_sync(DeleteFileSystemObjectHandler handler) const
{
  try_set_delete_file_system_object_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_delete_file_system_object_handler_async(
  DeleteFileSystemObjectAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_delete_file_system_object_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const NodeId& in0, MethodResultCallback<> complete)
      {
        DeleteFileSystemObjectInputArguments typedIn{.objectToDelete = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<NodeId>{{Arg<NodeId>{.name = "ObjectToDelete"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileDirectoryTypeTraits::delete_file_system_object_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_delete_file_system_object_handler_sync(
  DeleteFileSystemObjectAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_file_system_object_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_delete_file_system_object_handler_sync(
  DeleteFileSystemObjectAsyncHandler handler) const
{
  try_set_delete_file_system_object_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_move_or_copy_handler_async(
  MoveOrCopyHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_move_or_copy_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId, NodeId, bool, String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const NodeId& in0, const NodeId& in1, const bool& in2, const String& in3)
        -> MethodResult<NodeId>
      {
        MoveOrCopyInputArguments typedIn{
          .objectToMoveOrCopy = in0, .targetDirectory = in1, .createCopy = in2, .newName = in3};
        return detail::method_result_from_struct<NodeId>(handler(call, typedIn),
          [](const MoveOrCopyOutputArguments& out) { return std::tuple<NodeId>{out.newNodeId}; });
      },
      Inputs<NodeId, NodeId, bool, String>{{Arg<NodeId>{.name = "ObjectToMoveOrCopy"},
        Arg<NodeId>{.name = "TargetDirectory"},
        Arg<bool>{.name = "CreateCopy"},
        Arg<String>{.name = "NewName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileDirectoryTypeTraits::move_or_copy_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_move_or_copy_handler_sync(MoveOrCopyHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_move_or_copy_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_move_or_copy_handler_sync(MoveOrCopyHandler handler) const
{
  try_set_move_or_copy_handler_sync(std::move(handler)).value();
}

void FileDirectory::set_move_or_copy_handler_async(
  MoveOrCopyAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileDirectory",
        "FileDirectory::set_move_or_copy_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId, NodeId, bool, String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const NodeId& in0,
        const NodeId& in1,
        const bool& in2,
        const String& in3,
        MethodResultCallback<NodeId>
          complete)
      {
        MoveOrCopyInputArguments typedIn{
          .objectToMoveOrCopy = in0, .targetDirectory = in1, .createCopy = in2, .newName = in3};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<MoveOrCopyOutputArguments>(
            std::move(complete),
            [](const MoveOrCopyOutputArguments& out) { return std::tuple<NodeId>{out.newNodeId}; },
            logger,
            call.method_id()));
      },
      Inputs<NodeId, NodeId, bool, String>{{Arg<NodeId>{.name = "ObjectToMoveOrCopy"},
        Arg<NodeId>{.name = "TargetDirectory"},
        Arg<bool>{.name = "CreateCopy"},
        Arg<String>{.name = "NewName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileDirectoryTypeTraits::move_or_copy_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileDirectory::try_set_move_or_copy_handler_sync(MoveOrCopyAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_move_or_copy_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileDirectory::set_move_or_copy_handler_sync(MoveOrCopyAsyncHandler handler) const
{
  try_set_move_or_copy_handler_sync(std::move(handler)).value();
}

}  // namespace ua
