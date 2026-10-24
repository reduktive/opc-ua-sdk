// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_temporary_file_transfer.h"

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

struct TemporaryFileTransferTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::TemporaryFileTransferType};
  }

  static QualifiedName client_processing_timeout_browse_name()
  {
    return QualifiedName{0, "ClientProcessingTimeout"};
  }

  static QualifiedName generate_file_for_read_browse_name()
  {
    return QualifiedName{0, "GenerateFileForRead"};
  }

  static QualifiedName generate_file_for_write_browse_name()
  {
    return QualifiedName{0, "GenerateFileForWrite"};
  }

  static QualifiedName close_and_commit_browse_name()
  {
    return QualifiedName{0, "CloseAndCommit"};
  }
};

}  // namespace

TemporaryFileTransfer::TemporaryFileTransfer(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TemporaryFileTransfer::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TemporaryFileTransferTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TemporaryFileTransferResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TemporaryFileTransferResult{
        TemporaryFileTransfer{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

TemporaryFileTransferResult TemporaryFileTransfer::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TemporaryFileTransferResult>(addressSpace.executor(),
      [&](std::function<void(TemporaryFileTransferResult)> complete)
      {
        TemporaryFileTransfer::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TemporaryFileTransfer TemporaryFileTransfer::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void TemporaryFileTransfer::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void TemporaryFileTransfer::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TemporaryFileTransferType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    TemporaryFileTransferTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TemporaryFileTransferResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TemporaryFileTransferResult{::ua::detail::address_space_gone("TemporaryFileTransfer")});
        return;
      }
      complete(
        TemporaryFileTransfer{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TemporaryFileTransferResult TemporaryFileTransfer::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TemporaryFileTransferResult>(addressSpace.executor(),
      [&](std::function<void(TemporaryFileTransferResult)> complete)
      {
        TemporaryFileTransfer::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TemporaryFileTransfer TemporaryFileTransfer::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TemporaryFileTransfer::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void TemporaryFileTransfer::generate_file_for_read_method_async(
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
    TemporaryFileTransferTypeTraits::generate_file_for_read_browse_name(),
    std::move(complete));
}

MethodAccessorResult TemporaryFileTransfer::try_generate_file_for_read_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { generate_file_for_read_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TemporaryFileTransfer::generate_file_for_read_method_sync() const
{
  return ::ua::detail::good_value(try_generate_file_for_read_method_sync());
}

void TemporaryFileTransfer::generate_file_for_write_method_async(
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
    TemporaryFileTransferTypeTraits::generate_file_for_write_browse_name(),
    std::move(complete));
}

MethodAccessorResult TemporaryFileTransfer::try_generate_file_for_write_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { generate_file_for_write_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TemporaryFileTransfer::generate_file_for_write_method_sync() const
{
  return ::ua::detail::good_value(try_generate_file_for_write_method_sync());
}

void TemporaryFileTransfer::close_and_commit_method_async(
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
    TemporaryFileTransferTypeTraits::close_and_commit_browse_name(),
    std::move(complete));
}

MethodAccessorResult TemporaryFileTransfer::try_close_and_commit_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { close_and_commit_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TemporaryFileTransfer::close_and_commit_method_sync() const
{
  return ::ua::detail::good_value(try_close_and_commit_method_sync());
}

// --- Common property helper ---

void TemporaryFileTransfer::find_property_async(
  QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Property>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    "TemporaryFileTransfer",
    std::move(complete));
}

// --- Property accessors ---

void TemporaryFileTransfer::client_processing_timeout_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    TemporaryFileTransferTypeTraits::client_processing_timeout_browse_name(), std::move(complete));
}

PropertyResult TemporaryFileTransfer::try_client_processing_timeout_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { client_processing_timeout_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TemporaryFileTransfer::client_processing_timeout_property_sync() const
{
  return ::ua::detail::good_value(try_client_processing_timeout_property_sync());
}

// --- Method handler registration ---

void TemporaryFileTransfer::set_generate_file_for_read_handler_async(
  GenerateFileForReadHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_generate_file_for_read_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<NodeId, uint32_t, NodeId>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const Variant& in0) -> MethodResult<NodeId, uint32_t, NodeId>
      {
        GenerateFileForReadInputArguments typedIn{.generateOptions = in0};
        return detail::method_result_from_struct<NodeId, uint32_t, NodeId>(handler(call, typedIn),
          [](const GenerateFileForReadOutputArguments& out) {
            return std::tuple<NodeId, uint32_t, NodeId>{
              out.fileNodeId, out.fileHandle, out.completionStateMachine};
          });
      },
      Inputs<Variant>{{Arg<Variant>{.name = "GenerateOptions"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::generate_file_for_read_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_generate_file_for_read_handler_sync(
  GenerateFileForReadHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_generate_file_for_read_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_generate_file_for_read_handler_sync(GenerateFileForReadHandler handler) const
{
  try_set_generate_file_for_read_handler_sync(std::move(handler)).value();
}

void TemporaryFileTransfer::set_generate_file_for_read_handler_async(
  GenerateFileForReadAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_generate_file_for_read_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<NodeId, uint32_t, NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<NodeId, uint32_t, NodeId> complete)
      {
        GenerateFileForReadInputArguments typedIn{.generateOptions = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<GenerateFileForReadOutputArguments>(
            std::move(complete),
            [](const GenerateFileForReadOutputArguments& out) {
              return std::tuple<NodeId, uint32_t, NodeId>{
                out.fileNodeId, out.fileHandle, out.completionStateMachine};
            },
            logger,
            call.method_id()));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "GenerateOptions"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::generate_file_for_read_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_generate_file_for_read_handler_sync(
  GenerateFileForReadAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_generate_file_for_read_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_generate_file_for_read_handler_sync(
  GenerateFileForReadAsyncHandler handler) const
{
  try_set_generate_file_for_read_handler_sync(std::move(handler)).value();
}

void TemporaryFileTransfer::set_generate_file_for_write_handler_async(
  GenerateFileForWriteHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_generate_file_for_write_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<NodeId, uint32_t>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const Variant& in0) -> MethodResult<NodeId, uint32_t>
      {
        GenerateFileForWriteInputArguments typedIn{.generateOptions = in0};
        return detail::method_result_from_struct<NodeId, uint32_t>(handler(call, typedIn),
          [](const GenerateFileForWriteOutputArguments& out)
          { return std::tuple<NodeId, uint32_t>{out.fileNodeId, out.fileHandle}; });
      },
      Inputs<Variant>{{Arg<Variant>{.name = "GenerateOptions"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::generate_file_for_write_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_generate_file_for_write_handler_sync(
  GenerateFileForWriteHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_generate_file_for_write_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_generate_file_for_write_handler_sync(
  GenerateFileForWriteHandler handler) const
{
  try_set_generate_file_for_write_handler_sync(std::move(handler)).value();
}

void TemporaryFileTransfer::set_generate_file_for_write_handler_async(
  GenerateFileForWriteAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_generate_file_for_write_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<NodeId, uint32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<NodeId, uint32_t> complete)
      {
        GenerateFileForWriteInputArguments typedIn{.generateOptions = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<GenerateFileForWriteOutputArguments>(
            std::move(complete),
            [](const GenerateFileForWriteOutputArguments& out)
            { return std::tuple<NodeId, uint32_t>{out.fileNodeId, out.fileHandle}; },
            logger,
            call.method_id()));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "GenerateOptions"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::generate_file_for_write_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_generate_file_for_write_handler_sync(
  GenerateFileForWriteAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_generate_file_for_write_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_generate_file_for_write_handler_sync(
  GenerateFileForWriteAsyncHandler handler) const
{
  try_set_generate_file_for_write_handler_sync(std::move(handler)).value();
}

void TemporaryFileTransfer::set_close_and_commit_handler_async(
  CloseAndCommitHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_close_and_commit_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<NodeId>
      {
        CloseAndCommitInputArguments typedIn{.fileHandle = in0};
        return detail::method_result_from_struct<NodeId>(handler(call, typedIn),
          [](const CloseAndCommitOutputArguments& out)
          { return std::tuple<NodeId>{out.completionStateMachine}; });
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::close_and_commit_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_close_and_commit_handler_sync(
  CloseAndCommitHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_and_commit_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_close_and_commit_handler_sync(CloseAndCommitHandler handler) const
{
  try_set_close_and_commit_handler_sync(std::move(handler)).value();
}

void TemporaryFileTransfer::set_close_and_commit_handler_async(
  CloseAndCommitAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TemporaryFileTransfer",
        "TemporaryFileTransfer::set_close_and_commit_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<NodeId> complete)
      {
        CloseAndCommitInputArguments typedIn{.fileHandle = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<CloseAndCommitOutputArguments>(
            std::move(complete),
            [](const CloseAndCommitOutputArguments& out)
            { return std::tuple<NodeId>{out.completionStateMachine}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TemporaryFileTransferTypeTraits::close_and_commit_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TemporaryFileTransfer::try_set_close_and_commit_handler_sync(
  CloseAndCommitAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_and_commit_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TemporaryFileTransfer::set_close_and_commit_handler_sync(CloseAndCommitAsyncHandler handler) const
{
  try_set_close_and_commit_handler_sync(std::move(handler)).value();
}

}  // namespace ua
