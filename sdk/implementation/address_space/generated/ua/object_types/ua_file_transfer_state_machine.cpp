// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_transfer_state_machine.h"

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

struct FileTransferStateMachineTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::FileTransferStateMachineType};
  }

  static QualifiedName idle_browse_name()
  {
    return QualifiedName{0, "Idle"};
  }

  static QualifiedName read_prepare_browse_name()
  {
    return QualifiedName{0, "ReadPrepare"};
  }

  static QualifiedName read_transfer_browse_name()
  {
    return QualifiedName{0, "ReadTransfer"};
  }

  static QualifiedName apply_write_browse_name()
  {
    return QualifiedName{0, "ApplyWrite"};
  }

  static QualifiedName error_browse_name()
  {
    return QualifiedName{0, "Error"};
  }

  static QualifiedName idle_to_read_prepare_browse_name()
  {
    return QualifiedName{0, "IdleToReadPrepare"};
  }

  static QualifiedName read_prepare_to_read_transfer_browse_name()
  {
    return QualifiedName{0, "ReadPrepareToReadTransfer"};
  }

  static QualifiedName read_transfer_to_idle_browse_name()
  {
    return QualifiedName{0, "ReadTransferToIdle"};
  }

  static QualifiedName idle_to_apply_write_browse_name()
  {
    return QualifiedName{0, "IdleToApplyWrite"};
  }

  static QualifiedName apply_write_to_idle_browse_name()
  {
    return QualifiedName{0, "ApplyWriteToIdle"};
  }

  static QualifiedName read_prepare_to_error_browse_name()
  {
    return QualifiedName{0, "ReadPrepareToError"};
  }

  static QualifiedName read_transfer_to_error_browse_name()
  {
    return QualifiedName{0, "ReadTransferToError"};
  }

  static QualifiedName apply_write_to_error_browse_name()
  {
    return QualifiedName{0, "ApplyWriteToError"};
  }

  static QualifiedName error_to_idle_browse_name()
  {
    return QualifiedName{0, "ErrorToIdle"};
  }

  static QualifiedName reset_browse_name()
  {
    return QualifiedName{0, "Reset"};
  }
};

}  // namespace

FileTransferStateMachine::FileTransferStateMachine(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void FileTransferStateMachine::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    FileTransferStateMachineTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(FileTransferStateMachineResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(FileTransferStateMachineResult{
        FileTransferStateMachine{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

FileTransferStateMachineResult FileTransferStateMachine::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileTransferStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(FileTransferStateMachineResult)> complete)
      {
        FileTransferStateMachine::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FileTransferStateMachine FileTransferStateMachine::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void FileTransferStateMachine::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void FileTransferStateMachine::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // FileTransferStateMachineType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    FileTransferStateMachineTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(FileTransferStateMachineResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          FileTransferStateMachineResult{::ua::detail::address_space_gone("FileTransferStateMachine")});
        return;
      }
      complete(
        FileTransferStateMachine{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

FileTransferStateMachineResult FileTransferStateMachine::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileTransferStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(FileTransferStateMachineResult)> complete)
      {
        FileTransferStateMachine::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FileTransferStateMachine FileTransferStateMachine::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void FileTransferStateMachine::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void FileTransferStateMachine::reset_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::reset_browse_name(),
    std::move(complete));
}

MethodAccessorResult FileTransferStateMachine::try_reset_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { reset_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor FileTransferStateMachine::reset_method_sync() const
{
  return ::ua::detail::good_value(try_reset_method_sync());
}

// --- Method handler registration ---

void FileTransferStateMachine::set_reset_handler_async(
  ResetHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileTransferStateMachine",
        "FileTransferStateMachine::set_reset_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileTransferStateMachineTypeTraits::reset_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileTransferStateMachine::try_set_reset_handler_sync(ResetHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileTransferStateMachine::set_reset_handler_sync(ResetHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

void FileTransferStateMachine::set_reset_handler_async(
  ResetAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "FileTransferStateMachine",
        "FileTransferStateMachine::set_reset_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      FileTransferStateMachineTypeTraits::reset_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult FileTransferStateMachine::try_set_reset_handler_sync(ResetAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void FileTransferStateMachine::set_reset_handler_sync(ResetAsyncHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void FileTransferStateMachine::idle_async(std::function<void(InitialStateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(InitialStateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<InitialState>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::idle_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

InitialStateResult FileTransferStateMachine::try_idle_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<InitialStateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(InitialStateResult)> complete) { idle_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

InitialState FileTransferStateMachine::idle_sync() const
{
  return ::ua::detail::good_value(try_idle_sync());
}

void FileTransferStateMachine::read_prepare_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_prepare_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

StateResult FileTransferStateMachine::try_read_prepare_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { read_prepare_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State FileTransferStateMachine::read_prepare_sync() const
{
  return ::ua::detail::good_value(try_read_prepare_sync());
}

void FileTransferStateMachine::read_transfer_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_transfer_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

StateResult FileTransferStateMachine::try_read_transfer_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { read_transfer_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State FileTransferStateMachine::read_transfer_sync() const
{
  return ::ua::detail::good_value(try_read_transfer_sync());
}

void FileTransferStateMachine::apply_write_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::apply_write_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

StateResult FileTransferStateMachine::try_apply_write_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { apply_write_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State FileTransferStateMachine::apply_write_sync() const
{
  return ::ua::detail::good_value(try_apply_write_sync());
}

void FileTransferStateMachine::error_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::error_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

StateResult FileTransferStateMachine::try_error_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { error_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State FileTransferStateMachine::error_sync() const
{
  return ::ua::detail::good_value(try_error_sync());
}

void FileTransferStateMachine::idle_to_read_prepare_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::idle_to_read_prepare_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_idle_to_read_prepare_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { idle_to_read_prepare_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::idle_to_read_prepare_sync() const
{
  return ::ua::detail::good_value(try_idle_to_read_prepare_sync());
}

void FileTransferStateMachine::read_prepare_to_read_transfer_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_prepare_to_read_transfer_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_read_prepare_to_read_transfer_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { read_prepare_to_read_transfer_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::read_prepare_to_read_transfer_sync() const
{
  return ::ua::detail::good_value(try_read_prepare_to_read_transfer_sync());
}

void FileTransferStateMachine::read_transfer_to_idle_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_transfer_to_idle_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_read_transfer_to_idle_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { read_transfer_to_idle_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::read_transfer_to_idle_sync() const
{
  return ::ua::detail::good_value(try_read_transfer_to_idle_sync());
}

void FileTransferStateMachine::idle_to_apply_write_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::idle_to_apply_write_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_idle_to_apply_write_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { idle_to_apply_write_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::idle_to_apply_write_sync() const
{
  return ::ua::detail::good_value(try_idle_to_apply_write_sync());
}

void FileTransferStateMachine::apply_write_to_idle_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::apply_write_to_idle_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_apply_write_to_idle_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { apply_write_to_idle_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::apply_write_to_idle_sync() const
{
  return ::ua::detail::good_value(try_apply_write_to_idle_sync());
}

void FileTransferStateMachine::read_prepare_to_error_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_prepare_to_error_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_read_prepare_to_error_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { read_prepare_to_error_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::read_prepare_to_error_sync() const
{
  return ::ua::detail::good_value(try_read_prepare_to_error_sync());
}

void FileTransferStateMachine::read_transfer_to_error_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::read_transfer_to_error_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_read_transfer_to_error_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { read_transfer_to_error_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::read_transfer_to_error_sync() const
{
  return ::ua::detail::good_value(try_read_transfer_to_error_sync());
}

void FileTransferStateMachine::apply_write_to_error_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::apply_write_to_error_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_apply_write_to_error_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { apply_write_to_error_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::apply_write_to_error_sync() const
{
  return ::ua::detail::good_value(try_apply_write_to_error_sync());
}

void FileTransferStateMachine::error_to_idle_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTransferStateMachineTypeTraits::error_to_idle_browse_name(),
    "FileTransferStateMachine",
    std::move(complete));
}

TransitionResult FileTransferStateMachine::try_error_to_idle_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { error_to_idle_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition FileTransferStateMachine::error_to_idle_sync() const
{
  return ::ua::detail::good_value(try_error_to_idle_sync());
}

}  // namespace ua
