// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_program_state_machine.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct ProgramStateMachineTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ProgramStateMachineType};
  }

  static QualifiedName current_state_browse_name()
  {
    return QualifiedName{0, "CurrentState"};
  }

  static QualifiedName last_transition_browse_name()
  {
    return QualifiedName{0, "LastTransition"};
  }

  static QualifiedName creatable_browse_name()
  {
    return QualifiedName{0, "Creatable"};
  }

  static QualifiedName deletable_browse_name()
  {
    return QualifiedName{0, "Deletable"};
  }

  static QualifiedName auto_delete_browse_name()
  {
    return QualifiedName{0, "AutoDelete"};
  }

  static QualifiedName recycle_count_browse_name()
  {
    return QualifiedName{0, "RecycleCount"};
  }

  static QualifiedName instance_count_browse_name()
  {
    return QualifiedName{0, "InstanceCount"};
  }

  static QualifiedName max_instance_count_browse_name()
  {
    return QualifiedName{0, "MaxInstanceCount"};
  }

  static QualifiedName max_recycle_count_browse_name()
  {
    return QualifiedName{0, "MaxRecycleCount"};
  }

  static QualifiedName program_diagnostic_browse_name()
  {
    return QualifiedName{0, "ProgramDiagnostic"};
  }

  static QualifiedName final_result_data_browse_name()
  {
    return QualifiedName{0, "FinalResultData"};
  }

  static QualifiedName halted_browse_name()
  {
    return QualifiedName{0, "Halted"};
  }

  static QualifiedName ready_browse_name()
  {
    return QualifiedName{0, "Ready"};
  }

  static QualifiedName running_browse_name()
  {
    return QualifiedName{0, "Running"};
  }

  static QualifiedName suspended_browse_name()
  {
    return QualifiedName{0, "Suspended"};
  }

  static QualifiedName halted_to_ready_browse_name()
  {
    return QualifiedName{0, "HaltedToReady"};
  }

  static QualifiedName ready_to_running_browse_name()
  {
    return QualifiedName{0, "ReadyToRunning"};
  }

  static QualifiedName running_to_halted_browse_name()
  {
    return QualifiedName{0, "RunningToHalted"};
  }

  static QualifiedName running_to_ready_browse_name()
  {
    return QualifiedName{0, "RunningToReady"};
  }

  static QualifiedName running_to_suspended_browse_name()
  {
    return QualifiedName{0, "RunningToSuspended"};
  }

  static QualifiedName suspended_to_running_browse_name()
  {
    return QualifiedName{0, "SuspendedToRunning"};
  }

  static QualifiedName suspended_to_halted_browse_name()
  {
    return QualifiedName{0, "SuspendedToHalted"};
  }

  static QualifiedName suspended_to_ready_browse_name()
  {
    return QualifiedName{0, "SuspendedToReady"};
  }

  static QualifiedName ready_to_halted_browse_name()
  {
    return QualifiedName{0, "ReadyToHalted"};
  }
};

}  // namespace

ProgramStateMachine::ProgramStateMachine(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ProgramStateMachine::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ProgramStateMachineTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ProgramStateMachineResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ProgramStateMachineResult{
        ProgramStateMachine{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ProgramStateMachineResult ProgramStateMachine::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ProgramStateMachineResult)> complete)
      {
        ProgramStateMachine::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramStateMachine ProgramStateMachine::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ProgramStateMachine::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ProgramStateMachine::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ProgramStateMachineType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ProgramStateMachineTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ProgramStateMachineResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ProgramStateMachineResult{::ua::detail::address_space_gone("ProgramStateMachine")});
        return;
      }
      complete(
        ProgramStateMachine{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ProgramStateMachineResult ProgramStateMachine::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ProgramStateMachineResult)> complete)
      {
        ProgramStateMachine::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramStateMachine ProgramStateMachine::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ProgramStateMachine::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ProgramStateMachine::find_property_async(
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
    "ProgramStateMachine",
    std::move(complete));
}

// --- Property accessors ---

void ProgramStateMachine::creatable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::creatable_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_creatable_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { creatable_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::creatable_property_sync() const
{
  return ::ua::detail::good_value(try_creatable_property_sync());
}

void ProgramStateMachine::deletable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::deletable_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_deletable_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { deletable_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::deletable_property_sync() const
{
  return ::ua::detail::good_value(try_deletable_property_sync());
}

void ProgramStateMachine::auto_delete_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::auto_delete_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_auto_delete_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { auto_delete_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::auto_delete_property_sync() const
{
  return ::ua::detail::good_value(try_auto_delete_property_sync());
}

void ProgramStateMachine::recycle_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::recycle_count_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_recycle_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { recycle_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::recycle_count_property_sync() const
{
  return ::ua::detail::good_value(try_recycle_count_property_sync());
}

void ProgramStateMachine::instance_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::instance_count_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_instance_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { instance_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::instance_count_property_sync() const
{
  return ::ua::detail::good_value(try_instance_count_property_sync());
}

void ProgramStateMachine::max_instance_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::max_instance_count_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_max_instance_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_instance_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::max_instance_count_property_sync() const
{
  return ::ua::detail::good_value(try_max_instance_count_property_sync());
}

void ProgramStateMachine::max_recycle_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramStateMachineTypeTraits::max_recycle_count_browse_name(), std::move(complete));
}

PropertyResult ProgramStateMachine::try_max_recycle_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_recycle_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramStateMachine::max_recycle_count_property_sync() const
{
  return ::ua::detail::good_value(try_max_recycle_count_property_sync());
}

// --- Typed value read shortcuts ---

void ProgramStateMachine::read_creatable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::creatable_browse_name(),
    &Variant::is_boolean,
    {"ProgramStateMachine", "creatable", "ProgramStateMachine::read_creatable_async"},
    std::move(complete));
}

BoolResult ProgramStateMachine::try_read_creatable_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_creatable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ProgramStateMachine::read_creatable_sync() const
{
  return ::ua::detail::good_value(try_read_creatable_sync());
}

void ProgramStateMachine::read_deletable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::deletable_browse_name(),
    &Variant::is_boolean,
    {"ProgramStateMachine", "deletable", "ProgramStateMachine::read_deletable_async"},
    std::move(complete));
}

BoolResult ProgramStateMachine::try_read_deletable_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_deletable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ProgramStateMachine::read_deletable_sync() const
{
  return ::ua::detail::good_value(try_read_deletable_sync());
}

void ProgramStateMachine::read_auto_delete_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::auto_delete_browse_name(),
    &Variant::is_boolean,
    {"ProgramStateMachine", "auto_delete", "ProgramStateMachine::read_auto_delete_async"},
    std::move(complete));
}

BoolResult ProgramStateMachine::try_read_auto_delete_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_auto_delete_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ProgramStateMachine::read_auto_delete_sync() const
{
  return ::ua::detail::good_value(try_read_auto_delete_sync());
}

void ProgramStateMachine::read_recycle_count_async(std::function<void(Int32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Int32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<int32_t>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::recycle_count_browse_name(),
    &Variant::is_int32,
    {"ProgramStateMachine", "recycle_count", "ProgramStateMachine::read_recycle_count_async"},
    std::move(complete));
}

Int32Result ProgramStateMachine::try_read_recycle_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Int32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Int32Result)> complete) { read_recycle_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

int32_t ProgramStateMachine::read_recycle_count_sync() const
{
  return ::ua::detail::good_value(try_read_recycle_count_sync());
}

void ProgramStateMachine::read_instance_count_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::instance_count_browse_name(),
    &Variant::is_uint32,
    {"ProgramStateMachine", "instance_count", "ProgramStateMachine::read_instance_count_async"},
    std::move(complete));
}

UInt32Result ProgramStateMachine::try_read_instance_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_instance_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ProgramStateMachine::read_instance_count_sync() const
{
  return ::ua::detail::good_value(try_read_instance_count_sync());
}

void ProgramStateMachine::read_max_instance_count_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::max_instance_count_browse_name(),
    &Variant::is_uint32,
    {"ProgramStateMachine", "max_instance_count", "ProgramStateMachine::read_max_instance_count_async"},
    std::move(complete));
}

UInt32Result ProgramStateMachine::try_read_max_instance_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_instance_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ProgramStateMachine::read_max_instance_count_sync() const
{
  return ::ua::detail::good_value(try_read_max_instance_count_sync());
}

void ProgramStateMachine::read_max_recycle_count_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::max_recycle_count_browse_name(),
    &Variant::is_uint32,
    {"ProgramStateMachine", "max_recycle_count", "ProgramStateMachine::read_max_recycle_count_async"},
    std::move(complete));
}

UInt32Result ProgramStateMachine::try_read_max_recycle_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_recycle_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ProgramStateMachine::read_max_recycle_count_sync() const
{
  return ::ua::detail::good_value(try_read_max_recycle_count_sync());
}

// --- Typed value write shortcuts ---

void ProgramStateMachine::write_creatable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::creatable_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_creatable_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_creatable_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_creatable_sync(bool value) const
{
  try_write_creatable_sync(value).value();
}

void ProgramStateMachine::write_deletable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::deletable_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_deletable_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_deletable_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_deletable_sync(bool value) const
{
  try_write_deletable_sync(value).value();
}

void ProgramStateMachine::write_auto_delete_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::auto_delete_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_auto_delete_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_auto_delete_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_auto_delete_sync(bool value) const
{
  try_write_auto_delete_sync(value).value();
}

void ProgramStateMachine::write_recycle_count_async(
  int32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::recycle_count_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_recycle_count_sync(int32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_recycle_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_recycle_count_sync(int32_t value) const
{
  try_write_recycle_count_sync(value).value();
}

void ProgramStateMachine::write_instance_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::instance_count_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_instance_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_instance_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_instance_count_sync(uint32_t value) const
{
  try_write_instance_count_sync(value).value();
}

void ProgramStateMachine::write_max_instance_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::max_instance_count_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_max_instance_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_instance_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_max_instance_count_sync(uint32_t value) const
{
  try_write_max_instance_count_sync(value).value();
}

void ProgramStateMachine::write_max_recycle_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramStateMachineTypeTraits::max_recycle_count_browse_name(),
    "ProgramStateMachine",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramStateMachine::try_write_max_recycle_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_recycle_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramStateMachine::write_max_recycle_count_sync(uint32_t value) const
{
  try_write_max_recycle_count_sync(value).value();
}

// --- Child-object accessors ---

void ProgramStateMachine::current_state_async(
  std::function<void(FiniteStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FiniteStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<FiniteStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::current_state_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

FiniteStateVariableResult ProgramStateMachine::try_current_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FiniteStateVariableResult)> complete)
      { current_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteStateVariable ProgramStateMachine::current_state_sync() const
{
  return ::ua::detail::good_value(try_current_state_sync());
}

void ProgramStateMachine::last_transition_async(
  std::function<void(FiniteTransitionVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FiniteTransitionVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<FiniteTransitionVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::last_transition_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

FiniteTransitionVariableResult ProgramStateMachine::try_last_transition_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteTransitionVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FiniteTransitionVariableResult)> complete)
      { last_transition_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteTransitionVariable ProgramStateMachine::last_transition_sync() const
{
  return ::ua::detail::good_value(try_last_transition_sync());
}

void ProgramStateMachine::program_diagnostic_async(
  std::function<void(ProgramDiagnostic2Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ProgramDiagnostic2Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ProgramDiagnostic2>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::program_diagnostic_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

ProgramDiagnostic2Result ProgramStateMachine::try_program_diagnostic_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramDiagnostic2Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ProgramDiagnostic2Result)> complete)
      { program_diagnostic_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramDiagnostic2 ProgramStateMachine::program_diagnostic_sync() const
{
  return ::ua::detail::good_value(try_program_diagnostic_sync());
}

void ProgramStateMachine::final_result_data_async(
  std::function<void(BaseObjectResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseObjectResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseObject>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::final_result_data_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

BaseObjectResult ProgramStateMachine::try_final_result_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseObjectResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseObjectResult)> complete) { final_result_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseObject ProgramStateMachine::final_result_data_sync() const
{
  return ::ua::detail::good_value(try_final_result_data_sync());
}

void ProgramStateMachine::halted_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::halted_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

StateResult ProgramStateMachine::try_halted_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { halted_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ProgramStateMachine::halted_sync() const
{
  return ::ua::detail::good_value(try_halted_sync());
}

void ProgramStateMachine::ready_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::ready_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

StateResult ProgramStateMachine::try_ready_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { ready_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ProgramStateMachine::ready_sync() const
{
  return ::ua::detail::good_value(try_ready_sync());
}

void ProgramStateMachine::running_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::running_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

StateResult ProgramStateMachine::try_running_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { running_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ProgramStateMachine::running_sync() const
{
  return ::ua::detail::good_value(try_running_sync());
}

void ProgramStateMachine::suspended_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::suspended_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

StateResult ProgramStateMachine::try_suspended_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { suspended_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ProgramStateMachine::suspended_sync() const
{
  return ::ua::detail::good_value(try_suspended_sync());
}

void ProgramStateMachine::halted_to_ready_async(std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::halted_to_ready_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_halted_to_ready_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { halted_to_ready_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::halted_to_ready_sync() const
{
  return ::ua::detail::good_value(try_halted_to_ready_sync());
}

void ProgramStateMachine::ready_to_running_async(
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
    ProgramStateMachineTypeTraits::ready_to_running_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_ready_to_running_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { ready_to_running_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::ready_to_running_sync() const
{
  return ::ua::detail::good_value(try_ready_to_running_sync());
}

void ProgramStateMachine::running_to_halted_async(
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
    ProgramStateMachineTypeTraits::running_to_halted_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_running_to_halted_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { running_to_halted_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::running_to_halted_sync() const
{
  return ::ua::detail::good_value(try_running_to_halted_sync());
}

void ProgramStateMachine::running_to_ready_async(
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
    ProgramStateMachineTypeTraits::running_to_ready_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_running_to_ready_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { running_to_ready_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::running_to_ready_sync() const
{
  return ::ua::detail::good_value(try_running_to_ready_sync());
}

void ProgramStateMachine::running_to_suspended_async(
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
    ProgramStateMachineTypeTraits::running_to_suspended_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_running_to_suspended_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { running_to_suspended_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::running_to_suspended_sync() const
{
  return ::ua::detail::good_value(try_running_to_suspended_sync());
}

void ProgramStateMachine::suspended_to_running_async(
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
    ProgramStateMachineTypeTraits::suspended_to_running_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_suspended_to_running_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { suspended_to_running_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::suspended_to_running_sync() const
{
  return ::ua::detail::good_value(try_suspended_to_running_sync());
}

void ProgramStateMachine::suspended_to_halted_async(
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
    ProgramStateMachineTypeTraits::suspended_to_halted_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_suspended_to_halted_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { suspended_to_halted_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::suspended_to_halted_sync() const
{
  return ::ua::detail::good_value(try_suspended_to_halted_sync());
}

void ProgramStateMachine::suspended_to_ready_async(
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
    ProgramStateMachineTypeTraits::suspended_to_ready_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_suspended_to_ready_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { suspended_to_ready_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::suspended_to_ready_sync() const
{
  return ::ua::detail::good_value(try_suspended_to_ready_sync());
}

void ProgramStateMachine::ready_to_halted_async(std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramStateMachineTypeTraits::ready_to_halted_browse_name(),
    "ProgramStateMachine",
    std::move(complete));
}

TransitionResult ProgramStateMachine::try_ready_to_halted_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { ready_to_halted_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ProgramStateMachine::ready_to_halted_sync() const
{
  return ::ua::detail::good_value(try_ready_to_halted_sync());
}

}  // namespace ua
