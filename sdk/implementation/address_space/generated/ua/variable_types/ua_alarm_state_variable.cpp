// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_state_variable.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>

#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"

namespace ua
{
namespace
{

struct AlarmStateVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::AlarmStateVariableType};
  }

  static QualifiedName highest_active_severity_browse_name()
  {
    return QualifiedName{0, "HighestActiveSeverity"};
  }

  static QualifiedName highest_unack_severity_browse_name()
  {
    return QualifiedName{0, "HighestUnackSeverity"};
  }

  static QualifiedName active_count_browse_name()
  {
    return QualifiedName{0, "ActiveCount"};
  }

  static QualifiedName unacknowledged_count_browse_name()
  {
    return QualifiedName{0, "UnacknowledgedCount"};
  }

  static QualifiedName unconfirmed_count_browse_name()
  {
    return QualifiedName{0, "UnconfirmedCount"};
  }

  static QualifiedName filter_browse_name()
  {
    return QualifiedName{0, "Filter"};
  }
};

}  // namespace

AlarmStateVariable::AlarmStateVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AlarmStateVariable::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AlarmStateVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AlarmStateVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AlarmStateVariableResult{
        AlarmStateVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AlarmStateVariableResult AlarmStateVariable::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(AlarmStateVariableResult)> complete)
      {
        AlarmStateVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmStateVariable AlarmStateVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void AlarmStateVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    VariableInstantiationAttributes{attributes},
    std::move(complete));
}

void AlarmStateVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AlarmStateVariableType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AlarmStateVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AlarmStateVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AlarmStateVariableResult{::ua::detail::address_space_gone("AlarmStateVariable")});
        return;
      }
      complete(AlarmStateVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AlarmStateVariableResult AlarmStateVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(AlarmStateVariableResult)> complete)
      {
        AlarmStateVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmStateVariable AlarmStateVariable::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AlarmStateVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void AlarmStateVariable::find_property_async(
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
    "AlarmStateVariable",
    std::move(complete));
}

// --- Property accessors ---

void AlarmStateVariable::highest_active_severity_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AlarmStateVariableTypeTraits::highest_active_severity_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_highest_active_severity_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { highest_active_severity_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::highest_active_severity_property_sync() const
{
  return ::ua::detail::good_value(try_highest_active_severity_property_sync());
}

void AlarmStateVariable::highest_unack_severity_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AlarmStateVariableTypeTraits::highest_unack_severity_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_highest_unack_severity_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { highest_unack_severity_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::highest_unack_severity_property_sync() const
{
  return ::ua::detail::good_value(try_highest_unack_severity_property_sync());
}

void AlarmStateVariable::active_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmStateVariableTypeTraits::active_count_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_active_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { active_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::active_count_property_sync() const
{
  return ::ua::detail::good_value(try_active_count_property_sync());
}

void AlarmStateVariable::unacknowledged_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmStateVariableTypeTraits::unacknowledged_count_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_unacknowledged_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { unacknowledged_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::unacknowledged_count_property_sync() const
{
  return ::ua::detail::good_value(try_unacknowledged_count_property_sync());
}

void AlarmStateVariable::unconfirmed_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmStateVariableTypeTraits::unconfirmed_count_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_unconfirmed_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { unconfirmed_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::unconfirmed_count_property_sync() const
{
  return ::ua::detail::good_value(try_unconfirmed_count_property_sync());
}

void AlarmStateVariable::filter_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmStateVariableTypeTraits::filter_browse_name(), std::move(complete));
}

PropertyResult AlarmStateVariable::try_filter_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { filter_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlarmStateVariable::filter_property_sync() const
{
  return ::ua::detail::good_value(try_filter_property_sync());
}

// --- Typed value read shortcuts ---

void AlarmStateVariable::read_highest_active_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::highest_active_severity_browse_name(),
    &Variant::is_uint16,
    {"AlarmStateVariable",
      "highest_active_severity",
      "AlarmStateVariable::read_highest_active_severity_async"},
    std::move(complete));
}

UInt16Result AlarmStateVariable::try_read_highest_active_severity_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_highest_active_severity_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t AlarmStateVariable::read_highest_active_severity_sync() const
{
  return ::ua::detail::good_value(try_read_highest_active_severity_sync());
}

void AlarmStateVariable::read_highest_unack_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::highest_unack_severity_browse_name(),
    &Variant::is_uint16,
    {"AlarmStateVariable", "highest_unack_severity", "AlarmStateVariable::read_highest_unack_severity_async"},
    std::move(complete));
}

UInt16Result AlarmStateVariable::try_read_highest_unack_severity_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_highest_unack_severity_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t AlarmStateVariable::read_highest_unack_severity_sync() const
{
  return ::ua::detail::good_value(try_read_highest_unack_severity_sync());
}

void AlarmStateVariable::read_active_count_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::active_count_browse_name(),
    &Variant::is_uint32,
    {"AlarmStateVariable", "active_count", "AlarmStateVariable::read_active_count_async"},
    std::move(complete));
}

UInt32Result AlarmStateVariable::try_read_active_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_active_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t AlarmStateVariable::read_active_count_sync() const
{
  return ::ua::detail::good_value(try_read_active_count_sync());
}

void AlarmStateVariable::read_unacknowledged_count_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::unacknowledged_count_browse_name(),
    &Variant::is_uint32,
    {"AlarmStateVariable", "unacknowledged_count", "AlarmStateVariable::read_unacknowledged_count_async"},
    std::move(complete));
}

UInt32Result AlarmStateVariable::try_read_unacknowledged_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_unacknowledged_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t AlarmStateVariable::read_unacknowledged_count_sync() const
{
  return ::ua::detail::good_value(try_read_unacknowledged_count_sync());
}

void AlarmStateVariable::read_unconfirmed_count_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::unconfirmed_count_browse_name(),
    &Variant::is_uint32,
    {"AlarmStateVariable", "unconfirmed_count", "AlarmStateVariable::read_unconfirmed_count_async"},
    std::move(complete));
}

UInt32Result AlarmStateVariable::try_read_unconfirmed_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_unconfirmed_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t AlarmStateVariable::read_unconfirmed_count_sync() const
{
  return ::ua::detail::good_value(try_read_unconfirmed_count_sync());
}

// --- Typed value write shortcuts ---

void AlarmStateVariable::write_highest_active_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::highest_active_severity_browse_name(),
    "AlarmStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmStateVariable::try_write_highest_active_severity_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_highest_active_severity_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmStateVariable::write_highest_active_severity_sync(uint16_t value) const
{
  try_write_highest_active_severity_sync(value).value();
}

void AlarmStateVariable::write_highest_unack_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::highest_unack_severity_browse_name(),
    "AlarmStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmStateVariable::try_write_highest_unack_severity_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_highest_unack_severity_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmStateVariable::write_highest_unack_severity_sync(uint16_t value) const
{
  try_write_highest_unack_severity_sync(value).value();
}

void AlarmStateVariable::write_active_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::active_count_browse_name(),
    "AlarmStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmStateVariable::try_write_active_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_active_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmStateVariable::write_active_count_sync(uint32_t value) const
{
  try_write_active_count_sync(value).value();
}

void AlarmStateVariable::write_unacknowledged_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::unacknowledged_count_browse_name(),
    "AlarmStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmStateVariable::try_write_unacknowledged_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_unacknowledged_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmStateVariable::write_unacknowledged_count_sync(uint32_t value) const
{
  try_write_unacknowledged_count_sync(value).value();
}

void AlarmStateVariable::write_unconfirmed_count_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmStateVariableTypeTraits::unconfirmed_count_browse_name(),
    "AlarmStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmStateVariable::try_write_unconfirmed_count_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_unconfirmed_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmStateVariable::write_unconfirmed_count_sync(uint32_t value) const
{
  try_write_unconfirmed_count_sync(value).value();
}

}  // namespace ua
