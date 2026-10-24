// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_base_variable.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_instantiation_service.h"
#include "ua_namespace_route.h"
#include "ua_to_result.h"

#include <future>

namespace ua
{

BaseVariable::BaseVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : mAddressSpace(std::move(addressSpace)), mNodeId(std::move(nodeId)), mOwned(std::move(owned))
{}

const NodeId& BaseVariable::node_id() const
{
  return mNodeId;
}

void BaseVariable::release()
{
  if (mOwned)
  {
    mOwned->release();
    mOwned.reset();
  }
}

// --- create_variable_impl_async ---

void BaseVariable::create_variable_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, NodeId typeDefinition, InstantiationOptions options,
  VariableInstantiationAttributes attributes, CreateImplCompleteCallback complete) noexcept
{
  try
  {
    InstantiationService inst{addressSpace};
    inst.instantiate_variable_async(parent,
      browseName,
      typeDefinition,
      options,
      attributes,
      [weakAddressSpace = addressSpace.weak(), complete = complete](NodeSubtreeResult result) mutable
      {
        if (!result.has_value())
        {
          complete(CreateResult{result.status_code(), result.shared_detail()});
          return;
        }
        auto lockedAddressSpace = weakAddressSpace.lock();
        if (!lockedAddressSpace)
        {
          complete(CreateResult{detail::address_space_gone("BaseVariable")});
          return;
        }
        const StatusCode answered = result.status_code();
        auto subtree = std::move(result).value();
        auto rootId = subtree.root();
        complete(CreateResult{
          CreateResultData{std::move(*lockedAddressSpace), std::move(rootId), std::move(subtree)}, answered});
      });
  }
  catch (...)
  {
    // Honour the noexcept contract: surface a setup failure (e.g. the AddressSpace
    // copy or the completion closure allocation throwing) through the callback as a
    // bad CreateResult rather than letting the exception escape and call std::terminate.
    if (complete)
    {
      complete(CreateResult{ua::exception_to_status_code(std::current_exception())});
    }
  }
}

// --- Value consumer API ---

void BaseVariable::read_value_async(ReadValueCompleteCallback complete) const noexcept
{
  if (!complete)
  {
    return;
  }
  if (!mAddressSpace)
  {
    complete(DataValueResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  // The two-layer read: this is a caller asking for a value, so a bad QUALITY rides on the
  // returned DataValue's status and the Result stays good. The flattening variant exists for
  // the SDK's own alarm callers, which must not use a suspect reading.
  instance_utils::read_variable_data_value_async(*mAddressSpace,
    mNodeId,
    [complete = std::move(complete)](DataValueResult r) mutable { complete(std::move(r)); });
}

DataValueResult BaseVariable::try_read_value_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DataValueResult>(
      (mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(DataValueResult)> complete) { read_value_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

DataValue BaseVariable::read_value_sync() const
{
  return ua::detail::good_data_value(try_read_value_sync());
}

void BaseVariable::write_value_async(DataValue value, WriteValueCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    if (complete)
      complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  // A caller that passes no callback still has the value written; a failure is logged instead.
  complete = ua::detail::completion_or_log(
    std::move(complete), mAddressSpace->logger(), "BaseVariable::write_value_async");
  instance_utils::write_variable_value_async(*mAddressSpace,
    mNodeId,
    std::move(value),

    [complete = std::move(complete)](VoidResult r) mutable { complete(std::move(r)); });
}

VoidResult BaseVariable::try_write_value_sync(DataValue value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete)
      { write_value_async(std::move(value), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void BaseVariable::write_value_sync(DataValue value) const
{
  try_write_value_sync(std::move(value)).value();
}

// --- Value handler registration ---

void BaseVariable::set_value_source_async(
  std::shared_ptr<ValueSource> source, std::function<void(VoidResult)> done) const noexcept
{
  if (!mAddressSpace)
  {
    if (done)
      done(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  // A caller that passes no callback still has the source installed; a failure is logged instead.
  done = ua::detail::completion_or_log(
    std::move(done), mAddressSpace->logger(), "BaseVariable::set_value_source_async");
  instance_utils::resolve_and_set_value_source_async(*mAddressSpace,
    mNodeId,
    std::move(source),
    [done = std::move(done)](VoidResult r) mutable { done(std::move(r)); });
}

VoidResult BaseVariable::try_set_value_source_sync(std::shared_ptr<ValueSource> source) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete)
      { set_value_source_async(std::move(source), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void BaseVariable::set_value_source_sync(std::shared_ptr<ValueSource> source) const
{
  try_set_value_source_sync(std::move(source)).value();
}

}  // namespace ua
