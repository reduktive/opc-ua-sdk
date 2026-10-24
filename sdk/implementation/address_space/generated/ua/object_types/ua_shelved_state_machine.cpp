// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_shelved_state_machine.h"

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

struct ShelvedStateMachineTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ShelvedStateMachineType};
  }

  static QualifiedName unshelve_time_browse_name()
  {
    return QualifiedName{0, "UnshelveTime"};
  }

  static QualifiedName unshelved_browse_name()
  {
    return QualifiedName{0, "Unshelved"};
  }

  static QualifiedName timed_shelved_browse_name()
  {
    return QualifiedName{0, "TimedShelved"};
  }

  static QualifiedName one_shot_shelved_browse_name()
  {
    return QualifiedName{0, "OneShotShelved"};
  }

  static QualifiedName unshelved_to_timed_shelved_browse_name()
  {
    return QualifiedName{0, "UnshelvedToTimedShelved"};
  }

  static QualifiedName unshelved_to_one_shot_shelved_browse_name()
  {
    return QualifiedName{0, "UnshelvedToOneShotShelved"};
  }

  static QualifiedName timed_shelved_to_unshelved_browse_name()
  {
    return QualifiedName{0, "TimedShelvedToUnshelved"};
  }

  static QualifiedName timed_shelved_to_one_shot_shelved_browse_name()
  {
    return QualifiedName{0, "TimedShelvedToOneShotShelved"};
  }

  static QualifiedName one_shot_shelved_to_unshelved_browse_name()
  {
    return QualifiedName{0, "OneShotShelvedToUnshelved"};
  }

  static QualifiedName one_shot_shelved_to_timed_shelved_browse_name()
  {
    return QualifiedName{0, "OneShotShelvedToTimedShelved"};
  }

  static QualifiedName timed_shelve_browse_name()
  {
    return QualifiedName{0, "TimedShelve"};
  }

  static QualifiedName timed_shelve2_browse_name()
  {
    return QualifiedName{0, "TimedShelve2"};
  }

  static QualifiedName unshelve_browse_name()
  {
    return QualifiedName{0, "Unshelve"};
  }

  static QualifiedName unshelve2_browse_name()
  {
    return QualifiedName{0, "Unshelve2"};
  }

  static QualifiedName one_shot_shelve_browse_name()
  {
    return QualifiedName{0, "OneShotShelve"};
  }

  static QualifiedName one_shot_shelve2_browse_name()
  {
    return QualifiedName{0, "OneShotShelve2"};
  }
};

}  // namespace

ShelvedStateMachine::ShelvedStateMachine(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ShelvedStateMachine::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ShelvedStateMachineTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ShelvedStateMachineResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ShelvedStateMachineResult{
        ShelvedStateMachine{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ShelvedStateMachineResult ShelvedStateMachine::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ShelvedStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ShelvedStateMachineResult)> complete)
      {
        ShelvedStateMachine::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ShelvedStateMachine ShelvedStateMachine::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ShelvedStateMachine::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ShelvedStateMachine::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ShelvedStateMachineType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ShelvedStateMachineTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ShelvedStateMachineResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ShelvedStateMachineResult{::ua::detail::address_space_gone("ShelvedStateMachine")});
        return;
      }
      complete(
        ShelvedStateMachine{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ShelvedStateMachineResult ShelvedStateMachine::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ShelvedStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ShelvedStateMachineResult)> complete)
      {
        ShelvedStateMachine::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ShelvedStateMachine ShelvedStateMachine::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ShelvedStateMachine::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void ShelvedStateMachine::timed_shelve_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::timed_shelve_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_timed_shelve_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { timed_shelve_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::timed_shelve_method_sync() const
{
  return ::ua::detail::good_value(try_timed_shelve_method_sync());
}

void ShelvedStateMachine::timed_shelve2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::timed_shelve2_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_timed_shelve2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { timed_shelve2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::timed_shelve2_method_sync() const
{
  return ::ua::detail::good_value(try_timed_shelve2_method_sync());
}

void ShelvedStateMachine::unshelve_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::unshelve_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_unshelve_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { unshelve_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::unshelve_method_sync() const
{
  return ::ua::detail::good_value(try_unshelve_method_sync());
}

void ShelvedStateMachine::unshelve2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::unshelve2_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_unshelve2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { unshelve2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::unshelve2_method_sync() const
{
  return ::ua::detail::good_value(try_unshelve2_method_sync());
}

void ShelvedStateMachine::one_shot_shelve_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::one_shot_shelve_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_one_shot_shelve_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { one_shot_shelve_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::one_shot_shelve_method_sync() const
{
  return ::ua::detail::good_value(try_one_shot_shelve_method_sync());
}

void ShelvedStateMachine::one_shot_shelve2_method_async(
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
    ShelvedStateMachineTypeTraits::one_shot_shelve2_browse_name(),
    std::move(complete));
}

MethodAccessorResult ShelvedStateMachine::try_one_shot_shelve2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { one_shot_shelve2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ShelvedStateMachine::one_shot_shelve2_method_sync() const
{
  return ::ua::detail::good_value(try_one_shot_shelve2_method_sync());
}

// --- Common property helper ---

void ShelvedStateMachine::find_property_async(
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
    "ShelvedStateMachine",
    std::move(complete));
}

// --- Property accessors ---

void ShelvedStateMachine::unshelve_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ShelvedStateMachineTypeTraits::unshelve_time_browse_name(), std::move(complete));
}

PropertyResult ShelvedStateMachine::try_unshelve_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { unshelve_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ShelvedStateMachine::unshelve_time_property_sync() const
{
  return ::ua::detail::good_value(try_unshelve_time_property_sync());
}

// --- Method handler registration ---

void ShelvedStateMachine::set_timed_shelve_handler_async(
  TimedShelveHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_timed_shelve_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Variant& in0) -> MethodResult<>
      {
        TimedShelveInputArguments typedIn{.shelvingTime = in0};
        return handler(call, typedIn);
      },
      Inputs<Variant>{{Arg<Variant>{.name = "ShelvingTime"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::timed_shelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_timed_shelve_handler_sync(TimedShelveHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_timed_shelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_timed_shelve_handler_sync(TimedShelveHandler handler) const
{
  try_set_timed_shelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_timed_shelve_handler_async(
  TimedShelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_timed_shelve_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<> complete)
      {
        TimedShelveInputArguments typedIn{.shelvingTime = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "ShelvingTime"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::timed_shelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_timed_shelve_handler_sync(
  TimedShelveAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_timed_shelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_timed_shelve_handler_sync(TimedShelveAsyncHandler handler) const
{
  try_set_timed_shelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_timed_shelve2_handler_async(
  TimedShelve2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_timed_shelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const Variant& in0, const LocalizedText& in1) -> MethodResult<>
      {
        TimedShelve2InputArguments typedIn{.shelvingTime = in0, .comment = in1};
        return handler(call, typedIn);
      },
      Inputs<Variant, LocalizedText>{
        {Arg<Variant>{.name = "ShelvingTime"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::timed_shelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_timed_shelve2_handler_sync(TimedShelve2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_timed_shelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_timed_shelve2_handler_sync(TimedShelve2Handler handler) const
{
  try_set_timed_shelve2_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_timed_shelve2_handler_async(
  TimedShelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_timed_shelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, const LocalizedText& in1, MethodResultCallback<> complete)
      {
        TimedShelve2InputArguments typedIn{.shelvingTime = in0, .comment = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant, LocalizedText>{
        {Arg<Variant>{.name = "ShelvingTime"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::timed_shelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_timed_shelve2_handler_sync(
  TimedShelve2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_timed_shelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_timed_shelve2_handler_sync(TimedShelve2AsyncHandler handler) const
{
  try_set_timed_shelve2_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_unshelve_handler_async(
  UnshelveHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_unshelve_handler_async",
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
      ShelvedStateMachineTypeTraits::unshelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_unshelve_handler_sync(UnshelveHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unshelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_unshelve_handler_sync(UnshelveHandler handler) const
{
  try_set_unshelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_unshelve_handler_async(
  UnshelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_unshelve_handler_async",
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
      ShelvedStateMachineTypeTraits::unshelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_unshelve_handler_sync(UnshelveAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unshelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_unshelve_handler_sync(UnshelveAsyncHandler handler) const
{
  try_set_unshelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_unshelve2_handler_async(
  Unshelve2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_unshelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        Unshelve2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::unshelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_unshelve2_handler_sync(Unshelve2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unshelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_unshelve2_handler_sync(Unshelve2Handler handler) const
{
  try_set_unshelve2_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_unshelve2_handler_async(
  Unshelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_unshelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        Unshelve2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::unshelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_unshelve2_handler_sync(Unshelve2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unshelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_unshelve2_handler_sync(Unshelve2AsyncHandler handler) const
{
  try_set_unshelve2_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_one_shot_shelve_handler_async(
  OneShotShelveHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_one_shot_shelve_handler_async",
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
      ShelvedStateMachineTypeTraits::one_shot_shelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_one_shot_shelve_handler_sync(
  OneShotShelveHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_one_shot_shelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_one_shot_shelve_handler_sync(OneShotShelveHandler handler) const
{
  try_set_one_shot_shelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_one_shot_shelve_handler_async(
  OneShotShelveAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_one_shot_shelve_handler_async",
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
      ShelvedStateMachineTypeTraits::one_shot_shelve_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_one_shot_shelve_handler_sync(
  OneShotShelveAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_one_shot_shelve_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_one_shot_shelve_handler_sync(OneShotShelveAsyncHandler handler) const
{
  try_set_one_shot_shelve_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_one_shot_shelve2_handler_async(
  OneShotShelve2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_one_shot_shelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        OneShotShelve2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::one_shot_shelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_one_shot_shelve2_handler_sync(
  OneShotShelve2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_one_shot_shelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_one_shot_shelve2_handler_sync(OneShotShelve2Handler handler) const
{
  try_set_one_shot_shelve2_handler_sync(std::move(handler)).value();
}

void ShelvedStateMachine::set_one_shot_shelve2_handler_async(
  OneShotShelve2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ShelvedStateMachine",
        "ShelvedStateMachine::set_one_shot_shelve2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        OneShotShelve2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ShelvedStateMachineTypeTraits::one_shot_shelve2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ShelvedStateMachine::try_set_one_shot_shelve2_handler_sync(
  OneShotShelve2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_one_shot_shelve2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ShelvedStateMachine::set_one_shot_shelve2_handler_sync(OneShotShelve2AsyncHandler handler) const
{
  try_set_one_shot_shelve2_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void ShelvedStateMachine::unshelved_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::unshelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

StateResult ShelvedStateMachine::try_unshelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { unshelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ShelvedStateMachine::unshelved_sync() const
{
  return ::ua::detail::good_value(try_unshelved_sync());
}

void ShelvedStateMachine::timed_shelved_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::timed_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

StateResult ShelvedStateMachine::try_timed_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { timed_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ShelvedStateMachine::timed_shelved_sync() const
{
  return ::ua::detail::good_value(try_timed_shelved_sync());
}

void ShelvedStateMachine::one_shot_shelved_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ShelvedStateMachineTypeTraits::one_shot_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

StateResult ShelvedStateMachine::try_one_shot_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { one_shot_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ShelvedStateMachine::one_shot_shelved_sync() const
{
  return ::ua::detail::good_value(try_one_shot_shelved_sync());
}

void ShelvedStateMachine::unshelved_to_timed_shelved_async(
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
    ShelvedStateMachineTypeTraits::unshelved_to_timed_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_unshelved_to_timed_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { unshelved_to_timed_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::unshelved_to_timed_shelved_sync() const
{
  return ::ua::detail::good_value(try_unshelved_to_timed_shelved_sync());
}

void ShelvedStateMachine::unshelved_to_one_shot_shelved_async(
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
    ShelvedStateMachineTypeTraits::unshelved_to_one_shot_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_unshelved_to_one_shot_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { unshelved_to_one_shot_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::unshelved_to_one_shot_shelved_sync() const
{
  return ::ua::detail::good_value(try_unshelved_to_one_shot_shelved_sync());
}

void ShelvedStateMachine::timed_shelved_to_unshelved_async(
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
    ShelvedStateMachineTypeTraits::timed_shelved_to_unshelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_timed_shelved_to_unshelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { timed_shelved_to_unshelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::timed_shelved_to_unshelved_sync() const
{
  return ::ua::detail::good_value(try_timed_shelved_to_unshelved_sync());
}

void ShelvedStateMachine::timed_shelved_to_one_shot_shelved_async(
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
    ShelvedStateMachineTypeTraits::timed_shelved_to_one_shot_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_timed_shelved_to_one_shot_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { timed_shelved_to_one_shot_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::timed_shelved_to_one_shot_shelved_sync() const
{
  return ::ua::detail::good_value(try_timed_shelved_to_one_shot_shelved_sync());
}

void ShelvedStateMachine::one_shot_shelved_to_unshelved_async(
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
    ShelvedStateMachineTypeTraits::one_shot_shelved_to_unshelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_one_shot_shelved_to_unshelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { one_shot_shelved_to_unshelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::one_shot_shelved_to_unshelved_sync() const
{
  return ::ua::detail::good_value(try_one_shot_shelved_to_unshelved_sync());
}

void ShelvedStateMachine::one_shot_shelved_to_timed_shelved_async(
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
    ShelvedStateMachineTypeTraits::one_shot_shelved_to_timed_shelved_browse_name(),
    "ShelvedStateMachine",
    std::move(complete));
}

TransitionResult ShelvedStateMachine::try_one_shot_shelved_to_timed_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete)
      { one_shot_shelved_to_timed_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ShelvedStateMachine::one_shot_shelved_to_timed_shelved_sync() const
{
  return ::ua::detail::good_value(try_one_shot_shelved_to_timed_shelved_sync());
}

}  // namespace ua
