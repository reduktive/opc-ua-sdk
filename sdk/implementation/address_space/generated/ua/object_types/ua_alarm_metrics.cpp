// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_metrics.h"

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

struct AlarmMetricsTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AlarmMetricsType};
  }

  static QualifiedName alarm_count_browse_name()
  {
    return QualifiedName{0, "AlarmCount"};
  }

  static QualifiedName start_time_browse_name()
  {
    return QualifiedName{0, "StartTime"};
  }

  static QualifiedName maximum_active_state_browse_name()
  {
    return QualifiedName{0, "MaximumActiveState"};
  }

  static QualifiedName maximum_un_ack_browse_name()
  {
    return QualifiedName{0, "MaximumUnAck"};
  }

  static QualifiedName current_alarm_rate_browse_name()
  {
    return QualifiedName{0, "CurrentAlarmRate"};
  }

  static QualifiedName maximum_alarm_rate_browse_name()
  {
    return QualifiedName{0, "MaximumAlarmRate"};
  }

  static QualifiedName maximum_re_alarm_count_browse_name()
  {
    return QualifiedName{0, "MaximumReAlarmCount"};
  }

  static QualifiedName average_alarm_rate_browse_name()
  {
    return QualifiedName{0, "AverageAlarmRate"};
  }

  static QualifiedName reset_browse_name()
  {
    return QualifiedName{0, "Reset"};
  }
};

}  // namespace

AlarmMetrics::AlarmMetrics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AlarmMetrics::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AlarmMetricsTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AlarmMetricsResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AlarmMetricsResult{
        AlarmMetrics{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

AlarmMetricsResult AlarmMetrics::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmMetricsResult>(addressSpace.executor(),
      [&](std::function<void(AlarmMetricsResult)> complete)
      {
        AlarmMetrics::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmMetrics AlarmMetrics::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AlarmMetrics::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AlarmMetrics::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AlarmMetricsType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AlarmMetricsTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AlarmMetricsResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AlarmMetricsResult{::ua::detail::address_space_gone("AlarmMetrics")});
        return;
      }
      complete(AlarmMetrics{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AlarmMetricsResult AlarmMetrics::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmMetricsResult>(addressSpace.executor(),
      [&](std::function<void(AlarmMetricsResult)> complete)
      {
        AlarmMetrics::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmMetrics AlarmMetrics::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AlarmMetrics::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void AlarmMetrics::reset_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::reset_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmMetrics::try_reset_method_sync() const noexcept
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

MethodAccessor AlarmMetrics::reset_method_sync() const
{
  return ::ua::detail::good_value(try_reset_method_sync());
}

// --- Method handler registration ---

void AlarmMetrics::set_reset_handler_async(
  ResetHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmMetrics",
        "AlarmMetrics::set_reset_handler_async",
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
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmMetricsTypeTraits::reset_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmMetrics::try_set_reset_handler_sync(ResetHandler handler) const noexcept
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

void AlarmMetrics::set_reset_handler_sync(ResetHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

void AlarmMetrics::set_reset_handler_async(
  ResetAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmMetrics",
        "AlarmMetrics::set_reset_handler_async",
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
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmMetricsTypeTraits::reset_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmMetrics::try_set_reset_handler_sync(ResetAsyncHandler handler) const noexcept
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

void AlarmMetrics::set_reset_handler_sync(ResetAsyncHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void AlarmMetrics::alarm_count_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::alarm_count_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

BaseDataVariableResult AlarmMetrics::try_alarm_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { alarm_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmMetrics::alarm_count_sync() const
{
  return ::ua::detail::good_value(try_alarm_count_sync());
}

void AlarmMetrics::start_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::start_time_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

BaseDataVariableResult AlarmMetrics::try_start_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { start_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmMetrics::start_time_sync() const
{
  return ::ua::detail::good_value(try_start_time_sync());
}

void AlarmMetrics::maximum_active_state_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::maximum_active_state_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

BaseDataVariableResult AlarmMetrics::try_maximum_active_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { maximum_active_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmMetrics::maximum_active_state_sync() const
{
  return ::ua::detail::good_value(try_maximum_active_state_sync());
}

void AlarmMetrics::maximum_un_ack_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::maximum_un_ack_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

BaseDataVariableResult AlarmMetrics::try_maximum_un_ack_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { maximum_un_ack_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmMetrics::maximum_un_ack_sync() const
{
  return ::ua::detail::good_value(try_maximum_un_ack_sync());
}

void AlarmMetrics::current_alarm_rate_async(
  std::function<void(AlarmRateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AlarmRateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AlarmRateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::current_alarm_rate_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

AlarmRateVariableResult AlarmMetrics::try_current_alarm_rate_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmRateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AlarmRateVariableResult)> complete)
      { current_alarm_rate_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmRateVariable AlarmMetrics::current_alarm_rate_sync() const
{
  return ::ua::detail::good_value(try_current_alarm_rate_sync());
}

void AlarmMetrics::maximum_alarm_rate_async(
  std::function<void(AlarmRateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AlarmRateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AlarmRateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::maximum_alarm_rate_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

AlarmRateVariableResult AlarmMetrics::try_maximum_alarm_rate_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmRateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AlarmRateVariableResult)> complete)
      { maximum_alarm_rate_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmRateVariable AlarmMetrics::maximum_alarm_rate_sync() const
{
  return ::ua::detail::good_value(try_maximum_alarm_rate_sync());
}

void AlarmMetrics::maximum_re_alarm_count_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::maximum_re_alarm_count_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

BaseDataVariableResult AlarmMetrics::try_maximum_re_alarm_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { maximum_re_alarm_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmMetrics::maximum_re_alarm_count_sync() const
{
  return ::ua::detail::good_value(try_maximum_re_alarm_count_sync());
}

void AlarmMetrics::average_alarm_rate_async(
  std::function<void(AlarmRateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AlarmRateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AlarmRateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmMetricsTypeTraits::average_alarm_rate_browse_name(),
    "AlarmMetrics",
    std::move(complete));
}

AlarmRateVariableResult AlarmMetrics::try_average_alarm_rate_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmRateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AlarmRateVariableResult)> complete)
      { average_alarm_rate_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmRateVariable AlarmMetrics::average_alarm_rate_sync() const
{
  return ::ua::detail::good_value(try_average_alarm_rate_sync());
}

}  // namespace ua
