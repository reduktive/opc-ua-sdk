// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_log_object.h"

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

struct LogObjectTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LogObjectType};
  }

  static QualifiedName get_records_browse_name()
  {
    return QualifiedName{0, "GetRecords"};
  }

  static QualifiedName max_records_browse_name()
  {
    return QualifiedName{0, "MaxRecords"};
  }

  static QualifiedName max_storage_duration_browse_name()
  {
    return QualifiedName{0, "MaxStorageDuration"};
  }

  static QualifiedName minimum_severity_browse_name()
  {
    return QualifiedName{0, "MinimumSeverity"};
  }
};

}  // namespace

LogObject::LogObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LogObject::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LogObjectTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LogObjectResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LogObjectResult{
        LogObject{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

LogObjectResult LogObject::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LogObjectResult>(addressSpace.executor(),
      [&](std::function<void(LogObjectResult)> complete)
      {
        LogObject::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LogObject LogObject::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LogObject::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LogObject::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LogObjectType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LogObjectTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LogObjectResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LogObjectResult{::ua::detail::address_space_gone("LogObject")});
        return;
      }
      complete(LogObject{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LogObjectResult LogObject::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LogObjectResult>(addressSpace.executor(),
      [&](std::function<void(LogObjectResult)> complete)
      {
        LogObject::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LogObject LogObject::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LogObject::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void LogObject::get_records_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LogObjectTypeTraits::get_records_browse_name(),
    std::move(complete));
}

MethodAccessorResult LogObject::try_get_records_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_records_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor LogObject::get_records_method_sync() const
{
  return ::ua::detail::good_value(try_get_records_method_sync());
}

// --- Common property helper ---

void LogObject::find_property_async(
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
    "LogObject",
    std::move(complete));
}

// --- Property accessors ---

void LogObject::max_records_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LogObjectTypeTraits::max_records_browse_name(), std::move(complete));
}

PropertyResult LogObject::try_max_records_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { max_records_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LogObject::max_records_property_sync() const
{
  return ::ua::detail::good_value(try_max_records_property_sync());
}

void LogObject::max_storage_duration_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LogObjectTypeTraits::max_storage_duration_browse_name(), std::move(complete));
}

PropertyResult LogObject::try_max_storage_duration_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_storage_duration_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LogObject::max_storage_duration_property_sync() const
{
  return ::ua::detail::good_value(try_max_storage_duration_property_sync());
}

void LogObject::minimum_severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LogObjectTypeTraits::minimum_severity_browse_name(), std::move(complete));
}

PropertyResult LogObject::try_minimum_severity_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { minimum_severity_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LogObject::minimum_severity_property_sync() const
{
  return ::ua::detail::good_value(try_minimum_severity_property_sync());
}

// --- Typed value read shortcuts ---

void LogObject::read_max_records_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    LogObjectTypeTraits::max_records_browse_name(),
    &Variant::is_uint32,
    {"LogObject", "max_records", "LogObject::read_max_records_async"},
    std::move(complete));
}

UInt32Result LogObject::try_read_max_records_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_records_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t LogObject::read_max_records_sync() const
{
  return ::ua::detail::good_value(try_read_max_records_sync());
}

void LogObject::read_minimum_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    LogObjectTypeTraits::minimum_severity_browse_name(),
    &Variant::is_uint16,
    {"LogObject", "minimum_severity", "LogObject::read_minimum_severity_async"},
    std::move(complete));
}

UInt16Result LogObject::try_read_minimum_severity_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_minimum_severity_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t LogObject::read_minimum_severity_sync() const
{
  return ::ua::detail::good_value(try_read_minimum_severity_sync());
}

// --- Typed value write shortcuts ---

void LogObject::write_max_records_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LogObjectTypeTraits::max_records_browse_name(),
    "LogObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LogObject::try_write_max_records_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_max_records_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LogObject::write_max_records_sync(uint32_t value) const
{
  try_write_max_records_sync(value).value();
}

void LogObject::write_minimum_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LogObjectTypeTraits::minimum_severity_browse_name(),
    "LogObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LogObject::try_write_minimum_severity_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_minimum_severity_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LogObject::write_minimum_severity_sync(uint16_t value) const
{
  try_write_minimum_severity_sync(value).value();
}

// --- Method handler registration ---

void LogObject::set_get_records_handler_async(
  GetRecordsHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "LogObject",
        "LogObject::set_get_records_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<DateTime, DateTime, uint32_t, uint16_t, Variant, ByteString>,
      std::tuple<Variant, ByteString>>
      adapter{[handler = std::move(handler)](const MethodCall& call,
                const DateTime& in0,
                const DateTime& in1,
                const uint32_t& in2,
                const uint16_t& in3,
                const Variant& in4,
                const ByteString& in5) -> MethodResult<Variant, ByteString>
        {
          GetRecordsInputArguments typedIn{.startTime = in0,
            .endTime = in1,
            .maxReturnRecords = in2,
            .minimumSeverity = in3,
            .requestMask = in4,
            .continuationPointIn = in5};
          return detail::method_result_from_struct<Variant, ByteString>(handler(call, typedIn),
            [](const GetRecordsOutputArguments& out)
            { return std::tuple<Variant, ByteString>{out.results, out.continuationPointOut}; });
        },
        Inputs<DateTime, DateTime, uint32_t, uint16_t, Variant, ByteString>{
          {Arg<DateTime>{.name = "StartTime"},
            Arg<DateTime>{.name = "EndTime"},
            Arg<uint32_t>{.name = "MaxReturnRecords"},
            Arg<uint16_t>{.name = "MinimumSeverity"},
            Arg<Variant>{.name = "RequestMask"},
            Arg<ByteString>{.name = "ContinuationPointIn"}}},
        mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, LogObjectTypeTraits::get_records_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult LogObject::try_set_get_records_handler_sync(GetRecordsHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_records_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LogObject::set_get_records_handler_sync(GetRecordsHandler handler) const
{
  try_set_get_records_handler_sync(std::move(handler)).value();
}

void LogObject::set_get_records_handler_async(
  GetRecordsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "LogObject",
        "LogObject::set_get_records_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<DateTime, DateTime, uint32_t, uint16_t, Variant, ByteString>,
      std::tuple<Variant, ByteString>>
      adapter{[handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
                const DateTime& in0,
                const DateTime& in1,
                const uint32_t& in2,
                const uint16_t& in3,
                const Variant& in4,
                const ByteString& in5,
                MethodResultCallback<Variant, ByteString>
                  complete)
        {
          GetRecordsInputArguments typedIn{.startTime = in0,
            .endTime = in1,
            .maxReturnRecords = in2,
            .minimumSeverity = in3,
            .requestMask = in4,
            .continuationPointIn = in5};
          handler(call,
            typedIn,
            detail::struct_method_result_callback<GetRecordsOutputArguments>(
              std::move(complete),
              [](const GetRecordsOutputArguments& out)
              { return std::tuple<Variant, ByteString>{out.results, out.continuationPointOut}; },
              logger,
              call.method_id()));
        },
        Inputs<DateTime, DateTime, uint32_t, uint16_t, Variant, ByteString>{
          {Arg<DateTime>{.name = "StartTime"},
            Arg<DateTime>{.name = "EndTime"},
            Arg<uint32_t>{.name = "MaxReturnRecords"},
            Arg<uint16_t>{.name = "MinimumSeverity"},
            Arg<Variant>{.name = "RequestMask"},
            Arg<ByteString>{.name = "ContinuationPointIn"}}},
        mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, LogObjectTypeTraits::get_records_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult LogObject::try_set_get_records_handler_sync(GetRecordsAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_records_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LogObject::set_get_records_handler_sync(GetRecordsAsyncHandler handler) const
{
  try_set_get_records_handler_sync(std::move(handler)).value();
}

}  // namespace ua
