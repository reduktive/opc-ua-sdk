// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_group.h"

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

struct CertificateGroupTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::CertificateGroupType};
  }

  static QualifiedName trust_list_browse_name()
  {
    return QualifiedName{0, "TrustList"};
  }

  static QualifiedName certificate_types_browse_name()
  {
    return QualifiedName{0, "CertificateTypes"};
  }

  static QualifiedName purpose_browse_name()
  {
    return QualifiedName{0, "Purpose"};
  }

  static QualifiedName certificate_expired_browse_name()
  {
    return QualifiedName{0, "CertificateExpired"};
  }

  static QualifiedName trust_list_out_of_date_browse_name()
  {
    return QualifiedName{0, "TrustListOutOfDate"};
  }

  static QualifiedName get_rejected_list_browse_name()
  {
    return QualifiedName{0, "GetRejectedList"};
  }
};

}  // namespace

CertificateGroup::CertificateGroup(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void CertificateGroup::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    CertificateGroupTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(CertificateGroupResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(CertificateGroupResult{
        CertificateGroup{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

CertificateGroupResult CertificateGroup::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupResult>(addressSpace.executor(),
      [&](std::function<void(CertificateGroupResult)> complete)
      {
        CertificateGroup::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroup CertificateGroup::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void CertificateGroup::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void CertificateGroup::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // CertificateGroupType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    CertificateGroupTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(CertificateGroupResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(CertificateGroupResult{::ua::detail::address_space_gone("CertificateGroup")});
        return;
      }
      complete(CertificateGroup{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

CertificateGroupResult CertificateGroup::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupResult>(addressSpace.executor(),
      [&](std::function<void(CertificateGroupResult)> complete)
      {
        CertificateGroup::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroup CertificateGroup::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void CertificateGroup::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void CertificateGroup::get_rejected_list_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupTypeTraits::get_rejected_list_browse_name(),
    std::move(complete));
}

MethodAccessorResult CertificateGroup::try_get_rejected_list_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_rejected_list_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor CertificateGroup::get_rejected_list_method_sync() const
{
  return ::ua::detail::good_value(try_get_rejected_list_method_sync());
}

// --- Common property helper ---

void CertificateGroup::find_property_async(
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
    "CertificateGroup",
    std::move(complete));
}

// --- Property accessors ---

void CertificateGroup::certificate_types_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(CertificateGroupTypeTraits::certificate_types_browse_name(), std::move(complete));
}

PropertyResult CertificateGroup::try_certificate_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { certificate_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property CertificateGroup::certificate_types_property_sync() const
{
  return ::ua::detail::good_value(try_certificate_types_property_sync());
}

void CertificateGroup::purpose_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(CertificateGroupTypeTraits::purpose_browse_name(), std::move(complete));
}

PropertyResult CertificateGroup::try_purpose_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { purpose_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property CertificateGroup::purpose_property_sync() const
{
  return ::ua::detail::good_value(try_purpose_property_sync());
}

// --- Typed value read shortcuts ---

void CertificateGroup::read_certificate_types_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    CertificateGroupTypeTraits::certificate_types_browse_name(),
    &Variant::is_node_id,
    {"CertificateGroup", "certificate_types", "CertificateGroup::read_certificate_types_async"},
    std::move(complete));
}

NodeIdResult CertificateGroup::try_read_certificate_types_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_certificate_types_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId CertificateGroup::read_certificate_types_sync() const
{
  return ::ua::detail::good_value(try_read_certificate_types_sync());
}

void CertificateGroup::read_purpose_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    CertificateGroupTypeTraits::purpose_browse_name(),
    &Variant::is_node_id,
    {"CertificateGroup", "purpose", "CertificateGroup::read_purpose_async"},
    std::move(complete));
}

NodeIdResult CertificateGroup::try_read_purpose_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_purpose_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId CertificateGroup::read_purpose_sync() const
{
  return ::ua::detail::good_value(try_read_purpose_sync());
}

// --- Typed value write shortcuts ---

void CertificateGroup::write_certificate_types_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    CertificateGroupTypeTraits::certificate_types_browse_name(),
    "CertificateGroup",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult CertificateGroup::try_write_certificate_types_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_certificate_types_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateGroup::write_certificate_types_sync(NodeId value) const
{
  try_write_certificate_types_sync(value).value();
}

void CertificateGroup::write_purpose_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    CertificateGroupTypeTraits::purpose_browse_name(),
    "CertificateGroup",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult CertificateGroup::try_write_purpose_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_purpose_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateGroup::write_purpose_sync(NodeId value) const
{
  try_write_purpose_sync(value).value();
}

// --- Method handler registration ---

void CertificateGroup::set_get_rejected_list_handler_async(
  GetRejectedListHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "CertificateGroup",
        "CertificateGroup::set_get_rejected_list_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<ByteString>>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<std::vector<ByteString>>
      {
        return detail::method_result_from_struct<std::vector<ByteString>>(handler(call),
          [](const GetRejectedListOutputArguments& out)
          { return std::tuple<std::vector<ByteString>>{out.certificates}; });
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      CertificateGroupTypeTraits::get_rejected_list_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult CertificateGroup::try_set_get_rejected_list_handler_sync(
  GetRejectedListHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_rejected_list_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateGroup::set_get_rejected_list_handler_sync(GetRejectedListHandler handler) const
{
  try_set_get_rejected_list_handler_sync(std::move(handler)).value();
}

void CertificateGroup::set_get_rejected_list_handler_async(
  GetRejectedListAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "CertificateGroup",
        "CertificateGroup::set_get_rejected_list_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<ByteString>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<std::vector<ByteString>> complete)
      {
        handler(call,
          detail::struct_method_result_callback<GetRejectedListOutputArguments>(
            std::move(complete),
            [](const GetRejectedListOutputArguments& out)
            { return std::tuple<std::vector<ByteString>>{out.certificates}; },
            logger,
            call.method_id()));
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      CertificateGroupTypeTraits::get_rejected_list_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult CertificateGroup::try_set_get_rejected_list_handler_sync(
  GetRejectedListAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_rejected_list_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void CertificateGroup::set_get_rejected_list_handler_sync(GetRejectedListAsyncHandler handler) const
{
  try_set_get_rejected_list_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void CertificateGroup::trust_list_async(std::function<void(TrustListResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TrustListResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TrustList>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupTypeTraits::trust_list_browse_name(),
    "CertificateGroup",
    std::move(complete));
}

TrustListResult CertificateGroup::try_trust_list_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TrustListResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TrustListResult)> complete) { trust_list_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TrustList CertificateGroup::trust_list_sync() const
{
  return ::ua::detail::good_value(try_trust_list_sync());
}

void CertificateGroup::certificate_expired_async(
  std::function<void(CertificateExpirationAlarmResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(CertificateExpirationAlarmResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<CertificateExpirationAlarm>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupTypeTraits::certificate_expired_browse_name(),
    "CertificateGroup",
    std::move(complete));
}

CertificateExpirationAlarmResult CertificateGroup::try_certificate_expired_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateExpirationAlarmResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(CertificateExpirationAlarmResult)> complete)
      { certificate_expired_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateExpirationAlarm CertificateGroup::certificate_expired_sync() const
{
  return ::ua::detail::good_value(try_certificate_expired_sync());
}

void CertificateGroup::trust_list_out_of_date_async(
  std::function<void(TrustListOutOfDateAlarmResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TrustListOutOfDateAlarmResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TrustListOutOfDateAlarm>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupTypeTraits::trust_list_out_of_date_browse_name(),
    "CertificateGroup",
    std::move(complete));
}

TrustListOutOfDateAlarmResult CertificateGroup::try_trust_list_out_of_date_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TrustListOutOfDateAlarmResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TrustListOutOfDateAlarmResult)> complete)
      { trust_list_out_of_date_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TrustListOutOfDateAlarm CertificateGroup::trust_list_out_of_date_sync() const
{
  return ::ua::detail::good_value(try_trust_list_out_of_date_sync());
}

}  // namespace ua
