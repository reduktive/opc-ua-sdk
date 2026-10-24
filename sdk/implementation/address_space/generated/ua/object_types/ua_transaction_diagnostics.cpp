// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_transaction_diagnostics.h"

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

struct TransactionDiagnosticsTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::TransactionDiagnosticsType};
  }

  static QualifiedName start_time_browse_name()
  {
    return QualifiedName{0, "StartTime"};
  }

  static QualifiedName end_time_browse_name()
  {
    return QualifiedName{0, "EndTime"};
  }

  static QualifiedName result_browse_name()
  {
    return QualifiedName{0, "Result"};
  }

  static QualifiedName affected_trust_lists_browse_name()
  {
    return QualifiedName{0, "AffectedTrustLists"};
  }

  static QualifiedName affected_certificate_groups_browse_name()
  {
    return QualifiedName{0, "AffectedCertificateGroups"};
  }

  static QualifiedName errors_browse_name()
  {
    return QualifiedName{0, "Errors"};
  }
};

}  // namespace

TransactionDiagnostics::TransactionDiagnostics(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TransactionDiagnostics::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TransactionDiagnosticsTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TransactionDiagnosticsResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TransactionDiagnosticsResult{
        TransactionDiagnostics{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

TransactionDiagnosticsResult TransactionDiagnostics::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransactionDiagnosticsResult>(addressSpace.executor(),
      [&](std::function<void(TransactionDiagnosticsResult)> complete)
      {
        TransactionDiagnostics::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TransactionDiagnostics TransactionDiagnostics::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void TransactionDiagnostics::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void TransactionDiagnostics::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TransactionDiagnosticsType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    TransactionDiagnosticsTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TransactionDiagnosticsResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TransactionDiagnosticsResult{::ua::detail::address_space_gone("TransactionDiagnostics")});
        return;
      }
      complete(
        TransactionDiagnostics{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TransactionDiagnosticsResult TransactionDiagnostics::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransactionDiagnosticsResult>(addressSpace.executor(),
      [&](std::function<void(TransactionDiagnosticsResult)> complete)
      {
        TransactionDiagnostics::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TransactionDiagnostics TransactionDiagnostics::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TransactionDiagnostics::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void TransactionDiagnostics::find_property_async(
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
    "TransactionDiagnostics",
    std::move(complete));
}

// --- Property accessors ---

void TransactionDiagnostics::start_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransactionDiagnosticsTypeTraits::start_time_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_start_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { start_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::start_time_property_sync() const
{
  return ::ua::detail::good_value(try_start_time_property_sync());
}

void TransactionDiagnostics::end_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransactionDiagnosticsTypeTraits::end_time_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_end_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { end_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::end_time_property_sync() const
{
  return ::ua::detail::good_value(try_end_time_property_sync());
}

void TransactionDiagnostics::result_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransactionDiagnosticsTypeTraits::result_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_result_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { result_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::result_property_sync() const
{
  return ::ua::detail::good_value(try_result_property_sync());
}

void TransactionDiagnostics::affected_trust_lists_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    TransactionDiagnosticsTypeTraits::affected_trust_lists_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_affected_trust_lists_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { affected_trust_lists_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::affected_trust_lists_property_sync() const
{
  return ::ua::detail::good_value(try_affected_trust_lists_property_sync());
}

void TransactionDiagnostics::affected_certificate_groups_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    TransactionDiagnosticsTypeTraits::affected_certificate_groups_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_affected_certificate_groups_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { affected_certificate_groups_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::affected_certificate_groups_property_sync() const
{
  return ::ua::detail::good_value(try_affected_certificate_groups_property_sync());
}

void TransactionDiagnostics::errors_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransactionDiagnosticsTypeTraits::errors_browse_name(), std::move(complete));
}

PropertyResult TransactionDiagnostics::try_errors_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { errors_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TransactionDiagnostics::errors_property_sync() const
{
  return ::ua::detail::good_value(try_errors_property_sync());
}

// --- Typed value read shortcuts ---

void TransactionDiagnostics::read_result_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::result_browse_name(),
    &Variant::is_status_code,
    {"TransactionDiagnostics", "result", "TransactionDiagnostics::read_result_async"},
    std::move(complete));
}

Result<StatusCode> TransactionDiagnostics::try_read_result_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<StatusCode>>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Result<StatusCode>)> complete) { read_result_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StatusCode TransactionDiagnostics::read_result_sync() const
{
  return ::ua::detail::good_value(try_read_result_sync());
}

void TransactionDiagnostics::read_affected_trust_lists_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::affected_trust_lists_browse_name(),
    &Variant::is_node_id,
    {"TransactionDiagnostics",
      "affected_trust_lists",
      "TransactionDiagnostics::read_affected_trust_lists_async"},
    std::move(complete));
}

NodeIdResult TransactionDiagnostics::try_read_affected_trust_lists_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_affected_trust_lists_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId TransactionDiagnostics::read_affected_trust_lists_sync() const
{
  return ::ua::detail::good_value(try_read_affected_trust_lists_sync());
}

void TransactionDiagnostics::read_affected_certificate_groups_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::affected_certificate_groups_browse_name(),
    &Variant::is_node_id,
    {"TransactionDiagnostics",
      "affected_certificate_groups",
      "TransactionDiagnostics::read_affected_certificate_groups_async"},
    std::move(complete));
}

NodeIdResult TransactionDiagnostics::try_read_affected_certificate_groups_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_affected_certificate_groups_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId TransactionDiagnostics::read_affected_certificate_groups_sync() const
{
  return ::ua::detail::good_value(try_read_affected_certificate_groups_sync());
}

// --- Typed value write shortcuts ---

void TransactionDiagnostics::write_result_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::result_browse_name(),
    "TransactionDiagnostics",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TransactionDiagnostics::try_write_result_sync(StatusCode value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_result_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TransactionDiagnostics::write_result_sync(StatusCode value) const
{
  try_write_result_sync(value).value();
}

void TransactionDiagnostics::write_affected_trust_lists_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::affected_trust_lists_browse_name(),
    "TransactionDiagnostics",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TransactionDiagnostics::try_write_affected_trust_lists_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_affected_trust_lists_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TransactionDiagnostics::write_affected_trust_lists_sync(NodeId value) const
{
  try_write_affected_trust_lists_sync(value).value();
}

void TransactionDiagnostics::write_affected_certificate_groups_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TransactionDiagnosticsTypeTraits::affected_certificate_groups_browse_name(),
    "TransactionDiagnostics",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TransactionDiagnostics::try_write_affected_certificate_groups_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_affected_certificate_groups_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TransactionDiagnostics::write_affected_certificate_groups_sync(NodeId value) const
{
  try_write_affected_certificate_groups_sync(value).value();
}

}  // namespace ua
